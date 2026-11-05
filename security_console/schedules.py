"""Per-project scan schedules: admin API and console ticker."""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.audit import record
from security_console.authz import can_manage_all_projects
from security_console.images import valid_image_ref
from security_console.queue import QUEUE_CAP
from security_console.repos import valid_repo

Reply = Response | tuple[Response, int]

log = logging.getLogger("security_console")

_ALLOWED_TOOLS = frozenset({"semgrep", "checkov", "sonar", "trivy"})
_MIN_DAYS = 1
_MAX_DAYS = 90
_POLL_SECONDS = 60.0
_QUEUE_RETRY = timedelta(hours=1)

_stop = threading.Event()
_thread: threading.Thread | None = None
_lock: threading.Lock | None = None
_scans: dict[str, dict[str, Any]] | None = None
_save: Callable[[dict[str, Any]], None] | None = None
_utcnow: Callable[[], str] | None = None


def bind_schedule_store(
    lock: threading.Lock,
    scans: dict[str, dict[str, Any]],
    save: Callable[[dict[str, Any]], None],
    utcnow: Callable[[], str],
) -> None:
    """Attach the console scan map used when the ticker enqueues work."""

    global _lock, _scans, _save, _utcnow
    _lock = lock
    _scans = scans
    _save = save
    _utcnow = utcnow


def start_schedule_ticker() -> None:
    """Start the background loop that enqueues due project schedules."""

    global _thread
    if _thread is not None and _thread.is_alive():
        return
    if _lock is None or _scans is None or _save is None or _utcnow is None:
        raise RuntimeError("schedule store is not bound")
    _stop.clear()

    def loop() -> None:
        while not _stop.is_set():
            try:
                _tick_once()
            except Exception:
                log.exception("schedule ticker failed")
            _stop.wait(_POLL_SECONDS)

    _thread = threading.Thread(target=loop, name="scan-schedules", daemon=True)
    _thread.start()


def stop_schedule_ticker() -> None:
    """Stop the background loop. Used by tests."""

    _stop.set()
    global _thread
    if _thread is not None:
        _thread.join(timeout=5)
        _thread = None


def parse_schedule_body(body: Any) -> tuple[dict[str, Any] | None, str]:
    """Validate schedule upsert fields. Error is empty when valid."""

    if not isinstance(body, dict):
        return None, "Schedule details are incomplete."
    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        return None, "Enabled must be true or false."
    try:
        interval_days = int(body.get("interval_days"))
    except (TypeError, ValueError):
        return None, "Interval days must be a whole number."
    if interval_days < _MIN_DAYS or interval_days > _MAX_DAYS:
        return None, f"Interval days must be between {_MIN_DAYS} and {_MAX_DAYS}."
    raw_tools = body.get("tools")
    if raw_tools is None:
        tools: list[str] = []
    elif not isinstance(raw_tools, list):
        return None, "Tools must be a list."
    else:
        tools = []
        for item in raw_tools:
            if not isinstance(item, str) or item not in _ALLOWED_TOOLS:
                return None, "One or more tools are invalid."
            if item not in tools:
                tools.append(item)
    return {
        "enabled": enabled,
        "interval_days": interval_days,
        "tools": tools,
    }, ""


def tools_for_target(kind: str, tools: list[str]) -> list[str]:
    """Return the tools that apply to one target kind."""

    if kind == "image":
        chosen = [tool for tool in tools if tool == "trivy"]
        return chosen or ["trivy"]
    chosen = [tool for tool in tools if tool in {"semgrep", "checkov", "sonar"}]
    return chosen or ["semgrep", "checkov", "sonar"]


def enqueue_project_targets(
    project: dict[str, Any],
    tools: list[str],
    *,
    advance_last_enqueued: bool = True,
) -> dict[str, Any]:
    """Queue one scan per project target. Respects QUEUE_CAP and busy skips.

    Returns counts: ``enqueued``, ``skipped``, ``invalid``, and ``queue_full``.
    """

    if _lock is None or _scans is None or _save is None or _utcnow is None:
        raise RuntimeError("schedule store is not bound")

    project_id = int(project["id"])
    project_slug = str(project.get("slug") or "")
    project_name = str(project.get("name") or project_slug)
    targets = list(project.get("targets") or [])
    enqueued = 0
    skipped = 0
    invalid = 0
    queue_full = False
    created: list[dict[str, Any]] = []

    with _lock:
        items = list(_scans.values())
        queued_count = sum(1 for row in items if row.get("status") == "queued")

        for target in targets:
            kind = str(target.get("kind") or "")
            value = str(target.get("target") or "").strip()
            if kind == "image":
                if not valid_image_ref(value):
                    invalid += 1
                    continue
                repo = ""
                image = value
            elif kind == "repo":
                if not valid_repo(value):
                    invalid += 1
                    continue
                repo = value
                image = ""
            else:
                invalid += 1
                continue

            busy = any(
                row.get("project_id") == project_id
                and row.get("status") in {"queued", "running"}
                and (
                    (kind == "repo" and str(row.get("repo") or "") == repo)
                    or (kind == "image" and str(row.get("image") or "") == image)
                )
                for row in items
            )
            if busy:
                skipped += 1
                continue

            if queued_count >= QUEUE_CAP:
                queue_full = True
                break

            scan_tools = tools_for_target(kind, tools)
            scan_id = uuid.uuid4().hex[:12]
            item = {
                "id": scan_id,
                "target": kind,
                "repo": repo,
                "image": image,
                "tools": scan_tools,
                "status": "queued",
                "findings": [],
                "sonar": None,
                "phase": "",
                "error": "",
                "created_at": _utcnow(),
                "finished_at": "",
                "owner": "schedule",
                "requested_sha": "",
                "commit_sha": "",
                "failure_reason": "",
                "priority": -1,
                "project_id": project_id,
                "project_slug": project_slug,
                "project_name": project_name,
            }
            _scans[scan_id] = item
            _save(item)
            items.append(item)
            created.append(item)
            queued_count += 1
            enqueued += 1

    return {
        "enqueued": enqueued,
        "skipped": skipped,
        "invalid": invalid,
        "queue_full": queue_full,
        "scans": created,
        "advance_last_enqueued": advance_last_enqueued,
    }


def _tick_once() -> None:
    due = db.list_due_schedules(limit=10)
    for schedule in due:
        project = {
            "id": schedule["project_id"],
            "slug": schedule.get("project_slug") or "",
            "name": schedule.get("project_name") or "",
            "targets": list(schedule.get("targets") or []),
        }
        if not project["targets"]:
            db.bump_schedule_next_run(
                int(schedule["id"]),
                delay=timedelta(days=int(schedule["interval_days"])),
                mark_enqueued=False,
            )
            continue
        result = enqueue_project_targets(
            project,
            list(schedule.get("tools") or []),
        )
        if result["enqueued"] == 0 and result["queue_full"]:
            db.bump_schedule_next_run(
                int(schedule["id"]),
                delay=_QUEUE_RETRY,
                mark_enqueued=False,
            )
            continue
        db.bump_schedule_next_run(
            int(schedule["id"]),
            delay=timedelta(days=int(schedule["interval_days"])),
            mark_enqueued=result["enqueued"] > 0,
        )


def install_schedules(app: Flask) -> None:
    """Attach schedule routes. Mutations require projects.manage_all."""

    @app.get("/api/schedules")
    def list_schedules() -> Reply:
        return _call(app, _list_schedules)

    @app.put("/api/schedules/<slug>")
    def upsert_schedule(slug: str) -> Reply:
        return _call(app, lambda: _upsert_schedule(slug))

    @app.delete("/api/schedules/<slug>")
    def delete_schedule(slug: str) -> Reply:
        return _call(app, lambda: _delete_schedule(slug))

    @app.post("/api/schedules/<slug>/run")
    def run_schedule(slug: str) -> Reply:
        return _call(app, lambda: _run_schedule(slug))


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.exception("schedule request failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _require_manage() -> Reply | None:
    user = getattr(g, "user", None)
    if not isinstance(user, dict) or not can_manage_all_projects(user):
        return jsonify({"error": "You do not have permission."}), 403
    return None


def _public_schedule(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "project_id": row["project_id"],
        "project_slug": row.get("project_slug") or "",
        "project_name": row.get("project_name") or "",
        "target_count": int(row.get("target_count") or 0),
        "enabled": bool(row.get("enabled")),
        "interval_days": int(row["interval_days"]),
        "tools": list(row.get("tools") or []),
        "next_run_at": row.get("next_run_at") or "",
        "last_enqueued_at": row.get("last_enqueued_at") or "",
        "created_at": row.get("created_at") or "",
        "updated_at": row.get("updated_at") or "",
    }


def _list_schedules() -> Reply:
    denied = _require_manage()
    if denied is not None:
        return denied
    rows = db.list_project_schedules()
    return jsonify([_public_schedule(row) for row in rows])


def _upsert_schedule(slug: str) -> Reply:
    denied = _require_manage()
    if denied is not None:
        return denied
    project = db.get_project_by_slug(str(slug or "").strip().lower())
    if project is None:
        return jsonify({"error": "Project not found."}), 404
    parsed, error = parse_schedule_body(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), 400
    user = g.user
    existing = db.get_schedule_by_project_id(int(project["id"]))
    reset_next = False
    if existing is None:
        reset_next = bool(parsed["enabled"])
    else:
        if parsed["enabled"] and not existing.get("enabled"):
            reset_next = True
        if int(parsed["interval_days"]) != int(existing.get("interval_days") or 0):
            reset_next = True
    row = db.upsert_project_schedule(
        project_id=int(project["id"]),
        enabled=bool(parsed["enabled"]),
        interval_days=int(parsed["interval_days"]),
        tools=list(parsed["tools"]),
        user_id=int(user["id"]) if user.get("id") is not None else None,
        reset_next_run=reset_next,
    )
    record(
        action="schedule.upsert",
        target_type="project",
        target_id=str(project.get("slug") or ""),
        detail={
            "enabled": parsed["enabled"],
            "interval_days": parsed["interval_days"],
            "tools": parsed["tools"],
        },
    )
    return jsonify(_public_schedule(row))


def _delete_schedule(slug: str) -> Reply:
    denied = _require_manage()
    if denied is not None:
        return denied
    project = db.get_project_by_slug(str(slug or "").strip().lower())
    if project is None:
        return jsonify({"error": "Project not found."}), 404
    removed = db.delete_project_schedule(int(project["id"]))
    if not removed:
        return jsonify({"error": "Schedule not found."}), 404
    record(
        action="schedule.delete",
        target_type="project",
        target_id=str(project.get("slug") or ""),
    )
    return jsonify({"ok": True})


def _run_schedule(slug: str) -> Reply:
    denied = _require_manage()
    if denied is not None:
        return denied
    project = db.get_project_by_slug(str(slug or "").strip().lower())
    if project is None:
        return jsonify({"error": "Project not found."}), 404
    schedule = db.get_schedule_by_project_id(int(project["id"]))
    tools = list(schedule.get("tools") or []) if schedule else []
    if not project.get("targets"):
        return jsonify({"error": "This project has no targets."}), 400
    if _lock is None or _scans is None or _save is None or _utcnow is None:
        return jsonify({"error": "Scheduler is not ready."}), 503
    result = enqueue_project_targets(
        project,
        tools,
        advance_last_enqueued=True,
    )
    if result["enqueued"] == 0 and result["queue_full"]:
        return jsonify(
            {
                "error": (
                    "Too many scans are waiting. "
                    "Try again when the queue is shorter."
                )
            }
        ), 429
    if result["enqueued"] > 0 and schedule is not None:
        db.touch_schedule_enqueued(int(schedule["id"]))
    record(
        action="schedule.run",
        target_type="project",
        target_id=str(project.get("slug") or ""),
        detail={
            "enqueued": result["enqueued"],
            "skipped": result["skipped"],
            "invalid": result["invalid"],
        },
    )
    return jsonify(
        {
            "enqueued": result["enqueued"],
            "skipped": result["skipped"],
            "invalid": result["invalid"],
            "scan_ids": [item["id"] for item in result["scans"]],
        }
    ), 202
