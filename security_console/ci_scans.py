"""Machine CI API: enqueue project scans and poll with a severity policy."""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.access import (
    expand_sonar_findings,
    find_reusable_scan,
    present_scan,
    severity_bucket,
    severity_counts,
)
from security_console.audit import record
from security_console.images import valid_image_ref
from security_console.queue import QUEUE_CAP, attach_queue_position
from security_console.repos import normalize_commit_sha, valid_repo

Reply = Response | tuple[Response, int]

log = logging.getLogger("security_console")

_REPO_TOOLS = ("semgrep", "checkov", "sonar", "trivy")
_ALLOWED = frozenset(_REPO_TOOLS)

_lock: threading.Lock | None = None
_scans: dict[str, dict[str, Any]] | None = None
_save: Callable[[dict[str, Any]], None] | None = None
_utcnow: Callable[[], str] | None = None


def bind_ci_store(
    lock: threading.Lock,
    scans: dict[str, dict[str, Any]],
    save: Callable[[dict[str, Any]], None],
    utcnow: Callable[[], str],
) -> None:
    """Attach the console scan map used when CI enqueues work."""

    global _lock, _scans, _save, _utcnow
    _lock = lock
    _scans = scans
    _save = save
    _utcnow = utcnow


def evaluate_ci_policy(scan: dict[str, Any]) -> dict[str, Any]:
    """Return CI pass/fail from terminal scan state and finding severities.

    While queued/running, ``passed`` is null and ``pending`` is true.
    """

    status = str(scan.get("status") or "").strip().lower()
    if status not in {"done", "failed"}:
        return {"pending": True, "passed": None, "reasons": []}

    reasons: list[str] = []
    if status == "failed":
        reasons.append("scan_failed")

    requested = [
        str(tool).strip().lower()
        for tool in (scan.get("tools") or [])
        if str(tool).strip().lower() in _ALLOWED
    ]
    by_tool = {
        str(row.get("tool") or "").strip().lower(): row
        for row in (scan.get("tool_results") or [])
        if isinstance(row, dict) and row.get("tool")
    }
    for tool in requested:
        row = by_tool.get(tool)
        if row is not None and str(row.get("status") or "").lower() == "failed":
            reasons.append(f"tool_failed:{tool}")

    findings = list(scan.get("findings") or [])
    if not any(str(row.get("tool") or "") == "sonar" for row in findings):
        findings = findings + expand_sonar_findings(
            scan.get("sonar") if isinstance(scan.get("sonar"), dict) else None
        )
    buckets = severity_counts(findings)
    if buckets.get("critical", 0) > 0:
        reasons.append("severity_critical")
    if buckets.get("high", 0) > 0:
        reasons.append("severity_high")

    sonar = scan.get("sonar") if isinstance(scan.get("sonar"), dict) else None
    if sonar is not None:
        gate = str(sonar.get("quality_gate") or "").strip().upper()
        if gate == "ERROR":
            reasons.append("sonar_quality_gate_error")

    # Deduplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            ordered.append(reason)

    return {
        "pending": False,
        "passed": len(ordered) == 0 and status == "done",
        "reasons": ordered,
    }


def install_ci_scans(app: Flask) -> None:
    """Attach CI scan routes (authenticated via CI_SCAN_TOKEN in auth guard)."""

    @app.post("/api/ci/scans")
    def ci_create_scan() -> Reply:
        return _call(app, _create)

    @app.get("/api/ci/scans/<scan_id>")
    def ci_get_scan(scan_id: str) -> Reply:
        return _call(app, lambda: _get(scan_id))


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.exception("ci scan request failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _ci_user() -> dict[str, Any]:
    user = getattr(g, "user", None)
    if isinstance(user, dict) and user.get("username") == "ci":
        return user
    return {
        "id": 0,
        "username": "ci",
        "role": "super_admin",
        "capabilities": {},
    }


def _default_tools(target: str, requested: list[str]) -> list[str]:
    if target == "image":
        return ["trivy"]
    if requested:
        return [tool for tool in requested if tool in _ALLOWED]
    return list(_REPO_TOOLS)


def _parse_create_body(
    body: Any,
) -> tuple[dict[str, Any] | None, str, int]:
    if not isinstance(body, dict):
        return None, "Invalid scan.", 400
    slug = str(body.get("project") or "").strip().lower()
    if not slug:
        return None, "project is required.", 400
    target = str(body.get("target") or "repo").strip().lower()
    if target not in {"repo", "image"}:
        return None, "Invalid scan type.", 400
    raw_tools = body.get("tools")
    if raw_tools is None:
        tools = _default_tools(target, [])
    elif not isinstance(raw_tools, list):
        return None, "Tools must be a list.", 400
    else:
        tools = []
        for item in raw_tools:
            if not isinstance(item, str) or item not in _ALLOWED:
                return None, "One or more tools are invalid.", 400
            if item not in tools:
                tools.append(item)
        tools = _default_tools(target, tools)
        if target == "image" and tools != ["trivy"]:
            return None, "Image scans run with Trivy only.", 400
        if target == "repo" and not tools:
            return None, "Select at least one tool.", 400

    project = db.get_project_by_slug(slug)
    if project is None:
        return None, "Project not found.", 404
    kind_targets = [
        item
        for item in project.get("targets") or []
        if item.get("kind") == target
    ]
    if not kind_targets:
        return None, "This project has no " + target + " target.", 400
    want = (
        (body.get("image") or "").strip()
        if target == "image"
        else (body.get("repo") or "").strip()
    )
    chosen = None
    if want:
        for item in kind_targets:
            if str(item.get("target") or "") == want:
                chosen = item
                break
        if chosen is None:
            return None, "That target is not part of this project.", 400
    else:
        chosen = kind_targets[0]
    if target == "image":
        image = str(chosen.get("target") or "")
        repo = ""
        if not valid_image_ref(image):
            return None, "Image name is invalid. Use a name like nginx:1.27.", 400
    else:
        repo = str(chosen.get("target") or "")
        image = ""
        if not valid_repo(repo):
            return None, "Repository URL must start with http or https.", 400

    requested_sha = normalize_commit_sha(body.get("requested_sha"))
    if requested_sha is None:
        return None, "Commit SHA is invalid.", 400
    if target == "image" and requested_sha:
        return None, "Image scans do not take a commit.", 400

    return {
        "project": project,
        "target": target,
        "repo": repo,
        "image": image,
        "tools": tools,
        "requested_sha": requested_sha,
        "force": bool(body.get("force")),
    }, "", 200


def _create() -> Reply:
    if _lock is None or _scans is None or _save is None or _utcnow is None:
        return jsonify({"error": "CI scan API is not ready."}), 503
    parsed, error, code = _parse_create_body(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), code

    project = parsed["project"]
    user = _ci_user()
    with _lock:
        items = list(_scans.values())
        reusable = find_reusable_scan(
            user,
            items,
            target=parsed["target"],
            repo=parsed["repo"],
            image=parsed["image"],
            tools=parsed["tools"],
            requested_sha=parsed["requested_sha"],
            group_keys=None,
            force=parsed["force"],
        )
        if reusable is not None:
            item, reason = reusable
            shown = _public_scan(user, item)
            if shown is None:
                return jsonify({"error": "Not found"}), 404
            shown["reused"] = True
            shown["reuse_reason"] = reason
            return jsonify(shown), 200
        queued_count = sum(1 for row in items if row.get("status") == "queued")
        if queued_count >= QUEUE_CAP:
            return jsonify(
                {
                    "error": (
                        "Too many scans are waiting. "
                        "Try again when the queue is shorter."
                    )
                }
            ), 429
        scan_id = uuid.uuid4().hex[:12]
        item = {
            "id": scan_id,
            "target": parsed["target"],
            "repo": parsed["repo"],
            "image": parsed["image"],
            "tools": parsed["tools"],
            "status": "queued",
            "findings": [],
            "sonar": None,
            "phase": "",
            "error": "",
            "created_at": _utcnow(),
            "finished_at": "",
            "started_at": "",
            "owner": "ci",
            "requested_sha": parsed["requested_sha"],
            "commit_sha": "",
            "failure_reason": "",
            "priority": 0,
            "project_id": int(project["id"]),
            "project_slug": str(project.get("slug") or ""),
            "project_name": str(project.get("name") or project.get("slug") or ""),
        }
        _scans[scan_id] = item
        _save(item)
        shown = _public_scan(user, item)
    record(
        action="ci.scan.create",
        target_type="project",
        target_id=str(project.get("slug") or ""),
        detail={
            "scan_id": scan_id,
            "target": parsed["target"],
            "tools": parsed["tools"],
            "requested_sha": parsed["requested_sha"],
        },
    )
    return jsonify(shown or attach_queue_position(item, list(_scans.values()))), 202


def _get(scan_id: str) -> Reply:
    if _lock is None or _scans is None:
        return jsonify({"error": "CI scan API is not ready."}), 503
    text = str(scan_id or "").strip().lower()
    if not text or len(text) > 64:
        return jsonify({"error": "Not found"}), 404
    with _lock:
        item = _scans.get(text)
        if item is None:
            return jsonify({"error": "Not found"}), 404
        item = attach_queue_position(item, list(_scans.values()))
    shown = _public_scan(_ci_user(), item)
    if shown is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(shown)


def _public_scan(user: dict[str, Any], item: dict[str, Any]) -> dict[str, Any] | None:
    shown = present_scan(
        user,
        attach_queue_position(item, list(_scans.values()) if _scans else [item]),
        summary=False,
        group_keys=None,
    )
    if shown is None:
        return None
    # Policy uses the in-memory row (full findings) before capability filter gaps.
    policy = evaluate_ci_policy(item)
    findings = list(shown.get("findings") or [])
    shown["severity"] = severity_counts(findings)
    shown["policy"] = policy
    if isinstance(shown.get("sonar"), dict):
        sonar = shown["sonar"]
        shown["sonar"] = {
            "project_key": sonar.get("project_key") or "",
            "quality_gate": sonar.get("quality_gate") or "",
            "url": sonar.get("url") or "",
            "bugs": sonar.get("bugs"),
            "vulnerabilities": sonar.get("vulnerabilities"),
            "code_smells": sonar.get("code_smells"),
            "security_hotspots": sonar.get("security_hotspots"),
            "error": sonar.get("error") or "",
        }
    return shown
