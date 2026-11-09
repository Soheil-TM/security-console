"""Machine CI API: enqueue project scans and poll with a severity policy."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.access import (
    expand_sonar_findings,
    find_reusable_scan,
    present_scan,
    project_key,
    severity_counts,
)
from security_console.audit import record
from security_console.gitlab_ci import (
    GitLabCiError,
    normalize_gitlab_base_url,
    resolve_gitlab_project,
    slug_for_gitlab,
)
from security_console.images import valid_image_ref
from security_console.queue import QUEUE_CAP, attach_queue_position
from security_console.repos import normalize_commit_sha, valid_repo

Reply = Response | tuple[Response, int]

log = logging.getLogger("security_console")

_REPO_TOOLS = ("semgrep", "checkov", "sonar", "trivy")
_ALLOWED = frozenset(_REPO_TOOLS)
_CI_RATE_LIMIT = 30
_CI_RATE_PROJECT_LIMIT = 10
_CI_RATE_TOKEN_LIMIT = 20
_CI_RATE_WINDOW = 60.0
_CI_RATE_KEY_CAP = 1024
_rate_lock = threading.Lock()
_rate_hits: deque[float] = deque()
_rate_project_hits: dict[tuple[str, int], deque[float]] = {}
_rate_token_hits: dict[str, deque[float]] = {}

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


def _prune_hits(hits: deque[float], now: float) -> None:
    while hits and now - hits[0] > _CI_RATE_WINDOW:
        hits.popleft()


def _prune_rate_maps(now: float) -> None:
    """Drop empty/stale keyed deques so memory stays bounded."""

    for store in (_rate_project_hits, _rate_token_hits):
        dead = [
            key
            for key, bucket in store.items()
            if not bucket or now - bucket[-1] > _CI_RATE_WINDOW
        ]
        for key in dead:
            store.pop(key, None)
        while len(store) > _CI_RATE_KEY_CAP:
            store.pop(next(iter(store)))


def _ci_rate_limited(project_key: tuple[str, int] | None = None) -> bool:
    """Return True when global, per-token, or per-project budget is exhausted.

    Order: global → per-token → per-GitLab-project. Single console process.
    """

    now = time.monotonic()
    token_key = str(getattr(g, "ci_token_id", "") or "unknown")
    with _rate_lock:
        _prune_hits(_rate_hits, now)
        _prune_rate_maps(now)
        if len(_rate_hits) >= _CI_RATE_LIMIT:
            return True
        token_bucket = _rate_token_hits.setdefault(token_key, deque())
        _prune_hits(token_bucket, now)
        if len(token_bucket) >= _CI_RATE_TOKEN_LIMIT:
            return True
        if project_key is not None:
            bucket = _rate_project_hits.setdefault(project_key, deque())
            _prune_hits(bucket, now)
            if len(bucket) >= _CI_RATE_PROJECT_LIMIT:
                return True
            bucket.append(now)
        token_bucket.append(now)
        _rate_hits.append(now)
        return False


def reset_ci_rate_limit() -> None:
    """Test helper: clear global, per-token, and per-project rate windows."""

    with _rate_lock:
        _rate_hits.clear()
        _rate_project_hits.clear()
        _rate_token_hits.clear()


def _rate_project_key_from_body(body: Any) -> tuple[str, int] | None:
    if not isinstance(body, dict):
        return None
    if body.get("gitlab_project_id") is None and not body.get("gitlab_base_url"):
        return None
    base = normalize_gitlab_base_url(str(body.get("gitlab_base_url") or ""))
    if base is None:
        return None
    try:
        project_id = int(body.get("gitlab_project_id"))
    except (TypeError, ValueError):
        return None
    if project_id < 1:
        return None
    return base, project_id


def _parse_tools(body: dict[str, Any], target: str) -> tuple[list[str] | None, str]:
    raw_tools = body.get("tools")
    if raw_tools is None:
        return _default_tools(target, []), ""
    if not isinstance(raw_tools, list):
        return None, "Tools must be a list."
    tools: list[str] = []
    for item in raw_tools:
        if not isinstance(item, str) or item not in _ALLOWED:
            return None, "One or more tools are invalid."
        if item not in tools:
            tools.append(item)
    tools = _default_tools(target, tools)
    if target == "image" and tools != ["trivy"]:
        return None, "Image scans run with Trivy only."
    if target == "repo" and not tools:
        return None, "Select at least one tool."
    return tools, ""


def _ci_meta_from_body(body: dict[str, Any]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    ref = str(body.get("ref") or "").strip()
    if ref and len(ref) <= 200:
        meta["ref"] = ref
    pipeline_id = str(body.get("pipeline_id") or "").strip()
    if pipeline_id and len(pipeline_id) <= 64:
        meta["pipeline_id"] = pipeline_id
    pipeline_url = str(body.get("pipeline_url") or "").strip()
    if pipeline_url and len(pipeline_url) <= 500 and "://" in pipeline_url:
        meta["pipeline_url"] = pipeline_url
    trigger = str(body.get("trigger") or "").strip()
    if trigger and len(trigger) <= 64:
        meta["trigger"] = trigger
    return meta


def _parse_gitlab_mode(
    body: dict[str, Any],
) -> tuple[dict[str, Any] | None, str, int]:
    raw_id = body.get("gitlab_project_id")
    try:
        gitlab_project_id = int(raw_id)
    except (TypeError, ValueError):
        return None, "gitlab_project_id is invalid.", 400
    tools, tool_error = _parse_tools(body, "repo")
    if tools is None:
        return None, tool_error, 400
    try:
        resolved = resolve_gitlab_project(
            gitlab_base_url=str(body.get("gitlab_base_url") or ""),
            gitlab_project_id=gitlab_project_id,
            requested_sha=str(body.get("requested_sha") or ""),
        )
    except GitLabCiError as exc:
        return None, exc.message, exc.status

    slug = slug_for_gitlab(resolved["base_url"], resolved["gitlab_project_id"])
    target_key = project_key({"repo": resolved["repo_url"], "image": ""})
    project = db.upsert_gitlab_linked_project(
        base_url=resolved["base_url"],
        gitlab_project_id=resolved["gitlab_project_id"],
        gitlab_path=resolved["path"],
        name=resolved["name"],
        repo_url=resolved["repo_url"],
        slug=slug,
        target_key=target_key,
    )
    ci_meta = _ci_meta_from_body(body)
    ci_meta["gitlab_project_id"] = resolved["gitlab_project_id"]
    ci_meta["gitlab_base_url"] = resolved["base_url"]
    ci_meta["gitlab_path"] = resolved["path"]
    return {
        "project": project,
        "target": "repo",
        "repo": resolved["repo_url"],
        "image": "",
        "tools": tools,
        "requested_sha": resolved["sha"],
        "force": bool(body.get("force")),
        "ci_meta": ci_meta,
        "gitlab": {
            "base_url": resolved["base_url"],
            "project_id": resolved["gitlab_project_id"],
            "path": resolved["path"],
        },
    }, "", 200


def _parse_slug_mode(
    body: dict[str, Any],
) -> tuple[dict[str, Any] | None, str, int]:
    slug = str(body.get("project") or "").strip().lower()
    if not slug:
        return None, "project or gitlab_project_id is required.", 400
    target = str(body.get("target") or "repo").strip().lower()
    if target not in {"repo", "image"}:
        return None, "Invalid scan type.", 400
    tools, tool_error = _parse_tools(body, target)
    if tools is None:
        return None, tool_error, 400

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
        "ci_meta": _ci_meta_from_body(body),
        "gitlab": project.get("gitlab"),
    }, "", 200


def _parse_create_body(
    body: Any,
) -> tuple[dict[str, Any] | None, str, int]:
    if not isinstance(body, dict):
        return None, "Invalid scan.", 400
    if body.get("gitlab_project_id") is not None or body.get("gitlab_base_url"):
        return _parse_gitlab_mode(body)
    return _parse_slug_mode(body)


def _create() -> Reply:
    if _lock is None or _scans is None or _save is None or _utcnow is None:
        return jsonify({"error": "CI scan API is not ready."}), 503
    body = request.get_json(silent=True)
    if _ci_rate_limited(_rate_project_key_from_body(body)):
        return jsonify({"error": "Too many CI scan requests. Try again shortly."}), 429
    parsed, error, code = _parse_create_body(body)
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
            "ci_meta": dict(parsed.get("ci_meta") or {}),
            "tool_results": [],
        }
        _scans[scan_id] = item
        _save(item)
        shown = _public_scan(user, item)
    detail = {
        "scan_id": scan_id,
        "target": parsed["target"],
        "tools": parsed["tools"],
        "requested_sha": parsed["requested_sha"],
    }
    gitlab = parsed.get("gitlab")
    if isinstance(gitlab, dict):
        detail["gitlab_project_id"] = gitlab.get("project_id")
        detail["gitlab_path"] = gitlab.get("path")
    record(
        action="ci.scan.create",
        target_type="project",
        target_id=str(project.get("slug") or ""),
        detail=detail,
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
    shown["project_id"] = item.get("project_id")
    shown["project_slug"] = item.get("project_slug") or shown.get("project_slug")
    ci_meta = item.get("ci_meta") if isinstance(item.get("ci_meta"), dict) else {}
    if ci_meta:
        shown["ci_meta"] = {
            key: ci_meta[key]
            for key in (
                "ref",
                "pipeline_id",
                "pipeline_url",
                "trigger",
                "gitlab_project_id",
                "gitlab_base_url",
                "gitlab_path",
            )
            if key in ci_meta
        }
        if ci_meta.get("gitlab_base_url") and ci_meta.get("gitlab_project_id"):
            shown["gitlab"] = {
                "base_url": ci_meta.get("gitlab_base_url"),
                "project_id": ci_meta.get("gitlab_project_id"),
                "path": ci_meta.get("gitlab_path") or "",
            }
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
