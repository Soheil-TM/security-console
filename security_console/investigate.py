"""Per-finding investigate triage for project scans before push gate."""

from __future__ import annotations

from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.access import (
    access_map,
    can_view_scan,
    expand_sonar_findings,
    present_scan,
    scan_project_ref,
)
from security_console.risk import can_accept_risk, finding_key

Reply = Response | tuple[Response, int]

DISPOSITION_STATUSES = (
    "true_positive",
    "false_positive",
    "accepted_risk",
    "needs_review",
)
GATE_OK_STATUSES = frozenset({"false_positive", "accepted_risk"})
REASON_STATUSES = frozenset({"false_positive", "accepted_risk"})
ASSIGNABLE_STATUSES = frozenset({"true_positive", "needs_review"})


def install_investigate(app: Flask) -> None:
    """Attach investigate and disposition routes."""

    @app.get("/api/security/investigate")
    def security_investigate() -> Reply:
        return _call(app, _investigate)

    @app.put("/api/security/dispositions")
    def security_disposition() -> Reply:
        return _call(app, _put_disposition)

    @app.get("/api/security/assignments")
    def security_assignments() -> Reply:
        return _call(app, _assignments)

    @app.get("/api/security/triage-inbox")
    def security_triage_inbox() -> Reply:
        return _call(app, _triage_inbox)


def _call(app: Flask, action: Any) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("investigate database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def allowed_findings(user: dict[str, Any], scan: dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings the user may see for this scan."""

    allowed = access_map(user)
    findings = [
        row
        for row in scan.get("findings") or []
        if allowed.get(str(row.get("tool") or ""))
    ]
    if allowed.get("sonar") and not any(
        str(row.get("tool") or "") == "sonar" for row in findings
    ):
        sonar = scan.get("sonar")
        findings = findings + expand_sonar_findings(
            sonar if isinstance(sonar, dict) else None
        )
    return findings


def gate_readiness(
    findings: list[dict[str, Any]],
    dispositions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Return whether every finding is FP or Accepted Risk with a reason."""

    blockers: list[dict[str, str]] = []
    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "accepted_risk": 0,
        "needs_review": 0,
        "undecided": 0,
    }
    for row in findings:
        key = finding_key(row)
        if not key:
            continue
        disp = dispositions.get(key)
        if disp is None:
            counts["undecided"] += 1
            blockers.append(
                {"finding_key": key, "reason": "No disposition yet."}
            )
            continue
        status = str(disp.get("status") or "")
        if status in counts:
            counts[status] += 1
        else:
            counts["undecided"] += 1
        if status not in GATE_OK_STATUSES:
            blockers.append(
                {
                    "finding_key": key,
                    "reason": "Status must be False Positive or Accepted Risk.",
                }
            )
            continue
        if len(str(disp.get("reason") or "").strip()) < 12:
            blockers.append(
                {
                    "finding_key": key,
                    "reason": "A reason of at least 12 characters is required.",
                }
            )
    return {
        "ready_for_gate": len(blockers) == 0,
        "empty_findings": not findings,
        "blockers": blockers,
        "counts": counts,
    }


def triage_snapshot(
    findings: list[dict[str, Any]],
    dispositions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Immutable snapshot of dispositions for the findings on one scan."""

    snapshot: dict[str, Any] = {}
    for row in findings:
        key = finding_key(row)
        if not key:
            continue
        disp = dispositions.get(key) or {}
        snapshot[key] = {
            "status": disp.get("status") or "",
            "reason": disp.get("reason") or "",
            "assignee": disp.get("assignee_username") or "",
        }
    return snapshot


def _investigate() -> Reply:
    user = g.user
    scan_id = str(request.args.get("scan") or "").strip()
    if not scan_id:
        return jsonify({"error": "scan is required."}), 400
    scan = db.get_scan_row(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404
    if scan.get("guest"):
        return jsonify({"error": "Guest scans cannot be investigated."}), 400
    if not scan.get("project_id") and not scan.get("project_slug"):
        return jsonify(
            {"error": "Investigate is only available for project scans."}
        ), 400
    try:
        group_keys = (
            None
            if user.get("role") == "admin"
            else db.group_project_keys(int(user["id"]))
        )
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    if not can_view_scan(user, scan, group_keys=group_keys):
        return jsonify({"error": "You do not have permission."}), 403

    project = scan_project_ref(scan)
    findings = allowed_findings(user, scan)
    dispositions = db.list_dispositions(project)
    readiness = gate_readiness(findings, dispositions)
    can_triage = user.get("role") in {"admin", "developer", "viewer"} and (
        user.get("role") == "admin"
        or project in (group_keys or set())
    )
    # Viewers may view investigate but only developers/admins/leads write.
    can_write = user.get("role") in {"admin", "developer"} and (
        user.get("role") == "admin"
        or db.user_in_project_groups(int(user["id"]), project)
        or project in (group_keys or set())
    )
    previous = _previous_done_scan(scan, project)
    return jsonify(
        {
            "project_key": project,
            "scan": present_scan(
                user, scan, summary=True, group_keys=group_keys
            ),
            "findings": [
                {
                    **row,
                    "finding_key": finding_key(row),
                }
                for row in findings
            ],
            "dispositions": dispositions,
            "assignees": db.list_project_assignees(project),
            "readiness": readiness,
            "can_triage": bool(can_write),
            "can_accept_risk": can_accept_risk(user, project),
            "baseline_scan_id": (
                previous["id"] if previous is not None else scan["id"]
            ),
            "statuses": list(DISPOSITION_STATUSES),
        }
    )


def _put_disposition() -> Reply:
    user = g.user
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Invalid request."}), 400
    scan_id = str(body.get("scan_id") or "").strip()
    key = str(body.get("finding_key") or "").strip()
    status = str(body.get("status") or "").strip()
    reason = str(body.get("reason") or "").strip()
    assignee_name = str(body.get("assignee_username") or "").strip()
    if not scan_id or not key:
        return jsonify({"error": "scan_id and finding_key are required."}), 400
    if status not in DISPOSITION_STATUSES:
        return jsonify({"error": "Disposition status is invalid."}), 400

    scan = db.get_scan_row(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404
    if scan.get("guest"):
        return jsonify({"error": "Guest scans cannot be investigated."}), 400
    if not scan.get("project_id") and not scan.get("project_slug"):
        return jsonify(
            {"error": "Investigate is only available for project scans."}
        ), 400
    project = scan_project_ref(scan)
    try:
        group_keys = (
            None
            if user.get("role") == "admin"
            else db.group_project_keys(int(user["id"]))
        )
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    if not can_view_scan(user, scan, group_keys=group_keys):
        return jsonify({"error": "You do not have permission."}), 403
    if user.get("role") not in {"admin", "developer"}:
        return jsonify({"error": "You do not have permission."}), 403
    if user.get("role") != "admin" and not (
        db.user_in_project_groups(int(user["id"]), project)
        or project in (group_keys or set())
    ):
        return jsonify({"error": "You do not have permission."}), 403

    findings = allowed_findings(user, scan)
    if key not in {finding_key(row) for row in findings}:
        return jsonify({"error": "Finding not found on this scan."}), 404

    if status == "accepted_risk" and not can_accept_risk(user, project):
        return jsonify(
            {"error": "Only an admin or project lead can mark Accepted Risk."}
        ), 403
    if status in REASON_STATUSES and len(reason) < 12:
        return jsonify(
            {"error": "Write a reason of at least 12 characters."}
        ), 400
    if len(reason) > 2000:
        return jsonify({"error": "Reason is too long."}), 400

    assignee_id = None
    if assignee_name:
        if status not in ASSIGNABLE_STATUSES:
            return jsonify(
                {"error": "Assignee is only used for True Positive or Needs Review."}
            ), 400
        candidates = {
            item["username"]: item for item in db.list_project_assignees(project)
        }
        person = candidates.get(assignee_name)
        if person is None:
            return jsonify({"error": "Assignee must belong to the project group."}), 400
        assignee_id = int(person["id"])
    elif status not in ASSIGNABLE_STATUSES:
        assignee_id = None

    row = db.upsert_disposition(
        project_key=project,
        finding_key=key,
        status=status,
        reason=reason if status in REASON_STATUSES else reason,
        assignee_user_id=assignee_id,
        updated_by=str(user.get("username") or ""),
        updated_by_user_id=int(user["id"]),
        scan_id=scan_id,
    )
    dispositions = db.list_dispositions(project)
    readiness = gate_readiness(findings, dispositions)
    return jsonify({"disposition": row, "readiness": readiness})


def _assignments() -> Reply:
    user = g.user
    try:
        rows = db.list_my_assignments(int(user["id"]))
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    return jsonify({"assignments": rows})


def build_triage_inbox(
    user: dict[str, Any],
    *,
    assignments: list[dict[str, Any]],
    projects: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    dispositions_by_project: dict[str, dict[str, dict[str, Any]]],
    group_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Build inbox payload: assignments, needs_triage, badge, per-project map."""

    latest_by_project: dict[str, dict[str, Any]] = {}
    for item in scans:
        if item.get("guest") or item.get("status") != "done":
            continue
        if not item.get("project_id") and not item.get("project_slug"):
            continue
        if not can_view_scan(user, item, group_keys=group_keys):
            continue
        key = scan_project_ref(item)
        if not key:
            continue
        previous = latest_by_project.get(key)
        if previous is None or str(item.get("created_at") or "") > str(
            previous.get("created_at") or ""
        ):
            latest_by_project[key] = item

    project_names = {
        str(item.get("slug") or ""): str(item.get("name") or item.get("slug") or "")
        for item in projects
    }
    needs_triage: list[dict[str, Any]] = []
    triage_by_project: dict[str, Any] = {}
    for project_key, scan in sorted(
        latest_by_project.items(),
        key=lambda pair: str(pair[1].get("created_at") or ""),
        reverse=True,
    ):
        findings = allowed_findings(user, scan)
        dispositions = dispositions_by_project.get(project_key) or {}
        readiness = gate_readiness(findings, dispositions)
        open_count = (
            int(readiness["counts"].get("undecided") or 0)
            + int(readiness["counts"].get("true_positive") or 0)
            + int(readiness["counts"].get("needs_review") or 0)
        )
        entry = {
            "project_key": project_key,
            "project_name": project_names.get(project_key) or project_key,
            "scan_id": str(scan.get("id") or ""),
            "counts": readiness["counts"],
            "ready_for_gate": bool(readiness["ready_for_gate"]),
            "open_count": open_count,
        }
        triage_by_project[project_key] = entry
        if not readiness["ready_for_gate"]:
            needs_triage.append(entry)

    assigned_projects = {
        str(item.get("project_key") or "")
        for item in assignments
        if item.get("project_key")
    }
    extra_projects = [
        item
        for item in needs_triage
        if item["project_key"] not in assigned_projects
    ]
    badge_count = len(assignments) + len(extra_projects)
    return {
        "assignments": assignments,
        "needs_triage": needs_triage,
        "badge_count": badge_count,
        "triage_by_project": triage_by_project,
    }


def _triage_inbox() -> Reply:
    user = g.user
    try:
        user_id = int(user["id"])
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    group_keys = (
        None
        if user.get("role") == "admin"
        else db.group_project_keys(user_id)
    )
    assignments = db.list_my_assignments(user_id)
    project_user = None if user.get("role") == "admin" else user_id
    projects = db.list_projects(project_user)
    scans = db.list_scan_rows()
    dispositions_by_project: dict[str, dict[str, dict[str, Any]]] = {}
    for project in projects:
        slug = str(project.get("slug") or "")
        if slug:
            dispositions_by_project[slug] = db.list_dispositions(slug)
    for item in scans:
        if item.get("guest") or item.get("status") != "done":
            continue
        key = scan_project_ref(item)
        if key and key not in dispositions_by_project:
            dispositions_by_project[key] = db.list_dispositions(key)
    payload = build_triage_inbox(
        user,
        assignments=assignments,
        projects=projects,
        scans=scans,
        dispositions_by_project=dispositions_by_project,
        group_keys=group_keys,
    )
    return jsonify(payload)


def _previous_done_scan(
    current: dict[str, Any],
    project: str,
) -> dict[str, Any] | None:
    """Newest earlier done scan for the same project, if any."""

    current_id = str(current.get("id") or "")
    current_created = str(current.get("created_at") or "")
    record = db.get_project_by_slug(project)
    match_keys = db.project_match_keys(record) if record else {project}
    project_id = int(record["id"]) if record else current.get("project_id")
    candidates: list[dict[str, Any]] = []
    for item in db.list_scan_rows():
        if item.get("guest") or item.get("status") != "done":
            continue
        if str(item.get("id") or "") == current_id:
            continue
        if project_id is not None and item.get("project_id") == project_id:
            candidates.append(item)
            continue
        if str(item.get("project_slug") or "").lower() == project:
            candidates.append(item)
            continue
        from security_console.access import project_key

        if project_key(item) in match_keys:
            candidates.append(item)
    candidates.sort(key=lambda row: str(row.get("created_at") or ""))
    earlier = [
        row
        for row in candidates
        if str(row.get("created_at") or "") <= current_created
    ]
    return earlier[-1] if earlier else None
