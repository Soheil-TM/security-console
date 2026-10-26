"""Security history, scan diffs, and lead risk acceptance for push gates."""

from __future__ import annotations

from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.access import (
    can_view_scan,
    present_scan,
    project_key,
    scan_project_ref,
    severity_counts,
)
Reply = Response | tuple[Response, int]


def finding_key(row: dict[str, Any]) -> str:
    """Stable id for one finding across two scans of the same project."""

    return "|".join(
        [
            str(row.get("tool") or ""),
            str(row.get("check") or ""),
            str(row.get("path") or ""),
            str(row.get("line") if row.get("line") is not None else ""),
        ]
    )


def diff_findings(
    baseline: list[dict[str, Any]],
    current: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare two finding lists into fixed / remaining / new buckets."""

    before = {finding_key(row): row for row in baseline if finding_key(row)}
    after = {finding_key(row): row for row in current if finding_key(row)}
    fixed_keys = sorted(set(before) - set(after))
    remaining_keys = sorted(set(before) & set(after))
    new_keys = sorted(set(after) - set(before))
    fixed = [before[key] for key in fixed_keys]
    remaining = [after[key] for key in remaining_keys]
    new = [after[key] for key in new_keys]
    return {
        "fixed": fixed,
        "remaining": remaining,
        "new": new,
        "fixed_count": len(fixed),
        "remaining_count": len(remaining),
        "new_count": len(new),
        "baseline_severity": severity_counts(baseline),
        "current_severity": severity_counts(current),
        "remaining_keys": remaining_keys,
    }


def can_accept_risk(user: dict[str, Any], project: str) -> bool:
    """Admins and leads of a group that owns the project may accept risk."""

    if user.get("role") == "admin":
        return True
    if user.get("role") not in {"admin", "developer"}:
        return False
    try:
        return db.user_leads_project(int(user["id"]), project)
    except (psycopg.Error, TypeError, ValueError):
        return False


def install_risk(app: Flask) -> None:
    """Attach security-history and risk-acceptance routes."""

    @app.get("/api/security/history")
    def security_history() -> Reply:
        return _call(app, _history)

    @app.get("/api/security/diff")
    def security_diff() -> Reply:
        return _call(app, _diff)

    @app.post("/api/security/acceptances")
    def security_accept() -> Reply:
        return _call(app, _accept)

    @app.get("/api/security/gate")
    def security_gate() -> Reply:
        return _gate(app)


def _call(app: Flask, action: Any) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("risk database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _history() -> Reply:
    user = g.user
    project = str(request.args.get("project") or "").strip().lower()
    if not project:
        return jsonify({"error": "project is required."}), 400
    try:
        group_keys = (
            None
            if user.get("role") == "admin"
            else db.group_project_keys(int(user["id"]))
        )
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    if user.get("role") != "admin" and project not in (group_keys or set()):
        return jsonify({"error": "You do not have permission."}), 403

    record = db.get_project_by_slug(project)
    match_keys = db.project_match_keys(record) if record else {project}
    project_id = int(record["id"]) if record else None

    scans = []
    for item in db.list_scan_rows():
        if item.get("guest"):
            continue
        if not _scan_in_project(item, project, match_keys, project_id):
            continue
        if item.get("status") not in {"done", "failed"}:
            continue
        shown = present_scan(
            user, item, summary=True, group_keys=group_keys
        )
        if shown is None:
            continue
        scans.append(shown)
    scans.sort(key=lambda row: str(row.get("created_at") or ""))
    acceptances = db.list_risk_acceptances(project)
    latest = db.latest_active_acceptance(project)
    return jsonify(
        {
            "project_key": project,
            "scans": scans,
            "acceptances": acceptances,
            "gate": {
                "approved_for_push": latest is not None,
                "acceptance": latest,
            },
            "can_accept": can_accept_risk(user, project),
        }
    )


def _diff() -> Reply:
    user = g.user
    baseline_id = str(request.args.get("baseline") or "").strip()
    current_id = str(request.args.get("current") or "").strip()
    if not baseline_id or not current_id:
        return jsonify({"error": "baseline and current scan ids are required."}), 400
    baseline = db.get_scan_row(baseline_id)
    current = db.get_scan_row(current_id)
    if baseline is None or current is None:
        return jsonify({"error": "Scan not found."}), 404
    if baseline.get("guest") or current.get("guest"):
        return jsonify({"error": "Guest scans cannot enter the security history."}), 400
    try:
        group_keys = (
            None
            if user.get("role") == "admin"
            else db.group_project_keys(int(user["id"]))
        )
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    if not can_view_scan(user, baseline, group_keys=group_keys):
        return jsonify({"error": "You do not have permission."}), 403
    if not can_view_scan(user, current, group_keys=group_keys):
        return jsonify({"error": "You do not have permission."}), 403
    if not _same_project(baseline, current):
        return jsonify({"error": "Both scans must belong to the same project."}), 400

    allowed_tools = {
        tool
        for tool, ok in (
            {
                "semgrep": True,
                "checkov": True,
                "trivy": True,
                "sonar": True,
            }
            if user.get("role") == "admin"
            else {
                "semgrep": bool(user.get("allow_semgrep")),
                "checkov": bool(user.get("allow_checkov")),
                "trivy": bool(user.get("allow_trivy")),
                "sonar": bool(user.get("allow_sonar")),
            }
        ).items()
        if ok
    }
    before = [
        row
        for row in baseline.get("findings") or []
        if str(row.get("tool") or "") in allowed_tools
    ]
    after = [
        row
        for row in current.get("findings") or []
        if str(row.get("tool") or "") in allowed_tools
    ]
    compared = diff_findings(before, after)
    return jsonify(
        {
            "project_key": scan_project_ref(current),
            "baseline": present_scan(
                user, baseline, summary=True, group_keys=group_keys
            ),
            "current": present_scan(
                user, current, summary=True, group_keys=group_keys
            ),
            **compared,
            "can_accept": can_accept_risk(user, scan_project_ref(current)),
        }
    )


def _accept() -> Reply:
    user = g.user
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Invalid request."}), 400
    baseline_id = str(body.get("baseline_scan_id") or "").strip()
    current_id = str(body.get("current_scan_id") or "").strip()
    reason = str(body.get("reason") or "").strip()
    if not baseline_id or not current_id:
        return jsonify({"error": "baseline_scan_id and current_scan_id are required."}), 400
    if len(reason) < 12:
        return jsonify(
            {"error": "Write a reason of at least 12 characters for the acceptance."}
        ), 400
    if len(reason) > 2000:
        return jsonify({"error": "Reason is too long."}), 400

    baseline = db.get_scan_row(baseline_id)
    current = db.get_scan_row(current_id)
    if baseline is None or current is None:
        return jsonify({"error": "Scan not found."}), 404
    if baseline.get("guest") or current.get("guest"):
        return jsonify({"error": "Guest scans cannot be accepted."}), 400
    if current.get("status") != "done":
        return jsonify({"error": "Accept risk only against a finished successful scan."}), 400
    project = scan_project_ref(current)
    if not _same_project(baseline, current):
        return jsonify({"error": "Both scans must belong to the same project."}), 400
    if not can_accept_risk(user, project):
        return jsonify({"error": "Only an admin or project lead can accept risk."}), 403

    try:
        group_keys = (
            None
            if user.get("role") == "admin"
            else db.group_project_keys(int(user["id"]))
        )
    except (TypeError, ValueError):
        return jsonify({"error": "You do not have permission."}), 403
    if not can_view_scan(user, baseline, group_keys=group_keys):
        return jsonify({"error": "You do not have permission."}), 403
    if not can_view_scan(user, current, group_keys=group_keys):
        return jsonify({"error": "You do not have permission."}), 403

    if not current.get("project_id") and not current.get("project_slug"):
        return jsonify(
            {"error": "Accept risk for push requires a project scan."}
        ), 400

    from security_console.investigate import (
        allowed_findings,
        gate_readiness,
        triage_snapshot,
    )

    findings = allowed_findings(user, current)
    dispositions = db.list_dispositions(project)
    readiness = gate_readiness(findings, dispositions)
    if not readiness["ready_for_gate"]:
        return jsonify(
            {
                "error": (
                    "Finish investigate triage first. Every finding must be "
                    "False Positive or Accepted Risk."
                ),
                "readiness": readiness,
            }
        ), 400

    compared = diff_findings(
        list(baseline.get("findings") or []),
        list(current.get("findings") or []),
    )
    commit_sha = str(current.get("commit_sha") or current.get("requested_sha") or "")
    snapshot = triage_snapshot(findings, dispositions)
    row = db.insert_risk_acceptance(
        project_key=project,
        baseline_scan_id=baseline_id,
        current_scan_id=current_id,
        commit_sha=commit_sha,
        accepted_by=str(user.get("username") or ""),
        accepted_by_user_id=int(user["id"]),
        reason=reason,
        remaining_keys=list(compared["remaining_keys"]),
        baseline_severity=dict(compared["baseline_severity"]),
        current_severity=dict(compared["current_severity"]),
        fixed_count=int(compared["fixed_count"]),
        new_count=int(compared["new_count"]),
        remaining_count=int(compared["remaining_count"]),
        triage_snapshot=snapshot,
    )
    return jsonify(
        {
            "acceptance": row,
            "approved_for_push": True,
            "diff": {
                "fixed_count": compared["fixed_count"],
                "new_count": compared["new_count"],
                "remaining_count": compared["remaining_count"],
                "baseline_severity": compared["baseline_severity"],
                "current_severity": compared["current_severity"],
            },
            "readiness": readiness,
        }
    ), 201


def _gate(app: Flask) -> Reply:
    """Return whether push is approved. CI may use GATE_TOKEN instead of a session."""

    project = str(request.args.get("project") or "").strip().lower()
    commit = str(request.args.get("commit") or "").strip()
    if not project:
        return jsonify({"error": "project is required."}), 400

    user = getattr(g, "user", None)
    if not isinstance(user, dict):
        return jsonify({"error": "You do not have permission."}), 401
    if user.get("username") != "gate" and user.get("role") != "admin":
        try:
            keys = db.group_project_keys(int(user["id"]))
        except (psycopg.Error, TypeError, ValueError):
            return jsonify({"error": "Sign-in is unavailable."}), 503
        if project not in keys:
            return jsonify({"error": "You do not have permission."}), 403

    try:
        latest = db.latest_active_acceptance(project, commit_sha=commit)
    except psycopg.Error:
        app.logger.error("risk gate database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503
    return jsonify(
        {
            "project_key": project,
            "commit_sha": commit,
            "approved_for_push": latest is not None,
            "acceptance": latest,
        }
    )


def _scan_in_project(
    item: dict[str, Any],
    slug: str,
    match_keys: set[str],
    project_id: int | None,
) -> bool:
    if project_id is not None and item.get("project_id") == project_id:
        return True
    if str(item.get("project_slug") or "").lower() == slug:
        return True
    return project_key(item) in match_keys


def _same_project(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_id = left.get("project_id")
    right_id = right.get("project_id")
    if left_id is not None and right_id is not None:
        return int(left_id) == int(right_id)
    return scan_project_ref(left) == scan_project_ref(right)
