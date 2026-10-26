"""Investigate triage readiness and inbox helpers."""

from __future__ import annotations

from security_console.investigate import (
    build_triage_inbox,
    gate_readiness,
    triage_snapshot,
)
from security_console.risk import finding_key


def test_finding_key_matches_disposition_identity() -> None:
    row = {
        "tool": "semgrep",
        "check": "rule.x",
        "path": "app.py",
        "line": 10,
    }
    assert finding_key(row) == "semgrep|rule.x|app.py|10"


def test_gate_ready_when_all_fp_or_accepted() -> None:
    findings = [
        {"tool": "semgrep", "check": "a", "path": "a.py", "line": 1},
        {"tool": "trivy", "check": "CVE-1", "path": "pkg", "line": None},
    ]
    keys = [finding_key(row) for row in findings]
    dispositions = {
        keys[0]: {
            "status": "false_positive",
            "reason": "Not reachable in our build.",
        },
        keys[1]: {
            "status": "accepted_risk",
            "reason": "Vendor patch scheduled next quarter.",
        },
    }
    ready = gate_readiness(findings, dispositions)
    assert ready["ready_for_gate"] is True
    assert ready["counts"]["false_positive"] == 1
    assert ready["counts"]["accepted_risk"] == 1


def test_gate_blocked_for_true_positive_or_missing() -> None:
    findings = [
        {"tool": "semgrep", "check": "a", "path": "a.py", "line": 1},
        {"tool": "semgrep", "check": "b", "path": "b.py", "line": 2},
    ]
    keys = [finding_key(row) for row in findings]
    dispositions = {
        keys[0]: {
            "status": "true_positive",
            "reason": "",
            "assignee_username": "ada",
        }
    }
    ready = gate_readiness(findings, dispositions)
    assert ready["ready_for_gate"] is False
    assert ready["counts"]["true_positive"] == 1
    assert ready["counts"]["undecided"] == 1
    assert len(ready["blockers"]) == 2


def test_gate_blocked_when_accepted_risk_lacks_reason() -> None:
    findings = [{"tool": "semgrep", "check": "a", "path": "a.py", "line": 1}]
    key = finding_key(findings[0])
    ready = gate_readiness(
        findings,
        {key: {"status": "accepted_risk", "reason": "short"}},
    )
    assert ready["ready_for_gate"] is False


def test_empty_findings_are_ready() -> None:
    assert gate_readiness([], {})["ready_for_gate"] is True


def test_triage_snapshot_shape() -> None:
    findings = [{"tool": "semgrep", "check": "a", "path": "a.py", "line": 1}]
    key = finding_key(findings[0])
    snap = triage_snapshot(
        findings,
        {
            key: {
                "status": "accepted_risk",
                "reason": "Accepted after review meeting.",
                "assignee_username": "",
            }
        },
    )
    assert snap[key]["status"] == "accepted_risk"
    assert "Accepted after review" in snap[key]["reason"]


def test_inbox_lists_undecided_project_and_skips_ready() -> None:
    admin = {"role": "admin", "id": 1, "allow_semgrep": True, "allow_trivy": True}
    open_finding = {
        "tool": "semgrep",
        "check": "a",
        "path": "a.py",
        "line": 1,
        "severity": "HIGH",
    }
    key = finding_key(open_finding)
    scans = [
        {
            "id": "scan-open",
            "status": "done",
            "project_slug": "payments-api",
            "project_id": 1,
            "created_at": "2026-01-02 00:00:00 UTC",
            "findings": [open_finding],
            "tools": ["semgrep"],
        },
        {
            "id": "scan-ready",
            "status": "done",
            "project_slug": "ready-api",
            "project_id": 2,
            "created_at": "2026-01-02 00:00:00 UTC",
            "findings": [open_finding],
            "tools": ["semgrep"],
        },
    ]
    projects = [
        {"slug": "payments-api", "name": "Payments"},
        {"slug": "ready-api", "name": "Ready"},
    ]
    dispositions = {
        "payments-api": {},
        "ready-api": {
            key: {
                "status": "false_positive",
                "reason": "Not reachable in production path.",
            }
        },
    }
    inbox = build_triage_inbox(
        admin,
        assignments=[],
        projects=projects,
        scans=scans,
        dispositions_by_project=dispositions,
        group_keys=None,
    )
    needs_keys = {item["project_key"] for item in inbox["needs_triage"]}
    assert "payments-api" in needs_keys
    assert "ready-api" not in needs_keys
    assert inbox["triage_by_project"]["ready-api"]["ready_for_gate"] is True
    assert inbox["badge_count"] == 1


def test_inbox_badge_dedupes_assigned_project() -> None:
    admin = {"role": "admin", "id": 1, "allow_semgrep": True}
    finding = {
        "tool": "semgrep",
        "check": "a",
        "path": "a.py",
        "line": 1,
        "severity": "HIGH",
    }
    scans = [
        {
            "id": "s1",
            "status": "done",
            "project_slug": "payments-api",
            "project_id": 1,
            "created_at": "2026-01-02 00:00:00 UTC",
            "findings": [finding],
            "tools": ["semgrep"],
        }
    ]
    inbox = build_triage_inbox(
        admin,
        assignments=[
            {
                "project_key": "payments-api",
                "status": "true_positive",
                "scan_id": "s1",
            }
        ],
        projects=[{"slug": "payments-api", "name": "Payments"}],
        scans=scans,
        dispositions_by_project={"payments-api": {}},
        group_keys=None,
    )
    assert len(inbox["needs_triage"]) == 1
    assert inbox["badge_count"] == 1
