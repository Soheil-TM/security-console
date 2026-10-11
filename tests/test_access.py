"""Scan visibility does not depend on the database."""

from __future__ import annotations

from security_console.access import can_start_scan, present_scan


def test_viewer_cannot_start_and_only_sees_owned_scans() -> None:
    viewer = {
        "username": "viewer",
        "role": "viewer",
        "allow_semgrep": True,
        "allow_checkov": False,
        "allow_sonar": False,
    }
    own = {
        "id": "a",
        "repo": "https://example.com/a.git",
        "owner": "viewer",
        "tools": ["semgrep", "checkov"],
        "status": "done",
        "findings": [
            {"tool": "semgrep", "severity": "ERROR"},
            {"tool": "checkov", "severity": "HIGH"},
        ],
        "created_at": "2026-10-11",
    }
    other = dict(own, id="b", owner="someone")

    assert can_start_scan(viewer, ["semgrep"]) is False
    shown = present_scan(viewer, own, summary=True)
    hidden = present_scan(viewer, other, summary=False)

    assert hidden is None
    assert shown is not None
    assert shown["finding_count"] == 1
    assert "findings" not in shown
    assert shown["severity"]["critical"] == 1
