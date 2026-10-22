"""Security history diffs and risk acceptance for the push gate."""

from __future__ import annotations

from security_console.access import scan_project_ref
from security_console.risk import can_accept_risk, diff_findings, finding_key


def test_finding_key_is_stable() -> None:
    row = {
        "tool": "semgrep",
        "check": "rule.x",
        "path": "app.py",
        "line": 10,
        "severity": "HIGH",
        "message": "x",
    }
    assert finding_key(row) == "semgrep|rule.x|app.py|10"


def test_diff_splits_fixed_remaining_and_new() -> None:
    baseline = [
        {
            "tool": "semgrep",
            "check": "a",
            "path": "a.py",
            "line": 1,
            "severity": "HIGH",
        },
        {
            "tool": "trivy",
            "check": "CVE-1",
            "path": "pkg",
            "line": None,
            "severity": "CRITICAL",
        },
    ]
    current = [
        {
            "tool": "trivy",
            "check": "CVE-1",
            "path": "pkg",
            "line": None,
            "severity": "CRITICAL",
        },
        {
            "tool": "checkov",
            "check": "CKV_1",
            "path": "main.tf",
            "line": 3,
            "severity": "MEDIUM",
        },
    ]

    compared = diff_findings(baseline, current)

    assert compared["fixed_count"] == 1
    assert compared["remaining_count"] == 1
    assert compared["new_count"] == 1
    assert compared["fixed"][0]["check"] == "a"
    assert compared["remaining"][0]["check"] == "CVE-1"
    assert compared["new"][0]["check"] == "CKV_1"
    assert compared["baseline_severity"]["high"] == 1
    assert compared["current_severity"]["critical"] == 1


def test_admin_can_accept_risk_without_group_lookup() -> None:
    assert can_accept_risk({"role": "admin", "id": 1}, "payments-api") is True
    assert can_accept_risk({"role": "viewer", "id": 2}, "payments-api") is False


def test_scan_project_ref_groups_repo_and_image_under_slug() -> None:
    repo = {"project_slug": "payments-api", "target": "repo", "repo": "https://x/a"}
    image = {
        "project_slug": "payments-api",
        "target": "image",
        "image": "x/a:1",
    }
    assert scan_project_ref(repo) == scan_project_ref(image) == "payments-api"
