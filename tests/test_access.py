"""Scan visibility does not depend on the database."""

from __future__ import annotations

from datetime import UTC, datetime

from security_console.access import (
    can_start_scan,
    expand_sonar_findings,
    find_reusable_scan,
    present_scan,
    project_key,
    recent_per_project,
    severity_bucket,
    tools_cover,
)


def test_viewer_cannot_start_and_sees_allowed_tools_from_any_owner() -> None:
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
    shared = dict(own, id="b", owner="someone")
    blocked = dict(
        own,
        id="c",
        owner="someone",
        tools=["checkov"],
        findings=[{"tool": "checkov", "severity": "HIGH"}],
    )

    assert can_start_scan(viewer, ["semgrep"]) is False
    keys = {project_key(own)}
    shown = present_scan(viewer, own, summary=True, group_keys=keys)
    colleague = present_scan(viewer, shared, summary=False, group_keys=keys)
    hidden = present_scan(viewer, blocked, summary=False, group_keys=keys)
    outside = present_scan(
        viewer,
        dict(shared, id="d", repo="https://example.com/other.git"),
        summary=False,
        group_keys=keys,
    )

    assert hidden is None
    assert outside is None
    assert shown is not None
    assert shown["finding_count"] == 1
    assert "findings" not in shown
    assert shown["severity"]["high"] == 1
    assert colleague is not None
    assert colleague["owner"] == "someone"
    assert colleague["tools"] == ["semgrep"]
    assert [row["tool"] for row in colleague["findings"]] == ["semgrep"]


def test_severity_bucket_maps_sonar_labels() -> None:
    assert severity_bucket("BLOCKER") == "critical"
    assert severity_bucket("CRITICAL") == "critical"
    assert severity_bucket("MAJOR") == "high"
    assert severity_bucket("HIGH") == "high"
    assert severity_bucket("ERROR") == "high"
    assert severity_bucket("MINOR") == "medium"
    assert severity_bucket("MEDIUM") == "medium"
    assert severity_bucket("LOW") == "low"
    assert severity_bucket("INFO") == "info"
    assert severity_bucket("") == "info"


def test_expand_sonar_findings_issues_and_hotspots() -> None:
    rows = expand_sonar_findings(
        {
            "issues": [
                {
                    "file": "src/app.py",
                    "line": 12,
                    "rule": "python:S2077",
                    "severity": "MAJOR",
                    "message": "sql",
                }
            ],
            "hotspot_list": [
                {
                    "file": "src/db.py",
                    "line": 4,
                    "rule": "python:S2245",
                    "message": "review",
                    "vulnerabilityProbability": "HIGH",
                }
            ],
        }
    )
    assert len(rows) == 2
    assert rows[0] == {
        "tool": "sonar",
        "severity": "MAJOR",
        "check": "python:S2077",
        "path": "src/app.py",
        "line": 12,
        "message": "sql",
    }
    assert rows[1]["tool"] == "sonar"
    assert rows[1]["severity"] == "HIGH"
    assert severity_bucket(rows[0]["severity"]) == "high"
    assert severity_bucket(rows[1]["severity"]) == "high"


def test_present_scan_merges_sonar_into_findings() -> None:
    admin = {"role": "admin", "username": "admin"}
    scan = {
        "id": "s1",
        "repo": "https://example.com/a.git",
        "owner": "admin",
        "tools": ["semgrep", "sonar"],
        "status": "done",
        "findings": [
            {
                "tool": "semgrep",
                "severity": "HIGH",
                "check": "x",
                "path": "a.py",
                "line": 1,
                "message": "m",
            }
        ],
        "sonar": {
            "quality_gate": "ERROR",
            "bugs": 1,
            "vulnerabilities": 0,
            "code_smells": 0,
            "security_hotspots": 1,
            "issues": [
                {
                    "file": "b.py",
                    "line": 2,
                    "rule": "python:S1",
                    "severity": "BLOCKER",
                    "message": "blocker",
                }
            ],
            "hotspot_list": [
                {
                    "file": "c.py",
                    "line": 3,
                    "rule": "python:S2",
                    "message": "hot",
                    "vulnerabilityProbability": "HIGH",
                }
            ],
        },
        "created_at": "2026-10-11",
    }
    shown = present_scan(admin, scan, summary=False)
    assert shown is not None
    assert shown["finding_count"] == 3
    tools = [row["tool"] for row in shown["findings"]]
    assert tools.count("sonar") == 2
    assert tools.count("semgrep") == 1
    assert shown["severity"]["critical"] == 1
    assert shown["severity"]["high"] == 2

    # Already-stored sonar findings are not duplicated.
    with_stored = dict(
        scan,
        findings=scan["findings"]
        + [
            {
                "tool": "sonar",
                "severity": "MINOR",
                "check": "stored",
                "path": "d.py",
                "line": 1,
                "message": "m",
            }
        ],
    )
    again = present_scan(admin, with_stored, summary=False)
    assert again is not None
    assert again["finding_count"] == 2
    assert [row["tool"] for row in again["findings"]].count("sonar") == 1


def test_project_key_groups_repo_spellings_and_images() -> None:
    first = project_key({"repo": "https://Example.com/A.git"})
    second = project_key({"repo": "https://example.com/a/"})
    image = project_key({"target": "image", "image": "Nginx:latest"})

    assert first == second == "https://example.com/a"
    assert image == "image:nginx:latest"
    assert project_key({"image": "redis:7", "repo": ""}) == "image:redis:7"


def test_history_keeps_twenty_scans_for_each_project() -> None:
    user = {
        "username": "ada",
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": False,
        "allow_sonar": False,
        "allow_trivy": False,
    }
    scans = [
        {
            "id": f"a{index:02d}",
            "repo": "https://example.com/a.git",
            "owner": "other",
            "tools": ["semgrep"],
            "status": "done",
            "findings": [],
            "created_at": f"2026-10-{index + 1:02d}",
        }
        for index in range(21)
    ]
    scans.append(
        {
            "id": "b",
            "repo": "https://example.com/b.git",
            "owner": "other",
            "tools": ["semgrep"],
            "status": "done",
            "findings": [],
            "created_at": "2026-09-01",
        }
    )
    scans.append(
        {
            "id": "hidden",
            "repo": "https://example.com/a.git",
            "owner": "other",
            "tools": ["checkov"],
            "status": "done",
            "findings": [{"tool": "checkov", "severity": "HIGH"}],
            "created_at": "2026-11-01",
        }
    )

    shown = recent_per_project(
        user,
        scans,
        summary=True,
        group_keys={"https://example.com/a", "https://example.com/b"},
    )
    ids = [item["id"] for item in shown]
    repo_a = [item for item in shown if item["repo"].endswith("/a.git")]

    assert "b" in ids
    assert "hidden" not in ids
    assert len(repo_a) == 20
    assert "a20" in ids
    assert "a00" not in ids


def test_a_finished_scan_covers_the_requested_tools() -> None:
    assert tools_cover(["semgrep", "checkov"], ["semgrep"]) is True
    assert tools_cover(["semgrep"], ["semgrep", "checkov"]) is False


def test_a_running_scan_of_the_same_project_is_shared() -> None:
    user = {
        "username": "ada",
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": True,
        "allow_sonar": False,
        "allow_trivy": False,
    }
    running = {
        "id": "run1",
        "target": "repo",
        "repo": "https://example.com/app.git",
        "image": "",
        "tools": ["semgrep", "checkov"],
        "status": "running",
        "findings": [],
        "created_at": "2026-10-15 10:00:00 UTC",
        "owner": "other",
    }
    keys = {project_key(running)}

    found = find_reusable_scan(
        user,
        [running],
        target="repo",
        repo="https://example.com/app.git",
        image="",
        tools=["semgrep"],
        group_keys=keys,
    )

    assert found is not None
    assert found[0]["id"] == "run1"
    assert found[1] == "running"


def test_a_queued_scan_of_the_same_project_is_shared() -> None:
    from security_console.access import queue_position

    user = {
        "username": "ada",
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": True,
        "allow_sonar": False,
        "allow_trivy": False,
    }
    queued = {
        "id": "q00000000001",
        "target": "repo",
        "repo": "https://example.com/app.git",
        "image": "",
        "tools": ["semgrep", "checkov"],
        "status": "queued",
        "findings": [],
        "created_at": "2026-10-15 10:00:00 UTC",
        "owner": "other",
        "priority": 0,
    }
    later = dict(queued, id="q00000000002", created_at="2026-10-15 10:01:00 UTC")
    keys = {project_key(queued)}

    found = find_reusable_scan(
        user,
        [queued],
        target="repo",
        repo="https://example.com/app.git",
        image="",
        tools=["semgrep"],
        group_keys=keys,
    )

    assert found is not None
    assert found[0]["id"] == "q00000000001"
    assert found[1] == "queued"
    assert queue_position(queued, [queued, later]) == 1
    assert queue_position(later, [queued, later]) == 2


def test_a_recent_successful_scan_is_reused_for_twenty_four_hours() -> None:
    user = {
        "username": "ada",
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": False,
        "allow_sonar": False,
        "allow_trivy": True,
    }
    recent = {
        "id": "done1",
        "target": "repo",
        "repo": "https://example.com/app.git",
        "image": "",
        "tools": ["semgrep", "checkov"],
        "status": "done",
        "findings": [{"tool": "semgrep", "severity": "HIGH"}],
        "created_at": "2026-10-15 08:00:00 UTC",
        "finished_at": "2026-10-15 08:05:00 UTC",
        "owner": "other",
        "failure_reason": "",
        "commit_sha": "a" * 40,
    }
    old = dict(
        recent,
        id="old1",
        created_at="2026-10-13 08:00:00 UTC",
        finished_at="2026-10-13 08:05:00 UTC",
    )
    failed = dict(recent, id="bad1", status="failed")
    keys = {project_key(recent)}
    now = datetime(2026, 10, 15, 10, 0, tzinfo=UTC)

    reused = find_reusable_scan(
        user,
        [old, failed, recent],
        target="repo",
        repo="https://example.com/app.git",
        image="",
        tools=["semgrep"],
        group_keys=keys,
        now=now,
    )
    forced = find_reusable_scan(
        user,
        [recent],
        target="repo",
        repo="https://example.com/app.git",
        image="",
        tools=["semgrep"],
        group_keys=keys,
        now=now,
        force=True,
    )
    wrong_sha = find_reusable_scan(
        user,
        [recent],
        target="repo",
        repo="https://example.com/app.git",
        image="",
        tools=["semgrep"],
        requested_sha="b" * 40,
        group_keys=keys,
        now=now,
    )

    assert reused is not None
    assert reused[0]["id"] == "done1"
    assert reused[1] == "recent"
    assert forced is None
    assert wrong_sha is None


def test_reuse_stays_inside_the_callers_groups() -> None:
    user = {
        "username": "ada",
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": False,
        "allow_sonar": False,
        "allow_trivy": False,
    }
    scan = {
        "id": "secret",
        "target": "repo",
        "repo": "https://example.com/private.git",
        "image": "",
        "tools": ["semgrep"],
        "status": "done",
        "findings": [],
        "created_at": "2026-10-15 09:00:00 UTC",
        "finished_at": "2026-10-15 09:01:00 UTC",
        "owner": "boss",
        "failure_reason": "",
    }
    now = datetime(2026, 10, 15, 10, 0, tzinfo=UTC)

    found = find_reusable_scan(
        user,
        [scan],
        target="repo",
        repo="https://example.com/private.git",
        image="",
        tools=["semgrep"],
        group_keys=set(),
        now=now,
    )

    assert found is None
