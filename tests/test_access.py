"""Scan visibility does not depend on the database."""

from __future__ import annotations

from datetime import UTC, datetime

from security_console.access import (
    can_start_scan,
    find_reusable_scan,
    present_scan,
    project_key,
    recent_per_project,
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
    assert shown["severity"]["critical"] == 1
    assert colleague is not None
    assert colleague["owner"] == "someone"
    assert colleague["tools"] == ["semgrep"]
    assert [row["tool"] for row in colleague["findings"]] == ["semgrep"]


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
