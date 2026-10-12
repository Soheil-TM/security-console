"""Scan visibility does not depend on the database."""

from __future__ import annotations

from security_console.access import (
    can_start_scan,
    present_scan,
    project_key,
    recent_per_project,
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
    shown = present_scan(viewer, own, summary=True)
    colleague = present_scan(viewer, shared, summary=False)
    hidden = present_scan(viewer, blocked, summary=False)

    assert hidden is None
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

    shown = recent_per_project(user, scans, summary=True)
    ids = [item["id"] for item in shown]
    repo_a = [item for item in shown if item["repo"].endswith("/a.git")]

    assert "b" in ids
    assert "hidden" not in ids
    assert len(repo_a) == 20
    assert "a20" in ids
    assert "a00" not in ids
