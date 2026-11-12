"""A group shares one project's scans. The owner does not."""

from __future__ import annotations

import pytest

from security_console.access import can_scan_project, can_view_scan
from security_console.groups import _resolve_members, parse_group


def test_members_see_the_group_project_and_not_a_private_one() -> None:
    member = {
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": False,
        "allow_sonar": False,
        "allow_trivy": False,
    }
    group = {"https://github.com/org/app"}
    shared = {
        "repo": "https://github.com/org/app.git",
        "owner": "ada",
        "tools": ["semgrep"],
    }
    private = {
        "repo": "https://github.com/org/notes.git",
        "owner": "ada",
        "tools": ["semgrep"],
    }

    assert can_view_scan(member, shared, group_keys=group) is True
    assert can_view_scan(member, private, group_keys=group) is False
    assert can_view_scan(
        {"role": "admin", "capabilities": {"projects.manage_all": True}},
        private,
    ) is True


def test_a_developer_can_scan_only_a_group_project() -> None:
    developer = {
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": True,
        "allow_sonar": False,
        "allow_trivy": False,
    }
    keys = {"https://github.com/org/app"}

    assert can_scan_project(
        developer,
        ["semgrep"],
        "https://github.com/org/app",
        keys,
    )
    assert not can_scan_project(
        developer,
        ["semgrep"],
        "https://github.com/org/notes",
        keys,
    )
    assert not can_scan_project(
        developer,
        ["sonar"],
        "https://github.com/org/app",
        keys,
    )
    assert can_scan_project(
        {"role": "admin", "capabilities": {"projects.manage_all": True}},
        ["semgrep"],
        "https://github.com/org/notes",
        set(),
    )


def test_parse_group_keeps_project_slugs_and_lead() -> None:
    parsed, error = parse_group(
        {
            "name": "  Mace   eBPF ",
            "description": "Kernel work",
            "project_slugs": [],
            "members": [{"username": "ada", "lead": True}],
        }
    )

    assert error == ""
    assert parsed is not None
    assert parsed["name"] == "Mace eBPF"
    assert parsed["project_ids"] == []
    assert parsed["members"] == [{"username": "ada", "lead": True}]


def test_parse_group_accepts_a_group_without_a_project() -> None:
    parsed, error = parse_group(
        {
            "name": "Empty",
            "project_slugs": [],
            "members": [{"username": "ada", "lead": True}],
        }
    )

    assert error == ""
    assert parsed is not None
    assert parsed["project_ids"] == []


def test_resolve_members_requires_a_lead(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "security_console.groups.db.users_by_username",
        lambda names: [{"id": 1, "username": "ada", "role": "admin", "disabled": False}],
    )
    resolved, error = _resolve_members(
        [{"username": "ada", "lead": False}],
        force_lead="",
    )
    assert resolved == []
    assert error == "A group needs a lead."


def test_resolve_members_accepts_empty_projects_payload_with_lead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inline project-form create posts empty project_slugs and a lead."""
    monkeypatch.setattr(
        "security_console.groups.db.users_by_username",
        lambda names: [
            {"id": 7, "username": "soheil", "role": "admin", "disabled": False}
        ],
    )
    parsed, parse_error = parse_group(
        {
            "name": "Inline",
            "description": "",
            "project_slugs": [],
            "members": [{"username": "soheil", "lead": True}],
        }
    )
    assert parse_error == ""
    assert parsed is not None
    assert parsed["project_ids"] == []
    resolved, member_error = _resolve_members(parsed["members"], force_lead="")
    assert member_error == ""
    assert resolved == [(7, True)]
