"""A group shares one project's scans. The owner does not."""

from __future__ import annotations

from security_console.access import can_scan_project, can_view_scan
from security_console.groups import parse_group


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
    assert can_view_scan({"role": "admin"}, private) is True


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
        {"role": "admin"},
        ["semgrep"],
        "https://github.com/org/notes",
        set(),
    )


def test_parse_group_keeps_a_repo_and_its_lead() -> None:
    parsed, error = parse_group(
        {
            "name": "  Mace   eBPF ",
            "description": "Kernel work",
            "repos": ["https://github.com/org/mace.git"],
            "images": [],
            "members": [{"username": "ada", "lead": True}],
        }
    )

    assert error == ""
    assert parsed is not None
    assert parsed["name"] == "Mace eBPF"
    assert parsed["projects"][0]["key"] == "https://github.com/org/mace"
    assert parsed["members"] == [{"username": "ada", "lead": True}]


def test_parse_group_rejects_a_group_without_a_project() -> None:
    parsed, error = parse_group(
        {
            "name": "Empty",
            "repos": [],
            "images": [],
            "members": [{"username": "ada", "lead": True}],
        }
    )

    assert parsed is None
    assert error == "Add a repository or an image."
