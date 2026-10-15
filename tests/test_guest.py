from datetime import UTC, datetime

from security_console.access import (
    can_view_scan,
    find_reusable_scan,
    recent_per_project,
)
from security_console.guest import (
    expired,
    parse_guest_scan,
    present_guest_scan,
    recent_count,
)
from security_console.jobs import parse_job

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def _scan(**extra: object) -> dict[str, object]:
    item: dict[str, object] = {
        "id": "abc123abc123",
        "target": "repo",
        "repo": "https://gitlab.example.com/team/app.git",
        "image": "",
        "tools": ["trivy"],
        "status": "done",
        "findings": [{"tool": "trivy", "severity": "HIGH", "check": "CVE-1"}],
        "created_at": "2026-10-15 11:30:00 UTC",
        "finished_at": "2026-10-15 11:31:00 UTC",
    }
    item.update(extra)
    return item


def test_a_public_repo_scan_needs_no_token() -> None:
    fields, secrets, error = parse_guest_scan(
        {"target": "repo", "repo": "https://github.com/org/app", "tools": ["trivy"]}
    )

    assert error == ""
    assert fields == {
        "target": "repo",
        "repo": "https://github.com/org/app",
        "image": "",
        "tools": ["trivy"],
    }
    assert secrets == {}


def test_sonar_is_not_offered_to_a_guest() -> None:
    fields, _secrets, error = parse_guest_scan(
        {"target": "repo", "repo": "https://github.com/org/app", "tools": ["sonar"]}
    )

    assert fields is None
    assert error == "Select at least one tool."


def test_a_service_name_without_a_domain_is_rejected() -> None:
    for repo in ("http://db:5432/x", "http://scanner/x"):
        fields, _secrets, _error = parse_guest_scan(
            {"target": "repo", "repo": repo, "tools": ["trivy"]}
        )
        assert fields is None
    fields, _secrets, _error = parse_guest_scan(
        {"target": "image", "image": "registry:5000/app:1"}
    )
    assert fields is None


def test_local_image_ids_are_not_accepted() -> None:
    fields, _secrets, _error = parse_guest_scan(
        {"target": "image", "image": "sha256:" + "a" * 64}
    )

    assert fields is None


def test_a_github_token_uses_basic_auth_and_gitlab_uses_the_header() -> None:
    _fields, github, _error = parse_guest_scan(
        {
            "target": "repo",
            "repo": "https://github.com/org/app",
            "tools": ["semgrep"],
            "token": "ghp_secret",
        }
    )
    _fields, gitlab, _error = parse_guest_scan(
        {
            "target": "repo",
            "repo": "https://gitlab.example.com/team/app.git",
            "tools": ["semgrep"],
            "token": "glpat-secret",
        }
    )

    assert github == {"clone_token": "ghp_secret", "clone_style": "basic"}
    assert gitlab == {"clone_token": "glpat-secret", "clone_style": "header"}


def test_registry_credentials_come_in_pairs() -> None:
    _fields, _secrets, error = parse_guest_scan(
        {
            "target": "image",
            "image": "registry.example.com/app:1",
            "registry_password": "x",
        }
    )
    fields, secrets, _error = parse_guest_scan(
        {
            "target": "image",
            "image": "registry.example.com/app:1",
            "registry_username": "robot",
            "registry_password": "x",
        }
    )

    assert error == "Enter both the registry username and the token."
    assert fields is not None
    assert secrets == {"registry_username": "robot", "registry_password": "x"}


def test_the_scanner_accepts_the_clone_style() -> None:
    job = parse_job(
        {
            "id": "abc123abc123",
            "target": "repo",
            "repo": "https://github.com/org/app",
            "tools": ["trivy"],
            "clone_token": "ghp_secret",
            "clone_style": "basic",
        }
    )

    assert job["clone_style"] == "basic"


def test_guest_scans_stay_out_of_group_reports() -> None:
    member = {"id": 2, "role": "developer", "allow_trivy": True}
    keys = {"https://gitlab.example.com/team/app"}
    scan = _scan(guest="g1")

    assert not can_view_scan(member, scan, group_keys=keys)
    assert can_view_scan({"role": "admin"}, scan)
    assert recent_per_project({"role": "admin"}, [scan], summary=True) == []


def test_reuse_does_not_cross_between_guests_and_teams() -> None:
    admin = {"role": "admin"}
    team = _scan(id="team00000000")
    mine = _scan(id="mine00000000", guest="g1")
    request = {
        "target": "repo",
        "repo": "https://gitlab.example.com/team/app.git",
        "image": "",
        "tools": ["trivy"],
        "now": NOW,
    }

    found_by_guest = find_reusable_scan(admin, [team], guest="g1", **request)
    found_by_team = find_reusable_scan(admin, [mine], **request)
    found_own = find_reusable_scan(admin, [team, mine], guest="g1", **request)

    assert found_by_guest is None
    assert found_by_team is None
    assert found_own is not None and found_own[0]["id"] == "mine00000000"


def test_the_hourly_count_follows_the_session_and_the_address() -> None:
    items = [
        _scan(guest="g1", guest_ip="10.0.0.5"),
        _scan(guest="g2", guest_ip="10.0.0.5"),
        _scan(guest="g3", guest_ip="10.0.0.9"),
        _scan(guest="g1", created_at="2026-10-15 09:00:00 UTC"),
        _scan(),
    ]

    assert recent_count(items, "g1", "10.0.0.5", now=NOW) == 2


def test_guest_scans_expire_after_a_week() -> None:
    old = _scan(guest="g1", created_at="2026-10-01 10:00:00 UTC")

    assert expired(old, now=NOW)
    assert not expired(_scan(guest="g1"), now=NOW)
    assert not expired(_scan(created_at="2026-01-01 10:00:00 UTC"), now=NOW)


def test_the_guest_view_hides_the_session_and_address() -> None:
    shown = present_guest_scan(
        _scan(guest="g1", guest_ip="10.0.0.5", private=True), summary=False
    )

    assert "guest" not in shown
    assert "guest_ip" not in shown
    assert shown["private"] is True
    assert shown["severity"]["high"] == 1
