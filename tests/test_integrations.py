"""Connection forms and how a scan finds the saved GitLab or registry."""

from __future__ import annotations

import pytest

from security_console.integrations import (
    join_registry_image,
    matching_gitlab,
    matching_registry,
    parse_integration,
    registry_prefix,
)
from security_console.jobs import JobError, parse_job


def test_parse_integration_keeps_a_gitlab_address() -> None:
    parsed, error = parse_integration(
        {
            "kind": "gitlab",
            "name": "  Internal  ",
            "base_url": "https://gitlab.example.com/",
            "secret": "glpat-secret-token",
        },
        secret_required=True,
    )

    assert error == ""
    assert parsed is not None
    assert parsed["name"] == "Internal"
    assert parsed["base_url"] == "https://gitlab.example.com"
    assert parsed["username"] == ""


def test_parse_integration_rejects_a_registry_without_a_user() -> None:
    parsed, error = parse_integration(
        {
            "kind": "registry",
            "name": "Registry",
            "base_url": "192.168.1.20:5000",
            "secret": "registry-secret",
        },
        secret_required=True,
    )

    assert parsed is None
    assert error == "Username is invalid."


def test_a_repository_uses_the_longest_gitlab_match() -> None:
    rows = [
        {"kind": "gitlab", "base_url": "https://gitlab.example.com", "secret": "a"},
        {
            "kind": "gitlab",
            "base_url": "https://gitlab.example.com/team",
            "secret": "b",
        },
    ]

    match = matching_gitlab("https://gitlab.example.com/team/app.git", rows)

    assert match is not None
    assert match["secret"] == "b"
    assert matching_gitlab("https://github.com/org/app.git", rows) is None


def test_an_image_name_is_prefixed_with_the_registry() -> None:
    assert registry_prefix("https://192.168.1.20:5000/") == "192.168.1.20:5000"
    assert join_registry_image("192.168.1.20:5000", "team/app:1") == (
        "192.168.1.20:5000/team/app:1"
    )
    assert (
        join_registry_image("192.168.1.20:5000", "192.168.1.20:5000/team/app:1")
        == "192.168.1.20:5000/team/app:1"
    )
    rows = [
        {
            "kind": "registry",
            "base_url": "192.168.1.20:5000",
            "username": "robot",
            "secret": "registry-secret",
        }
    ]

    match = matching_registry("192.168.1.20:5000/team/app:1", rows)

    assert match is not None
    assert match["username"] == "robot"


def test_parse_job_keeps_a_token_out_of_the_repository_url() -> None:
    job = parse_job(
        {
            "id": "abc123def456",
            "target": "repo",
            "repo": "https://gitlab.example.com/team/app.git",
            "tools": ["semgrep"],
            "clone_token": "glpat-secret-token",
            "privileged": True,
        }
    )

    assert job["repo"] == "https://gitlab.example.com/team/app.git"
    assert job["clone_token"] == "glpat-secret-token"
    assert "privileged" not in job
    with pytest.raises(JobError):
        parse_job(
            {
                "id": "abc123def456",
                "target": "repo",
                "repo": "https://gitlab.example.com/team/app.git",
                "tools": ["semgrep"],
                "clone_token": "has a space",
            }
        )
