"""First-class projects: slug targets and access helpers."""

from __future__ import annotations

from security_console.access import project_key, scan_project_ref
from security_console.db import project_match_keys
from security_console.projects import parse_project


def test_parse_project_builds_repo_and_image_targets() -> None:
    parsed, error = parse_project(
        {
            "name": " Payments API ",
            "slug": "payments-api",
            "description": "Core payments",
            "repos": ["https://github.com/org/payments.git"],
            "images": ["registry.example/payments:1"],
            "group_ids": [],
        }
    )

    assert error == ""
    assert parsed is not None
    assert parsed["slug"] == "payments-api"
    assert parsed["targets"][0]["key"] == "https://github.com/org/payments"
    assert parsed["targets"][1]["key"] == "image:registry.example/payments:1"


def test_parse_project_rejects_bad_slug() -> None:
    parsed, error = parse_project(
        {
            "name": "Bad",
            "slug": "Bad_Slug",
            "repos": ["https://github.com/org/a.git"],
            "group_ids": [],
        }
    )

    assert parsed is None
    assert "Slug" in error


def test_scan_project_ref_prefers_slug() -> None:
    scan = {
        "project_slug": "payments-api",
        "repo": "https://github.com/org/other.git",
        "target": "repo",
    }
    assert scan_project_ref(scan) == "payments-api"
    assert project_key(scan) == "https://github.com/org/other"


def test_project_match_keys_includes_slug_and_targets() -> None:
    project = {
        "slug": "payments-api",
        "targets": [
            {"key": "https://github.com/org/payments"},
            {"key": "image:registry.example/payments:1"},
        ],
    }
    keys = project_match_keys(project)
    assert "payments-api" in keys
    assert "https://github.com/org/payments" in keys
    assert "image:registry.example/payments:1" in keys
