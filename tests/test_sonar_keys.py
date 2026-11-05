"""Deterministic per-repository SonarQube project keys."""

from __future__ import annotations

from security_console.sonar_keys import (
    derive_sonar_project_key,
    normalize_repo_key,
    sonar_key_for_job,
)


def test_normalize_repo_key_strips_git_and_slash() -> None:
    assert (
        normalize_repo_key("https://gitlab.example.com/Team/App.GIT/")
        == "https://gitlab.example.com/team/app"
    )


def test_derive_sonar_key_is_stable_and_charset_safe() -> None:
    url = "https://192.168.114.73/402iti002/testsoheil.git"
    first = derive_sonar_project_key(url)
    second = derive_sonar_project_key(url.rstrip(".git") + ".git")
    assert first == second
    assert first.startswith("sc-")
    assert len(first) == 43


def test_different_repos_get_different_keys() -> None:
    a = derive_sonar_project_key("https://example.com/org/a.git")
    b = derive_sonar_project_key("https://example.com/org/b.git")
    assert a != b


def test_sonar_key_for_job_prefers_explicit() -> None:
    key = sonar_key_for_job(
        {
            "repo": "https://example.com/org/a.git",
            "sonar_project_key": "sc-customkey000000000000000000000000000000",
        }
    )
    assert key.startswith("sc-custom")


def test_sonar_key_for_job_derives_from_repo() -> None:
    repo = "https://example.com/org/a.git"
    assert sonar_key_for_job({"repo": repo}) == derive_sonar_project_key(repo)
