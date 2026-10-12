"""Trivy database refresh tries official mirrors in order, then stops."""

from __future__ import annotations

from typing import Any

from security_console.runtime import (
    TRIVY_JAVA_REPOSITORIES,
    TRIVY_VULN_REPOSITORIES,
)
from security_console.trivy_db import refresh_trivy_databases


def _repo(spec: dict[str, Any]) -> str:
    command = spec["command"]
    for flag in ("--db-repository", "--java-db-repository"):
        if flag in command:
            return str(command[command.index(flag) + 1])
    raise AssertionError("repository flag missing")


def test_refresh_starts_at_the_default_repository_and_stops() -> None:
    seen: list[str] = []

    def run(spec: dict[str, Any]) -> tuple[int, str, str]:
        seen.append(_repo(spec))
        return 0, "", ""

    assert refresh_trivy_databases(run) == ""
    assert seen == [
        TRIVY_VULN_REPOSITORIES[0],
        TRIVY_JAVA_REPOSITORIES[0],
    ]

    seen.clear()
    assert refresh_trivy_databases(run) == ""
    assert seen[0] == "ghcr.io/aquasecurity/trivy-db:2"
    assert seen[1] == "ghcr.io/aquasecurity/trivy-java-db:1"


def test_network_failure_uses_the_next_mirror() -> None:
    seen: list[str] = []

    def run(spec: dict[str, Any]) -> tuple[int, str, str]:
        repository = _repo(spec)
        seen.append(repository)
        if repository.startswith("ghcr.io"):
            return 1, "", "dial tcp: i/o timeout"
        if "java" in repository and "public.ecr.aws" in repository:
            return 1, "", "tls: handshake failure"
        return 0, "", ""

    assert refresh_trivy_databases(run) == ""
    assert seen == [
        TRIVY_VULN_REPOSITORIES[0],
        TRIVY_VULN_REPOSITORIES[1],
        TRIVY_JAVA_REPOSITORIES[0],
        TRIVY_JAVA_REPOSITORIES[1],
        TRIVY_JAVA_REPOSITORIES[2],
    ]


def test_every_mirror_can_fail_without_dropping_the_cache() -> None:
    def run(spec: dict[str, Any]) -> tuple[int, str, str]:
        return 1, "", "connect: connection refused"

    message = refresh_trivy_databases(run)

    assert "vulnerability database" in message
    assert "Java database" in message
    assert "cached database" in message
    assert "ghcr.io/aquasecurity/trivy-db:2" in message
    assert "mirror.gcr.io/aquasecurity/trivy-java-db:1" in message
    assert "delete" not in message.lower()


def test_a_local_failure_does_not_try_another_mirror() -> None:
    seen: list[str] = []

    def run(spec: dict[str, Any]) -> tuple[int, str, str]:
        seen.append(_repo(spec))
        if "--download-db-only" in spec["command"]:
            return 1, "", "unknown flag: --download-db-only"
        return 0, "", ""

    message = refresh_trivy_databases(run)

    assert seen == [
        TRIVY_VULN_REPOSITORIES[0],
        TRIVY_JAVA_REPOSITORIES[0],
    ]
    assert "vulnerability database" in message
    assert "Java database" not in message


def test_a_raised_timeout_moves_to_the_next_mirror() -> None:
    def run(spec: dict[str, Any]) -> tuple[int, str, str]:
        repository = _repo(spec)
        if repository == TRIVY_VULN_REPOSITORIES[0]:
            raise TimeoutError("Read timed out")
        if repository == TRIVY_JAVA_REPOSITORIES[0]:
            raise PermissionError("permission denied: /cache")
        return 0, "", ""

    message = refresh_trivy_databases(run)

    assert "vulnerability database" not in message
    assert "Java database" in message
    assert "permission denied" in message
