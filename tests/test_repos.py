"""Clone URLs stay on public or ordinary private git hosts."""

from __future__ import annotations

from typing import Any

import pytest

from security_console.repos import (
    clone_pins,
    git_clone_args,
    git_env,
    ip_is_blocked,
    repo_targets_blocked_address,
    valid_repo,
)


def test_valid_repo_accepts_public_and_private_http() -> None:
    assert valid_repo("https://github.com/org/repo.git")
    assert valid_repo("http://192.168.205.20/git/app.git")
    assert valid_repo("https://10.1.2.3/repo.git")


def test_valid_repo_rejects_credentials_metadata_and_loopback() -> None:
    assert not valid_repo("https://user:secret@github.com/org/repo.git")
    assert not valid_repo("http://169.254.169.254/latest/meta-data")
    assert not valid_repo("http://127.0.0.1/repo.git")
    assert not valid_repo("http://[::1]/repo.git")
    assert not valid_repo("http://metadata.google.internal/computeMetadata/v1/")
    assert not valid_repo("http://100.100.100.200/latest/meta-data/")
    assert not valid_repo("https://100.64.0.1/repo.git")
    assert not valid_repo("http://[fd00:ec2::254]/latest/meta-data")
    assert not valid_repo("http://[::ffff:169.254.169.254]/latest")
    assert not valid_repo("http://010.0.0.1/repo.git")
    assert valid_repo("http://[::ffff:10.1.2.3]/repo.git")
    assert not valid_repo("file:///etc/passwd")
    assert not valid_repo("https://github.com/org/../repo.git")
    assert not valid_repo("https://github.com/org/repo.git\n")


def test_link_local_is_blocked_and_private_is_not() -> None:
    assert ip_is_blocked("169.254.169.254")
    assert ip_is_blocked("127.0.0.1")
    assert ip_is_blocked("::1")
    assert ip_is_blocked("::ffff:127.0.0.1")
    assert ip_is_blocked("100.100.100.200")
    assert ip_is_blocked("fd00:ec2::254")
    assert not ip_is_blocked("192.168.1.10")
    assert not ip_is_blocked("10.0.0.8")
    assert not ip_is_blocked("::ffff:10.0.0.8")


def test_dns_to_metadata_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def answers(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        return [(2, 1, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr("security_console.repos.socket.getaddrinfo", answers)

    assert repo_targets_blocked_address("https://evil.example/repo.git")


def test_git_clone_does_not_inherit_console_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_JWT_KEY", "super-secret-jwt-key-value")
    monkeypatch.setenv("https_proxy", "http://proxy.internal:3128")

    command = git_clone_args("https://github.com/org/repo.git", "/scans/abc")
    env = git_env("/usr/bin")

    assert command[:1] == ["git"]
    assert "--" in command
    assert command[command.index("--") + 1] == "https://github.com/org/repo.git"
    assert "CONSOLE_JWT_KEY" not in env
    assert env["https_proxy"] == "http://proxy.internal:3128"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "credential.helper=" in command
    assert "http.followRedirects=false" in command


def test_git_clone_pins_the_address_it_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def answers(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        return [
            (2, 1, 6, "", ("203.0.113.10", 443)),
            (10, 1, 6, "", ("2001:db8::10", 443, 0, 0)),
        ]

    monkeypatch.setattr("security_console.repos.socket.getaddrinfo", answers)
    pins = clone_pins("https://example.com/app.git")
    command = git_clone_args(
        "https://example.com/app.git",
        "/scans/abc",
        pins,
    )

    assert pins == [
        "example.com:443:203.0.113.10",
        "example.com:443:[2001:db8::10]",
    ]
    assert "http.curloptResolve=example.com:443:203.0.113.10" in command
    assert "http.curloptResolve=example.com:443:[2001:db8::10]" in command
    assert "http.followRedirects=false" in command
