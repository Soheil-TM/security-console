"""A requested SHA is the commit that is checked out."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from security_console.repos import git_env, git_fetch_sha_commands, git_rev_parse_args
from security_console.runner import CloneError, _clone, _require_head


def _git(args: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        env={
            **git_env("/usr/bin"),
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        },
    )
    return completed.stdout.strip()


def _source(path: Path) -> tuple[str, str]:
    path.mkdir()
    _git(["git", "init"], path)
    _git(
        [
            "git",
            "config",
            "uploadpack.allowReachableSHA1InWant",
            "true",
        ],
        path,
    )
    _git(["git", "config", "uploadpack.allowAnySHA1InWant", "true"], path)
    (path / "file.txt").write_text("one\n")
    _git(["git", "add", "file.txt"], path)
    _git(["git", "commit", "-m", "one"], path)
    first = _git(["git", "rev-parse", "HEAD"], path)
    (path / "file.txt").write_text("two\n")
    _git(["git", "add", "file.txt"], path)
    _git(["git", "commit", "-m", "two"], path)
    second = _git(["git", "rev-parse", "HEAD"], path)
    return first, second


def test_fetch_checks_out_the_requested_commit_not_the_branch_tip(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    dest = tmp_path / "dest"
    first, second = _source(source)
    commands = git_fetch_sha_commands(str(source), str(dest), first)
    assert all("protocol.file.allow=never" in command for command in commands)
    # The fixture remote is a local directory. Production keeps file:// disabled;
    # the test turns only that one option on so Git will read the fixture.
    local = []
    blocked = "protocol.file.allow=never"
    for command in commands:
        rewritten = []
        for part in command:
            if part == blocked:
                rewritten.append("protocol.file.allow=always")
            else:
                rewritten.append(part)
        local.append(rewritten)
    for command in local:
        subprocess.run(command, check=True, env=git_env("/usr/bin"))
    head = subprocess.run(
        git_rev_parse_args(str(dest)),
        check=True,
        capture_output=True,
        text=True,
        env=git_env("/usr/bin"),
    ).stdout.strip()

    assert head == first
    assert head != second
    assert (dest / "file.txt").read_text() == "one\n"


def test_sha_fetch_failure_does_not_clone_the_default_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], timeout: int) -> Any:
        calls.append(command)

        class _Result:
            returncode = 1
            stderr = "remote refused the sha"
            stdout = ""

        return _Result()

    monkeypatch.setattr(
        "security_console.runner.clone_pins",
        lambda _url: ["example.com:443:203.0.113.10"],
    )
    monkeypatch.setattr("security_console.runner._run_git", fake_run)

    with pytest.raises(CloneError) as caught:
        _clone(
            "https://example.com/app.git",
            tmp_path / "dest",
            "a" * 40,
        )

    assert caught.value.reason == "clone_failed"
    assert calls
    assert all("clone" not in command for command in calls)


def test_head_mismatch_is_not_a_successful_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "a" * 40
    actual = "b" * 40

    def fake_run(command: list[str], timeout: int) -> Any:
        class _Result:
            returncode = 0
            stdout = actual + "\n" if "rev-parse" in command else ""
            stderr = ""

        return _Result()

    monkeypatch.setattr("security_console.runner._run_git", fake_run)

    with pytest.raises(CloneError) as caught:
        _require_head(tmp_path, requested)

    assert caught.value.reason == "sha_mismatch"
    assert actual in str(caught.value)
    assert requested in str(caught.value)
