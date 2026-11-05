"""Console reattach to scanner jobs after restart."""

from __future__ import annotations

from typing import Any

import pytest

from security_console import dispatch


def test_poll_remote_job_does_not_post(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, body: Any, timeout: int) -> Any:
        calls.append((method, path))
        if method == "GET":
            return {
                "status": "done",
                "findings": [],
                "tool_results": [{"tool": "semgrep", "status": "ok"}],
                "error": "",
                "phase": "",
            }
        raise AssertionError("unexpected POST")

    monkeypatch.setattr(dispatch, "_request", fake_request)
    monkeypatch.setattr(dispatch, "_deadline", lambda: 60)
    phases: list[str] = []
    outcome = dispatch.poll_remote_job("abcdef123456", phases.append, None)
    assert outcome["status"] == "done"
    assert calls == [("GET", "/v1/jobs/abcdef123456")]


def test_probe_remote_job_returns_none_when_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(method: str, path: str, body: Any, timeout: int) -> Any:
        raise dispatch.JobGone("missing")

    monkeypatch.setattr(dispatch, "scanner_url", lambda: "http://scanner")
    monkeypatch.setattr(dispatch, "_request", boom)
    assert dispatch.probe_remote_job("abcdef123456") is None


def test_remote_scan_posts_then_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_request(method: str, path: str, body: Any, timeout: int) -> Any:
        calls.append(method)
        if method == "POST":
            return {"id": "abcdef123456"}
        return {
            "status": "done",
            "findings": [],
            "tool_results": [],
            "error": "",
        }

    monkeypatch.setattr(dispatch, "_request", fake_request)
    monkeypatch.setattr(dispatch, "_deadline", lambda: 60)
    monkeypatch.setattr(dispatch, "scanner_url", lambda: "http://scanner")
    monkeypatch.setattr(dispatch, "parse_job", lambda job: job)
    outcome = dispatch.dispatch_scan(
        {
            "id": "abcdef123456",
            "target": "repo",
            "repo": "https://example.com/a.git",
            "image": "",
            "tools": ["semgrep"],
            "requested_sha": "",
        },
        lambda _phase: None,
    )
    assert outcome["status"] == "done"
    assert calls[0] == "POST"
    assert "GET" in calls
