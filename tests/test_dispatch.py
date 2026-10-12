"""The console calls the worker instead of opening the Docker socket."""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Literal

import pytest

from security_console import dispatch


class _Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *_args: object) -> Literal[False]:
        return False

    def read(self) -> bytes:
        return self.payload


def test_remote_scan_sends_the_job_and_not_a_docker_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SCANNER_URL", "http://scanner:8092")
    monkeypatch.setenv("SCANNER_TOKEN", "scanner-token-value-24")
    captured: dict[str, Any] = {}

    def fake_open(request: Any, timeout: int = 0) -> _Body:
        captured.setdefault("calls", []).append(request.full_url)
        if request.data:
            captured["body"] = json.loads(request.data.decode())
            captured["auth"] = request.get_header("Authorization")
            return _Body(b'{"id":"abc123def456"}')
        return _Body(
            b'{"status":"done","phase":"Trivy","findings":[],"sonar":null,"error":""}'
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    phases: list[str] = []
    result = dispatch.dispatch_scan(
        {
            "id": "abc123def456",
            "target": "image",
            "image": "nginx:1.27",
            "tools": ["trivy"],
            "privileged": True,
        },
        phases.append,
    )

    assert captured["auth"] == "Bearer scanner-token-value-24"
    assert captured["body"] == {
        "id": "abc123def456",
        "target": "image",
        "repo": "",
        "image": "nginx:1.27",
        "tools": ["trivy"],
    }
    assert result["status"] == "done"
    assert phases == ["Trivy"]
    assert "docker.sock" not in json.dumps(captured["body"])
