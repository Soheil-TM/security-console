"""SonarQube issue rows are saved with the scan, not loaded when it is opened."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit

import pytest

from security_console.runner import (
    _empty_sonar,
    _fetch_sonar_summary,
    _sonar_issue_list,
)


class _Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *_args: object) -> Literal[False]:
        return False

    def read(self) -> bytes:
        return self.payload


def _page(payload: dict[str, Any]) -> _Body:
    return _Body(json.dumps(payload).encode())


def _summary_pages(key: str, message: str) -> dict[str, _Body]:
    return {
        "/api/qualitygates/project_status": _page(
            {"projectStatus": {"status": "ERROR"}}
        ),
        "/api/measures/component": _page(
            {
                "component": {
                    "measures": [
                        {"metric": "bugs", "value": "3"},
                        {"metric": "vulnerabilities", "value": "1"},
                        {"metric": "code_smells", "value": "4"},
                        {"metric": "security_hotspots", "value": "2"},
                    ]
                }
            }
        ),
        "/api/issues/search": _page(
            {
                "issues": [
                    {
                        "component": key + ":src/app.py",
                        "line": 12,
                        "rule": "python:S2077",
                        "type": "VULNERABILITY",
                        "severity": "MAJOR",
                        "message": message,
                        "codeSnippet": "SELECT SECRET FROM accounts",
                    },
                    "not-a-dict",
                    {"component": 15, "message": None, "line": True},
                ]
            }
        ),
        "/api/hotspots/search": _page(
            {
                "hotspots": [
                    {
                        "component": key + ":src/db.py",
                        "line": 4,
                        "rule": "ignored-field",
                        "ruleKey": "python:S2245",
                        "message": "review this",
                        "status": "TO_REVIEW",
                        "vulnerabilityProbability": "HIGH",
                        "source": "password = 'hunter2'",
                    }
                ]
            }
        ),
    }


def test_fetch_sonar_summary_stores_trimmed_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = "payments-api"
    message = "m" * 201
    pages = _summary_pages(key, message)
    seen: list[Any] = []

    def fake_open(request: Any, timeout: int = 0) -> _Body:
        seen.append(request)
        path = urlsplit(request.full_url).path
        match = next(body for suffix, body in pages.items() if path.endswith(suffix))
        return match

    monkeypatch.setenv("SONAR_URL", "http://sonarqube:9000/sonar")
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    result = _fetch_sonar_summary(key, "user-token-value")

    assert result["quality_gate"] == "ERROR"
    assert result["bugs"] == 3
    assert result["vulnerabilities"] == 1
    assert result["code_smells"] == 4
    assert result["security_hotspots"] == 2
    assert result["error"] == ""
    assert result["issues"] == [
        {
            "file": "src/app.py",
            "line": 12,
            "rule": "python:S2077",
            "type": "VULNERABILITY",
            "severity": "MAJOR",
            "message": "m" * 200,
        },
        {
            "file": "",
            "line": None,
            "rule": "",
            "type": "",
            "severity": "",
            "message": "",
        },
    ]
    assert result["hotspot_list"] == [
        {
            "file": "src/db.py",
            "line": 4,
            "rule": "python:S2245",
            "message": "review this",
            "status": "TO_REVIEW",
            "vulnerabilityProbability": "HIGH",
        }
    ]
    stored = json.dumps(result)
    assert "SELECT SECRET" not in stored
    assert "hunter2" not in stored
    assert "security-console" not in stored
    issue_query = parse_qs(urlsplit(seen[2].full_url).query)
    assert issue_query["componentKeys"] == [key]
    assert issue_query["resolved"] == ["false"]
    assert issue_query["ps"] == ["500"]
    hotspot_query = parse_qs(urlsplit(seen[3].full_url).query)
    assert hotspot_query["projectKey"] == [key]
    assert hotspot_query["status"] == ["TO_REVIEW"]
    assert hotspot_query["ps"] == ["200"]
    assert all(
        item.get_header("Authorization") == "Bearer user-token-value" for item in seen
    )


def test_issue_lookup_failure_keeps_the_summary_and_hotspots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = "payments-api"
    pages = _summary_pages(key, "short")

    def fake_open(request: Any, timeout: int = 0) -> _Body:
        path = urlsplit(request.full_url).path
        if path.endswith("/api/issues/search"):
            raise urllib.error.URLError("issues down")
        match = next(body for suffix, body in pages.items() if path.endswith(suffix))
        return match

    monkeypatch.setenv("SONAR_URL", "http://sonarqube:9000/sonar")
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    result = _fetch_sonar_summary(key, "user-token-value")

    assert result["quality_gate"] == "ERROR"
    assert result["bugs"] == 3
    assert result["vulnerabilities"] == 1
    assert result["code_smells"] == 4
    assert result["security_hotspots"] == 2
    assert result["issues"] == []
    assert result["hotspot_list"][0]["rule"] == "python:S2245"
    assert result["hotspot_list"][0]["file"] == "src/db.py"


def test_issue_list_stops_at_five_hundred() -> None:
    payload = {
        "issues": [
            {"component": "app:src/f.py", "message": "x", "line": 1},
        ]
        * 501
    }

    rows = _sonar_issue_list(payload, "app")

    assert len(rows) == 500
    assert rows[0]["file"] == "src/f.py"


def test_empty_sonar_keeps_the_error_and_empty_lists() -> None:
    result = _empty_sonar("payments-api", "e" * 1600)

    assert result["issues"] == []
    assert result["hotspot_list"] == []
    assert result["error"] == "e" * 1500
    assert result["bugs"] == 0
    assert result["quality_gate"] == ""
