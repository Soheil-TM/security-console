"""CI scan API: token auth, enqueue, and severity policy."""

from __future__ import annotations

import os
import threading

import pytest
from argon2 import PasswordHasher
from flask.testing import FlaskClient

from security_console import db
from security_console.ci_scans import bind_ci_store, evaluate_ci_policy
from security_console.db import (
    insert_project,
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
)

_HASHER = PasswordHasher()
_CI_TOKEN = "ci-test-token-must-be-long-enough"


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


pytestmark_db = pytest.mark.skipif(
    not _db_ready(),
    reason="console database settings are required for CI scan storage tests",
)


def test_policy_pending_while_running() -> None:
    result = evaluate_ci_policy(
        {"status": "running", "tools": ["semgrep"], "findings": [], "tool_results": []}
    )
    assert result["pending"] is True
    assert result["passed"] is None


def test_policy_pass_clean_done() -> None:
    result = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["semgrep"],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
            "findings": [
                {
                    "tool": "semgrep",
                    "severity": "LOW",
                    "check": "x",
                    "path": "a.py",
                    "message": "m",
                }
            ],
            "sonar": {"quality_gate": "OK"},
        }
    )
    assert result["pending"] is False
    assert result["passed"] is True
    assert result["reasons"] == []


def test_policy_fail_critical_and_high() -> None:
    critical = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["semgrep"],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
            "findings": [
                {
                    "tool": "semgrep",
                    "severity": "CRITICAL",
                    "check": "x",
                    "path": "a.py",
                    "message": "m",
                }
            ],
        }
    )
    assert critical["passed"] is False
    assert "severity_critical" in critical["reasons"]

    high = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["semgrep"],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
            "findings": [
                {
                    "tool": "semgrep",
                    "severity": "HIGH",
                    "check": "x",
                    "path": "a.py",
                    "message": "m",
                }
            ],
        }
    )
    assert high["passed"] is False
    assert "severity_high" in high["reasons"]


def test_policy_medium_only_passes() -> None:
    result = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["semgrep"],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
            "findings": [
                {
                    "tool": "semgrep",
                    "severity": "MEDIUM",
                    "check": "x",
                    "path": "a.py",
                    "message": "m",
                }
            ],
        }
    )
    assert result["passed"] is True


def test_policy_tool_failed_and_scan_failed() -> None:
    tool = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["semgrep", "checkov"],
            "tool_results": [
                {"tool": "semgrep", "status": "ok"},
                {"tool": "checkov", "status": "failed", "error": "timeout"},
            ],
            "findings": [],
        }
    )
    assert tool["passed"] is False
    assert "tool_failed:checkov" in tool["reasons"]


def test_policy_checkov_no_targets_does_not_fail_tool() -> None:
    result = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["checkov", "semgrep"],
            "tool_results": [
                {
                    "tool": "checkov",
                    "status": "ok",
                    "coverage": "no_targets",
                    "summary": {"resource_count": 0, "passed": 0, "failed": 0},
                },
                {"tool": "semgrep", "status": "ok"},
            ],
            "findings": [],
            "sonar": {"quality_gate": "OK"},
        }
    )
    assert result["pending"] is False
    assert result["passed"] is True
    assert "tool_failed:checkov" not in result["reasons"]

    failed = evaluate_ci_policy(
        {
            "status": "failed",
            "tools": ["semgrep"],
            "tool_results": [],
            "findings": [],
            "error": "clone failed",
        }
    )
    assert failed["passed"] is False
    assert "scan_failed" in failed["reasons"]


def test_policy_sonar_gate_error() -> None:
    result = evaluate_ci_policy(
        {
            "status": "done",
            "tools": ["sonar"],
            "tool_results": [{"tool": "sonar", "status": "ok"}],
            "findings": [],
            "sonar": {"quality_gate": "ERROR", "project_key": "sc-x"},
        }
    )
    assert result["passed"] is False
    assert "sonar_quality_gate_error" in result["reasons"]


@pytest.fixture()
def ci_client(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    if not _db_ready():
        pytest.skip("console database settings are required")
    monkeypatch.setenv("CONSOLE_ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "0")
    monkeypatch.setenv("CONSOLE_JWT_KEY", "test-jwt-key-must-be-32-characters")
    monkeypatch.setenv("CI_SCAN_TOKEN", _CI_TOKEN)
    monkeypatch.setenv("GATE_TOKEN", "gate-token-must-be-long-enough-xx")
    prepare_database()
    from flask import Flask

    from security_console.auth import install_auth, prepare_auth

    prepare_auth()
    reset_auth_tables()
    reset_scan_table()
    uid = insert_user("boss", _HASHER.hash("boss-password"), "admin")
    insert_project(
        slug="alpha",
        name="Alpha",
        description="",
        created_by=uid,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/alpha.git",
                "key": "repo:https://example.com/alpha.git",
            }
        ],
        group_ids=[],
    )
    scans: dict = {}
    lock = threading.Lock()

    def save(item: dict) -> None:
        db.upsert_scan(item)

    bind_ci_store(lock, scans, save, lambda: "2026-11-05 12:00:00 UTC")
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    client = app.test_client()
    client.scans = scans  # type: ignore[attr-defined]
    yield client
    reset_scan_table()
    reset_auth_tables()


def _ci_headers() -> dict[str, str]:
    return {
        "Authorization": "Bearer " + _CI_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


@pytestmark_db
def test_ci_rejects_missing_and_gate_token(ci_client: FlaskClient) -> None:
    bare = ci_client.post("/api/ci/scans", json={"project": "alpha"})
    assert bare.status_code == 401
    gate = ci_client.post(
        "/api/ci/scans",
        json={"project": "alpha", "tools": ["semgrep"]},
        headers={
            "Authorization": "Bearer gate-token-must-be-long-enough-xx",
            "Content-Type": "application/json",
        },
    )
    assert gate.status_code == 401


@pytestmark_db
def test_ci_enqueue_and_get_policy_pending(ci_client: FlaskClient) -> None:
    created = ci_client.post(
        "/api/ci/scans",
        json={
            "project": "alpha",
            "target": "repo",
            "tools": ["semgrep"],
            "requested_sha": "a" * 40,
        },
        headers=_ci_headers(),
    )
    assert created.status_code == 202
    body = created.get_json()
    assert body["owner"] == "ci"
    assert body["status"] == "queued"
    assert body["tools"] == ["semgrep"]
    assert body["requested_sha"] == "a" * 40
    assert body["policy"]["pending"] is True
    scan_id = body["id"]
    assert scan_id in ci_client.scans  # type: ignore[attr-defined]

    polled = ci_client.get("/api/ci/scans/" + scan_id, headers=_ci_headers())
    assert polled.status_code == 200
    assert polled.get_json()["policy"]["pending"] is True


@pytestmark_db
def test_ci_unknown_project(ci_client: FlaskClient) -> None:
    response = ci_client.post(
        "/api/ci/scans",
        json={"project": "missing", "tools": ["semgrep"]},
        headers=_ci_headers(),
    )
    assert response.status_code == 404


@pytestmark_db
def test_ci_queue_cap(ci_client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from security_console import ci_scans
    from security_console import queue as queue_mod

    monkeypatch.setattr(ci_scans, "QUEUE_CAP", 1)
    monkeypatch.setattr(queue_mod, "QUEUE_CAP", 1)
    first = ci_client.post(
        "/api/ci/scans",
        json={"project": "alpha", "tools": ["semgrep"], "force": True},
        headers=_ci_headers(),
    )
    assert first.status_code == 202
    second = ci_client.post(
        "/api/ci/scans",
        json={"project": "alpha", "tools": ["checkov"], "force": True},
        headers=_ci_headers(),
    )
    assert second.status_code == 429
