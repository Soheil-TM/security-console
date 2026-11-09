"""P2: CI scan guard accepts DB tokens; uniform 401; file fallback flag."""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta

import pytest
from argon2 import PasswordHasher
from flask.testing import FlaskClient

from security_console import db
from security_console.ci_api_tokens import create_token, revoke_token
from security_console.ci_scans import bind_ci_store, reset_ci_rate_limit
from security_console.db import (
    insert_project,
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
)

_HASHER = PasswordHasher()
_FILE_TOKEN = "ci-file-fallback-token-must-be-long"
_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


@pytest.fixture()
def ci_app(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    if not _db_ready():
        pytest.skip("database required")
    monkeypatch.setenv("CONSOLE_ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "0")
    monkeypatch.setenv("CONSOLE_JWT_KEY", "test-jwt-key-must-be-32-characters")
    monkeypatch.setenv("CI_SCAN_TOKEN", _FILE_TOKEN)
    monkeypatch.setenv("CI_SCAN_FILE_TOKEN", "1")
    monkeypatch.setenv("GATE_TOKEN", "gate-token-must-be-long-enough-xx")
    monkeypatch.delenv("CI_SCAN_TOKEN_FILE", raising=False)
    prepare_database()
    from flask import Flask

    from security_console.auth import install_auth, prepare_auth

    prepare_auth()
    reset_auth_tables()
    reset_scan_table()
    reset_ci_rate_limit()
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
                "key": "https://example.com/alpha",
            }
        ],
        group_ids=[],
    )
    scans: dict = {}
    lock = threading.Lock()
    bind_ci_store(lock, scans, db.upsert_scan, lambda: "2026-11-09 12:00:00 UTC")
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    return app.test_client()


def _body() -> dict:
    return {
        "project": "alpha",
        "target": "repo",
        "requested_sha": _SHA,
        "force": True,
    }


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_db_token_authenticates(ci_app: FlaskClient) -> None:
    token, meta = create_token(
        name="job",
        created_by=None,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    resp = ci_app.post(
        "/api/ci/scans",
        headers={"Authorization": "Bearer " + token},
        json=_body(),
    )
    assert resp.status_code == 202, resp.get_data(as_text=True)
    assert meta["prefix"] in token


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_uniform_401_for_bad_tokens(ci_app: FlaskClient) -> None:
    token, meta = create_token(
        name="temp",
        created_by=None,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    revoke_token(int(meta["id"]))
    expired, exp_meta = create_token(
        name="old",
        created_by=None,
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    cases = [
        token,
        expired,
        "csc_deadbeef_not-a-real-secret-value-xxxxx",
        "csc_bad",
        "totally-wrong",
        "",
    ]
    messages = set()
    for presented in cases:
        headers = {}
        if presented:
            headers["Authorization"] = "Bearer " + presented
        resp = ci_app.post("/api/ci/scans", headers=headers, json=_body())
        assert resp.status_code == 401, presented
        messages.add(resp.get_json()["error"])
    assert messages == {"You are not signed in."}
    # silence unused
    assert exp_meta["status"] in {"expired", "active"}


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_file_fallback_off_rejects_file_token(
    ci_app: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CI_SCAN_FILE_TOKEN", "0")
    resp = ci_app.post(
        "/api/ci/scans",
        headers={"Authorization": "Bearer " + _FILE_TOKEN},
        json=_body(),
    )
    assert resp.status_code == 401


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_file_fallback_on_accepts_file_token(ci_app: FlaskClient) -> None:
    resp = ci_app.post(
        "/api/ci/scans",
        headers={"Authorization": "Bearer " + _FILE_TOKEN},
        json=_body(),
    )
    assert resp.status_code == 202, resp.get_data(as_text=True)


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gate_token_rejected_on_ci_scans(ci_app: FlaskClient) -> None:
    resp = ci_app.post(
        "/api/ci/scans",
        headers={"Authorization": "Bearer gate-token-must-be-long-enough-xx"},
        json=_body(),
    )
    assert resp.status_code == 401
