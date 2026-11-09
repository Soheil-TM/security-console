"""P3: admin /api/ci/tokens session CRUD; CI/GATE rejected; audit; hash-only."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from argon2 import PasswordHasher
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from security_console import db
from security_console.ci_api_tokens import create_token, hash_token
from security_console.db import (
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
)

_HASHER = PasswordHasher()
_FILE_TOKEN = "ci-file-fallback-token-must-be-long"
_GATE = "gate-token-must-be-long-enough-xx"


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


@pytest.fixture()
def admin_app(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    if not _db_ready():
        pytest.skip("database required")
    monkeypatch.setenv("CONSOLE_ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "0")
    monkeypatch.setenv("CONSOLE_JWT_KEY", "test-jwt-key-must-be-32-characters")
    monkeypatch.setenv("CI_SCAN_TOKEN", _FILE_TOKEN)
    monkeypatch.setenv("CI_SCAN_FILE_TOKEN", "1")
    monkeypatch.setenv("GATE_TOKEN", _GATE)
    monkeypatch.delenv("CI_SCAN_TOKEN_FILE", raising=False)
    prepare_database()
    from flask import Flask

    from security_console.auth import install_auth, prepare_auth

    prepare_auth()
    reset_auth_tables()
    reset_scan_table()
    insert_user("boss", _HASHER.hash("boss-password"), "admin")
    insert_user(
        "root",
        _HASHER.hash("root-password"),
        "super_admin",
    )
    insert_user("viewer", _HASHER.hash("viewer-password"), "viewer")
    insert_user("dev", _HASHER.hash("dev-password"), "developer")
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    return app.test_client()


def _login(client: FlaskClient, username: str, password: str) -> TestResponse:
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def _csrf(login: TestResponse) -> str:
    for raw in login.headers.getlist("Set-Cookie"):
        if raw.startswith("csrf_token="):
            return raw.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError("csrf cookie missing")


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_admin_create_list_revoke_and_audit(admin_app: FlaskClient) -> None:
    login = _login(admin_app, "boss", "boss-password")
    assert login.status_code == 200
    csrf = _csrf(login)

    future = (datetime.now(UTC) + timedelta(days=14)).isoformat()
    created = admin_app.post(
        "/api/ci/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"name": "gitlab-runner", "expires_at": future},
    )
    assert created.status_code == 201, created.get_data(as_text=True)
    body = created.get_json()
    assert isinstance(body, dict)
    plaintext = body["token"]
    assert plaintext.startswith("csc_")
    assert body["prefix"] in plaintext
    assert body["name"] == "gitlab-runner"
    assert body["status"] == "active"
    token_id = int(body["id"])

    listed = admin_app.get("/api/ci/tokens")
    assert listed.status_code == 200
    rows = listed.get_json()
    assert isinstance(rows, list)
    assert len(rows) == 1
    assert "token" not in rows[0]
    assert "token_hash" not in rows[0]
    assert rows[0]["prefix"] == body["prefix"]
    assert rows[0]["id"] == token_id

    # Hash-only in DB; plaintext never stored.
    db_row = db.get_ci_api_token_by_prefix(body["prefix"])
    assert db_row is not None
    assert db_row["token_hash"] == hash_token(plaintext)
    assert plaintext not in str(db_row.values())

    revoked = admin_app.post(
        f"/api/ci/tokens/{token_id}/revoke",
        headers={"X-CSRF-Token": csrf},
        json={},
    )
    assert revoked.status_code == 200
    rev_body = revoked.get_json()
    assert rev_body["status"] == "revoked"
    assert "token" not in rev_body
    assert rev_body["revoked_at"]

    again = admin_app.post(
        f"/api/ci/tokens/{token_id}/revoke",
        headers={"X-CSRF-Token": csrf},
        json={},
    )
    assert again.status_code == 200
    assert again.get_json()["status"] == "revoked"

    deleted = admin_app.delete(
        f"/api/ci/tokens/{token_id}",
        headers={"X-CSRF-Token": csrf},
    )
    assert deleted.status_code == 200, deleted.get_data(as_text=True)
    assert deleted.get_json()["ok"] is True
    assert db.get_ci_api_token_by_prefix(body["prefix"]) is None
    assert admin_app.get("/api/ci/tokens").get_json() == []

    events = db.list_audit_events(limit=50)
    actions = [e["action"] for e in events]
    assert "ci.token.create" in actions
    assert "ci.token.revoke" in actions
    assert "ci.token.delete" in actions
    for event in events:
        if event["action"] in {
            "ci.token.create",
            "ci.token.revoke",
            "ci.token.delete",
        }:
            blob = str(event.get("detail") or {}) + str(event.get("target_id") or "")
            assert plaintext not in blob
            assert "token_hash" not in blob


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_delete_refuses_active_token(admin_app: FlaskClient) -> None:
    login = _login(admin_app, "boss", "boss-password")
    csrf = _csrf(login)
    created = admin_app.post(
        "/api/ci/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"name": "keep-me", "never": True},
    )
    assert created.status_code == 201
    token_id = int(created.get_json()["id"])
    refused = admin_app.delete(
        f"/api/ci/tokens/{token_id}",
        headers={"X-CSRF-Token": csrf},
    )
    assert refused.status_code == 400
    assert "revoke" in (refused.get_json() or {}).get("error", "").lower()



@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_super_admin_can_create_never_expire(admin_app: FlaskClient) -> None:
    login = _login(admin_app, "root", "root-password")
    assert login.status_code == 200
    csrf = _csrf(login)
    created = admin_app.post(
        "/api/ci/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"name": "forever", "never": True},
    )
    assert created.status_code == 201
    body = created.get_json()
    assert body["expires_at"] is None
    assert body["token"].startswith("csc_")


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_non_admin_forbidden(admin_app: FlaskClient) -> None:
    for user, password in (("viewer", "viewer-password"), ("dev", "dev-password")):
        client = admin_app
        login = _login(client, user, password)
        assert login.status_code == 200
        csrf = _csrf(login)
        assert client.get("/api/ci/tokens").status_code == 403
        assert (
            client.post(
                "/api/ci/tokens",
                headers={"X-CSRF-Token": csrf},
                json={"name": "nope", "never": True},
            ).status_code
            == 403
        )


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_ci_and_gate_tokens_rejected_on_admin_routes(
    admin_app: FlaskClient,
) -> None:
    token, _meta = create_token(
        name="machine",
        created_by=None,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    # Fresh client: no session cookies from prior logins in other tests —
    # use Authorization only.
    for auth in (
        "Bearer " + token,
        "Bearer " + _FILE_TOKEN,
        "Bearer " + _GATE,
    ):
        get_resp = admin_app.get(
            "/api/ci/tokens",
            headers={"Authorization": auth},
        )
        assert get_resp.status_code in {401, 403}, auth
        post_resp = admin_app.post(
            "/api/ci/tokens",
            headers={"Authorization": auth, "X-CSRF-Token": "x"},
            json={"name": "nope", "never": True},
        )
        assert post_resp.status_code in {401, 403}, auth


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_name_and_expires_validation(admin_app: FlaskClient) -> None:
    login = _login(admin_app, "boss", "boss-password")
    csrf = _csrf(login)

    bad_name = admin_app.post(
        "/api/ci/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"name": "bad!!!", "never": True},
    )
    assert bad_name.status_code == 400

    past = admin_app.post(
        "/api/ci/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "name": "stale",
            "expires_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        },
    )
    assert past.status_code == 400
    assert "future" in (past.get_json() or {}).get("error", "").lower()

    missing_csrf = admin_app.post(
        "/api/ci/tokens",
        json={"name": "nocsrf", "never": True},
    )
    assert missing_csrf.status_code == 403


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_unsigned_in_rejected(admin_app: FlaskClient) -> None:
    fresh = admin_app.application.test_client()
    assert fresh.get("/api/ci/tokens").status_code == 401
