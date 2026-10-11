"""HTTP contract for console login and access control."""

from __future__ import annotations

import os

import pytest
from argon2 import PasswordHasher
from flask import Flask, jsonify

from security_console.auth import install_auth, prepare_auth
from security_console.db import insert_user, prepare_database, reset_auth_tables

_HASHER = PasswordHasher()


@pytest.fixture(scope="session", autouse=True)
def schema():
    """Create the auth tables once for this database."""

    prepare_database()


@pytest.fixture()
def client():
    """Return a client against an empty auth database and one admin."""

    reset_auth_tables()
    insert_user("admin", _HASHER.hash("correct-password"), "admin")
    insert_user("viewer", _HASHER.hash("viewer-password"), "viewer")
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.post("/api/scans")
    def create_scan():
        return jsonify({"id": "scan-1"}), 202

    @app.get("/api/scans")
    def list_scans():
        return jsonify([])

    @app.get("/api/falco")
    def list_falco():
        return jsonify([])

    @app.post("/api/falco")
    def ingest_falco():
        return jsonify({"ok": True})

    install_auth(app)
    return app.test_client()


def _login(client, username: str, password: str):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def test_login_rejects_unknown_user_and_wrong_password_the_same(client):
    unknown = _login(client, "missing", "correct-password")
    wrong = _login(client, "admin", "wrong-password")

    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.get_json()["error"] == wrong.get_json()["error"]


def test_login_sets_httponly_cookies(client):
    response = _login(client, "admin", "correct-password")

    assert response.status_code == 200
    assert response.get_json()["role"] == "admin"
    access = response.headers.getlist("Set-Cookie")
    joined = " ".join(access)
    assert "access_token=" in joined
    assert "HttpOnly" in joined
    assert "SameSite=Strict" in joined


def test_scans_require_a_session(client):
    response = client.get("/api/scans")

    assert response.status_code == 401


def test_viewer_cannot_start_a_scan(client):
    login = _login(client, "viewer", "viewer-password")
    csrf = _csrf(login)

    response = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 403


def test_developer_without_a_tool_cannot_start_it(client):
    insert_user(
        "dev",
        _HASHER.hash("developer-password"),
        "developer",
        allow_semgrep=False,
        allow_checkov=False,
        allow_sonar=False,
    )
    login = _login(client, "dev", "developer-password")
    csrf = _csrf(login)

    response = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 403


def test_developer_with_a_tool_can_start_it(client):
    insert_user(
        "dev",
        _HASHER.hash("developer-password"),
        "developer",
        allow_semgrep=True,
        allow_checkov=False,
        allow_sonar=False,
    )
    login = _login(client, "dev", "developer-password")
    csrf = _csrf(login)

    response = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 202


def test_admin_can_start_a_scan(client):
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    response = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 202


def test_me_returns_the_signed_in_user(client):
    _login(client, "admin", "correct-password")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.get_json()["username"] == "admin"


def test_logout_ends_the_session(client):
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    logged_out = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    me = client.get("/api/auth/me")

    assert logged_out.status_code == 200
    assert me.status_code == 401


def test_refresh_replaces_the_session(client):
    _login(client, "admin", "correct-password")

    refreshed = client.post("/api/auth/refresh")
    me = client.get("/api/auth/me")

    assert refreshed.status_code == 200
    assert me.status_code == 200


def test_falco_ingest_requires_the_shared_token(client):
    rejected = client.post("/api/falco", json={"rule": "test"})
    accepted = client.post(
        "/api/falco",
        json={"rule": "test"},
        headers={"User-Agent": os.environ["FALCO_INGEST_TOKEN"]},
    )

    assert rejected.status_code == 401
    assert accepted.status_code == 200


def test_login_rate_limit(client):
    for _ in range(5):
        _login(client, "admin", "wrong-password")

    blocked = _login(client, "admin", "correct-password")

    assert blocked.status_code == 429


def test_viewer_cannot_list_users(client):
    login = _login(client, "viewer", "viewer-password")
    csrf = _csrf(login)

    listing = client.get("/api/users")
    created = client.post(
        "/api/users",
        json={
            "username": "new-user",
            "email": "new@example.com",
            "password": "correct-password",
            "role": "viewer",
            "access": {"semgrep": True, "checkov": False, "sonar": False},
        },
        headers={"X-CSRF-Token": csrf},
    )

    assert listing.status_code == 403
    assert created.status_code == 403


def test_admin_manages_users(client):
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    created = client.post(
        "/api/users",
        json={
            "username": "new-user",
            "email": "New@Example.com",
            "password": "correct-password",
            "role": "developer",
            "access": {"semgrep": True, "checkov": False, "sonar": True},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    user_id = created.get_json()["id"]
    assert created.get_json()["email"] == "new@example.com"
    assert created.get_json()["access"]["sonar"] is True

    updated = client.patch(
        f"/api/users/{user_id}",
        json={
            "username": "new-user",
            "email": "new@example.com",
            "role": "viewer",
            "access": {"semgrep": True, "checkov": True, "sonar": False},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert updated.status_code == 200
    assert updated.get_json()["role"] == "viewer"
    assert updated.get_json()["access"]["sonar"] is False

    removed = client.delete(
        f"/api/users/{user_id}",
        headers={"X-CSRF-Token": csrf},
    )
    assert removed.status_code == 200


def test_admin_cannot_delete_self(client):
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    me = client.get("/api/auth/me").get_json()

    response = client.delete(
        f"/api/users/{me['id']}",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 409


def test_first_password_must_be_replaced_before_the_console_opens(client):
    insert_user(
        "fresh",
        _HASHER.hash("admin"),
        "developer",
        must_change_password=True,
    )
    login = _login(client, "fresh", "admin")
    csrf = _csrf(login)

    blocked = client.get("/api/scans")
    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": "admin",
            "new_password": "replacement-pass",
        },
        headers={"X-CSRF-Token": csrf},
    )
    opened = client.get("/api/scans")

    assert login.status_code == 200
    assert login.get_json()["must_change_password"] is True
    assert blocked.status_code == 403
    assert changed.status_code == 200
    assert opened.status_code == 200
    assert client.get("/api/auth/me").get_json()["must_change_password"] is False


def test_empty_database_signs_in_as_admin(client):
    reset_auth_tables()
    prepare_auth()

    response = _login(client, "admin", "admin")

    assert response.status_code == 200
    assert response.get_json()["username"] == "admin"
    assert response.get_json()["must_change_password"] is True


def test_password_change_checks_the_current_password(client):
    login = _login(client, "viewer", "viewer-password")
    csrf = _csrf(login)
    rejected = client.post(
        "/api/auth/password",
        json={
            "current_password": "wrong-password",
            "new_password": "replacement-pass",
        },
        headers={"X-CSRF-Token": csrf},
    )
    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": "viewer-password",
            "new_password": "replacement-pass",
        },
        headers={"X-CSRF-Token": csrf},
    )
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    relogin = _login(client, "viewer", "replacement-pass")

    assert rejected.status_code == 401
    assert changed.status_code == 200
    assert relogin.status_code == 200


def _csrf(response) -> str:
    cookie = response.headers.getlist("Set-Cookie")
    for header in cookie:
        if header.startswith("csrf_token="):
            return header.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError("csrf cookie missing")
