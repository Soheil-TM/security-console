"""HTTP contract for console login and access control."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from argon2 import PasswordHasher
from flask import Flask, Response, jsonify
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from security_console.auth import install_auth, prepare_auth
from security_console.db import (
    connect,
    insert_user,
    prepare_database,
    reset_auth_tables,
)

Reply = Response | tuple[Response, int]
_HASHER = PasswordHasher()


@pytest.fixture(scope="session", autouse=True)
def schema() -> None:
    """Create the auth tables once for this database."""

    prepare_database()


@pytest.fixture()
def client() -> FlaskClient:
    """Return a client against an empty auth database and one admin."""

    reset_auth_tables()
    insert_user("admin", _HASHER.hash("correct-password"), "admin")
    insert_user("viewer", _HASHER.hash("viewer-password"), "viewer")
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.post("/api/scans")
    def create_scan() -> Reply:
        return jsonify({"id": "scan-1"}), 202

    @app.get("/api/scans")
    def list_scans() -> Response:
        return jsonify([])

    @app.get("/api/scans/<scan_id>")
    def get_scan(scan_id: str) -> Response:
        return jsonify({"id": scan_id})

    @app.get("/api/images")
    def list_images() -> Response:
        return jsonify([])

    install_auth(app)
    return app.test_client()


def _login(client: FlaskClient, username: str, password: str) -> TestResponse:
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def test_login_rejects_unknown_user_and_wrong_password_the_same(
    client: FlaskClient,
) -> None:
    unknown = _login(client, "missing", "correct-password")
    wrong = _login(client, "admin", "wrong-password")

    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.get_json()["error"] == wrong.get_json()["error"]


def test_login_sets_httponly_cookies(client: FlaskClient) -> None:
    response = _login(client, "admin", "correct-password")

    assert response.status_code == 200
    assert response.get_json()["role"] == "admin"
    access = response.headers.getlist("Set-Cookie")
    joined = " ".join(access)
    assert "access_token=" in joined
    assert "HttpOnly" in joined
    assert "SameSite=Strict" in joined


def test_scans_require_a_session(client: FlaskClient) -> None:
    response = client.get("/api/scans")

    assert response.status_code == 401


def test_viewer_cannot_start_a_scan(client: FlaskClient) -> None:
    login = _login(client, "viewer", "viewer-password")
    csrf = _csrf(login)

    response = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 403


def test_developer_without_a_tool_cannot_start_it(client: FlaskClient) -> None:
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


def test_developer_with_a_tool_can_start_it(client: FlaskClient) -> None:
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


def test_admin_can_start_a_scan(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    response = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 202


def test_me_returns_the_signed_in_user(client: FlaskClient) -> None:
    _login(client, "admin", "correct-password")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.get_json()["username"] == "admin"


def test_logout_ends_the_session(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    logged_out = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    me = client.get("/api/auth/me")

    assert logged_out.status_code == 200
    assert me.status_code == 401


def test_refresh_replaces_the_session(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    rejected = client.post("/api/auth/refresh")
    refreshed = client.post("/api/auth/refresh", headers={"X-CSRF-Token": csrf})
    me = client.get("/api/auth/me")

    assert rejected.status_code == 403
    assert refreshed.status_code == 200
    assert me.status_code == 200


def test_password_gate_blocks_alternate_methods_and_paths(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ADMIN_PASSWORD", "generated-admin-password")
    reset_auth_tables()
    prepare_auth()
    login = _login(client, "admin", "admin")
    csrf = _csrf(login)
    paths = (
        "/api/scans",
        "/api/scans/",
        "/api//scans",
        "/api/scans/abc123def456",
        "/api/images",
        "/api/users",
        "/api/users/1",
    )

    for method in ("HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"):
        for path in paths:
            response = client.open(
                path,
                method=method,
                json={},
                headers={"X-CSRF-Token": csrf},
            )
            assert response.status_code == 403, (method, path)


def test_login_rate_limit(client: FlaskClient) -> None:
    for _ in range(5):
        _login(client, "admin", "wrong-password")

    blocked = _login(client, "admin", "correct-password")

    assert blocked.status_code == 429


def test_viewer_cannot_list_users(client: FlaskClient) -> None:
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


def test_admin_manages_users(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    created = client.post(
        "/api/users",
        json={
            "first_name": "New",
            "last_name": "User",
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
    assert created.get_json()["first_name"] == "New"
    assert created.get_json()["last_name"] == "User"
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
    assert updated.get_json()["first_name"] == "New"
    assert updated.get_json()["role"] == "viewer"
    assert updated.get_json()["access"]["sonar"] is False

    removed = client.delete(
        f"/api/users/{user_id}",
        headers={"X-CSRF-Token": csrf},
    )
    assert removed.status_code == 200


def test_admin_cannot_delete_self(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    me = client.get("/api/auth/me").get_json()

    response = client.delete(
        f"/api/users/{me['id']}",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 409


def test_first_password_must_be_replaced_before_the_console_opens(
    client: FlaskClient,
) -> None:
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


def test_empty_database_signs_in_as_admin(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CONSOLE_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("CONSOLE_ADMIN_PASSWORD_FILE", raising=False)
    reset_auth_tables()
    prepare_auth()

    response = _login(client, "admin", "admin")

    assert response.status_code == 200
    assert response.get_json()["username"] == "admin"
    assert response.get_json()["must_change_password"] is True


def test_password_file_does_not_replace_the_initial_password(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ADMIN_PASSWORD", "generated-admin-password")
    reset_auth_tables()
    prepare_auth()

    rejected = _login(client, "admin", "generated-admin-password")
    accepted = _login(client, "admin", "admin")

    assert rejected.status_code == 401
    assert accepted.status_code == 200
    assert accepted.get_json()["must_change_password"] is True


def test_existing_database_is_not_reset_to_admin(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ADMIN_PASSWORD", "generated-admin-password")
    prepare_auth()
    prepare_auth()

    assert _login(client, "admin", "admin").status_code == 401
    kept = _login(client, "admin", "correct-password")

    assert kept.status_code == 200
    assert kept.get_json()["must_change_password"] is False


_SENSITIVE = (
    ("GET", "/api/scans"),
    ("POST", "/api/scans"),
    ("GET", "/api/scans/abc123def456"),
    ("GET", "/api/images"),
    ("GET", "/api/users"),
    ("GET", "/api/sonar/setup"),
    ("POST", "/api/sonar/setup"),
    ("POST", "/api/users"),
    ("PATCH", "/api/users/1"),
    ("DELETE", "/api/users/1"),
)


def test_password_gate_blocks_sensitive_routes_until_the_change(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ADMIN_PASSWORD", "generated-admin-password")
    reset_auth_tables()
    prepare_auth()
    login = _login(client, "admin", "admin")
    csrf = _csrf(login)

    for method, path in _SENSITIVE:
        response = client.open(
            path,
            method=method,
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 403, path
        assert "password" in response.get_json()["error"].lower()

    assert client.get("/api/auth/me").get_json()["must_change_password"] is True
    refreshed = client.post("/api/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert refreshed.status_code == 200
    assert refreshed.get_json()["must_change_password"] is True
    assert client.get("/api/scans").status_code == 403

    csrf = _csrf(refreshed)
    assert client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": csrf},
    ).status_code == 200
    again = _login(client, "admin", "admin")
    assert again.get_json()["must_change_password"] is True
    assert client.get("/api/users").status_code == 403

    csrf = _csrf(again)
    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": "admin",
            "new_password": "replacement-pass",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 200
    csrf = _csrf(changed)
    assert client.get("/api/scans").status_code == 200
    assert client.get("/api/scans/abc123def456").status_code == 200
    assert client.get("/api/images").status_code == 200
    started = client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert started.status_code == 202
    assert client.get("/api/users").status_code == 200
    created = client.post(
        "/api/users",
        json={
            "first_name": "New",
            "last_name": "User",
            "username": "new-user",
            "email": "new@example.com",
            "password": "replacement-pass",
            "role": "viewer",
            "access": {
                "semgrep": False,
                "checkov": False,
                "sonar": False,
                "trivy": False,
            },
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201


def test_viewer_keeps_role_limits_after_the_password_change(
    client: FlaskClient,
) -> None:
    insert_user(
        "locked",
        _HASHER.hash("admin"),
        "viewer",
        must_change_password=True,
    )
    login = _login(client, "locked", "admin")
    csrf = _csrf(login)
    assert client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    ).status_code == 403

    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": "admin",
            "new_password": "replacement-pass",
        },
        headers={"X-CSRF-Token": csrf},
    )
    csrf = _csrf(changed)

    assert client.get("/api/scans").status_code == 200
    assert client.post(
        "/api/scans",
        json={"repo": "https://example.com/app.git", "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    ).status_code == 403
    assert client.get("/api/users").status_code == 403


def test_forwarded_client_is_ignored_unless_the_proxy_is_trusted(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )

    blocked = _login(client, "admin", "correct-password")

    assert blocked.status_code == 429


def test_trusted_proxy_uses_the_forwarded_client(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRUSTED_PROXIES", "127.0.0.1")
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )

    direct = _login(client, "admin", "correct-password")
    forwarded = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct-password"},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )

    assert direct.status_code == 200
    assert forwarded.status_code == 429


def test_password_change_revokes_other_sessions(client: FlaskClient) -> None:
    login = _login(client, "viewer", "viewer-password")
    csrf = _csrf(login)
    other = client.application.test_client()
    other_login = _login(other, "viewer", "viewer-password")
    other_csrf = _csrf(other_login)

    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": "viewer-password",
            "new_password": "replacement-pass",
        },
        headers={"X-CSRF-Token": csrf},
    )

    assert changed.status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401
    assert (
        other.post(
            "/api/auth/refresh",
            headers={"X-CSRF-Token": other_csrf},
        ).status_code
        == 401
    )


def test_security_headers_and_hsts(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("COOKIE_SECURE", "0")
    plain = client.get("/api/auth/me")
    assert plain.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in plain.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in plain.headers

    monkeypatch.setenv("COOKIE_SECURE", "1")
    login = _login(client, "admin", "correct-password")
    joined = " ".join(login.headers.getlist("Set-Cookie"))

    assert "Secure" in joined
    assert "max-age=31536000" in login.headers["Strict-Transport-Security"]


def test_password_change_checks_the_current_password(client: FlaskClient) -> None:
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


@pytest.mark.parametrize(
    "value",
    [0, 1, 4, 10, 45, 61, 120, None, "never", "infinite", "", False, True, 15.5],
)
def test_idle_timeout_rejects_unbounded_values(
    client: FlaskClient,
    value: object,
) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    response = client.put(
        "/api/auth/idle-timeout",
        json={"idle_timeout_minutes": value},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 400
    assert client.get("/api/auth/me").get_json()["idle_timeout_minutes"] == 15


def test_idle_timeout_accepts_only_the_bounded_choices(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)

    for minutes in (5, 15, 30, 60):
        saved = client.put(
            "/api/auth/idle-timeout",
            json={"idle_timeout_minutes": minutes},
            headers={"X-CSRF-Token": csrf},
        )
        me = client.get("/api/auth/me")

        assert saved.status_code == 200
        assert saved.get_json()["idle_timeout_minutes"] == minutes
        assert me.get_json()["idle_timeout_minutes"] == minutes
        assert me.get_json()["absolute_timeout_hours"] == 12


def test_background_requests_do_not_extend_the_idle_clock(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    client.put(
        "/api/auth/idle-timeout",
        json={"idle_timeout_minutes": 15},
        headers={"X-CSRF-Token": csrf},
    )
    _rewind_open_sessions(idle_minutes=10)

    listed = client.get("/api/scans")
    refreshed = client.post(
        "/api/auth/refresh",
        headers={"X-CSRF-Token": csrf},
    )
    me = client.get("/api/auth/me")

    assert listed.status_code == 200
    assert refreshed.status_code == 200
    assert me.get_json()["remaining_seconds"] < 6 * 60


def test_activity_resets_only_the_idle_clock(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    _rewind_open_sessions(idle_minutes=10)

    touched = client.post(
        "/api/auth/activity",
        headers={"X-CSRF-Token": csrf},
    )

    assert touched.status_code == 200
    assert touched.get_json()["remaining_seconds"] > 14 * 60


def test_idle_expiry_revokes_the_session(client: FlaskClient) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    client.put(
        "/api/auth/idle-timeout",
        json={"idle_timeout_minutes": 5},
        headers={"X-CSRF-Token": csrf},
    )
    _rewind_open_sessions(idle_minutes=6)
    held = _clone_client(client)

    expired = client.get("/api/scans")
    refresh = held.post(
        "/api/auth/refresh",
        headers={"X-CSRF-Token": csrf},
    )
    activity = held.post(
        "/api/auth/activity",
        headers={"X-CSRF-Token": csrf},
    )

    assert expired.status_code == 401
    assert expired.get_json()["code"] == "idle_expired"
    assert refresh.status_code == 401
    assert activity.status_code == 401
    assert client.get("/api/auth/me").status_code == 401


def test_shortening_the_timeout_expires_an_already_idle_session(
    client: FlaskClient,
) -> None:
    login = _login(client, "admin", "correct-password")
    csrf = _csrf(login)
    _rewind_open_sessions(idle_minutes=10)

    expired = client.put(
        "/api/auth/idle-timeout",
        json={"idle_timeout_minutes": 5},
        headers={"X-CSRF-Token": csrf},
    )

    assert expired.status_code == 401
    assert expired.get_json()["code"] == "idle_expired"
    assert client.get("/api/auth/me").status_code == 401


def test_activity_is_allowed_before_the_password_is_changed(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ADMIN_PASSWORD", "generated-admin-password")
    reset_auth_tables()
    prepare_auth()
    login = _login(client, "admin", "admin")
    csrf = _csrf(login)

    response = client.post(
        "/api/auth/activity",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200
    assert client.get("/api/scans").status_code == 403


def test_absolute_lifetime_ends_an_active_session(client: FlaskClient) -> None:
    _login(client, "admin", "correct-password")
    _rewind_open_sessions(age_hours=13)

    expired = client.get("/api/auth/me")

    assert expired.status_code == 401
    assert expired.get_json()["code"] == "absolute_expired"


def _clone_client(client: FlaskClient) -> FlaskClient:
    """Return a second client that still holds the cookies from the first."""

    other = client.application.test_client()
    cookies = getattr(client, "_cookies", {})
    values = cookies.values() if hasattr(cookies, "values") else cookies
    for cookie in values:
        other.set_cookie(
            cookie.key,
            cookie.value,
            domain=getattr(cookie, "domain", None) or "localhost",
            path=getattr(cookie, "path", None) or "/",
        )
    return other


def _rewind_open_sessions(*, idle_minutes: int = 0, age_hours: int = 0) -> None:
    """Move live session timestamps backward without touching revoked rows."""

    now = datetime.now(UTC)
    with connect() as conn:
        if idle_minutes:
            conn.execute(
                """
                UPDATE refresh_tokens
                SET last_activity_at = %s
                WHERE revoked_at IS NULL
                """,
                (now - timedelta(minutes=idle_minutes),),
            )
        if age_hours:
            conn.execute(
                """
                UPDATE refresh_tokens
                SET created_at = %s
                WHERE revoked_at IS NULL
                """,
                (now - timedelta(hours=age_hours),),
            )
        conn.commit()


def _csrf(response: TestResponse) -> str:
    cookie = response.headers.getlist("Set-Cookie")
    for header in cookie:
        if header.startswith("csrf_token="):
            return header.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError("csrf cookie missing")
