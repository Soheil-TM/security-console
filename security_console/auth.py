"""Cookie sessions for the console API.

Access tokens are short-lived JWTs. Refresh tokens are random values stored
only as a hash. Both live in HttpOnly cookies. Falco 0.45 cannot set an
arbitrary header, so its webhook proves identity with the User-Agent value.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import psycopg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from flask import Flask, Response, current_app, g, jsonify, request
from jwt import InvalidTokenError

from security_console import db
from security_console.access import access_map

_HASHER = PasswordHasher()
_DUMMY_HASH = _HASHER.hash("console-dummy-password")
_OPEN = {("POST", "/api/auth/login"), ("POST", "/api/auth/refresh")}
_ACCESS_MINUTES = 20
_REFRESH_DAYS = 7
_LOGIN_LIMIT = 5
_BOOTSTRAP_PASSWORD = "admin"
_BOOTSTRAP_FLAG = "bootstrap_admin_v1"
_WHILE_CHANGING_PASSWORD = {
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/password"),
    ("POST", "/api/auth/logout"),
}


def prepare_auth() -> None:
    """Create the auth schema and the first admin when the table is empty.

    The first password is admin. That account must replace it before the
    console can be used. An existing admin is switched to that password
    once, so a later restart does not undo the replacement.
    """

    if len(jwt_key()) < 32:
        raise RuntimeError("console JWT key must be at least 32 characters")
    db.prepare_database()
    username = os.environ.get("CONSOLE_ADMIN_USERNAME", "admin").strip()
    if not _valid_username(username):
        raise RuntimeError("initial admin username is not configured")
    if db.count_users() == 0:
        _insert_bootstrap_admin(username)
        db.set_flag(_BOOTSTRAP_FLAG)
        return
    if db.has_flag(_BOOTSTRAP_FLAG):
        return
    db.require_password_change(username, hash_password(_BOOTSTRAP_PASSWORD))
    db.set_flag(_BOOTSTRAP_FLAG)


def _insert_bootstrap_admin(username: str) -> None:
    db.insert_user(
        username,
        hash_password(_BOOTSTRAP_PASSWORD),
        "admin",
        allow_semgrep=True,
        allow_checkov=True,
        allow_sonar=True,
        allow_trivy=True,
        must_change_password=True,
    )


def jwt_key() -> str:
    """Return the HMAC key used to sign access tokens."""

    return db.read_secret("CONSOLE_JWT_KEY", "CONSOLE_JWT_KEY_FILE")


def falco_token() -> str:
    """Return the shared ingest token, or an empty string when unset."""

    return db.read_secret("FALCO_INGEST_TOKEN", "FALCO_INGEST_TOKEN_FILE")


def install_auth(app: Flask) -> None:
    """Attach login routes and deny API calls that have no valid session."""

    app.after_request(_security_headers)
    app.before_request(_guard)

    @app.post("/api/auth/login")
    def login() -> Response:
        return _call_db(app, lambda: _login(app))

    @app.post("/api/auth/logout")
    def logout() -> Response:
        return _call_db(app, _logout)

    @app.post("/api/auth/refresh")
    def refresh() -> Response:
        return _call_db(app, _refresh)

    @app.get("/api/auth/me")
    def me() -> Response:
        return jsonify(_session_payload(g.user))

    from security_console.users import install_users

    install_users(app)


def _call_db(app: Flask, action: Callable[[], Response]) -> Response:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("auth database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _guard() -> Response | None:
    try:
        return _guard_request()
    except psycopg.Error:
        current_app.logger.error("auth database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _guard_request() -> Response | None:
    if request.path == "/api/falco" and request.method == "POST":
        if not _falco_authorized():
            return jsonify({"error": "Not authorized."}), 401
        return None
    if request.method == "GET" and request.path in {"/", "/login"}:
        return None
    if (request.method, request.path) in _OPEN:
        return None
    if not request.path.startswith("/api/"):
        return None
    user = _current_user()
    if user is None:
        return jsonify({"error": "You are not signed in."}), 401
    g.user = user
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_ok():
        return jsonify({"error": "Request rejected."}), 403
    if user.get("must_change_password") and (
        request.method,
        request.path,
    ) not in _WHILE_CHANGING_PASSWORD:
        return jsonify(
            {"error": "Change your password before continuing."}
        ), 403
    if (
        request.path == "/api/users" or request.path.startswith("/api/users/")
    ) and user["role"] != "admin":
        return jsonify({"error": "You do not have permission."}), 403
    if request.path == "/api/scans" and request.method == "POST":
        body = request.get_json(silent=True) or {}
        requested = body.get("tools") if isinstance(body, dict) else []
        tools = [
            tool
            for tool in requested or []
            if tool in {"semgrep", "checkov", "sonar", "trivy"}
        ]
        if user["role"] not in {"admin", "developer"} or (
            tools and not _tools_allowed(user, tools)
        ):
            return jsonify({"error": "You do not have permission."}), 403
    return None


def _login(app: Flask) -> Response:
    ip = (request.remote_addr or "unknown")[:64]
    if db.recent_failures(ip) >= _LOGIN_LIMIT:
        app.logger.info("login rate limit ip=%s", ip)
        return jsonify({"error": "Too many attempts. Wait one minute."}), 429
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Username or password is incorrect."}), 401
    username = body.get("username")
    password = body.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or len(username) > 64
        or len(password) > 128
    ):
        db.record_attempt(ip, False)
        return jsonify({"error": "Username or password is incorrect."}), 401
    user = db.find_user(username.strip())
    hashed = user["password_hash"] if user else _DUMMY_HASH
    matches = verify_password(hashed, password)
    if user is None or user["disabled"] or not matches:
        db.record_attempt(ip, False)
        app.logger.info("failed login ip=%s", ip)
        return jsonify({"error": "Username or password is incorrect."}), 401
    db.record_attempt(ip, True)
    app.logger.info("login user_id=%s ip=%s", user["id"], ip)
    response = jsonify(_session_payload(user))
    _start_session(response, user)
    return response


def _refresh() -> Response:
    raw = request.cookies.get("refresh_token", "")
    if not raw:
        return _unauthorized()
    taken = db.take_refresh(_hash(raw))
    if taken is None:
        response = _unauthorized()
        _clear_cookies(response)
        return response
    user = db.find_user_by_id(int(taken["user_id"]))
    if user is None or user["disabled"]:
        response = _unauthorized()
        _clear_cookies(response)
        return response
    response = jsonify(_session_payload(user))
    _start_session(response, user)
    return response


def _logout() -> Response:
    token = request.cookies.get("access_token", "")
    claims = _decode(token) if token else None
    if claims is not None:
        exp = datetime.fromtimestamp(int(claims["exp"]), UTC)
        db.revoke_access(str(claims["jti"]), exp)
    raw = request.cookies.get("refresh_token", "")
    if raw:
        db.revoke_refresh(_hash(raw))
    response = jsonify({"ok": True})
    _clear_cookies(response)
    return response


def _current_user() -> dict[str, Any] | None:
    claims = _decode(request.cookies.get("access_token", ""))
    if claims is None or claims.get("typ") != "access":
        return None
    jti = str(claims.get("jti") or "")
    if not jti or db.access_revoked(jti):
        return None
    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        return None
    user = db.find_user_by_id(user_id)
    if user is None or user["disabled"]:
        return None
    if user["role"] not in {"admin", "developer", "viewer"}:
        return None
    return user


def _session_payload(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(user["id"]),
        "username": user["username"],
        "email": user.get("email") or "",
        "role": user["role"],
        "access": access_map(user),
        "must_change_password": bool(user.get("must_change_password")),
    }


def _tools_allowed(user: dict[str, Any], tools: list[str]) -> bool:
    allowed = access_map(user)
    return all(allowed.get(tool, False) for tool in tools)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""

    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return whether the password matches. A bad hash is a mismatch."""

    try:
        return bool(_HASHER.verify(password_hash, password))
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def valid_username(username: str) -> bool:
    """Usernames are short and limited to letters, digits, and ._ -."""

    return _valid_username(username)


def _start_session(response: Response, user: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    access_exp = now + timedelta(minutes=_ACCESS_MINUTES)
    refresh_exp = now + timedelta(days=_REFRESH_DAYS)
    jti = secrets.token_hex(16)
    token = jwt.encode(
        {
            "sub": str(user["id"]),
            "role": user["role"],
            "username": user["username"],
            "typ": "access",
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": access_exp,
        },
        jwt_key(),
        algorithm="HS256",
    )
    refresh = secrets.token_urlsafe(32)
    db.store_refresh(int(user["id"]), _hash(refresh), refresh_exp)
    csrf = secrets.token_urlsafe(24)
    flags = _cookie_flags()
    response.set_cookie(
        "access_token",
        token,
        max_age=_ACCESS_MINUTES * 60,
        path="/",
        **flags,
    )
    response.set_cookie(
        "refresh_token",
        refresh,
        max_age=_REFRESH_DAYS * 24 * 3600,
        path="/api/auth",
        **flags,
    )
    response.set_cookie(
        "csrf_token",
        csrf,
        max_age=_REFRESH_DAYS * 24 * 3600,
        path="/",
        httponly=False,
        secure=flags["secure"],
        samesite="Strict",
    )


def _clear_cookies(response: Response) -> None:
    flags = _cookie_flags()
    response.delete_cookie("access_token", path="/", **flags)
    response.delete_cookie("refresh_token", path="/api/auth", **flags)
    response.delete_cookie(
        "csrf_token",
        path="/",
        secure=flags["secure"],
        samesite="Strict",
    )


def _cookie_flags() -> dict[str, Any]:
    return {
        "httponly": True,
        "secure": os.environ.get("COOKIE_SECURE", "0") == "1",
        "samesite": "Strict",
    }


def _decode(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        claims = jwt.decode(token, jwt_key(), algorithms=["HS256"])
    except InvalidTokenError:
        return None
    if not isinstance(claims, dict):
        return None
    return claims


def _falco_authorized() -> bool:
    expected = falco_token()
    presented = request.headers.get("User-Agent", "")
    if not expected or not presented:
        return False
    return hmac.compare_digest(presented, expected)


def _csrf_ok() -> bool:
    header = request.headers.get("X-CSRF-Token", "")
    cookie = request.cookies.get("csrf_token", "")
    if not header or not cookie:
        return False
    return hmac.compare_digest(header, cookie)


def _unauthorized() -> Response:
    return jsonify({"error": "You are not signed in."}), 401


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_username(username: str) -> bool:
    if not 1 <= len(username) <= 64:
        return False
    return all(ch.isalnum() or ch in "._-" for ch in username)


def _security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

