"""Cookie sessions for the console API.

Access tokens are short-lived JWTs. Refresh tokens are random values stored
only as a hash. Both live in HttpOnly cookies.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import psycopg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from flask import Flask, Response, current_app, g, jsonify, redirect, request
from jwt import InvalidTokenError

from security_console import db
from security_console.access import access_map, can_open_sonar_ui

Reply = Response | tuple[Response, int]

_HASHER = PasswordHasher()
_DUMMY_HASH = _HASHER.hash("console-dummy-password")
_OPEN = {("POST", "/api/auth/login")}
_ACCESS_MINUTES = 20
_REFRESH_DAYS = 7
_LOGIN_LIMIT = 5
# OWASP session management: idle timeouts stay short, and there is no
# "never expire" setting. 60 minutes is the hard cap. 12 hours is the
# absolute lifetime, counted from sign-in and kept across refreshes.
_IDLE_MINUTES = frozenset({5, 15, 30, 60})
_IDLE_DEFAULT = 15
_ABSOLUTE_HOURS = 12
_EXPIRY_ERROR = {
    "idle_expired": "Your session ended because of inactivity.",
    "absolute_expired": (
        f"Your session reached the {_ABSOLUTE_HOURS} hour limit. Sign in again."
    ),
}
_BOOTSTRAP_PASSWORD = "admin"
_BOOTSTRAP_FLAG = "bootstrap_admin_v1"
# While the first password is still in place the session may only refresh,
# read itself, change the password, or log out. Refresh stays usable when the
# access token expires on that screen. It does not clear the requirement.
_WHILE_CHANGING_PASSWORD = {
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/password"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/refresh"),
    ("POST", "/api/auth/activity"),
}


class ConfigError(RuntimeError):
    """The process was started with a configuration it must refuse."""


def validate_runtime_config() -> None:
    """Refuse production when session cookies would travel over plain HTTP.

    ``CONSOLE_ENV=development`` is the explicit local setting and may use
    HTTP. Production must set ``COOKIE_SECURE=1`` and sit behind TLS.
    """

    mode = os.environ.get("CONSOLE_ENV", "development").strip().lower()
    if mode not in {"development", "production"}:
        raise ConfigError("CONSOLE_ENV must be development or production")
    if mode == "production" and os.environ.get("COOKIE_SECURE", "0") != "1":
        raise ConfigError("production requires COOKIE_SECURE=1")


def prepare_auth() -> None:
    """Create the auth schema and the first admin when the table is empty.

    The first account is username admin and password admin, and it must
    replace that password before any other API call succeeds. An existing
    database is left unchanged: startup never writes the password admin
    over an account that is already stored.
    """

    if len(jwt_key()) < 32:
        raise RuntimeError("console JWT key must be at least 32 characters")
    db.prepare_database()
    if db.count_users() > 0:
        if not db.has_flag(_BOOTSTRAP_FLAG):
            db.set_flag(_BOOTSTRAP_FLAG)
        return
    username = os.environ.get("CONSOLE_ADMIN_USERNAME", "admin").strip()
    if not _valid_username(username):
        raise RuntimeError("initial admin username is not configured")
    _insert_bootstrap_admin(username)
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
        allow_sonar_ui=True,
    )


def jwt_key() -> str:
    """Return the HMAC key used to sign access tokens."""

    return db.read_secret("CONSOLE_JWT_KEY", "CONSOLE_JWT_KEY_FILE")


def install_auth(app: Flask) -> None:
    """Attach login routes and deny API calls that have no valid session."""

    app.after_request(_security_headers)
    app.before_request(_guard)

    @app.post("/api/auth/login")
    def login() -> Reply:
        return _call_db(app, lambda: _login(app))

    @app.post("/api/auth/logout")
    def logout() -> Reply:
        return _call_db(app, _logout)

    @app.post("/api/auth/refresh")
    def refresh() -> Reply:
        return _call_db(app, _refresh)

    @app.get("/api/auth/me")
    def me() -> Response:
        return jsonify(_me_payload())

    @app.post("/api/auth/activity")
    def activity() -> Reply:
        return _call_db(app, _record_activity)

    @app.put("/api/auth/idle-timeout")
    def idle_timeout() -> Reply:
        return _call_db(app, _set_idle_timeout)

    from security_console.groups import install_groups
    from security_console.integrations import install_integrations
    from security_console.investigate import install_investigate
    from security_console.projects import install_projects
    from security_console.risk import install_risk
    from security_console.users import install_users

    install_users(app)
    install_groups(app)
    install_projects(app)
    install_integrations(app)
    install_risk(app)
    install_investigate(app)


def _call_db(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("auth database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _guard() -> Reply | None:
    try:
        return _guard_request()
    except psycopg.Error:
        current_app.logger.error("auth database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _guard_request() -> Reply | None:
    if request.method == "GET" and request.path in {"/", "/login"}:
        return None
    if request.path.startswith("/api/guest/"):
        return None
    if (request.method, request.path) in _OPEN:
        return None
    if (request.method, request.path) == ("POST", "/api/auth/refresh"):
        if not _csrf_ok():
            return jsonify({"error": "Request rejected."}), 403
        return None
    if request.method == "GET" and request.path == "/api/security/gate":
        return _gate_guard()
    if not request.path.startswith("/api/"):
        return None
    user = _current_user()
    if user is None:
        return jsonify({"error": "You are not signed in."}), 401
    g.user = user
    expired = _reject_expired_session()
    if expired is not None:
        return expired
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
    if request.path == "/api/sonar/setup" and user["role"] != "admin":
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


def _gate_guard() -> Reply | None:
    """Allow the push-gate check with a gate token or a normal signed-in session."""

    from security_console.secrets import read_secret, same_secret

    expected = read_secret("GATE_TOKEN", "GATE_TOKEN_FILE")
    header = request.headers.get("Authorization", "")
    presented = (
        header[7:].strip()
        if header.lower().startswith("bearer ")
        else request.headers.get("X-Gate-Token", "").strip()
    )
    if expected and same_secret(presented, expected):
        g.user = {"role": "admin", "username": "gate", "id": 0}
        return None
    user = _current_user()
    if user is None:
        return jsonify({"error": "You are not signed in."}), 401
    g.user = user
    expired = _reject_expired_session()
    if expired is not None:
        return expired
    return None


def _login(app: Flask) -> Reply:
    ip = client_ip()
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
    return _issue_session(user)


def _refresh() -> Response:
    raw = request.cookies.get("refresh_token", "")
    if not raw:
        return _unauthorized()
    taken = db.take_refresh(_hash(raw))
    if taken is None:
        return _end_session()
    user = db.find_user_by_id(int(taken["user_id"]))
    if user is None or user["disabled"]:
        return _end_session()
    code = _expiry_code(
        user,
        taken["last_activity_at"],
        taken["created_at"],
    )
    if code is not None:
        return _expired_session(code)
    return _issue_session(
        user,
        last_activity_at=_as_aware(taken["last_activity_at"]),
        created_at=_as_aware(taken["created_at"]),
    )


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
    try:
        token_version = int(claims.get("ver") or 0)
        current_version = int(user.get("session_version") or 0)
    except (TypeError, ValueError):
        return None
    if token_version != current_version:
        return None
    g.access_claims = claims
    return user


def _session_payload(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(user["id"]),
        "username": user["username"],
        "first_name": user.get("first_name") or "",
        "last_name": user.get("last_name") or "",
        "email": user.get("email") or "",
        "role": user["role"],
        "access": access_map(user),
        "must_change_password": bool(user.get("must_change_password")),
        "idle_timeout_minutes": _idle_minutes(user),
        "absolute_timeout_hours": _ABSOLUTE_HOURS,
    }


def _idle_minutes(user: dict[str, Any]) -> int:
    """Return this account's idle timeout, falling back when the row is odd.

    A missing or out-of-range value becomes the default. It never becomes
    unlimited.
    """

    try:
        value = int(user.get("idle_timeout_minutes") or _IDLE_DEFAULT)
    except (TypeError, ValueError):
        return _IDLE_DEFAULT
    if value not in _IDLE_MINUTES:
        return _IDLE_DEFAULT
    return value


def parse_idle_minutes(value: Any) -> int | None:
    """Return an allowed idle timeout, or None when the value is not allowed.

    Only 5, 15, 30, and 60 minutes are accepted. Zero, negatives, floats,
    and any "never" or "infinite" value are rejected.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value not in _IDLE_MINUTES:
        return None
    return value


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _expiry_code(
    user: dict[str, Any],
    activity_at: datetime,
    started_at: datetime,
    now: datetime | None = None,
) -> str | None:
    """Return why this session is over, or None while it is still valid."""

    clock = now or datetime.now(UTC)
    if clock - _as_aware(started_at) >= timedelta(hours=_ABSOLUTE_HOURS):
        return "absolute_expired"
    if clock - _as_aware(activity_at) >= timedelta(minutes=_idle_minutes(user)):
        return "idle_expired"
    return None


def _timeout_status(
    user: dict[str, Any],
    *,
    activity_at: datetime,
    started_at: datetime,
    now: datetime | None = None,
) -> dict[str, int]:
    clock = now or datetime.now(UTC)
    idle_left = (
        _as_aware(activity_at) + timedelta(minutes=_idle_minutes(user)) - clock
    )
    absolute_left = (
        _as_aware(started_at) + timedelta(hours=_ABSOLUTE_HOURS) - clock
    )
    return {
        "remaining_seconds": max(0, int(idle_left.total_seconds())),
        "absolute_remaining_seconds": max(0, int(absolute_left.total_seconds())),
    }


def _me_payload() -> dict[str, Any]:
    payload = _session_payload(g.user)
    claims = getattr(g, "access_claims", None)
    if not isinstance(claims, dict):
        return payload
    try:
        session = db.get_session(int(claims["sid"]))
    except (KeyError, TypeError, ValueError):
        return payload
    if session is None:
        return payload
    payload.update(
        _timeout_status(
            g.user,
            activity_at=session["last_activity_at"],
            started_at=session["created_at"],
        )
    )
    return payload


def _record_activity() -> Response:
    claims = getattr(g, "access_claims", None)
    if not isinstance(claims, dict):
        return _unauthorized()
    try:
        session_id = int(claims["sid"])
    except (KeyError, TypeError, ValueError):
        return _unauthorized()
    if not db.touch_session(session_id):
        return _unauthorized()
    session = db.get_session(session_id)
    if session is None:
        return _unauthorized()
    payload = _session_payload(g.user)
    payload.update(
        _timeout_status(
            g.user,
            activity_at=session["last_activity_at"],
            started_at=session["created_at"],
        )
    )
    payload["ok"] = True
    return jsonify(payload)


def _set_idle_timeout() -> Reply:
    body = request.get_json(silent=True)
    minutes = None
    if isinstance(body, dict) and "idle_timeout_minutes" in body:
        minutes = parse_idle_minutes(body.get("idle_timeout_minutes"))
    if minutes is None:
        response = jsonify(
            {"error": "Idle timeout must be 5, 15, 30, or 60 minutes."}
        )
        response.status_code = 400
        return response
    user_id = int(g.user["id"])
    db.set_idle_timeout(user_id, minutes)
    fresh = db.find_user_by_id(user_id)
    if fresh is None:
        return jsonify({"error": "You are not signed in."}), 401
    g.user = fresh
    claims = getattr(g, "access_claims", None)
    session = None
    if isinstance(claims, dict):
        try:
            session = db.get_session(int(claims["sid"]))
        except (KeyError, TypeError, ValueError):
            session = None
    if session is not None:
        code = _expiry_code(
            fresh,
            session["last_activity_at"],
            session["created_at"],
        )
        if code is not None:
            db.revoke_session(int(session["id"]))
            return _expired_session(code)
    payload = _me_payload()
    return jsonify(payload)


def _reject_expired_session() -> Response | None:
    """End the request when this access token's session is no longer valid."""

    claims = getattr(g, "access_claims", None)
    user = getattr(g, "user", None)
    if not isinstance(claims, dict) or not isinstance(user, dict):
        return _unauthorized()
    try:
        session_id = int(claims["sid"])
    except (KeyError, TypeError, ValueError):
        return _unauthorized()
    session = db.get_session(session_id)
    if (
        session is None
        or session.get("revoked_at") is not None
        or int(session["user_id"]) != int(user["id"])
    ):
        return _unauthorized()
    code = _expiry_code(
        user,
        session["last_activity_at"],
        session["created_at"],
    )
    if code is None:
        return None
    db.revoke_session(session_id)
    return _expired_session(code)


def _expired_session(code: str) -> Response:
    """Revoke the presented access token and clear every session cookie."""

    _revoke_presented_access()
    response = jsonify(
        {"error": _EXPIRY_ERROR.get(code, "You are not signed in."), "code": code}
    )
    response.status_code = 401
    _clear_cookies(response)
    return response


def _revoke_presented_access() -> None:
    claims = _decode(request.cookies.get("access_token", ""))
    if not isinstance(claims, dict):
        return
    jti = str(claims.get("jti") or "")
    try:
        exp = datetime.fromtimestamp(int(claims["exp"]), UTC)
    except (KeyError, TypeError, ValueError):
        return
    if jti:
        db.revoke_access(jti, exp)


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


def _issue_session(
    user: dict[str, Any],
    *,
    last_activity_at: datetime | None = None,
    created_at: datetime | None = None,
) -> Response:
    """Start a session and tell the browser how long it has left."""

    now = datetime.now(UTC)
    activity = last_activity_at or now
    started = created_at or now
    payload = _session_payload(user)
    payload.update(
        _timeout_status(
            user,
            activity_at=activity,
            started_at=started,
            now=now,
        )
    )
    response = jsonify(payload)
    _start_session(
        response,
        user,
        last_activity_at=activity,
        created_at=started,
    )
    return response


def _start_session(
    response: Response,
    user: dict[str, Any],
    *,
    last_activity_at: datetime | None = None,
    created_at: datetime | None = None,
) -> None:
    now = datetime.now(UTC)
    activity = last_activity_at or now
    started = created_at or now
    access_exp = now + timedelta(minutes=_ACCESS_MINUTES)
    absolute_end = started + timedelta(hours=_ABSOLUTE_HOURS)
    refresh_exp = min(now + timedelta(days=_REFRESH_DAYS), absolute_end)
    refresh_max_age = max(0, int((refresh_exp - now).total_seconds()))
    refresh = secrets.token_urlsafe(32)
    session_id = db.store_refresh(
        int(user["id"]),
        _hash(refresh),
        refresh_exp,
        activity,
        started,
    )
    jti = secrets.token_hex(16)
    token = jwt.encode(
        {
            "sub": str(user["id"]),
            "role": user["role"],
            "username": user["username"],
            "typ": "access",
            "jti": jti,
            "sid": session_id,
            "ver": int(user.get("session_version") or 0),
            "iat": int(now.timestamp()),
            "exp": access_exp,
        },
        jwt_key(),
        algorithm="HS256",
    )
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
        max_age=refresh_max_age,
        path="/api/auth",
        **flags,
    )
    response.set_cookie(
        "csrf_token",
        csrf,
        max_age=refresh_max_age,
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


def restart_session(response: Response, user: dict[str, Any]) -> None:
    """Issue a new session after this account's previous sessions were revoked."""

    _start_session(response, user)


def client_ip() -> str:
    """Return the caller address. Forwarded headers count only from a trusted proxy.

    The right-most address is used, which is the client the trusted proxy
    observed when it appends or replaces ``X-Forwarded-For``. A direct caller
    cannot supply that header.
    """

    remote = request.remote_addr or ""
    fallback = (remote or "unknown")[:64]
    if not _trusted_proxy(remote):
        return fallback
    hops = [
        part.strip()
        for part in request.headers.get("X-Forwarded-For", "").split(",")
        if part.strip()
    ]
    if not hops:
        return fallback
    try:
        ipaddress.ip_address(hops[-1])
    except ValueError:
        return fallback
    return hops[-1][:64]


def _trusted_proxy(remote: str) -> bool:
    raw = os.environ.get("TRUSTED_PROXIES", "").strip()
    if not raw or not remote:
        return False
    try:
        address = ipaddress.ip_address(remote)
    except ValueError:
        return False
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            if "/" in item:
                network = ipaddress.ip_network(item, strict=False)
                if address in network:
                    return True
            elif address == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def cookie_flags() -> dict[str, Any]:
    """Cookie options shared by the session and the guest cookie."""

    return _cookie_flags()


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


def _csrf_ok() -> bool:
    header = request.headers.get("X-CSRF-Token", "")
    cookie = request.cookies.get("csrf_token", "")
    if not header or not cookie:
        return False
    return hmac.compare_digest(header, cookie)


def _unauthorized() -> Response:
    response = jsonify({"error": "You are not signed in."})
    response.status_code = 401
    return response


def _end_session() -> Response:
    """Reject a refresh and drop the session cookies."""

    response = _unauthorized()
    _clear_cookies(response)
    return response


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_username(username: str) -> bool:
    if not 1 <= len(username) <= 64:
        return False
    return all(ch.isalnum() or ch in "._-" for ch in username)


def sonar_page_user() -> dict[str, Any] | Response:
    """Return the account that may open SonarQube, or a response that refuses."""

    user = _current_user()
    if user is None:
        if request.method == "GET":
            return redirect("/login")
        denied = jsonify({"error": "You are not signed in."})
        denied.status_code = 401
        return denied
    g.user = user
    expired = _reject_expired_session()
    if expired is not None:
        return expired
    if user.get("must_change_password"):
        return redirect("/")
    if not can_open_sonar_ui(user):
        return Response("You do not have permission.", status=403)
    return user


def _security_headers(response: Response) -> Response:
    if request.path == "/sonar" or request.path.startswith("/sonar/"):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Server"] = "security-console"
        return response
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Server"] = "security-console"
    if os.environ.get("COOKIE_SECURE", "0") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

