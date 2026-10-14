"""Admin user management and the signed-in user's password change."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request
from psycopg.errors import UniqueViolation

from security_console import db
from security_console.access import ROLES, TOOLS, access_map
from security_console.auth import (
    hash_password,
    restart_session,
    valid_username,
    verify_password,
)

Reply = Response | tuple[Response, int]
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def install_users(app: Flask) -> None:
    """Attach account routes. The request guard already requires a session."""

    @app.get("/api/users")
    def list_accounts() -> Reply:
        return _call(app, _list_accounts)

    @app.post("/api/users")
    def create_account() -> Reply:
        return _call(app, lambda: _create_account(app))

    @app.patch("/api/users/<int:user_id>")
    def update_account(user_id: int) -> Reply:
        return _call(app, lambda: _update_account(app, user_id))

    @app.delete("/api/users/<int:user_id>")
    def remove_account(user_id: int) -> Reply:
        return _call(app, lambda: _remove_account(app, user_id))

    @app.post("/api/auth/password")
    def change_password() -> Reply:
        return _call(app, lambda: _change_password(app))


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("user database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    """Return account fields that are safe to send to the browser."""

    created = user.get("created_at")
    created_at = ""
    if created is not None:
        isoformat = getattr(created, "isoformat", None)
        if callable(isoformat):
            created_at = str(isoformat())
    return {
        "id": int(user["id"]),
        "username": user["username"],
        "first_name": user.get("first_name") or "",
        "last_name": user.get("last_name") or "",
        "email": user.get("email") or "",
        "role": user["role"],
        "disabled": bool(user.get("disabled")),
        "access": access_map(user),
        "created_at": created_at,
    }


def _list_accounts() -> Response:
    return jsonify([public_user(user) for user in db.list_users()])


def _create_account(app: Flask) -> Reply:
    parsed = _account_body(request.get_json(silent=True), password_required=True)
    if isinstance(parsed, Response):
        return parsed
    try:
        user_id = db.insert_user(
            parsed["username"],
            hash_password(parsed["password"]),
            parsed["role"],
            parsed["email"],
            parsed["allow_semgrep"],
            parsed["allow_checkov"],
            parsed["allow_sonar"],
            parsed["allow_trivy"],
            must_change_password=parsed["must_change_password"],
            allow_sonar_ui=parsed["allow_sonar_ui"],
            first_name=parsed["first_name"],
            last_name=parsed["last_name"],
        )
    except UniqueViolation:
        return jsonify({"error": "That username is already registered."}), 409
    created = db.find_user_by_id(user_id)
    app.logger.info("user created id=%s", user_id)
    if created is None:
        return jsonify({"error": "Could not create the user."}), 500
    return jsonify(public_user(created)), 201


def _update_account(app: Flask, user_id: int) -> Reply:
    current = db.find_user_by_id(user_id)
    if current is None:
        return jsonify({"error": "User not found."}), 404
    parsed = _account_body(
        request.get_json(silent=True),
        password_required=False,
        current=current,
    )
    if isinstance(parsed, Response):
        return parsed
    if _removes_last_admin(current, parsed):
        return jsonify({"error": "The last admin cannot be removed."}), 409
    password_hash = None
    if parsed["password"]:
        if not _can_reset_password(g.user, current):
            return jsonify({"error": "You cannot reset this password."}), 403
        password_hash = hash_password(parsed["password"])
    try:
        db.update_user(
            user_id,
            parsed["username"],
            parsed["email"],
            parsed["role"],
            parsed["disabled"],
            parsed["allow_semgrep"],
            parsed["allow_checkov"],
            parsed["allow_sonar"],
            parsed["allow_trivy"],
            password_hash,
            allow_sonar_ui=parsed["allow_sonar_ui"],
            first_name=parsed["first_name"],
            last_name=parsed["last_name"],
            must_change_password=parsed["must_change_password"],
        )
    except UniqueViolation:
        return jsonify({"error": "That username is already registered."}), 409
    updated = db.find_user_by_id(user_id)
    app.logger.info("user updated id=%s", user_id)
    if updated is None:
        return jsonify({"error": "User not found."}), 404
    return jsonify(public_user(updated))


def _remove_account(app: Flask, user_id: int) -> Reply:
    current = db.find_user_by_id(user_id)
    if current is None:
        return jsonify({"error": "User not found."}), 404
    if int(g.user["id"]) == user_id:
        return jsonify({"error": "Do not delete your own account here."}), 409
    if current["role"] == "admin" and db.count_other_admins(user_id) == 0:
        return jsonify({"error": "The last admin cannot be removed."}), 409
    db.delete_user(user_id)
    app.logger.info("user deleted id=%s", user_id)
    return jsonify({"ok": True})


def _change_password(app: Flask) -> Reply:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Current password is incorrect."}), 400
    current_password = body.get("current_password")
    new_password = body.get("new_password")
    if (
        not isinstance(current_password, str)
        or not isinstance(new_password, str)
        or len(current_password) > 128
        or len(new_password) > 128
    ):
        return jsonify({"error": "Current password is incorrect."}), 400
    stored = db.find_user(g.user["username"])
    if stored is None or not verify_password(
        stored["password_hash"],
        current_password,
    ):
        return jsonify({"error": "Current password is incorrect."}), 401
    if len(new_password) < 12:
        return jsonify(
            {"error": "The new password must be at least 12 characters."}
        ), 400
    db.set_password_hash(int(g.user["id"]), hash_password(new_password))
    fresh = db.find_user_by_id(int(g.user["id"]))
    app.logger.info("password changed user_id=%s", g.user["id"])
    if fresh is None:
        return jsonify({"error": "Could not change the password."}), 500
    response = jsonify({"ok": True})
    restart_session(response, fresh)
    return response


def _account_body(
    body: Any,
    *,
    password_required: bool,
    current: dict[str, Any] | None = None,
) -> dict[str, Any] | Response:
    if not isinstance(body, dict):
        return _reject("The account details are incomplete.", 400)
    username = body.get("username")
    role = body.get("role")
    password = body.get("password") or ""
    raw_access = body.get("access")
    access: dict[str, Any] = raw_access if isinstance(raw_access, dict) else {}
    if not isinstance(username, str) or not valid_username(username.strip()):
        return _reject("Username is invalid.", 400)
    first_name = _kept_name(body, "first_name", "First name", current)
    if isinstance(first_name, Response):
        return first_name
    last_name = _kept_name(body, "last_name", "Last name", current)
    if isinstance(last_name, Response):
        return last_name
    email_text = _email_text(body, current)
    if isinstance(email_text, Response):
        return email_text
    if role not in ROLES:
        return _reject("Role is invalid.", 400)
    if not isinstance(password, str) or len(password) > 128:
        return _reject("Password is invalid.", 400)
    if password_required and len(password) < 12:
        return _reject("Password must be at least 12 characters.", 400)
    if password and len(password) < 12:
        return _reject("Password must be at least 12 characters.", 400)
    disabled = bool(body.get("disabled"))
    flags = {
        tool: bool(access.get(tool))
        for tool in TOOLS
    }
    sonar_ui = bool(access.get("sonar_ui"))
    if role == "admin":
        flags = {tool: True for tool in TOOLS}
        sonar_ui = True
    return {
        "username": username.strip(),
        "first_name": first_name,
        "last_name": last_name,
        "email": email_text,
        "role": role,
        "password": password,
        "disabled": disabled,
        "allow_semgrep": flags["semgrep"],
        "allow_checkov": flags["checkov"],
        "allow_sonar": flags["sonar"],
        "allow_trivy": flags["trivy"],
        "allow_sonar_ui": sonar_ui,
        "must_change_password": _must_change(body, password, password_required),
    }


def _must_change(body: dict[str, Any], password: str, required: bool) -> bool:
    """A new account uses the checkbox. A reset uses it only with a password."""

    if required:
        return bool(body.get("must_change_password"))
    if not password:
        return False
    if "must_change_password" not in body:
        return True
    return bool(body.get("must_change_password"))


def _can_reset_password(actor: dict[str, Any], target: dict[str, Any]) -> bool:
    """An admin resets other people. Only admin resets another admin."""

    if actor.get("role") != "admin":
        return False
    if int(actor.get("id") or 0) == int(target["id"]):
        return False
    if target.get("role") == "admin" and actor.get("username") != "admin":
        return False
    return True


def _email_text(
    body: dict[str, Any],
    current: dict[str, Any] | None,
) -> str | Response:
    """Allow a blank email. A filled one must look like an address."""

    if "email" not in body and current is not None:
        return str(current.get("email") or "")
    email = body.get("email", "")
    if not isinstance(email, str):
        return _reject("Email is invalid.", 400)
    text = email.strip().lower()
    if not text:
        return ""
    if len(text) > 254 or _EMAIL.fullmatch(text) is None:
        return _reject("Email is invalid.", 400)
    return text


def _kept_name(
    body: dict[str, Any],
    key: str,
    label: str,
    current: dict[str, Any] | None,
) -> str | Response:
    """Require a name on create. An update keeps the stored name if omitted."""

    if key not in body and current is not None:
        return str(current.get(key) or "")
    value = body.get(key)
    if not isinstance(value, str):
        return _reject(label + " is invalid.", 400)
    text = " ".join(value.split())
    if not text or len(text) > 80 or any(ord(ch) < 32 for ch in text):
        return _reject(label + " is invalid.", 400)
    return text


def _reject(message: str, status: int) -> Response:
    response = jsonify({"error": message})
    response.status_code = status
    return response


def _removes_last_admin(
    current: dict[str, Any],
    parsed: dict[str, Any],
) -> bool:
    if current["role"] != "admin":
        return False
    stays_admin = parsed["role"] == "admin" and not parsed["disabled"]
    if stays_admin:
        return False
    return db.count_other_admins(int(current["id"])) == 0
