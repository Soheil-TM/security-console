"""Admin user management and the signed-in user's password change."""

from __future__ import annotations

import re
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request
from psycopg.errors import UniqueViolation

from security_console import db
from security_console.access import ROLES, TOOLS, access_map
from security_console.auth import hash_password, valid_username, verify_password

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def install_users(app: Flask) -> None:
    """Attach account routes. The request guard already requires a session."""

    @app.get("/api/users")
    def list_accounts() -> Response:
        return _call(app, _list_accounts)

    @app.post("/api/users")
    def create_account() -> Response:
        return _call(app, lambda: _create_account(app))

    @app.patch("/api/users/<int:user_id>")
    def update_account(user_id: int) -> Response:
        return _call(app, lambda: _update_account(app, user_id))

    @app.delete("/api/users/<int:user_id>")
    def remove_account(user_id: int) -> Response:
        return _call(app, lambda: _remove_account(app, user_id))

    @app.post("/api/auth/password")
    def change_password() -> Response:
        return _call(app, lambda: _change_password(app))


def _call(app: Flask, action: Any) -> Response:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("user database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    """Return account fields that are safe to send to the browser."""

    created = user.get("created_at")
    return {
        "id": int(user["id"]),
        "username": user["username"],
        "email": user.get("email") or "",
        "role": user["role"],
        "disabled": bool(user.get("disabled")),
        "access": access_map(user),
        "created_at": created.isoformat() if hasattr(created, "isoformat") else "",
    }


def _list_accounts() -> Response:
    return jsonify([public_user(user) for user in db.list_users()])


def _create_account(app: Flask) -> Response:
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
        )
    except UniqueViolation:
        return jsonify({"error": "That username is already registered."}), 409
    created = db.find_user_by_id(user_id)
    app.logger.info("user created id=%s", user_id)
    if created is None:
        return jsonify({"error": "Could not create the user."}), 500
    return jsonify(public_user(created)), 201


def _update_account(app: Flask, user_id: int) -> Response:
    current = db.find_user_by_id(user_id)
    if current is None:
        return jsonify({"error": "User not found."}), 404
    parsed = _account_body(request.get_json(silent=True), password_required=False)
    if isinstance(parsed, Response):
        return parsed
    if _removes_last_admin(current, parsed):
        return jsonify({"error": "The last admin cannot be removed."}), 409
    password_hash = None
    if parsed["password"]:
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
        )
    except UniqueViolation:
        return jsonify({"error": "That username is already registered."}), 409
    updated = db.find_user_by_id(user_id)
    app.logger.info("user updated id=%s", user_id)
    if updated is None:
        return jsonify({"error": "User not found."}), 404
    return jsonify(public_user(updated))


def _remove_account(app: Flask, user_id: int) -> Response:
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


def _change_password(app: Flask) -> Response:
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
    app.logger.info("password changed user_id=%s", g.user["id"])
    return jsonify({"ok": True})


def _account_body(
    body: Any,
    *,
    password_required: bool,
) -> dict[str, Any] | Response:
    if not isinstance(body, dict):
        return jsonify({"error": "The account details are incomplete."}), 400
    username = body.get("username")
    email = body.get("email")
    role = body.get("role")
    password = body.get("password") or ""
    access = body.get("access") if isinstance(body.get("access"), dict) else {}
    if not isinstance(username, str) or not valid_username(username.strip()):
        return jsonify({"error": "Username is invalid."}), 400
    if (
        not isinstance(email, str)
        or len(email.strip()) > 254
        or not _EMAIL.fullmatch(email.strip())
    ):
        return jsonify({"error": "Email is invalid."}), 400
    if role not in ROLES:
        return jsonify({"error": "Role is invalid."}), 400
    if not isinstance(password, str) or len(password) > 128:
        return jsonify({"error": "Password is invalid."}), 400
    if password_required and len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters."}), 400
    if password and len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters."}), 400
    disabled = bool(body.get("disabled"))
    flags = {
        tool: bool(access.get(tool))
        for tool in TOOLS
    }
    if role == "admin":
        flags = {tool: True for tool in TOOLS}
    return {
        "username": username.strip(),
        "email": email.strip().lower(),
        "role": role,
        "password": password,
        "disabled": disabled,
        "allow_semgrep": flags["semgrep"],
        "allow_checkov": flags["checkov"],
        "allow_sonar": flags["sonar"],
        "allow_trivy": flags["trivy"],
    }


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
