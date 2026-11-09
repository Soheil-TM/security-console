"""Admin HTTP API for managed CI API tokens."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import ci_api_tokens
from security_console.audit import record
from security_console.authz import is_admin_role, is_super_admin

Reply = Response | tuple[Response, int]

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./-]{0,79}$")
_MAX_NAME = 80


def install_ci_tokens(app: Flask) -> None:
    """Attach admin session routes for CI API token management."""

    @app.get("/api/ci/tokens")
    def list_ci_tokens() -> Reply:
        return _call(app, _list)

    @app.post("/api/ci/tokens")
    def create_ci_token() -> Reply:
        return _call(app, _create)

    @app.post("/api/ci/tokens/<int:token_id>/revoke")
    def revoke_ci_token(token_id: int) -> Reply:
        return _call(app, lambda: _revoke(token_id))

    @app.delete("/api/ci/tokens/<int:token_id>")
    def delete_ci_token(token_id: int) -> Reply:
        return _call(app, lambda: _delete(token_id))


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.exception("ci token admin request failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _require_admin() -> Reply | None:
    user = getattr(g, "user", None)
    if not isinstance(user, dict) or not (
        is_super_admin(user) or is_admin_role(user)
    ):
        return jsonify({"error": "You do not have permission."}), 403
    return None


def _list() -> Reply:
    denied = _require_admin()
    if denied is not None:
        return denied
    return jsonify(ci_api_tokens.list_tokens())


def _create() -> Reply:
    denied = _require_admin()
    if denied is not None:
        return denied
    parsed, error = _parse_create(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), 400
    user = g.user
    created_by = int(user["id"]) if user.get("id") else None
    try:
        plaintext, public = ci_api_tokens.create_token(
            name=parsed["name"],
            created_by=created_by,
            expires_at=parsed["expires_at"],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    record(
        action="ci.token.create",
        target_type="ci_token",
        target_id=str(public["prefix"]),
        detail={
            "id": public["id"],
            "name": public["name"],
            "expires_at": _iso(public.get("expires_at")),
        },
    )
    payload = dict(public)
    payload["token"] = plaintext
    return jsonify(payload), 201


def _revoke(token_id: int) -> Reply:
    denied = _require_admin()
    if denied is not None:
        return denied
    if token_id < 1:
        return jsonify({"error": "Not found"}), 404
    row = ci_api_tokens.revoke_token(token_id)
    if row is None:
        return jsonify({"error": "Not found"}), 404
    record(
        action="ci.token.revoke",
        target_type="ci_token",
        target_id=str(row["prefix"]),
        detail={"id": row["id"], "name": row["name"]},
    )
    return jsonify(row)


def _delete(token_id: int) -> Reply:
    denied = _require_admin()
    if denied is not None:
        return denied
    if token_id < 1:
        return jsonify({"error": "Not found"}), 404
    try:
        row = ci_api_tokens.delete_token(token_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if row is None:
        return jsonify({"error": "Not found"}), 404
    record(
        action="ci.token.delete",
        target_type="ci_token",
        target_id=str(row["prefix"]),
        detail={"id": row["id"], "name": row["name"]},
    )
    return jsonify({"ok": True, "id": row["id"], "prefix": row["prefix"]})


def _parse_create(body: Any) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(body, dict):
        return None, "The token details are incomplete."
    name = body.get("name")
    if not isinstance(name, str):
        return None, "Token name is invalid."
    name = " ".join(name.split())
    if not name or len(name) > _MAX_NAME or not _NAME_RE.fullmatch(name):
        return None, "Token name is invalid."
    if any(ord(ch) < 32 for ch in name):
        return None, "Token name is invalid."

    never = bool(body.get("never"))
    raw_expires = body.get("expires_at")
    expires_at: datetime | None
    if never:
        expires_at = None
    elif raw_expires in (None, ""):
        expires_at = ci_api_tokens.default_expires_at(90)
    else:
        if not isinstance(raw_expires, str):
            return None, "expires_at is invalid."
        try:
            expires_at = datetime.fromisoformat(
                raw_expires.strip().replace("Z", "+00:00")
            )
        except ValueError:
            return None, "expires_at is invalid."
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            return None, "expires_at must be in the future."

    return {"name": name, "expires_at": expires_at}, ""


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    text = str(value).strip()
    return text or None
