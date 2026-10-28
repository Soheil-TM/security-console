"""Append-only audit log API (fail-closed writers live at call sites)."""

from __future__ import annotations

from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.authz import can_read_audit

Reply = Response | tuple[Response, int]


def record(
    *,
    action: str,
    target_type: str = "",
    target_id: str = "",
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
) -> None:
    """Write one audit event for the current user (or anonymous)."""

    user = getattr(g, "user", None) if g else None
    actor_id = int(user["id"]) if isinstance(user, dict) and user.get("id") else None
    actor_name = str(user.get("username") or "") if isinstance(user, dict) else ""
    db.insert_audit_event(
        actor_user_id=actor_id,
        actor_username=actor_name,
        action=action,
        target_type=target_type,
        target_id=str(target_id or ""),
        outcome=outcome,
        detail=detail or {},
    )


def install_audit(app: Flask) -> None:
    @app.get("/api/audit")
    def list_audit() -> Reply:
        user = g.user
        if not can_read_audit(user):
            return jsonify({"error": "You do not have permission."}), 403
        try:
            limit = int(request.args.get("limit") or 100)
        except (TypeError, ValueError):
            limit = 100
        try:
            return jsonify(db.list_audit_events(limit=limit))
        except psycopg.Error:
            app.logger.error("audit read failed")
            return jsonify({"error": "Sign-in is unavailable."}), 503
