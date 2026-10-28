"""Group-scoped task workflow (isolated from risk / push gate)."""

from __future__ import annotations

from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request

from security_console import db
from security_console.authz import can_write_triage_by_role, is_group_lead

Reply = Response | tuple[Response, int]

_TRANSITIONS = {
    ("open", "in_progress"): "start",
    ("in_progress", "submitted"): "submit",
    ("submitted", "approved"): "approve",
    ("submitted", "rejected"): "reject",
    ("open", "cancelled"): "cancel",
    ("in_progress", "cancelled"): "cancel",
    ("rejected", "in_progress"): "rework",
}


def install_tasks(app: Flask) -> None:
    @app.get("/api/tasks")
    def list_tasks() -> Reply:
        return _call(app, _list)

    @app.post("/api/tasks")
    def create_task() -> Reply:
        return _call(app, _create)

    @app.post("/api/tasks/<int:task_id>/transition")
    def transition(task_id: int) -> Reply:
        return _call(app, lambda: _transition(task_id))


def _call(app: Flask, action: Any) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("tasks database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _member_group_ids(user_id: int) -> set[int]:
    groups = db.list_groups(user_id)
    return {int(group["id"]) for group in groups}


def _lead_group_ids(user: dict[str, Any]) -> set[int]:
    groups = db.list_groups(int(user["id"]))
    leads: set[int] = set()
    username = user.get("username")
    for group in groups:
        if any(
            item.get("username") == username and item.get("lead")
            for item in group.get("members") or []
        ):
            leads.add(int(group["id"]))
    return leads


def _list() -> Reply:
    user = g.user
    try:
        group_id = int(request.args.get("group_id") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "group_id is required."}), 400
    if group_id <= 0:
        return jsonify({"error": "group_id is required."}), 400
    if group_id not in _member_group_ids(int(user["id"])) and user.get(
        "role"
    ) not in {"super_admin", "admin"}:
        # admins with manage_all still need membership OR we allow via manage_all
        from security_console.authz import can_manage_all_groups

        if not can_manage_all_groups(user):
            return jsonify({"error": "You do not have permission."}), 403
    return jsonify(db.list_tasks_for_group(group_id))


def _create() -> Reply:
    user = g.user
    if not can_write_triage_by_role(user):
        return jsonify({"error": "You do not have permission."}), 403
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Invalid request."}), 400
    try:
        group_id = int(body.get("group_id") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "group_id is invalid."}), 400
    title = str(body.get("title") or "").strip()
    text = str(body.get("body") or "").strip()
    if not title or len(title) > 200:
        return jsonify({"error": "title is invalid."}), 400
    if group_id not in _member_group_ids(int(user["id"])):
        from security_console.authz import can_manage_all_groups

        if not can_manage_all_groups(user):
            return jsonify({"error": "You do not have permission."}), 403
    project_id = body.get("project_id")
    try:
        project_id_i = int(project_id) if project_id is not None else None
    except (TypeError, ValueError):
        return jsonify({"error": "project_id is invalid."}), 400
    if project_id_i is not None:
        group = db.get_group(group_id)
        linked = {
            int(item["id"])
            for item in (group or {}).get("projects") or []
            if isinstance(item, dict) and item.get("id") is not None
        }
        if project_id_i not in linked:
            return jsonify({"error": "project is not in that group."}), 400
    assignee = body.get("assignee_user_id")
    try:
        assignee_i = int(assignee) if assignee is not None else int(user["id"])
    except (TypeError, ValueError):
        return jsonify({"error": "assignee_user_id is invalid."}), 400
    row = db.insert_task(
        group_id=group_id,
        project_id=project_id_i,
        title=title,
        body=text,
        creator_user_id=int(user["id"]),
        assignee_user_id=assignee_i,
    )
    return jsonify(row), 201


def _transition(task_id: int) -> Reply:
    user = g.user
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Invalid request."}), 400
    to_status = str(body.get("status") or "").strip()
    try:
        version = int(body.get("version"))
    except (TypeError, ValueError):
        return jsonify({"error": "version is required."}), 400
    task = db.get_task(task_id)
    if task is None:
        return jsonify({"error": "Task not found."}), 404
    key = (task["status"], to_status)
    if key not in _TRANSITIONS:
        return jsonify({"error": "Illegal transition."}), 409
    event = _TRANSITIONS[key]
    leads = _lead_group_ids(user)
    is_lead = is_group_lead(
        lead_group_ids=leads, group_id=int(task["group_id"])
    )
    uid = int(user["id"])
    if event in {"start", "submit", "rework"}:
        if task.get("assignee_user_id") != uid:
            return jsonify({"error": "You do not have permission."}), 403
    elif event in {"approve", "reject"}:
        if not is_lead:
            return jsonify({"error": "You do not have permission."}), 403
        if task.get("creator_user_id") == uid and task.get("assignee_user_id") == uid:
            return jsonify({"error": "Cannot self-approve."}), 403
    elif event == "cancel":
        if task.get("creator_user_id") != uid and not is_lead:
            return jsonify({"error": "You do not have permission."}), 403
    updated = db.update_task_status(
        task_id,
        status=to_status,
        version=version,
        actor_user_id=uid,
        actor_username=str(user.get("username") or ""),
        event=event,
    )
    if updated is None:
        return jsonify({"error": "Version conflict."}), 409
    return jsonify(updated)
