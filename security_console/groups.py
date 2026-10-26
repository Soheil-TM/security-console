"""Project groups. A lead shares projects with the team."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request
from psycopg.errors import UniqueViolation

from security_console import db

Reply = Response | tuple[Response, int]
_MAX_NAME = 80
_MAX_DESCRIPTION = 500
_MAX_PROJECTS = 30
_MAX_MEMBERS = 50


def install_groups(app: Flask) -> None:
    """Attach group routes. The request guard already requires a session."""

    @app.get("/api/groups")
    def list_project_groups() -> Reply:
        return _call(app, _list_groups)

    @app.get("/api/groups/people")
    def list_group_people() -> Reply:
        return _call(app, _list_people)

    @app.post("/api/groups")
    def create_project_group() -> Reply:
        return _call(app, lambda: _create_group(app))

    @app.patch("/api/groups/<int:group_id>")
    def update_project_group(group_id: int) -> Reply:
        return _call(app, lambda: _update_group(app, group_id))

    @app.delete("/api/groups/<int:group_id>")
    def delete_project_group(group_id: int) -> Reply:
        return _call(app, lambda: _delete_group(app, group_id))


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("group database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def parse_group(body: Any) -> tuple[dict[str, Any] | None, str]:
    """Validate a group form. The error string is empty when it is valid."""

    if not isinstance(body, dict):
        return None, "The group details are incomplete."
    name = body.get("name")
    description = body.get("description") or ""
    if not isinstance(name, str) or not isinstance(description, str):
        return None, "The group details are incomplete."
    name = " ".join(name.split())
    description = description.strip()
    if not name or len(name) > _MAX_NAME or _has_control(name):
        return None, "Group name is invalid."
    if len(description) > _MAX_DESCRIPTION or _has_control(description):
        return None, "Description is invalid."
    projects, project_error = _projects(body)
    if project_error:
        return None, project_error
    members, member_error = _member_names(body)
    if member_error:
        return None, member_error
    return {
        "name": name,
        "description": description,
        "project_ids": projects,
        "members": members,
    }, ""


def public_group(
    group: dict[str, Any],
    *,
    can_edit: bool,
) -> dict[str, Any]:
    """Return group fields the browser may see."""

    return {
        "id": int(group["id"]),
        "name": group["name"],
        "description": group.get("description") or "",
        "created_at": _iso(group.get("created_at")),
        "can_edit": can_edit,
        "projects": [
            {
                "id": int(item["id"]),
                "slug": item["slug"],
                "name": item["name"],
            }
            for item in group.get("projects") or []
        ],
        "members": [
            {
                "username": item["username"],
                "role": item["role"],
                "lead": bool(item["lead"]),
            }
            for item in group.get("members") or []
        ],
        "events": [
            {
                "actor": item["actor"],
                "action": item["action"],
                "detail": item.get("detail") or "",
                "created_at": _iso(item.get("created_at")),
            }
            for item in group.get("events") or []
        ],
    }


def _list_people() -> Reply:
    """Names an admin or developer may add to a group. No email."""

    if g.user.get("role") not in {"admin", "developer"}:
        return jsonify({"error": "You do not have permission."}), 403
    people = [
        {
            "username": row["username"],
            "first_name": row.get("first_name") or "",
            "last_name": row.get("last_name") or "",
            "role": row["role"],
        }
        for row in db.list_users()
        if not row.get("disabled")
    ]
    return jsonify(people)


def _list_groups() -> Response:
    user = g.user
    user_id = None if user.get("role") == "admin" else int(user["id"])
    groups = [
        public_group(group, can_edit=_can_edit(user, group))
        for group in db.list_groups(user_id)
    ]
    return jsonify(groups)


def _create_group(app: Flask) -> Reply:
    user = g.user
    if user.get("role") not in {"admin", "developer"}:
        return jsonify({"error": "You do not have permission."}), 403
    parsed, error = parse_group(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), 400
    members, member_error = _resolve_members(
        parsed["members"],
        force_lead=user["username"] if user.get("role") == "developer" else "",
    )
    if member_error:
        return jsonify({"error": member_error}), 400
    try:
        group_id = db.insert_group(
            parsed["name"],
            parsed["description"],
            int(user["id"]),
            parsed["project_ids"],
            members,
            str(user.get("username") or ""),
            parsed["name"],
        )
    except UniqueViolation:
        return jsonify({"error": "That group name is already used."}), 409
    created = db.get_group(group_id)
    app.logger.info("group created id=%s", group_id)
    if created is None:
        return jsonify({"error": "Could not create the group."}), 500
    return jsonify(public_group(created, can_edit=True)), 201


def _update_group(app: Flask, group_id: int) -> Reply:
    current = db.get_group(group_id)
    if current is None:
        return jsonify({"error": "Group not found."}), 404
    if not _can_edit(g.user, current):
        return jsonify({"error": "You do not have permission."}), 403
    parsed, error = parse_group(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), 400
    members, member_error = _resolve_members(parsed["members"], force_lead="")
    if member_error:
        return jsonify({"error": member_error}), 400
    try:
        db.update_group(
            group_id,
            parsed["name"],
            parsed["description"],
            parsed["project_ids"],
            members,
            str(g.user.get("username") or ""),
            parsed["name"],
        )
    except UniqueViolation:
        return jsonify({"error": "That group name is already used."}), 409
    updated = db.get_group(group_id)
    app.logger.info("group updated id=%s", group_id)
    if updated is None:
        return jsonify({"error": "Group not found."}), 404
    return jsonify(public_group(updated, can_edit=True))


def _delete_group(app: Flask, group_id: int) -> Reply:
    current = db.get_group(group_id)
    if current is None:
        return jsonify({"error": "Group not found."}), 404
    if not _can_edit(g.user, current):
        return jsonify({"error": "You do not have permission."}), 403
    db.delete_group(group_id)
    app.logger.info("group deleted id=%s", group_id)
    return jsonify({"ok": True})


def _can_edit(user: dict[str, Any], group: dict[str, Any]) -> bool:
    if user.get("role") == "admin":
        return True
    username = user.get("username")
    return any(
        item["username"] == username and item["lead"]
        for item in group.get("members") or []
    )


def _resolve_members(
    requested: list[dict[str, Any]],
    *,
    force_lead: str,
) -> tuple[list[tuple[int, bool]], str]:
    names = [item["username"] for item in requested]
    if force_lead and force_lead not in names:
        names.append(force_lead)
        requested = [*requested, {"username": force_lead, "lead": True}]
    found = {
        row["username"]: row
        for row in db.users_by_username(names)
    }
    resolved: list[tuple[int, bool]] = []
    seen: set[str] = set()
    for item in requested:
        username = item["username"]
        if username in seen:
            continue
        seen.add(username)
        account = found.get(username)
        if account is None:
            return [], "Unknown user: " + username
        if account.get("disabled"):
            return [], "That account is disabled: " + username
        lead = bool(item["lead"]) or username == force_lead
        if lead and account.get("role") == "viewer":
            return [], "A viewer cannot lead a group."
        resolved.append((int(account["id"]), lead))
    if not any(lead for _user_id, lead in resolved):
        return [], "A group needs a lead."
    return resolved, ""


def _projects(
    body: dict[str, Any],
) -> tuple[list[int], str]:
    """Resolve attached first-class projects from slugs or ids."""

    slugs = body.get("project_slugs")
    ids = body.get("project_ids")
    resolved: list[int] = []
    seen: set[int] = set()
    if slugs is not None:
        if not isinstance(slugs, list) or not all(
            isinstance(item, str) for item in slugs
        ):
            return [], "A project is invalid."
        cleaned = [" ".join(item.split()).lower() for item in slugs if item.strip()]
        found = {item["slug"]: item for item in db.projects_by_slugs(cleaned)}
        for slug in cleaned:
            project = found.get(slug)
            if project is None:
                return [], "Unknown project: " + slug
            project_id = int(project["id"])
            if project_id in seen:
                return [], "That project is listed twice."
            seen.add(project_id)
            resolved.append(project_id)
    if ids is not None:
        if not isinstance(ids, list):
            return [], "A project is invalid."
        for item in ids:
            try:
                project_id = int(item)
            except (TypeError, ValueError):
                return [], "A project is invalid."
            if project_id in seen:
                continue
            if db.get_project_by_id(project_id) is None:
                return [], "Unknown project."
            seen.add(project_id)
            resolved.append(project_id)
    if len(resolved) > _MAX_PROJECTS:
        return [], "A group can hold 30 projects."
    return resolved, ""


def _member_names(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    raw = body.get("members")
    if not isinstance(raw, list):
        return [], "Add at least one member."
    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            return [], "A member is invalid."
        username = item.get("username")
        if not isinstance(username, str):
            return [], "A member is invalid."
        username = username.strip()
        if not username or len(username) > 64 or username in seen:
            return [], "A member is invalid."
        seen.add(username)
        members.append({"username": username, "lead": bool(item.get("lead"))})
    if not members:
        return [], "Add at least one member."
    if len(members) > _MAX_MEMBERS:
        return [], "A group can hold 50 members."
    return members, ""


def _has_control(value: str) -> bool:
    return any(ord(ch) < 32 for ch in value)


def _iso(value: Any) -> str:
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return ""
