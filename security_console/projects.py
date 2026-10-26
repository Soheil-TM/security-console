"""First-class security projects: slug, targets, and group ownership."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import psycopg
from flask import Flask, Response, g, jsonify, request
from psycopg.errors import UniqueViolation

from security_console import db
from security_console.access import project_key
from security_console.images import valid_image_ref
from security_console.repos import valid_repo

Reply = Response | tuple[Response, int]
_MAX_NAME = 80
_MAX_DESCRIPTION = 500
_MAX_TARGETS = 20
_MAX_GROUPS = 20
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def install_projects(app: Flask) -> None:
    """Attach project CRUD routes."""

    @app.get("/api/projects")
    def list_security_projects() -> Reply:
        return _call(app, _list_projects)

    @app.post("/api/projects")
    def create_security_project() -> Reply:
        return _call(app, lambda: _create_project(app))

    @app.get("/api/projects/<slug>")
    def get_security_project(slug: str) -> Reply:
        return _call(app, lambda: _get_project(slug))

    @app.put("/api/projects/<slug>")
    def update_security_project(slug: str) -> Reply:
        return _call(app, lambda: _update_project(app, slug))

    @app.delete("/api/projects/<slug>")
    def delete_security_project(slug: str) -> Reply:
        return _call(app, lambda: _delete_project(app, slug))


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("project database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def parse_project(body: Any) -> tuple[dict[str, Any] | None, str]:
    """Validate a project form. Empty error string means valid."""

    if not isinstance(body, dict):
        return None, "The project details are incomplete."
    name = body.get("name")
    slug = body.get("slug")
    description = body.get("description") or ""
    if not isinstance(name, str) or not isinstance(slug, str):
        return None, "The project details are incomplete."
    if not isinstance(description, str):
        return None, "The project details are incomplete."
    name = " ".join(name.split())
    slug = slug.strip().lower()
    description = description.strip()
    if not name or len(name) > _MAX_NAME or _has_control(name):
        return None, "Project name is invalid."
    if not _SLUG_RE.match(slug) or len(slug) > 64:
        return None, "Slug must be lowercase letters, numbers, and hyphens."
    if len(description) > _MAX_DESCRIPTION or _has_control(description):
        return None, "Description is invalid."
    targets, target_error = _targets(body)
    if target_error:
        return None, target_error
    group_ids, group_error = _group_ids(body)
    if group_error:
        return None, group_error
    return {
        "name": name,
        "slug": slug,
        "description": description,
        "targets": targets,
        "group_ids": group_ids,
    }, ""


def public_project(project: dict[str, Any], *, can_edit: bool) -> dict[str, Any]:
    """Return project fields the browser may see."""

    return {
        "id": int(project["id"]),
        "slug": project["slug"],
        "name": project["name"],
        "description": project.get("description") or "",
        "created_at": project.get("created_at") or "",
        "can_edit": can_edit,
        "targets": [
            {
                "kind": item["kind"],
                "target": item["target"],
                "key": item["key"],
            }
            for item in project.get("targets") or []
        ],
        "group_ids": [int(item) for item in project.get("group_ids") or []],
    }


def _list_projects() -> Response:
    user = g.user
    user_id = None if user.get("role") == "admin" else int(user["id"])
    projects = [
        public_project(item, can_edit=_can_edit(user, item))
        for item in db.list_projects(user_id)
    ]
    return jsonify(projects)


def _get_project(slug: str) -> Reply:
    project = db.get_project_by_slug(slug.strip().lower())
    if project is None:
        return jsonify({"error": "Project not found."}), 404
    if not _can_view(g.user, project):
        return jsonify({"error": "You do not have permission."}), 403
    return jsonify(public_project(project, can_edit=_can_edit(g.user, project)))


def _create_project(app: Flask) -> Reply:
    user = g.user
    parsed, error = parse_project(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), 400
    if not _may_create(user, parsed["group_ids"]):
        return jsonify({"error": "You do not have permission."}), 403
    try:
        created = db.insert_project(
            slug=parsed["slug"],
            name=parsed["name"],
            description=parsed["description"],
            created_by=int(user["id"]),
            targets=parsed["targets"],
            group_ids=parsed["group_ids"],
        )
    except UniqueViolation:
        return jsonify({"error": "That project slug is already used."}), 409
    app.logger.info("project created slug=%s", created["slug"])
    return jsonify(public_project(created, can_edit=True)), 201


def _update_project(app: Flask, slug: str) -> Reply:
    current = db.get_project_by_slug(slug.strip().lower())
    if current is None:
        return jsonify({"error": "Project not found."}), 404
    if not _can_edit(g.user, current):
        return jsonify({"error": "You do not have permission."}), 403
    parsed, error = parse_project(request.get_json(silent=True))
    if parsed is None:
        return jsonify({"error": error}), 400
    if not _may_create(g.user, parsed["group_ids"]):
        return jsonify({"error": "You do not have permission."}), 403
    try:
        updated = db.update_project(
            int(current["id"]),
            slug=parsed["slug"],
            name=parsed["name"],
            description=parsed["description"],
            targets=parsed["targets"],
            group_ids=parsed["group_ids"],
        )
    except UniqueViolation:
        return jsonify({"error": "That project slug is already used."}), 409
    if updated is None:
        return jsonify({"error": "Project not found."}), 404
    app.logger.info("project updated slug=%s", updated["slug"])
    return jsonify(public_project(updated, can_edit=True))


def _delete_project(app: Flask, slug: str) -> Reply:
    current = db.get_project_by_slug(slug.strip().lower())
    if current is None:
        return jsonify({"error": "Project not found."}), 404
    if not _can_edit(g.user, current):
        return jsonify({"error": "You do not have permission."}), 403
    db.delete_project(int(current["id"]))
    app.logger.info("project deleted slug=%s", slug)
    return jsonify({"ok": True})


def _may_create(user: dict[str, Any], group_ids: list[int]) -> bool:
    if user.get("role") == "admin":
        return True
    if user.get("role") != "developer":
        return False
    if not group_ids:
        return False
    return db.user_leads_any_of_groups(int(user["id"]), group_ids)


def _can_view(user: dict[str, Any], project: dict[str, Any]) -> bool:
    if user.get("role") == "admin":
        return True
    try:
        slugs = db.user_project_slugs(int(user["id"]))
    except (TypeError, ValueError):
        return False
    return str(project.get("slug") or "") in slugs


def _can_edit(user: dict[str, Any], project: dict[str, Any]) -> bool:
    if user.get("role") == "admin":
        return True
    group_ids = [int(item) for item in project.get("group_ids") or []]
    if not group_ids:
        return False
    try:
        return db.user_leads_any_of_groups(int(user["id"]), group_ids)
    except (TypeError, ValueError):
        return False


def _targets(body: dict[str, Any]) -> tuple[list[dict[str, str]], str]:
    repos = _lines(body.get("repos"))
    images = _lines(body.get("images"))
    if isinstance(repos, str):
        return [], repos
    if isinstance(images, str):
        return [], images
    raw = body.get("targets")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                return [], "A target is invalid."
            kind = item.get("kind")
            target = item.get("target")
            if kind == "repo" and isinstance(target, str):
                repos.append(target.strip())
            elif kind == "image" and isinstance(target, str):
                images.append(target.strip())
            else:
                return [], "A target is invalid."
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for repo in repos:
        repo = " ".join(repo.split())
        if not repo:
            continue
        if not valid_repo(repo):
            return [], "Repository URL must start with http or https."
        key = project_key({"repo": repo, "image": ""})
        if key in seen:
            return [], "That target is listed twice."
        seen.add(key)
        targets.append({"kind": "repo", "target": repo, "key": key})
    for image in images:
        image = " ".join(image.split())
        if not image:
            continue
        if not valid_image_ref(image):
            return [], "Image name is invalid. Use a name like nginx:1.27."
        key = project_key({"target": "image", "image": image, "repo": ""})
        if key in seen:
            return [], "That target is listed twice."
        seen.add(key)
        targets.append({"kind": "image", "target": image, "key": key})
    if not targets:
        return [], "Add at least one repository or image target."
    if len(targets) > _MAX_TARGETS:
        return [], "A project can hold 20 targets."
    return targets, ""


def _group_ids(body: dict[str, Any]) -> tuple[list[int], str]:
    raw = body.get("group_ids")
    if raw is None:
        return [], ""
    if not isinstance(raw, list):
        return [], "Group list is invalid."
    ids: list[int] = []
    seen: set[int] = set()
    for item in raw:
        try:
            group_id = int(item)
        except (TypeError, ValueError):
            return [], "Group list is invalid."
        if group_id <= 0 or group_id in seen:
            return [], "Group list is invalid."
        seen.add(group_id)
        ids.append(group_id)
    if len(ids) > _MAX_GROUPS:
        return [], "A project can belong to 20 groups."
    for group_id in ids:
        if db.get_group(group_id) is None:
            return [], "Unknown group."
    return ids, ""


def _lines(value: Any) -> list[str] | str:
    if value is None:
        return []
    if isinstance(value, str):
        rows = value.splitlines()
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        rows = value
    else:
        return "A target is invalid."
    cleaned = [" ".join(item.split()) for item in rows]
    return [item for item in cleaned if item]


def _has_control(value: str) -> bool:
    return any(ord(ch) < 32 for ch in value)
