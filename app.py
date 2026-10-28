#!/usr/bin/env python3
import json
import os
import sys
import threading
import uuid

import psycopg
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_urlsafe
from typing import Any

from flask import Flask, Response, g, jsonify, make_response, render_template, request

from security_console import db
from security_console.access import (
    can_scan_project,
    can_start_scan,
    find_reusable_scan,
    present_scan,
    project_key,
    recent_per_project,
)
from security_console.auth import (
    ConfigError,
    client_ip,
    cookie_flags,
    install_auth,
    prepare_auth,
    validate_runtime_config,
)
from security_console.dispatch import (
    dispatch_images,
    dispatch_scan,
    scanner_token,
    scanner_url,
)
from security_console.guest import (
    COOKIE as GUEST_COOKIE,
    COOKIE_DAYS as GUEST_COOKIE_DAYS,
    HOURLY_LIMIT as GUEST_HOURLY_LIMIT,
    expired as guest_expired,
    parse_guest_scan,
    present_guest_scan,
    recent_count as guest_recent_count,
    session_key as guest_session_key,
)
from security_console.images import valid_image_ref
from security_console.integrations import credentials_for
from security_console.queue import (
    QUEUE_CAP,
    attach_queue_position,
    bind_store,
    start_dispatcher,
)
from security_console.repos import normalize_commit_sha, valid_repo
from security_console.sonar_proxy import install_sonar_proxy
from security_console.sonar_setup import read_public_status, run_setup

View = Response | tuple[Response, int]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
DATA = Path(os.environ.get("DATA_DIR", "/data"))
RESTART_ERROR = "The console restarted during the scan."

lock = threading.Lock()
scans: dict[str, dict[str, Any]] = {}
guest_secrets: dict[str, dict[str, str]] = {}


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_state() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    scan_dir = DATA / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    _migrate_scan_files(scan_dir)
    try:
        db.fail_running_scans(RESTART_ERROR)
        for item in db.list_scan_rows():
            if guest_expired(item):
                db.delete_scan_row(str(item["id"]))
                (scan_dir / f"{item['id']}.json").unlink(missing_ok=True)
                continue
            scans[str(item["id"])] = item
    except psycopg.Error:
        app.logger.exception("scan table unavailable; falling back to files")
        for path in scan_dir.glob("*.json"):
            try:
                item = json.loads(path.read_text())
            except json.JSONDecodeError:
                continue
            if guest_expired(item):
                path.unlink(missing_ok=True)
                continue
            if item.get("status") == "running":
                item["status"] = "failed"
                item["error"] = RESTART_ERROR
                path.write_text(json.dumps(item, ensure_ascii=False))
            scans[item["id"]] = item


def _migrate_scan_files(scan_dir: Path) -> None:
    """Copy JSON scan files into Postgres when the row is missing."""

    for path in scan_dir.glob("*.json"):
        try:
            item = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        scan_id = str(item.get("id") or "")
        if not scan_id:
            continue
        if guest_expired(item):
            path.unlink(missing_ok=True)
            continue
        if item.get("status") == "running":
            item["status"] = "failed"
            item["error"] = RESTART_ERROR
            item["phase"] = ""
            item["finished_at"] = item.get("finished_at") or utcnow()
            path.write_text(json.dumps(item, ensure_ascii=False))
        try:
            if db.get_scan_row(scan_id) is None:
                db.upsert_scan(item)
        except psycopg.Error:
            app.logger.exception("could not migrate scan %s", scan_id)
            return


def prune_guest_scans() -> None:
    """Drop guest scans past their keep time. Call with ``lock`` held."""

    for scan_id, item in list(scans.items()):
        if item.get("status") in {"running", "queued"}:
            continue
        if guest_expired(item):
            scans.pop(scan_id, None)
            (DATA / "scans" / f"{scan_id}.json").unlink(missing_ok=True)
            with suppress(psycopg.Error):
                db.delete_scan_row(scan_id)


def save_scan(item: dict[str, Any]) -> None:
    path = DATA / "scans" / f"{item['id']}.json"
    path.write_text(json.dumps(item, ensure_ascii=False))
    with suppress(psycopg.Error):
        db.upsert_scan(item)


def _with_queue_fields(item: dict[str, Any]) -> dict[str, Any]:
    return attach_queue_position(item, list(scans.values()))


def execute_scan(scan_id: str) -> None:
    with lock:
        item = scans.get(scan_id)
        if item is None:
            return

    def on_phase(phase: str) -> None:
        with lock:
            current = scans.get(scan_id)
            if current is None:
                return
            current["phase"] = phase
            save_scan(current)

    def on_update(progress: dict) -> None:
        with lock:
            current = scans.get(scan_id)
            if current is None or current.get("status") != "running":
                return
            phase = progress.get("phase")
            if isinstance(phase, str) and phase:
                current["phase"] = phase
            findings = progress.get("findings")
            if isinstance(findings, list):
                current["findings"] = findings
            tool_results = progress.get("tool_results")
            if isinstance(tool_results, list):
                current["tool_results"] = tool_results
            error = progress.get("error")
            if isinstance(error, str) and error:
                current["error"] = error
            save_scan(current)

    try:
        try:
            if item.get("guest"):
                secrets = guest_secrets.pop(scan_id, {})
            else:
                secrets = credentials_for(item)
        except psycopg.Error:
            app.logger.error("integration lookup failed")
            with lock:
                current = scans.get(scan_id)
                if current is None:
                    return
                current["status"] = "failed"
                current["error"] = "Sign-in is unavailable."
                current["phase"] = ""
                current["finished_at"] = utcnow()
                save_scan(current)
            return
        outcome = dispatch_scan(
            {
                "id": item["id"],
                "target": item["target"],
                "repo": item["repo"],
                "image": item["image"],
                "tools": item["tools"],
                "requested_sha": item.get("requested_sha") or "",
                **secrets,
            },
            on_phase,
            on_update,
        )
        with lock:
            current = scans.get(scan_id)
            if current is None:
                return
            current["findings"] = outcome.get("findings") or []
            current["tool_results"] = outcome.get("tool_results") or []
            current["sonar"] = outcome.get("sonar")
            current["status"] = outcome.get("status") or "failed"
            current["error"] = outcome.get("error") or ""
            current["commit_sha"] = outcome.get("commit_sha") or ""
            current["failure_reason"] = outcome.get("failure_reason") or ""
            current["requested_sha"] = (
                outcome.get("requested_sha") or current.get("requested_sha") or ""
            )
            current["phase"] = ""
            current["finished_at"] = utcnow()
            save_scan(current)
    except Exception as exc:
        text = str(exc)
        for value in locals().get("secrets", {}).values():
            if value and value in text:
                text = text.replace(value, "***")
        with lock:
            current = scans.get(scan_id)
            if current is None:
                return
            current["status"] = "failed"
            current["phase"] = ""
            current["error"] = text[-2000:]
            current["commit_sha"] = current.get("commit_sha") or ""
            current["failure_reason"] = current.get("failure_reason") or ""
            current["finished_at"] = utcnow()
            save_scan(current)


@app.get("/")
@app.get("/login")
def index() -> Response:
    response = make_response(render_template("index.html", sonar_url="/sonar/"))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.post("/api/scans")
def create_scan() -> View:
    user = getattr(g, "user", None)
    if not isinstance(user, dict):
        return jsonify({"error": "You do not have permission."}), 403
    body = request.get_json(silent=True) or {}
    target = body.get("target") or "repo"
    if target not in {"repo", "image"}:
        return jsonify({"error": "Invalid scan type."}), 400
    tools = [
        tool
        for tool in body.get("tools") or []
        if tool in {"semgrep", "checkov", "sonar", "trivy"}
    ]
    image = ""
    repo = ""
    project_id = None
    project_slug = ""
    project_name = ""
    project_ref = str(body.get("project") or "").strip().lower()
    linked = None
    if project_ref:
        linked = db.get_project_by_slug(project_ref)
        if linked is None:
            return jsonify({"error": "Project not found."}), 404
        kind_targets = [
            item
            for item in linked.get("targets") or []
            if item.get("kind") == target
        ]
        if not kind_targets:
            return jsonify(
                {"error": "This project has no " + target + " target."}
            ), 400
        want = (
            (body.get("image") or "").strip()
            if target == "image"
            else (body.get("repo") or "").strip()
        )
        chosen = None
        if want:
            for item in kind_targets:
                if str(item.get("target") or "") == want:
                    chosen = item
                    break
            if chosen is None:
                return jsonify(
                    {"error": "That target is not part of this project."}
                ), 400
        else:
            chosen = kind_targets[0]
        if target == "image":
            image = str(chosen.get("target") or "")
        else:
            repo = str(chosen.get("target") or "")
        project_id = int(linked["id"])
        project_slug = str(linked["slug"])
        project_name = str(linked.get("name") or project_slug)
    requested_sha = normalize_commit_sha(body.get("requested_sha"))
    if requested_sha is None:
        return jsonify({"error": "Commit SHA is invalid."}), 400
    if target == "image":
        if not project_ref:
            image = (body.get("image") or "").strip()
        if not valid_image_ref(image):
            return jsonify(
                {"error": "Image name is invalid. Use a name like nginx:1.27."}
            ), 400
        if tools != ["trivy"]:
            return jsonify({"error": "Image scans run with Trivy only."}), 400
        if requested_sha:
            return jsonify({"error": "Image scans do not take a commit."}), 400
        if not project_ref and user.get("role") != "admin":
            return jsonify(
                {"error": "Select a project, or ask an admin to scan ad-hoc."}
            ), 403
    else:
        if not project_ref:
            repo = (body.get("repo") or "").strip()
        if not valid_repo(repo):
            return jsonify(
                {"error": "Repository URL must start with http or https."}
            ), 400
        if not tools:
            return jsonify({"error": "Select at least one tool."}), 400
        if not project_ref and user.get("role") != "admin":
            return jsonify(
                {"error": "Select a project, or ask an admin to scan ad-hoc."}
            ), 403
    scan_key = (
        project_slug
        if project_slug
        else project_key({"target": target, "repo": repo, "image": image})
    )
    try:
        group_keys = (
            set()
            if user.get("role") == "admin"
            else db.group_project_keys(int(user["id"]))
        )
    except psycopg.Error:
        app.logger.error("group lookup failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503
    if not can_scan_project(user, tools, scan_key, group_keys):
        if can_start_scan(user, tools):
            return jsonify(
                {"error": "This project is not in one of your groups."}
            ), 403
        return jsonify({"error": "You do not have permission."}), 403
    force = bool(body.get("force"))
    with lock:
        items = list(scans.values())
        reusable = find_reusable_scan(
            user,
            items,
            target=target,
            repo=repo,
            image=image,
            tools=tools,
            requested_sha=requested_sha,
            group_keys=group_keys,
            force=force,
        )
        if reusable is not None:
            item, reason = reusable
            shown = present_scan(
                user,
                _with_queue_fields(item),
                summary=False,
                group_keys=group_keys,
            )
            if shown is None:
                return jsonify({"error": "You do not have permission."}), 403
            shown["reused"] = True
            shown["reuse_reason"] = reason
            return jsonify(shown), 200
        queued_count = sum(1 for row in items if row.get("status") == "queued")
        if queued_count >= QUEUE_CAP:
            return jsonify(
                {
                    "error": (
                        "Too many scans are waiting. "
                        "Try again when the queue is shorter."
                    )
                }
            ), 429
        scan_id = uuid.uuid4().hex[:12]
        item = {
            "id": scan_id,
            "target": target,
            "repo": repo,
            "image": image,
            "tools": tools,
            "status": "queued",
            "findings": [],
            "sonar": None,
            "phase": "",
            "error": "",
            "created_at": utcnow(),
            "finished_at": "",
            "owner": user.get("username") or "",
            "requested_sha": requested_sha,
            "commit_sha": "",
            "failure_reason": "",
            "priority": 0,
        }
        if project_id is not None:
            item["project_id"] = project_id
            item["project_slug"] = project_slug
            item["project_name"] = project_name
        scans[scan_id] = item
        save_scan(item)
        shown = present_scan(
            user,
            _with_queue_fields(item),
            summary=False,
            group_keys=group_keys,
        )
    return jsonify(shown or _with_queue_fields(item)), 202


@app.get("/api/images")
def get_images() -> View:
    user = getattr(g, "user", None) or {}
    if not can_start_scan(user, ["trivy"]):
        return jsonify({"error": "You do not have permission."}), 403
    try:
        return jsonify(dispatch_images())
    except Exception:
        app.logger.error("image list failed")
        return jsonify({"error": "Could not list local images."}), 503


@app.get("/api/scans")
def list_scans() -> Response:
    user = getattr(g, "user", None) or {}
    summary = request.args.get("summary") == "1"
    try:
        group_keys = _group_keys(user)
    except psycopg.Error:
        app.logger.error("group lookup failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503
    with lock:
        items = [_with_queue_fields(item) for item in scans.values()]
    visible = recent_per_project(
        user,
        items,
        summary=summary,
        group_keys=group_keys,
    )
    return jsonify(visible)


@app.get("/api/scans/<scan_id>")
def get_scan(scan_id: str) -> View:
    user = getattr(g, "user", None) or {}
    with lock:
        item = scans.get(scan_id)
        if not item:
            return jsonify({"error": "Not found"}), 404
        item = _with_queue_fields(item)
    try:
        group_keys = _group_keys(user)
    except psycopg.Error:
        app.logger.error("group lookup failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503
    shown = present_scan(user, item, summary=False, group_keys=group_keys)
    if shown is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(shown)


def _guest_key() -> str:
    cookie = request.cookies.get(GUEST_COOKIE, "")
    return guest_session_key(cookie) if len(cookie) >= 32 else ""


def _guest_reply(payload: Any, status: int, cookie: str = "") -> Response:
    response = jsonify(payload)
    response.status_code = status
    if cookie:
        response.set_cookie(
            GUEST_COOKIE,
            cookie,
            max_age=GUEST_COOKIE_DAYS * 86400,
            path="/api/guest",
            **cookie_flags(),
        )
    return response


@app.post("/api/guest/scans")
def create_guest_scan() -> Response:
    if not request.is_json:
        return _guest_reply({"error": "Request rejected."}, 403)
    cookie = ""
    guest = _guest_key()
    if not guest:
        cookie = token_urlsafe(32)
        guest = guest_session_key(cookie)
    body = request.get_json(silent=True)
    fields, one_time, error = parse_guest_scan(body)
    if fields is None:
        return _guest_reply({"error": error}, 400, cookie)
    force = isinstance(body, dict) and body.get("force") is True
    ip = client_ip()
    with lock:
        prune_guest_scans()
        items = list(scans.values())
        reusable = find_reusable_scan(
            {"role": "admin"},
            items,
            target=fields["target"],
            repo=fields["repo"],
            image=fields["image"],
            tools=fields["tools"],
            force=force,
            guest=guest,
        )
        if reusable is not None:
            item, reason = reusable
            shown = present_guest_scan(_with_queue_fields(item), summary=False)
            shown["reused"] = True
            shown["reuse_reason"] = reason
            return _guest_reply(shown, 200, cookie)
        recent = guest_recent_count(items, guest, ip)
        if recent >= GUEST_HOURLY_LIMIT:
            return _guest_reply(
                {"error": "Too many scans this hour. Sign in or try again later."},
                429,
                cookie,
            )
        queued_count = sum(1 for row in items if row.get("status") == "queued")
        if queued_count >= QUEUE_CAP:
            return _guest_reply(
                {
                    "error": (
                        "Too many scans are waiting. "
                        "Try again when the queue is shorter."
                    )
                },
                429,
                cookie,
            )
        scan_id = uuid.uuid4().hex[:12]
        item = {
            "id": scan_id,
            **fields,
            "status": "queued",
            "findings": [],
            "sonar": None,
            "phase": "",
            "error": "",
            "created_at": utcnow(),
            "finished_at": "",
            "owner": "Guest",
            "guest": guest,
            "guest_ip": ip,
            "private": bool(one_time),
            "requested_sha": "",
            "commit_sha": "",
            "failure_reason": "",
            "priority": 0,
        }
        scans[scan_id] = item
        guest_secrets[scan_id] = one_time
        save_scan(item)
        shown = present_guest_scan(_with_queue_fields(item), summary=False)
    return _guest_reply(shown, 202, cookie)


@app.get("/api/guest/scans")
def list_guest_scans() -> Response:
    guest = _guest_key()
    with lock:
        mine = [
            _with_queue_fields(item)
            for item in scans.values()
            if guest and item.get("guest") == guest and not guest_expired(item)
        ]
    mine.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return jsonify([present_guest_scan(item, summary=True) for item in mine[:20]])


@app.get("/api/guest/scans/<scan_id>")
def get_guest_scan(scan_id: str) -> View:
    guest = _guest_key()
    with lock:
        item = scans.get(scan_id)
        if not guest or not item or item.get("guest") != guest:
            return jsonify({"error": "Not found"}), 404
        item = _with_queue_fields(item)
    return jsonify(present_guest_scan(item, summary=False))


@app.get("/api/sonar/setup")
@app.post("/api/sonar/setup")
def sonar_setup_route() -> View:
    user = getattr(g, "user", None)
    if not isinstance(user, dict) or user.get("role") != "admin":
        return jsonify({"error": "You do not have permission."}), 403
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        rotate = isinstance(body, dict) and body.get("rotate") is True
        try:
            run_setup(rotate=rotate)
        except Exception:
            app.logger.error("sonar setup failed")
    return jsonify(read_public_status())


@app.errorhandler(413)
def too_large(_exc: Exception) -> View:
    return jsonify({"error": "Request is too large."}), 413


install_auth(app)
install_sonar_proxy(app)


def _group_keys(user: dict[str, Any]) -> set[str] | None:
    """Return group projects for a member. Admins are not filtered."""

    if user.get("role") == "admin":
        return None
    return db.group_project_keys(int(user["id"]))


def boot() -> None:
    """Prepare storage, load scans, then start the queue dispatcher."""

    try:
        validate_runtime_config()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
    try:
        prepare_auth()
    except Exception as exc:
        print(f"auth startup failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
    load_state()
    if scanner_url() and len(scanner_token()) < 16:
        print("scanner token is not configured", file=sys.stderr)
        raise SystemExit(1)
    if os.environ.get("COOKIE_SECURE", "0") != "1":
        print(
            "development mode is using HTTP cookies; "
            "do not expose this port on an untrusted network",
            file=sys.stderr,
        )
    bind_store(lock, scans, save_scan)
    start_dispatcher(execute_scan)


if os.environ.get("CONSOLE_SKIP_BOOT") != "1":
    boot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
