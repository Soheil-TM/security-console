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
from typing import Any

from flask import Flask, Response, g, jsonify, render_template, request

from security_console import db
from security_console.access import (
    can_scan_project,
    can_start_scan,
    present_scan,
    project_key,
    recent_per_project,
)
from security_console.alerts import alert_from_payload
from security_console.auth import (
    ConfigError,
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
from security_console.images import valid_image_ref
from security_console.repos import normalize_commit_sha, valid_repo
from security_console.sonar_proxy import install_sonar_proxy
from security_console.sonar_setup import read_public_status, run_setup

View = Response | tuple[Response, int]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
DATA = Path(os.environ.get("DATA_DIR", "/data"))
MAX_ALERTS = 300

lock = threading.Lock()
scans: dict[str, dict[str, Any]] = {}
alerts: list[dict[str, Any]] = []


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_state() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    alert_file = DATA / "alerts.json"
    if alert_file.exists():
        with suppress(json.JSONDecodeError):
            alerts.extend(json.loads(alert_file.read_text())[-MAX_ALERTS:])
    scan_dir = DATA / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    for path in scan_dir.glob("*.json"):
        try:
            item = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if item.get("status") == "running":
            item["status"] = "failed"
            item["error"] = "The console restarted during the scan."
            path.write_text(json.dumps(item, ensure_ascii=False))
        scans[item["id"]] = item


def save_scan(item: dict[str, Any]) -> None:
    path = DATA / "scans" / f"{item['id']}.json"
    path.write_text(json.dumps(item, ensure_ascii=False))


def save_alerts() -> None:
    text = json.dumps(alerts[-MAX_ALERTS:], ensure_ascii=False)
    (DATA / "alerts.json").write_text(text)


def execute_scan(scan_id: str) -> None:
    item = scans[scan_id]

    def on_phase(phase: str) -> None:
        item["phase"] = phase
        save_scan(item)

    try:
        outcome = dispatch_scan(
            {
                "id": item["id"],
                "target": item["target"],
                "repo": item["repo"],
                "image": item["image"],
                "tools": item["tools"],
                "requested_sha": item.get("requested_sha") or "",
            },
            on_phase,
        )
        item["findings"] = outcome.get("findings") or []
        item["sonar"] = outcome.get("sonar")
        item["status"] = outcome.get("status") or "failed"
        item["error"] = outcome.get("error") or ""
        item["commit_sha"] = outcome.get("commit_sha") or ""
        item["failure_reason"] = outcome.get("failure_reason") or ""
        item["requested_sha"] = (
            outcome.get("requested_sha") or item.get("requested_sha") or ""
        )
        item["phase"] = ""
        item["finished_at"] = utcnow()
    except Exception as exc:
        item["status"] = "failed"
        item["phase"] = ""
        item["error"] = str(exc)[-2000:]
        item["commit_sha"] = item.get("commit_sha") or ""
        item["failure_reason"] = item.get("failure_reason") or ""
        item["finished_at"] = utcnow()
    finally:
        save_scan(item)


@app.get("/")
@app.get("/login")
def index() -> str:
    return render_template("index.html", sonar_url="/sonar/")


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
    requested_sha = normalize_commit_sha(body.get("requested_sha"))
    if requested_sha is None:
        return jsonify({"error": "Commit SHA is invalid."}), 400
    if target == "image":
        image = (body.get("image") or "").strip()
        if not valid_image_ref(image):
            return jsonify(
                {"error": "Image name is invalid. Use a name like nginx:1.27."}
            ), 400
        if tools != ["trivy"]:
            return jsonify({"error": "Image scans run with Trivy only."}), 400
        if requested_sha:
            return jsonify({"error": "Image scans do not take a commit."}), 400
    else:
        repo = (body.get("repo") or "").strip()
        if not valid_repo(repo):
            return jsonify(
                {"error": "Repository URL must start with http or https."}
            ), 400
        if not tools:
            return jsonify({"error": "Select at least one tool."}), 400
    scan_key = project_key({"target": target, "repo": repo, "image": image})
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
    with lock:
        if any(item["status"] == "running" for item in scans.values()):
            return jsonify({"error": "A scan is already running."}), 409
        scan_id = uuid.uuid4().hex[:12]
        item = {
            "id": scan_id,
            "target": target,
            "repo": repo,
            "image": image,
            "tools": tools,
            "status": "running",
            "findings": [],
            "sonar": None,
            "phase": "Trivy" if target == "image" else "clone",
            "error": "",
            "created_at": utcnow(),
            "finished_at": "",
            "owner": user.get("username") or "",
            "requested_sha": requested_sha,
            "commit_sha": "",
            "failure_reason": "",
        }
        scans[scan_id] = item
        save_scan(item)
    threading.Thread(target=execute_scan, args=(scan_id,), daemon=True).start()
    return jsonify(item), 202


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
    visible = recent_per_project(
        user,
        list(scans.values()),
        summary=summary,
        group_keys=group_keys,
    )
    return jsonify(visible)


@app.get("/api/scans/<scan_id>")
def get_scan(scan_id: str) -> View:
    user = getattr(g, "user", None) or {}
    item = scans.get(scan_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    try:
        group_keys = _group_keys(user)
    except psycopg.Error:
        app.logger.error("group lookup failed")
        return jsonify({"error": "Sign-in is unavailable."}), 503
    shown = present_scan(user, item, summary=False, group_keys=group_keys)
    if shown is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(shown)


@app.post("/api/falco")
def ingest_falco() -> Response:
    payload = request.get_json(silent=True)
    if payload is None:
        raw = request.get_data(as_text=True).strip()
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"output": raw[:2000]}
    if not isinstance(payload, dict):
        payload = {"output": ""}
    alert = alert_from_payload(payload, utcnow())
    with lock:
        alerts.append(alert)
        del alerts[:-MAX_ALERTS]
        save_alerts()
    return jsonify({"ok": True})


@app.get("/api/falco")
def list_falco() -> Response:
    return jsonify(list(reversed(alerts[-100:])))


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
    """Load saved scans, then refuse to serve until login storage is ready."""

    load_state()
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
    if scanner_url() and len(scanner_token()) < 16:
        print("scanner token is not configured", file=sys.stderr)
        raise SystemExit(1)
    if os.environ.get("COOKIE_SECURE", "0") != "1":
        print(
            "development mode is using HTTP cookies; "
            "do not expose this port on an untrusted network",
            file=sys.stderr,
        )


if os.environ.get("CONSOLE_SKIP_BOOT") != "1":
    boot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
