"""Project scan schedules: parse rules, queue enqueue, and HTTP gates."""

from __future__ import annotations

import os
import threading
from datetime import timedelta

import pytest
from argon2 import PasswordHasher
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from security_console.auth import install_auth, prepare_auth
from security_console.db import (
    delete_project,
    insert_project,
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
    reset_schedule_table,
)
from security_console.schedules import (
    bind_schedule_store,
    enqueue_project_targets,
    parse_schedule_body,
    tools_for_target,
)
from security_console import db

_HASHER = PasswordHasher()

def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


pytestmark_db = pytest.mark.skipif(
    not _db_ready(),
    reason="console database settings are required for schedule storage tests",
)


def test_parse_schedule_rejects_bad_interval() -> None:
    parsed, error = parse_schedule_body({"enabled": True, "interval_days": 0})
    assert parsed is None
    assert "Interval" in error

    parsed, error = parse_schedule_body({"enabled": True, "interval_days": 91})
    assert parsed is None
    assert "Interval" in error


def test_parse_schedule_rejects_unknown_tools() -> None:
    parsed, error = parse_schedule_body(
        {"enabled": True, "interval_days": 7, "tools": ["semgrep", "nuke"]}
    )
    assert parsed is None
    assert "tools" in error.lower()


def test_parse_schedule_accepts_valid_body() -> None:
    parsed, error = parse_schedule_body(
        {
            "enabled": False,
            "interval_days": 14,
            "tools": ["semgrep", "semgrep", "trivy"],
        }
    )
    assert error == ""
    assert parsed == {
        "enabled": False,
        "interval_days": 14,
        "tools": ["semgrep", "trivy"],
    }


def test_tools_for_target_filters_by_kind() -> None:
    assert tools_for_target("image", ["semgrep", "trivy"]) == ["trivy"]
    assert tools_for_target("image", []) == ["trivy"]
    assert tools_for_target("repo", ["trivy", "semgrep"]) == ["semgrep"]
    assert tools_for_target("repo", []) == ["semgrep", "checkov", "sonar"]


@pytest.fixture()
def schedule_client() -> FlaskClient:
    if not _db_ready():
        pytest.skip("console database settings are required")
    prepare_database()
    prepare_auth()
    reset_auth_tables()
    reset_scan_table()
    reset_schedule_table()
    insert_user(
        "boss",
        _HASHER.hash("boss-password"),
        "admin",
        capabilities={"projects.manage_all": True},
    )
    insert_user("viewer", _HASHER.hash("viewer-password"), "viewer")
    insert_user("dev", _HASHER.hash("dev-password"), "developer")
    insert_project(
        slug="alpha",
        name="Alpha",
        description="",
        created_by=1,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/alpha.git",
                "key": "repo:https://example.com/alpha.git",
            },
            {
                "kind": "image",
                "target": "nginx:1.27",
                "key": "image:nginx:1.27",
            },
        ],
        group_ids=[],
    )
    scans: dict = {}
    lock = threading.Lock()

    def save(item: dict) -> None:
        db.upsert_scan(item)

    def utcnow() -> str:
        return "2026-11-01 12:00:00 UTC"

    bind_schedule_store(lock, scans, save, utcnow)
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    app.extensions["schedule_scans"] = scans
    client = app.test_client()
    client.scans = scans  # type: ignore[attr-defined]
    yield client
    reset_schedule_table()
    reset_scan_table()
    # Leave projects/users for next fixture reset_auth_tables CASCADE.


def _login(client: FlaskClient, username: str, password: str) -> TestResponse:
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def _csrf(login: TestResponse) -> str:
    for raw in login.headers.getlist("Set-Cookie"):
        if raw.startswith("csrf_token="):
            return raw.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError("csrf cookie missing")


@pytestmark_db
def test_viewer_cannot_list_schedules(schedule_client: FlaskClient) -> None:
    login = _login(schedule_client, "viewer", "viewer-password")
    response = schedule_client.get("/api/schedules")
    assert login.status_code == 200
    assert response.status_code == 403


@pytestmark_db
def test_developer_without_cap_cannot_upsert(schedule_client: FlaskClient) -> None:
    login = _login(schedule_client, "dev", "dev-password")
    csrf = _csrf(login)
    response = schedule_client.put(
        "/api/schedules/alpha",
        json={"enabled": True, "interval_days": 7, "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403


@pytestmark_db
def test_manager_upserts_lists_and_rejects_bad_interval(
    schedule_client: FlaskClient,
) -> None:
    login = _login(schedule_client, "boss", "boss-password")
    csrf = _csrf(login)
    bad = schedule_client.put(
        "/api/schedules/alpha",
        json={"enabled": True, "interval_days": 0, "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert bad.status_code == 400

    missing = schedule_client.put(
        "/api/schedules/nope",
        json={"enabled": True, "interval_days": 7, "tools": ["semgrep"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert missing.status_code == 404

    ok = schedule_client.put(
        "/api/schedules/alpha",
        json={
            "enabled": True,
            "interval_days": 7,
            "tools": ["semgrep", "trivy"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert ok.status_code == 200
    body = ok.get_json()
    assert body["project_slug"] == "alpha"
    assert body["interval_days"] == 7
    assert body["enabled"] is True

    listed = schedule_client.get("/api/schedules")
    assert listed.status_code == 200
    rows = listed.get_json()
    assert len(rows) == 1
    assert rows[0]["project_slug"] == "alpha"


@pytestmark_db
def test_run_now_enqueues_all_targets(schedule_client: FlaskClient) -> None:
    login = _login(schedule_client, "boss", "boss-password")
    csrf = _csrf(login)
    schedule_client.put(
        "/api/schedules/alpha",
        json={
            "enabled": True,
            "interval_days": 3,
            "tools": ["semgrep", "trivy"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    response = schedule_client.post(
        "/api/schedules/alpha/run",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 202
    body = response.get_json()
    assert body["enqueued"] == 2
    scans = schedule_client.scans  # type: ignore[attr-defined]
    assert len(scans) == 2
    priorities = {item["priority"] for item in scans.values()}
    assert priorities == {-1}
    owners = {item["owner"] for item in scans.values()}
    assert owners == {"schedule"}

    again = schedule_client.post(
        "/api/schedules/alpha/run",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert again.status_code == 202
    assert again.get_json()["enqueued"] == 0
    assert again.get_json()["skipped"] == 2


@pytestmark_db
def test_enqueue_skips_busy_and_respects_queue_cap() -> None:
    prepare_database()
    reset_scan_table()
    reset_schedule_table()
    reset_auth_tables()
    uid = insert_user("sched", _HASHER.hash("x"), "admin")
    project = insert_project(
        slug="beta",
        name="Beta",
        description="",
        created_by=uid,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/beta.git",
                "key": "repo:https://example.com/beta.git",
            }
        ],
        group_ids=[],
    )
    scans: dict = {}
    lock = threading.Lock()
    bind_schedule_store(lock, scans, db.upsert_scan, lambda: "2026-11-01 12:00:00 UTC")

    first = enqueue_project_targets(project, ["semgrep"])
    assert first["enqueued"] == 1
    second = enqueue_project_targets(project, ["semgrep"])
    assert second["enqueued"] == 0
    assert second["skipped"] == 1

    # Fill the queue to the cap with foreign queued rows, clear project busy.
    scans.clear()
    reset_scan_table()
    from security_console.queue import QUEUE_CAP

    for index in range(QUEUE_CAP):
        item = {
            "id": f"{index:012x}"[-12:],
            "target": "repo",
            "repo": f"https://example.com/{index}.git",
            "image": "",
            "tools": ["semgrep"],
            "status": "queued",
            "findings": [],
            "sonar": None,
            "phase": "",
            "error": "",
            "created_at": "2026-11-01 12:00:00 UTC",
            "finished_at": "",
            "owner": "other",
            "requested_sha": "",
            "commit_sha": "",
            "failure_reason": "",
            "priority": 0,
        }
        scans[item["id"]] = item
        db.upsert_scan(item)

    capped = enqueue_project_targets(project, ["semgrep"])
    assert capped["enqueued"] == 0
    assert capped["queue_full"] is True

    schedule = db.upsert_project_schedule(
        project_id=int(project["id"]),
        enabled=True,
        interval_days=5,
        tools=["semgrep"],
        user_id=uid,
        reset_next_run=True,
    )
    db.bump_schedule_next_run(
        int(schedule["id"]),
        delay=timedelta(hours=1),
        mark_enqueued=False,
    )
    touched = db.get_schedule_by_project_id(int(project["id"]))
    assert touched is not None
    delete_project(int(project["id"]))
    assert db.get_schedule_by_project_id(int(project["id"])) is None
