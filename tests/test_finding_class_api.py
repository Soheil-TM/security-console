"""HTTP contract for PUT/DELETE /api/security/finding-class."""

from __future__ import annotations

import os

import pytest
from argon2 import PasswordHasher
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from security_console import db
from security_console.auth import install_auth, prepare_auth
from security_console.db import (
    insert_group,
    insert_project,
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
    upsert_scan,
)
from security_console.risk import finding_key

_HASHER = PasswordHasher()

FINDING = {
    "tool": "semgrep",
    "check": "rule.x",
    "path": "app.py",
    "line": 10,
    "severity": "HIGH",
}
FINDING_KEY = finding_key(FINDING)
REASON = "Tracked as quality debt in the backlog."


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


pytestmark = pytest.mark.skipif(
    not _db_ready(),
    reason="console database settings are required for finding-class API tests",
)


@pytest.fixture()
def class_client() -> FlaskClient:
    prepare_database()
    prepare_auth()
    reset_auth_tables()
    reset_scan_table()

    admin_id = insert_user(
        "boss",
        _HASHER.hash("boss-password"),
        "admin",
        capabilities={"projects.manage_all": True},
        allow_semgrep=True,
    )
    insert_user(
        "outsider",
        _HASHER.hash("outsider-password"),
        "developer",
        allow_semgrep=True,
    )
    project = insert_project(
        slug="class-demo",
        name="Class Demo",
        description="",
        created_by=admin_id,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/class-demo.git",
                "key": "repo:https://example.com/class-demo.git",
            }
        ],
        group_ids=[],
    )
    insert_group(
        "Class Team",
        "",
        admin_id,
        [int(project["id"])],
        [(admin_id, True)],
        "boss",
        "seed",
    )
    upsert_scan(
        {
            "id": "scan-class-1",
            "target": "repo",
            "repo": "https://example.com/class-demo.git",
            "project_id": int(project["id"]),
            "tools": ["semgrep"],
            "status": "done",
            "owner": "boss",
            "findings": [FINDING],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
        }
    )

    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    client = app.test_client()
    yield client
    reset_scan_table()
    reset_auth_tables()


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


def test_finding_class_rejects_short_reason(class_client: FlaskClient) -> None:
    login = _login(class_client, "boss", "boss-password")
    assert login.status_code == 200
    csrf = _csrf(login)
    response = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "quality",
            "reason": "short",
        },
    )
    assert response.status_code == 400
    assert "12" in response.get_json()["error"]
    assert FINDING_KEY not in db.list_class_overrides("class-demo")


def test_finding_class_override_and_clear(class_client: FlaskClient) -> None:
    login = _login(class_client, "boss", "boss-password")
    assert login.status_code == 200
    csrf = _csrf(login)

    response = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "quality",
            "reason": REASON,
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["override"]["finding_class"] == "quality"
    assert body["readiness"]["excluded_quality"] >= 1
    stored = db.list_class_overrides("class-demo")[FINDING_KEY]
    assert stored["finding_class"] == "quality"
    events = db.list_class_override_events("class-demo", [FINDING_KEY])[FINDING_KEY]
    assert events[0]["new_class"] == "quality"

    clear = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "auto",
            "reason": "Return to classifier default now.",
        },
    )
    assert clear.status_code == 200
    assert clear.get_json()["override"] is None
    assert FINDING_KEY not in db.list_class_overrides("class-demo")
    events = db.list_class_override_events("class-demo", [FINDING_KEY])[FINDING_KEY]
    assert events[0]["new_class"] == ""


def test_finding_class_denied_for_outsider(class_client: FlaskClient) -> None:
    login = _login(class_client, "outsider", "outsider-password")
    assert login.status_code == 200
    csrf = _csrf(login)
    response = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "quality",
            "reason": REASON,
        },
    )
    assert response.status_code == 403
    assert FINDING_KEY not in db.list_class_overrides("class-demo")
