"""HTTP contract for PUT /api/security/dispositions."""

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
NOTE = "Assigned for peer review."


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


pytestmark = pytest.mark.skipif(
    not _db_ready(),
    reason="console database settings are required for disposition API tests",
)


@pytest.fixture()
def disposition_client() -> FlaskClient:
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
    reviewer_id = insert_user(
        "sadmin",
        _HASHER.hash("reviewer-password"),
        "developer",
        allow_semgrep=True,
    )
    insert_user(
        "outsider",
        _HASHER.hash("outsider-password"),
        "developer",
        allow_semgrep=True,
    )
    project = insert_project(
        slug="triage-demo",
        name="Triage Demo",
        description="",
        created_by=admin_id,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/triage-demo.git",
                "key": "repo:https://example.com/triage-demo.git",
            }
        ],
        group_ids=[],
    )
    insert_group(
        "Triage Team",
        "",
        admin_id,
        [int(project["id"])],
        [(reviewer_id, False), (admin_id, True)],
        "boss",
        "seed",
    )
    upsert_scan(
        {
            "id": "scan-triage-1",
            "target": "repo",
            "repo": "https://example.com/triage-demo.git",
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


def _put_disposition(
    client: FlaskClient,
    csrf: str,
    *,
    status: str,
    reason: str,
    assignee: str = "",
) -> TestResponse:
    return client.put(
        "/api/security/dispositions",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-triage-1",
            "finding_key": FINDING_KEY,
            "status": status,
            "reason": reason,
            "assignee_username": assignee,
        },
    )


def test_disposition_rejects_short_reason(disposition_client: FlaskClient) -> None:
    login = _login(disposition_client, "boss", "boss-password")
    assert login.status_code == 200
    csrf = _csrf(login)

    response = _put_disposition(
        disposition_client,
        csrf,
        status="needs_review",
        reason="too-short",
        assignee="sadmin",
    )

    assert response.status_code == 400
    assert "12" in response.get_json()["error"]
    assert FINDING_KEY not in db.list_dispositions("triage-demo")


def test_disposition_needs_review_with_project_assignee(
    disposition_client: FlaskClient,
) -> None:
    login = _login(disposition_client, "boss", "boss-password")
    assert login.status_code == 200
    csrf = _csrf(login)

    response = _put_disposition(
        disposition_client,
        csrf,
        status="needs_review",
        reason=NOTE,
        assignee="sadmin",
    )

    assert response.status_code == 200
    body = response.get_json()
    disposition = body["disposition"]
    assert disposition["status"] == "needs_review"
    assert disposition["assignee_username"] == "sadmin"
    assert disposition["reason"] == NOTE
    stored = db.list_dispositions("triage-demo")[FINDING_KEY]
    assert stored["status"] == "needs_review"
    assert stored["assignee_username"] == "sadmin"


def test_disposition_rejects_assignee_outside_project_group(
    disposition_client: FlaskClient,
) -> None:
    login = _login(disposition_client, "boss", "boss-password")
    assert login.status_code == 200
    csrf = _csrf(login)

    response = _put_disposition(
        disposition_client,
        csrf,
        status="needs_review",
        reason=NOTE,
        assignee="outsider",
    )

    assert response.status_code == 400
    assert "project group" in response.get_json()["error"]
    assert FINDING_KEY not in db.list_dispositions("triage-demo")
