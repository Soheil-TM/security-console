"""Fail-closed overrides, atomic audit, concurrency, and DELETE contract."""

from __future__ import annotations

import os
import threading
from typing import Any
from unittest.mock import patch

import psycopg
import pytest
from argon2 import PasswordHasher
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from security_console import db
from security_console.access import present_scan
from security_console.auth import install_auth, prepare_auth
from security_console.classify import ClassOverridesUnavailable, enrich_findings
from security_console.db import (
    insert_group,
    insert_project,
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
    upsert_scan,
)
from security_console.fingerprint import (
    compute_risk_fingerprint,
    current_gate_scope_keys,
    risk_acceptance_still_valid,
)
from security_console.investigate import allowed_findings, gate_readiness
from security_console.risk import _findings_for_gate_verify, finding_key

_HASHER = PasswordHasher()
_ADMIN_ID = 0

FINDING = {
    "tool": "semgrep",
    "check": "rule.x",
    "path": "app.py",
    "line": 10,
    "severity": "HIGH",
}
FINDING_KEY = finding_key(FINDING)
REASON = "Tracked as quality debt in the backlog."
SONAR_SMELL = {
    "tool": "sonar",
    "check": "python:S125",
    "path": "a.py",
    "line": 1,
    "severity": "MAJOR",
    "sonar_type": "CODE_SMELL",
    "message": "Remove this commented-out code.",
}


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


pytestmark = pytest.mark.skipif(
    not _db_ready(),
    reason="console database settings are required for override integrity tests",
)


@pytest.fixture()
def class_client() -> FlaskClient:
    prepare_database()
    prepare_auth()
    reset_auth_tables()
    reset_scan_table()

    global _ADMIN_ID
    admin_id = insert_user(
        "boss",
        _HASHER.hash("boss-password"),
        "admin",
        capabilities={"projects.manage_all": True},
        allow_semgrep=True,
        allow_sonar=True,
    )
    _ADMIN_ID = int(admin_id)
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
            "project_slug": "class-demo",
            "tools": ["semgrep", "sonar"],
            "status": "done",
            "owner": "boss",
            "findings": [FINDING, SONAR_SMELL],
            "tool_results": [
                {"tool": "semgrep", "status": "ok"},
                {"tool": "sonar", "status": "ok"},
            ],
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


def test_delete_finding_class_requires_valid_reason(class_client: FlaskClient) -> None:
    login = _login(class_client, "boss", "boss-password")
    csrf = _csrf(login)
    class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "quality",
            "reason": REASON,
        },
    )
    bad = class_client.delete(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "reason": "short",
        },
    )
    assert bad.status_code == 400
    assert FINDING_KEY in db.list_class_overrides("class-demo")

    ok = class_client.delete(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "reason": "Clear override after triage review.",
        },
    )
    assert ok.status_code == 200
    assert FINDING_KEY not in db.list_class_overrides("class-demo")
    events = db.list_class_override_events("class-demo", [FINDING_KEY])[FINDING_KEY]
    assert events[0]["previous_class"] == "quality"
    assert events[0]["new_class"] == ""


def test_override_then_clear_history_previous_new(class_client: FlaskClient) -> None:
    login = _login(class_client, "boss", "boss-password")
    csrf = _csrf(login)
    first = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "quality",
            "reason": REASON,
        },
    )
    assert first.status_code == 200
    second = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "operational",
            "reason": "Reclass to operational after review.",
        },
    )
    assert second.status_code == 200
    events = db.list_class_override_events("class-demo", [FINDING_KEY])[FINDING_KEY]
    assert events[0]["previous_class"] == "quality"
    assert events[0]["new_class"] == "operational"
    assert events[1]["previous_class"] == "security"
    assert events[1]["new_class"] == "quality"


def test_concurrent_override_writers_preserve_ordered_history(
    class_client: FlaskClient,
) -> None:
    login = _login(class_client, "boss", "boss-password")
    assert login.status_code == 200
    errors: list[BaseException] = []

    def writer(finding_class: str, reason: str) -> None:
        try:
            db.upsert_class_override(
                project_key="class-demo",
                finding_key=FINDING_KEY,
                finding_class=finding_class,
                reason=reason,
                updated_by="boss",
                updated_by_user_id=_ADMIN_ID,
                scan_id="scan-class-1",
                baseline_class="security",
            )
        except BaseException as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    threads = [
        threading.Thread(
            target=writer,
            args=("quality", "First concurrent quality override."),
        ),
        threading.Thread(
            target=writer,
            args=("operational", "Second concurrent operational override."),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    stored = db.list_class_overrides("class-demo")[FINDING_KEY]
    assert stored["finding_class"] in {"quality", "operational"}
    events = db.list_class_override_events("class-demo", [FINDING_KEY])[FINDING_KEY]
    assert len(events) >= 2
    # Newest event must start from the class written by the earlier event.
    assert events[0]["previous_class"] == events[1]["new_class"]


def test_audit_failure_rolls_back_override(class_client: FlaskClient) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise psycopg.OperationalError("audit insert failed")

    with (
        patch("security_console.db._insert_audit_on_conn", side_effect=boom),
        pytest.raises(psycopg.OperationalError),
    ):
        db.upsert_class_override(
            project_key="class-demo",
            finding_key=FINDING_KEY,
            finding_class="quality",
            reason=REASON,
            updated_by="boss",
            updated_by_user_id=_ADMIN_ID,
            scan_id="scan-class-1",
            baseline_class="security",
        )
    assert FINDING_KEY not in db.list_class_overrides("class-demo")
    assert not db.list_class_override_events("class-demo", [FINDING_KEY]).get(
        FINDING_KEY
    )


def test_investigate_override_load_failure_returns_503(
    class_client: FlaskClient,
) -> None:
    login = _login(class_client, "boss", "boss-password")
    assert login.status_code == 200
    with patch(
        "security_console.investigate.load_class_overrides",
        side_effect=ClassOverridesUnavailable("down"),
    ):
        response = class_client.get("/api/security/investigate?scan=scan-class-1")
    assert response.status_code == 503


def test_allowed_findings_raises_when_overrides_unavailable(
    class_client: FlaskClient,
) -> None:
    scan = db.get_scan_row("scan-class-1")
    assert scan is not None
    user = {"role": "admin", "username": "boss", "id": 1, "allow_semgrep": True}
    with patch(
        "security_console.investigate.load_class_overrides",
        side_effect=ClassOverridesUnavailable("down"),
    ), pytest.raises(ClassOverridesUnavailable):
        allowed_findings(user, scan)


def test_gate_verify_denies_when_overrides_unavailable(
    class_client: FlaskClient,
) -> None:
    scan = db.get_scan_row("scan-class-1")
    assert scan is not None
    with patch(
        "security_console.classify.load_class_overrides",
        side_effect=ClassOverridesUnavailable("down"),
    ):
        assert _findings_for_gate_verify(scan, "class-demo") is None


def test_present_scan_flags_overrides_unavailable(class_client: FlaskClient) -> None:
    scan = db.get_scan_row("scan-class-1")
    assert scan is not None
    admin = {
        "role": "admin",
        "username": "boss",
        "id": _ADMIN_ID,
        "capabilities": {"projects.manage_all": True},
    }
    with patch(
        "security_console.classify.load_class_overrides",
        side_effect=ClassOverridesUnavailable("down"),
    ):
        shown = present_scan(admin, scan, summary=False)
    assert shown is not None
    assert shown["class_overrides_available"] is False


def test_sonar_code_smell_override_to_security_changes_scope(
    class_client: FlaskClient,
) -> None:
    smell_key = finding_key(SONAR_SMELL)
    raw = enrich_findings([SONAR_SMELL])
    assert smell_key not in current_gate_scope_keys(raw)
    overridden = enrich_findings(
        [SONAR_SMELL],
        overrides={
            smell_key: {
                "finding_class": "security",
                "reason": "Security-relevant smell.",
                "updated_by": "boss",
            }
        },
    )
    assert smell_key in current_gate_scope_keys(overridden)
    assert gate_readiness(overridden, {})["ready_for_gate"] is False


def test_server_enriched_sonar_class_matches_override(
    class_client: FlaskClient,
) -> None:
    smell_key = finding_key(SONAR_SMELL)
    db.upsert_class_override(
        project_key="class-demo",
        finding_key=smell_key,
        finding_class="security",
        reason="Promote CODE_SMELL to security class.",
        updated_by="boss",
        updated_by_user_id=_ADMIN_ID,
        scan_id="scan-class-1",
        baseline_class="quality",
    )
    scan = db.get_scan_row("scan-class-1")
    assert scan is not None
    admin = {
        "role": "admin",
        "username": "boss",
        "id": _ADMIN_ID,
        "capabilities": {"projects.manage_all": True},
        "allow_semgrep": True,
        "allow_sonar": True,
    }
    shown = present_scan(admin, scan, summary=False)
    assert shown is not None
    assert shown["class_overrides_available"] is True
    row = next(item for item in shown["findings"] if finding_key(item) == smell_key)
    assert row["finding_class"] == "security"
    assert row["classification_source"] == "manual"


def test_optimistic_concurrency_conflict(class_client: FlaskClient) -> None:
    login = _login(class_client, "boss", "boss-password")
    csrf = _csrf(login)
    first = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "quality",
            "reason": REASON,
        },
    )
    assert first.status_code == 200
    conflict = class_client.put(
        "/api/security/finding-class",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        json={
            "scan_id": "scan-class-1",
            "finding_key": FINDING_KEY,
            "finding_class": "operational",
            "reason": "Should conflict on stale stamp.",
            "if_updated_at": "2000-01-01 00:00:00 UTC",
        },
    )
    assert conflict.status_code == 409
    stored = db.list_class_overrides("class-demo")[FINDING_KEY]
    assert stored["finding_class"] == "quality"


def test_empty_acceptance_still_valid_when_unchanged() -> None:
    quality = {
        "tool": "sonar",
        "check": "python:S125",
        "path": "a.py",
        "line": 1,
        "sonar_type": "CODE_SMELL",
    }
    findings = enrich_findings([quality])
    fingerprint = compute_risk_fingerprint(
        project_key="payments-api",
        commit_sha="abc123def",
        finding_keys=[],
        dispositions={},
    )
    assert risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key="payments-api",
        commit_sha="abc123def",
        snapshot={},
        current_findings=findings,
        dispositions={},
    )


def test_risk_accept_returns_503_when_overrides_unavailable(
    class_client: FlaskClient,
) -> None:
    login = _login(class_client, "boss", "boss-password")
    csrf = _csrf(login)
    with patch(
        "security_console.investigate.load_class_overrides",
        side_effect=ClassOverridesUnavailable("down"),
    ):
        response = class_client.post(
            "/api/security/acceptances",
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
            json={
                "baseline_scan_id": "scan-class-1",
                "current_scan_id": "scan-class-1",
                "reason": "Accept residual risk for this push.",
            },
        )
    assert response.status_code == 503
