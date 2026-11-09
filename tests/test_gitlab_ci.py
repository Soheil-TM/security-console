"""GitLab CI auto-provision helpers and CI scan GitLab mode."""

from __future__ import annotations

import os
import threading
import uuid
from unittest.mock import patch

import pytest
from argon2 import PasswordHasher
from flask.testing import FlaskClient

from security_console import db
from security_console.ci_scans import bind_ci_store, reset_ci_rate_limit
from security_console.db import (
    insert_integration,
    insert_project,
    insert_user,
    prepare_database,
    reset_auth_tables,
    reset_scan_table,
)
from security_console.gitlab_ci import (
    UNAVAILABLE,
    clear_resolve_cache,
    normalize_gitlab_base_url,
    resolve_gitlab_project,
    slug_for_gitlab,
)

_HASHER = PasswordHasher()
_CI_TOKEN = "ci-test-token-must-be-long-enough"
_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_BASE = "https://gitlab.example.com"


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


pytestmark_db = pytest.mark.skipif(
    not _db_ready(),
    reason="console database settings are required",
)


def test_normalize_gitlab_base_url() -> None:
    assert normalize_gitlab_base_url("https://gitlab.example.com/") == _BASE
    assert normalize_gitlab_base_url("https://gitlab.example.com") == _BASE
    assert normalize_gitlab_base_url("http://127.0.0.1") is None
    assert normalize_gitlab_base_url("not a url") is None


def test_slug_for_gitlab_stable() -> None:
    a = slug_for_gitlab(_BASE, 42)
    assert a.startswith("gl-")
    assert a.endswith("-42")
    assert a == slug_for_gitlab(_BASE, 42)
    assert a != slug_for_gitlab("https://other.example.com", 42)


def test_resolve_rejects_unknown_instance_without_integration() -> None:
    clear_resolve_cache()
    if not _db_ready():
        pytest.skip("database required")
    prepare_database()
    reset_auth_tables()
    with pytest.raises(Exception) as raised:
        resolve_gitlab_project(
            gitlab_base_url=_BASE,
            gitlab_project_id=1,
            requested_sha=_SHA,
        )
    assert getattr(raised.value, "status", 0) == 403
    assert str(raised.value.message) == UNAVAILABLE


@pytest.fixture()
def ci_client(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    if not _db_ready():
        pytest.skip("console database settings are required")
    monkeypatch.setenv("CONSOLE_ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "0")
    monkeypatch.setenv("CONSOLE_JWT_KEY", "test-jwt-key-must-be-32-characters")
    monkeypatch.setenv("CI_SCAN_TOKEN", _CI_TOKEN)
    monkeypatch.setenv("GATE_TOKEN", "gate-token-must-be-long-enough-xx")
    prepare_database()
    from flask import Flask

    from security_console.auth import install_auth, prepare_auth

    prepare_auth()
    reset_auth_tables()
    reset_scan_table()
    reset_ci_rate_limit()
    clear_resolve_cache()
    insert_user("boss", _HASHER.hash("boss-password"), "admin")
    insert_integration(
        "gitlab",
        "gitlab-main-" + uuid.uuid4().hex[:8],
        _BASE,
        "",
        "gitlab-fake-token-for-tests-only",
        "",
    )
    scans: dict = {}
    lock = threading.Lock()

    def save(item: dict) -> None:
        db.upsert_scan(item)

    bind_ci_store(lock, scans, save, lambda: "2026-11-09 12:00:00 UTC")
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    client = app.test_client()
    client.scans_store = scans  # type: ignore[attr-defined]
    return client


def _ci_headers() -> dict[str, str]:
    return {"Authorization": "Bearer " + _CI_TOKEN}


def _fake_project_payload(*, project_id: int = 42, repo: str | None = None) -> dict:
    return {
        "id": project_id,
        "path_with_namespace": "team/app",
        "name_with_namespace": "Team / App",
        "http_url_to_repo": repo or (_BASE + "/team/app.git"),
    }


def _mock_ok(project_id: int = 42, repo: str | None = None):
    payload = _fake_project_payload(project_id=project_id, repo=repo)

    def fake_get(url: str, *, token: str, ca_pem: str):
        if "/repository/commits/" in url:
            return {"id": _SHA} if _SHA in url else None
        if url.rstrip("/").endswith(f"/projects/{project_id}"):
            return payload
        return None

    return fake_get


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gitlab_mode_creates_then_reuses_project(ci_client: FlaskClient) -> None:
    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=_mock_ok(42),
    ):
        first = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE,
                "gitlab_project_id": 42,
                "requested_sha": _SHA,
                "ref": "main",
                "pipeline_id": "9",
                "force": True,
            },
        )
        assert first.status_code == 202, first.get_data(as_text=True)
        body1 = first.get_json()
        assert body1["project_slug"].startswith("gl-")
        assert body1["gitlab"]["project_id"] == 42
        project_id = body1["project_id"]

        second = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE + "/",
                "gitlab_project_id": 42,
                "requested_sha": _SHA,
                "force": True,
            },
        )
        assert second.status_code in {200, 202}, second.get_data(as_text=True)
        body2 = second.get_json()
        assert body2["project_id"] == project_id
        assert body2["project_slug"] == body1["project_slug"]


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gitlab_mode_unknown_host_forbidden(ci_client: FlaskClient) -> None:
    denied = ci_client.post(
        "/api/ci/scans",
        headers=_ci_headers(),
        json={
            "gitlab_base_url": "https://evil.example.net",
            "gitlab_project_id": 1,
            "requested_sha": _SHA,
            "force": True,
        },
    )
    assert denied.status_code == 403
    assert denied.get_json()["error"] == UNAVAILABLE


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gitlab_mode_project_unavailable_opaque(ci_client: FlaskClient) -> None:
    def fake_get(url: str, *, token: str, ca_pem: str):
        return None

    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=fake_get,
    ):
        denied = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE,
                "gitlab_project_id": 40404,
                "requested_sha": _SHA,
                "force": True,
            },
        )
    assert denied.status_code == 403
    assert denied.get_json()["error"] == UNAVAILABLE


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gitlab_mode_forged_url_ignored(ci_client: FlaskClient) -> None:
    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=_mock_ok(42),
    ):
        created = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE,
                "gitlab_project_id": 42,
                "requested_sha": _SHA,
                "repo": "https://evil.example.net/not-used.git",
                "force": True,
            },
        )
    assert created.status_code == 202
    assert created.get_json()["repo"] == _BASE + "/team/app.git"


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gitlab_mode_sha_not_in_project(ci_client: FlaskClient) -> None:
    def fake_get(url: str, *, token: str, ca_pem: str):
        if "/repository/commits/" in url:
            return None
        return _fake_project_payload()

    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=fake_get,
    ):
        bad = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE,
                "gitlab_project_id": 42,
                "requested_sha": _SHA,
                "force": True,
            },
        )
    assert bad.status_code == 400
    assert bad.get_json()["error"] == "Commit SHA is invalid."


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gitlab_mode_ssh_clone_url_rejected(ci_client: FlaskClient) -> None:
    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=_mock_ok(
            55,
            repo="git@gitlab.example.com:team/app.git",
        ),
    ):
        bad = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE,
                "gitlab_project_id": 55,
                "requested_sha": _SHA,
                "force": True,
            },
        )
    assert bad.status_code == 400
    assert "http(s)" in bad.get_json()["error"]


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_gate_token_cannot_call_ci(ci_client: FlaskClient) -> None:
    denied = ci_client.post(
        "/api/ci/scans",
        headers={"Authorization": "Bearer gate-token-must-be-long-enough-xx"},
        json={"project": "anything"},
    )
    assert denied.status_code == 401


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_upsert_concurrency_one_project(ci_client: FlaskClient) -> None:
    from security_console.access import project_key
    from security_console.db import upsert_gitlab_linked_project

    repo = _BASE + "/team/app.git"
    slug = slug_for_gitlab(_BASE, 99)
    key = project_key({"repo": repo, "image": ""})
    results: list[int] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            project = upsert_gitlab_linked_project(
                base_url=_BASE,
                gitlab_project_id=99,
                gitlab_path="team/app",
                name="App",
                repo_url=repo,
                slug=slug,
                target_key=key,
            )
            results.append(int(project["id"]))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert results
    assert len(set(results)) == 1


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_parallel_http_posts_one_project_row(ci_client: FlaskClient) -> None:
    gl_id = 88881
    statuses: list[int] = []
    project_ids: list[int] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with patch(
                "security_console.gitlab_ci._gitlab_get_json",
                side_effect=_mock_ok(gl_id),
            ):
                resp = ci_client.post(
                    "/api/ci/scans",
                    headers=_ci_headers(),
                    json={
                        "gitlab_base_url": _BASE,
                        "gitlab_project_id": gl_id,
                        "requested_sha": _SHA,
                        "force": True,
                    },
                )
            statuses.append(resp.status_code)
            if resp.status_code in {200, 202}:
                project_ids.append(int(resp.get_json()["project_id"]))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert project_ids
    assert len(set(project_ids)) == 1
    assert all(code in {200, 202} for code in statuses)
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT project_id FROM project_gitlab_links
            WHERE gitlab_base_url = %s AND gitlab_project_id = %s
            """,
            (_BASE, gl_id),
        ).fetchall()
        conn.commit()
    assert len(rows) == 1


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_ci_rate_limit_global_and_per_project(
    ci_client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import security_console.ci_scans as ci_mod

    monkeypatch.setattr(ci_mod, "_CI_RATE_LIMIT", 3)
    monkeypatch.setattr(ci_mod, "_CI_RATE_PROJECT_LIMIT", 2)
    reset_ci_rate_limit()

    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=_mock_ok(71),
    ):
        codes = []
        for _ in range(4):
            resp = ci_client.post(
                "/api/ci/scans",
                headers=_ci_headers(),
                json={
                    "gitlab_base_url": _BASE,
                    "gitlab_project_id": 71,
                    "requested_sha": _SHA,
                    "force": True,
                },
            )
            codes.append(resp.status_code)
    # Per-project limit 2: third request for same project is 429 (global still 3).
    assert codes[0] in {200, 202}
    assert codes[1] in {200, 202}
    assert codes[2] == 429

    reset_ci_rate_limit()
    monkeypatch.setattr(ci_mod, "_CI_RATE_LIMIT", 2)
    monkeypatch.setattr(ci_mod, "_CI_RATE_PROJECT_LIMIT", 50)
    uid = insert_user("rl", _HASHER.hash("rl-password"), "admin")
    insert_project(
        slug="rate-legacy",
        name="Rate Legacy",
        description="",
        created_by=uid,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/rate.git",
                "key": "https://example.com/rate",
            }
        ],
        group_ids=[],
    )
    slug_codes = []
    for _ in range(3):
        resp = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "project": "rate-legacy",
                "target": "repo",
                "requested_sha": _SHA,
                "force": True,
            },
        )
        slug_codes.append(resp.status_code)
    assert slug_codes[0] in {200, 202}
    assert slug_codes[1] in {200, 202}
    assert slug_codes[2] == 429


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_ci_api_e2e_policy_fail_critical(ci_client: FlaskClient) -> None:
    from security_console import ci_scans as ci_mod

    with patch(
        "security_console.gitlab_ci._gitlab_get_json",
        side_effect=_mock_ok(66),
    ):
        created = ci_client.post(
            "/api/ci/scans",
            headers=_ci_headers(),
            json={
                "gitlab_base_url": _BASE,
                "gitlab_project_id": 66,
                "requested_sha": _SHA,
                "force": True,
            },
        )
    assert created.status_code == 202, created.get_data(as_text=True)
    scan_id = created.get_json()["id"]
    assert ci_mod._lock is not None and ci_mod._scans is not None
    with ci_mod._lock:
        item = ci_mod._scans[scan_id]
        item["status"] = "done"
        item["finished_at"] = "2026-11-09 12:01:00 UTC"
        item["tool_results"] = [
            {"tool": "semgrep", "status": "ok"},
            {"tool": "checkov", "status": "ok"},
            {"tool": "sonar", "status": "ok"},
            {"tool": "trivy", "status": "ok"},
        ]
        item["findings"] = [
            {
                "tool": "semgrep",
                "severity": "CRITICAL",
                "check": "x",
                "path": "a.py",
                "message": "bad",
            }
        ]
        if ci_mod._save is not None:
            ci_mod._save(item)

    polled = ci_client.get("/api/ci/scans/" + scan_id, headers=_ci_headers())
    assert polled.status_code == 200
    body = polled.get_json()
    assert body["policy"]["pending"] is False
    assert body["policy"]["passed"] is False
    assert "severity_critical" in body["policy"]["reasons"]


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_legacy_slug_mode_still_works(ci_client: FlaskClient) -> None:
    uid = insert_user("lead", _HASHER.hash("lead-password"), "admin")
    insert_project(
        slug="legacy",
        name="Legacy",
        description="",
        created_by=uid,
        targets=[
            {
                "kind": "repo",
                "target": "https://example.com/legacy.git",
                "key": "https://example.com/legacy",
            }
        ],
        group_ids=[],
    )
    created = ci_client.post(
        "/api/ci/scans",
        headers=_ci_headers(),
        json={
            "project": "legacy",
            "target": "repo",
            "requested_sha": _SHA,
            "force": True,
        },
    )
    assert created.status_code == 202, created.get_data(as_text=True)
    assert created.get_json()["project_slug"] == "legacy"
