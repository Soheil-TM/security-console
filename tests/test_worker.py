"""The worker speaks HTTP and does not forward Docker options."""

from __future__ import annotations

from typing import Any

import pytest
from flask.testing import FlaskClient

from security_console import worker


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setenv("SCANNER_TOKEN", "scanner-token-value-24")
    worker._jobs.clear()
    application = worker.create_app()
    application.config["TESTING"] = True
    return application.test_client()


def test_jobs_require_the_scanner_token(client: FlaskClient) -> None:
    rejected = client.post(
        "/v1/jobs",
        json={
            "id": "abc123def456",
            "target": "repo",
            "repo": "https://github.com/org/repo.git",
            "tools": ["semgrep"],
        },
    )
    health = client.get("/health")

    assert rejected.status_code == 401
    assert health.status_code == 200


def test_worker_stores_only_the_approved_job(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def launch(job: dict[str, Any]) -> None:
        seen["job"] = job
        worker._jobs[job["id"]] = {
            "status": "done",
            "phase": "",
            "findings": [],
            "notes": [],
            "sonar": None,
            "error": "",
        }

    monkeypatch.setattr(worker, "start_job", launch)
    response = client.post(
        "/v1/jobs",
        json={
            "id": "abc123def456",
            "target": "image",
            "image": "nginx:1.27",
            "tools": ["trivy"],
            "privileged": True,
            "volumes": {"/var/run/docker.sock": {"bind": "/var/run/docker.sock"}},
        },
        headers={"Authorization": "Bearer scanner-token-value-24"},
    )
    stored = client.get(
        "/v1/jobs/abc123def456",
        headers={"Authorization": "Bearer scanner-token-value-24"},
    )

    assert response.status_code == 202
    assert seen["job"]["image"] == "nginx:1.27"
    assert "privileged" not in seen["job"]
    assert "volumes" not in seen["job"]
    assert stored.status_code == 200
    assert stored.get_json()["status"] == "done"
