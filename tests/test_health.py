"""Console liveness probe."""

from __future__ import annotations

import importlib
import os
import sys

import pytest
from flask.testing import FlaskClient


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setenv("CONSOLE_SKIP_BOOT", "1")
    monkeypatch.setenv("CONSOLE_ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "0")
    monkeypatch.setenv("CONSOLE_JWT_KEY", "test-jwt-key-must-be-32-characters")
    # Fresh import so boot() is skipped under CONSOLE_SKIP_BOOT.
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    module.app.config["TESTING"] = True
    return module.app.test_client()


def test_health_returns_ok(client: FlaskClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"ok": True}
