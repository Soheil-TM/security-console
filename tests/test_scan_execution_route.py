"""Flask shell route for Scan Execution Center deep-links."""

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
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    module.app.config["TESTING"] = True
    return module.app.test_client()


def test_scans_path_serves_console_shell(client: FlaskClient) -> None:
    response = client.get("/scans/abcdef123456")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Security console" in body or "execution" in body.lower() or "scan-form" in body
    assert "text/html" in (response.content_type or "")


def test_scans_path_rejects_bad_id(client: FlaskClient) -> None:
    assert client.get("/scans/../etc/passwd").status_code in {404, 400, 308, 301}
    bad = client.get("/scans/not-hex-id!!")
    assert bad.status_code == 404
