"""SonarQube site access is separate from the scan summary."""

from __future__ import annotations

import gzip

from security_console.access import access_map, can_open_sonar_ui, can_start_scan
from security_console.sonar_proxy import browser_sonar_path, _unwrap


def test_workspace_is_not_a_scanner() -> None:
    developer = {
        "role": "developer",
        "allow_semgrep": True,
        "allow_checkov": True,
        "allow_sonar": True,
        "allow_trivy": True,
        "allow_sonar_ui": False,
    }
    assert can_open_sonar_ui(developer) is False
    assert access_map(developer)["sonar"] is True
    assert access_map(developer)["sonar_ui"] is False
    assert can_start_scan(developer, ["sonar"]) is True


def test_admin_and_granted_user_can_open_the_site() -> None:
    admin = {"role": "admin"}
    granted = {"role": "viewer", "allow_sonar_ui": True}
    assert can_open_sonar_ui(admin) is True
    assert access_map(admin)["sonar_ui"] is True
    assert can_open_sonar_ui(granted) is True


def test_gzip_body_is_unwrapped_for_the_browser() -> None:
    raw = gzip.compress(b"<!DOCTYPE html><title>SonarQube</title>")
    body, dropped = _unwrap(raw, {"Content-Encoding": "gzip"})
    assert body.startswith(b"<!DOCTYPE html>")
    assert dropped == {"content-encoding"}


def test_local_sonar_urls_stay_on_the_console() -> None:
    assert browser_sonar_path("http://sonarqube:9000/dashboard?id=app") == (
        "/sonar/dashboard?id=app"
    )
    assert browser_sonar_path("http://127.0.0.1:9000/sonar/projects") == (
        "/sonar/projects"
    )
    assert browser_sonar_path("/sonar/issues") == "/sonar/issues"
    assert browser_sonar_path("https://sonar.example.com/projects") == (
        "https://sonar.example.com/projects"
    )
