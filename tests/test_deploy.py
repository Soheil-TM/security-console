"""Rendered Compose publishes production only on loopback."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _rendered(files: list[str] | None) -> dict[str, Any]:
    command = ["docker", "compose"]
    for name in files or []:
        command.extend(["-f", name])
    command.extend(["config", "--format", "json"])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise AssertionError("compose config was not an object")
    return payload


def _console_ports(document: dict[str, Any]) -> list[dict[str, Any]]:
    services = document.get("services")
    if not isinstance(services, dict):
        raise AssertionError("compose config has no services")
    console = services.get("console")
    if not isinstance(console, dict):
        raise AssertionError("compose config has no console service")
    ports = console.get("ports") or []
    if not isinstance(ports, list):
        raise AssertionError("console ports were not a list")
    return [port for port in ports if isinstance(port, dict)]


def test_development_compose_publishes_the_console() -> None:
    ports = _console_ports(_rendered(None))

    assert ports == [
        {
            "mode": "ingress",
            "target": 8080,
            "published": "8091",
            "protocol": "tcp",
        }
    ]


def test_production_port_override_replaces_the_public_publish() -> None:
    ports = _console_ports(
        _rendered(["docker-compose.yml", "docker-compose.production.yml"])
    )

    assert ports == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8080,
            "published": "8091",
            "protocol": "tcp",
        }
    ]
    scanner = _rendered(
        ["docker-compose.yml", "docker-compose.production.yml"]
    )["services"]["scanner"]
    assert not scanner.get("ports")


def _service(name: str) -> dict[str, Any]:
    return _rendered(None)["services"][name]


def test_sonar_init_does_not_gate_the_scanner() -> None:
    scanner = _service("scanner")
    console = _service("console")
    setup = _service("sonar-init")

    assert "sonar-init" not in (scanner.get("depends_on") or {})
    assert "sonar-init" not in (console.get("depends_on") or {})
    assert setup.get("restart") == "on-failure"
    kernel = _service("host-setup")
    sonar = _service("sonarqube")
    assert kernel.get("privileged") is True
    assert "host-setup" in (sonar.get("depends_on") or {})
    assert "host-setup" not in (scanner.get("depends_on") or {})
    assert "host-setup" not in (console.get("depends_on") or {})
    token_mounts = [
        item
        for item in scanner.get("volumes") or []
        if isinstance(item, dict) and item.get("target") == "/run/sonar/token"
    ]
    assert len(token_mounts) == 1
    assert token_mounts[0].get("read_only") is True
    assert not any(
        str(item.get("source", "")).rstrip("/").endswith("/secrets")
        for item in scanner.get("volumes") or []
        if isinstance(item, dict)
    )
