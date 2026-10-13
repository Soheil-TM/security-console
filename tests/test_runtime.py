"""Scanner containers cannot be steered into a privileged Docker call."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from security_console.runtime import (
    SEMGREP_IMAGE,
    TRIVY_CACHE_VOLUME,
    TRIVY_IMAGE,
    TRIVY_JAVA_REPOSITORIES,
    TRIVY_VULN_REPOSITORIES,
    filesystem_spec,
    scanner_network,
    sonar_spec,
    trivy_db_update_spec,
    trivy_image_spec,
    uses_docker_socket,
)


def _flat(spec: dict[str, Any]) -> str:
    return json.dumps(spec)


def test_repository_scanners_drop_privileges_and_hide_the_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SCANNER_NETWORK", raising=False)
    monkeypatch.delenv("SCANNER_FORCE_ROOT", raising=False)
    monkeypatch.delenv("SCANNER_MEM_MB", raising=False)
    spec = filesystem_spec("semgrep", "/var/lib/security-scans/abc123def456")

    assert spec["image"] == SEMGREP_IMAGE
    assert spec["user"] == "65534:65534"
    assert spec["privileged"] is False
    assert spec["cap_drop"] == ["ALL"]
    assert spec["security_opt"] == ["no-new-privileges:true"]
    assert spec["read_only"] is True
    assert spec["network_mode"] == "bridge"
    assert spec["pids_limit"] == 512
    assert uses_docker_socket(spec) is False
    assert "SONAR_TOKEN" not in spec["environment"]
    assert "CONSOLE_JWT_KEY" not in spec["environment"]


def test_trivy_image_scan_never_mounts_the_docker_socket() -> None:
    remote = trivy_image_spec(
        "nginx:1.27",
        archive_host_path=None,
        tmp_host_path="/var/lib/security-scans/abc123def456/tmp",
    )
    local = trivy_image_spec(
        "nginx:1.27",
        archive_host_path="/var/lib/security-scans/abc123def456/image.tar",
        tmp_host_path="/var/lib/security-scans/abc123def456/tmp",
    )

    assert remote["image"] == TRIVY_IMAGE
    assert "nginx:1.27" in remote["command"]
    assert "--image-src" in remote["command"]
    assert "remote" in remote["command"]
    assert "--input" in local["command"]
    assert uses_docker_socket(remote) is False
    assert uses_docker_socket(local) is False
    assert "docker.sock" not in _flat(remote)
    assert "docker.sock" not in _flat(local)
    assert local["privileged"] is False
    assert local["network_mode"] != "host"
    filesystem = filesystem_spec("trivy", "/var/lib/security-scans/abc")
    for spec in (remote, local, filesystem):
        assert "--skip-db-update" in spec["command"]
        assert "--skip-java-db-update" in spec["command"]
        assert spec["volumes"][TRIVY_CACHE_VOLUME] == {"bind": "/cache", "mode": "rw"}
        assert "--download-db-only" not in spec["command"]
    tmp = "/var/lib/security-scans/abc123def456/tmp"
    for spec in (remote, local):
        assert spec["volumes"][tmp] == {"bind": "/tmp", "mode": "rw"}
        assert "/tmp" not in spec["tmpfs"]
        assert spec["tmpfs"]["/root"].startswith("rw,nosuid,nodev")
    assert filesystem["tmpfs"]["/tmp"] == "rw,nosuid,nodev,size=256m"
    with pytest.raises(RuntimeError, match="temporary directory"):
        trivy_image_spec(
            "nginx:1.27",
            archive_host_path=None,
            tmp_host_path="/var/lib/security-scans/abc/../../etc",
        )


def test_trivy_database_update_uses_only_official_mirrors() -> None:
    vuln = trivy_db_update_spec("vuln", TRIVY_VULN_REPOSITORIES[0])
    java = trivy_db_update_spec("java", TRIVY_JAVA_REPOSITORIES[0])

    assert vuln["command"][vuln["command"].index("--db-repository") + 1] == (
        "ghcr.io/aquasecurity/trivy-db:2"
    )
    assert java["command"][java["command"].index("--java-db-repository") + 1] == (
        "ghcr.io/aquasecurity/trivy-java-db:1"
    )
    assert vuln["volumes"] == {
        TRIVY_CACHE_VOLUME: {"bind": "/cache", "mode": "rw"}
    }
    assert "--timeout" in vuln["command"]
    assert "30s" in vuln["command"]
    assert uses_docker_socket(vuln) is False
    assert vuln["read_only"] is True
    assert vuln["privileged"] is False

    with pytest.raises(RuntimeError, match="not approved"):
        trivy_db_update_spec("vuln", "example.com/trivy-db:2")
    with pytest.raises(RuntimeError, match="not approved"):
        trivy_db_update_spec("other", TRIVY_VULN_REPOSITORIES[0])


def test_sonar_receives_only_its_own_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_DB_PASSWORD", "db-secret")
    spec = sonar_spec(
        "/var/lib/security-scans/abc123def456",
        project_key="demo",
        host_url="https://sonar.example",
        token_file="/var/lib/security-scans/.abc123def456-sonar/token",
    )

    rendered = json.dumps(spec)
    assert "SONAR_TOKEN" not in spec["environment"]
    assert spec["environment"]["SONAR_TOKEN_FILE"] == "/run/secrets/sonar_token"
    assert "CONSOLE_DB_PASSWORD" not in spec["environment"]
    assert "sonar-token" not in rendered
    assert "db-secret" not in rendered
    mount = spec["volumes"]["/var/lib/security-scans/.abc123def456-sonar/token"]
    assert mount == {"bind": "/run/secrets/sonar_token", "mode": "ro"}
    assert spec["entrypoint"][0] == "/bin/sh"
    assert "export SONAR_TOKEN" in spec["entrypoint"][2]
    for pinned in (
        "-Dsonar.host.url=https://sonar.example",
        "-Dsonar.scanner.proxyHost=",
        "-Dsonar.scanner.proxyPort=",
        "-Dsonar.scanner.proxyUser=",
        "-Dsonar.scanner.proxyPassword=",
        "-Dsonar.scanner.javaOpts=-Xmx384m",
        "-Dsonar.scanner.truststorePath=/tmp/sonar-truststore",
        "-Dsonar.scanner.truststorePassword=changeit",
        "-Dsonar.scanner.keystorePath=/tmp/sonar-client.p12",
        "-Dsonar.scanner.keystorePassword=unused-store",
        "-Dsonar.working.directory=/tmp/.scannerwork",
    ):
        assert pinned in spec["command"]
    assert spec["volumes"]["/var/lib/security-scans/abc123def456"]["mode"] == "ro"
    assert "cp \"$trust_src\" /tmp/sonar-truststore" in spec["entrypoint"][2]
    assert "-Dsonar.scanner.truststorePath=" not in spec["command"]
    assert "-Dsonar.scanner.keystorePath=" not in spec["command"]
    assert "sonar.token" not in " ".join(spec["command"])
    assert spec["cap_drop"] == ["ALL"]
    assert uses_docker_socket(spec) is False


def test_host_network_is_rewritten_to_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SCANNER_NETWORK", "host")
    assert scanner_network() == "bridge"

    monkeypatch.setenv("SCANNER_NETWORK", "scanners")
    assert scanner_network() == "scanners"

    monkeypatch.setenv("SCANNER_NETWORK", "bad name")
    assert scanner_network() == "bridge"


def test_force_root_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCANNER_FORCE_ROOT", "1")
    spec = filesystem_spec("checkov", "/var/lib/security-scans/abc123def456")

    assert "user" not in spec
    assert spec["cap_drop"] == ["ALL"]


def test_image_temp_directory_is_private_and_capped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from security_console.runner import (
        _directory_bytes,
        _enforce_directory_limit,
    )

    monkeypatch.setenv("SCAN_DIR", str(tmp_path))
    monkeypatch.setenv("HOST_SCAN_DIR", "/var/lib/security-scans")
    directory = tmp_path / "abc123def456" / "tmp"
    directory.mkdir(parents=True, mode=0o700)
    os.chmod(directory, 0o700)
    (directory / "layer").write_bytes(b"x" * 32)

    assert directory.stat().st_mode & 0o777 == 0o700
    assert _directory_bytes(directory) == 32

    killed: list[str] = []

    class _Container:
        def kill(self) -> None:
            killed.append("kill")

    stop = threading.Event()
    exceeded = threading.Event()
    _enforce_directory_limit(
        _Container(),
        directory,
        16,
        stop,
        exceeded,
        interval=0.01,
    )

    assert exceeded.is_set()
    assert killed == ["kill"]


def test_sonar_token_file_is_private_and_removed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SCAN_DIR", str(tmp_path))
    monkeypatch.setenv("HOST_SCAN_DIR", "/var/lib/security-scans")
    from security_console.runner import _prepare_sonar_token, _remove_sonar_token

    host = _prepare_sonar_token("abc123def456", "sonar-token")
    directory = tmp_path / ".abc123def456-sonar"
    token_path = directory / "token"

    assert host == os.path.join(
        "/var/lib/security-scans",
        ".abc123def456-sonar",
        "token",
    )
    assert token_path.read_text() == "sonar-token"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert token_path.stat().st_mode & 0o777 == 0o444
    _remove_sonar_token("abc123def456")
    assert not directory.exists()
