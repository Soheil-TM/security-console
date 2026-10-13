"""Approved scanner containers.

User input never selects the image, the entrypoint, the mounts, or the
privileges. The image under scan is an argument to the pinned Trivy image,
not the container image itself.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SEMGREP_IMAGE = "semgrep/semgrep:1.179.0"
CHECKOV_IMAGE = "bridgecrew/checkov:3.3.26"
TRIVY_IMAGE = "aquasec/trivy:0.75.0"
SONAR_IMAGE = "sonarsource/sonar-scanner-cli:12.2"
TRIVY_CACHE_VOLUME = "security-console-trivy-cache"
# Official vulnerability-database mirrors. Every refresh starts at the first.
TRIVY_VULN_REPOSITORIES = (
    "ghcr.io/aquasecurity/trivy-db:2",
    "public.ecr.aws/aquasecurity/trivy-db:2",
    "mirror.gcr.io/aquasecurity/trivy-db:2",
)
# The Java index is a different artifact and uses the :1 tag.
TRIVY_JAVA_REPOSITORIES = (
    "ghcr.io/aquasecurity/trivy-java-db:1",
    "public.ecr.aws/aquasecurity/trivy-java-db:1",
    "mirror.gcr.io/aquasecurity/trivy-java-db:1",
)
TRIVY_DB_TIMEOUT = "30s"
TRIVY_DB_WAIT_SECONDS = 40
APPROVED_IMAGES = frozenset(
    {SEMGREP_IMAGE, CHECKOV_IMAGE, TRIVY_IMAGE, SONAR_IMAGE}
)
_NETWORK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_TMPFS = {
    "/tmp": "rw,nosuid,nodev,size=256m",
    "/root": "rw,nosuid,nodev,size=64m",
    "/home": "rw,nosuid,nodev,size=64m",
}
# Image layers are unpacked while Trivy reads them. That working set is larger
# than the shared 256m /tmp, so an image scan uses its own directory instead.
TRIVY_IMAGE_TMP_BYTES = 2 * 1024 * 1024 * 1024


def scanner_network() -> str:
    """Network for scanner containers. ``host`` is never accepted."""

    value = os.environ.get("SCANNER_NETWORK", "bridge").strip() or "bridge"
    if value == "host" or not _NETWORK_NAME.fullmatch(value):
        return "bridge"
    return value


def _mem_limit(default: str) -> str:
    override = os.environ.get("SCANNER_MEM_MB", "").strip()
    if override.isdigit() and 128 <= int(override) <= 8192:
        return f"{override}m"
    return default


def _user_for(tool: str) -> str | None:
    """Run Semgrep and Checkov without root. Trivy and Sonar keep the image user.

    Trivy writes a cache volume that is created as root. Sonar keeps the
    scanner image user and writes its work files under ``/tmp``. Setting
    ``SCANNER_FORCE_ROOT=1`` restores the image user for every tool.
    """

    if os.environ.get("SCANNER_FORCE_ROOT", "").strip() == "1":
        return None
    if tool in {"semgrep", "checkov"}:
        return "65534:65534"
    return None


def _base(
    *,
    image: str,
    command: list[str],
    entrypoint: list[str] | None,
    volumes: dict[str, dict[str, str]],
    environment: dict[str, str],
    working_dir: str,
    mem_limit: str,
    read_only: bool,
    user: str | None,
) -> dict[str, Any]:
    if image not in APPROVED_IMAGES:
        raise RuntimeError("scanner image is not approved")
    spec: dict[str, Any] = {
        "image": image,
        "command": command,
        "volumes": volumes,
        "environment": environment,
        "working_dir": working_dir,
        "detach": True,
        "remove": False,
        "network_mode": scanner_network(),
        "read_only": read_only,
        "mem_limit": _mem_limit(mem_limit),
        "nano_cpus": 1_500_000_000,
        "pids_limit": 512,
        "privileged": False,
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "init": True,
        "extra_hosts": {
            "metadata.google.internal": "127.0.0.1",
            "metadata.google": "127.0.0.1",
        },
        "labels": {"security-console.role": "scanner"},
    }
    if entrypoint:
        spec["entrypoint"] = entrypoint
    if read_only:
        spec["tmpfs"] = dict(_TMPFS)
    if user:
        spec["user"] = user
    return spec


def filesystem_spec(tool: str, host_path: str) -> dict[str, Any]:
    """Container kwargs for one repository scanner over a read-only mount."""

    if tool == "semgrep":
        spec = _base(
            image=SEMGREP_IMAGE,
            command=["scan", "--config", "auto", "--json", "."],
            entrypoint=["semgrep"],
            volumes={host_path: {"bind": "/src", "mode": "ro"}},
            environment=_home_env(),
            working_dir="/src",
            mem_limit="1024m",
            read_only=True,
            user=_user_for("semgrep"),
        )
    elif tool == "checkov":
        spec = _base(
            image=CHECKOV_IMAGE,
            command=["-d", "/src", "-o", "json", "--quiet"],
            entrypoint=["checkov"],
            volumes={host_path: {"bind": "/src", "mode": "ro"}},
            environment=_home_env(),
            working_dir="/src",
            mem_limit="1024m",
            read_only=True,
            user=_user_for("checkov"),
        )
    elif tool == "trivy":
        spec = _base(
            image=TRIVY_IMAGE,
            command=_trivy_scan_command("fs", "/src"),
            entrypoint=["trivy"],
            volumes={
                host_path: {"bind": "/src", "mode": "ro"},
                TRIVY_CACHE_VOLUME: {"bind": "/cache", "mode": "rw"},
            },
            environment=_home_env(),
            working_dir="/src",
            mem_limit="1024m",
            read_only=True,
            user=_user_for("trivy"),
        )
    else:
        raise RuntimeError("scanner is not approved")
    spec["labels"] = {"security-console.role": "scanner", "security-console.tool": tool}
    return spec


def trivy_image_spec(
    image_ref: str,
    *,
    archive_host_path: str | None,
    tmp_host_path: str,
) -> dict[str, Any]:
    """Scan an image with Trivy without giving Trivy the Docker socket.

    A local image is saved to a tar first. A remote name is pulled by Trivy
    itself with ``--image-src remote``.
    """

    if archive_host_path:
        command = _trivy_scan_command(
            "image",
            "--input",
            "/image/image.tar",
        )
        volumes = {
            archive_host_path: {"bind": "/image/image.tar", "mode": "ro"},
            TRIVY_CACHE_VOLUME: {"bind": "/cache", "mode": "rw"},
        }
    else:
        command = _trivy_scan_command(
            "image",
            "--image-src",
            "remote",
            image_ref,
        )
        volumes = {TRIVY_CACHE_VOLUME: {"bind": "/cache", "mode": "rw"}}
    volumes[tmp_host_path] = _image_tmp_mount(tmp_host_path)
    spec = _base(
        image=TRIVY_IMAGE,
        command=command,
        entrypoint=["trivy"],
        volumes=volumes,
        environment=_home_env(),
        working_dir="/",
        mem_limit="1024m",
        read_only=True,
        user=_user_for("trivy"),
    )
    spec["tmpfs"] = {
        "/root": "rw,nosuid,nodev,size=64m",
        "/home": "rw,nosuid,nodev,size=64m",
    }
    spec["labels"] = {
        "security-console.role": "scanner",
        "security-console.tool": "trivy",
    }
    return spec


def _image_tmp_mount(path: str) -> dict[str, str]:
    """Bind one scan's temporary directory. It must not be a parent or a socket."""

    text = path.strip()
    parts = Path(text).parts
    if (
        not text.startswith("/")
        or ".." in parts
        or text == "/"
        or "docker.sock" in text
    ):
        raise RuntimeError("Image scan temporary directory is invalid.")
    return {"bind": "/tmp", "mode": "rw"}


def trivy_db_update_spec(kind: str, repository: str) -> dict[str, Any]:
    """Download one Trivy database into the shared cache volume.

    The repository must be one of the official mirrors. A scan container does
    not call this; it only reads the cache.
    """

    if kind == "vuln":
        allowed = TRIVY_VULN_REPOSITORIES
        command = [
            "fs",
            "--download-db-only",
            "--skip-java-db-update",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
            "--db-repository",
            repository,
            "--timeout",
            TRIVY_DB_TIMEOUT,
            ".",
        ]
    elif kind == "java":
        allowed = TRIVY_JAVA_REPOSITORIES
        command = [
            "fs",
            "--download-java-db-only",
            "--skip-db-update",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
            "--java-db-repository",
            repository,
            "--timeout",
            TRIVY_DB_TIMEOUT,
            ".",
        ]
    else:
        raise RuntimeError("database is not approved")
    if repository not in allowed:
        raise RuntimeError("database repository is not approved")
    spec = _base(
        image=TRIVY_IMAGE,
        command=command,
        entrypoint=["trivy"],
        volumes={TRIVY_CACHE_VOLUME: {"bind": "/cache", "mode": "rw"}},
        environment=_home_env(),
        working_dir="/",
        mem_limit="1024m",
        read_only=True,
        user=_user_for("trivy"),
    )
    spec["labels"] = {
        "security-console.role": "scanner",
        "security-console.tool": "trivy-db",
    }
    return spec


def _trivy_scan_command(subcommand: str, *tail: str) -> list[str]:
    """Scan flags. Database refresh happens before this container starts."""

    return [
        subcommand,
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig,secret",
        "--skip-version-check",
        "--skip-db-update",
        "--skip-java-db-update",
        "--cache-dir",
        "/cache",
        *tail,
    ]


# sonar-scanner-cli reads SONAR_TOKEN from the process environment. It has
# no stdin or token-file option. The shell below loads the file after Docker
# has recorded the container config, so the value is not part of inspect's
# Env or Args. The variable name is visible; the secret is not.
_SONAR_BOOT = """set -eu
token_file=${SONAR_TOKEN_FILE:-/run/secrets/sonar_token}
test -r "$token_file"
token=$(cat "$token_file")
if [ -z "$token" ]; then
  echo "SonarQube token is missing." >&2
  exit 1
fi
SONAR_TOKEN="$token"
export SONAR_TOKEN
unset SONAR_TOKEN_FILE
unset token
java_home=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")
trust_src="$java_home/lib/security/cacerts"
test -f "$trust_src"
cp "$trust_src" /tmp/sonar-truststore
chmod 444 /tmp/sonar-truststore
keytool -genkeypair -alias unused -keyalg RSA -keysize 2048 \
  -validity 1 -dname CN=unused -storetype PKCS12 \
  -keystore /tmp/sonar-client.p12 \
  -storepass unused-store -keypass unused-store >/dev/null
keytool -delete -alias unused \
  -keystore /tmp/sonar-client.p12 -storepass unused-store >/dev/null
mkdir -p /tmp/.scannerwork
exec sonar-scanner "$@"
"""


def sonar_spec(
    host_path: str,
    *,
    project_key: str,
    host_url: str,
    token_file: str,
) -> dict[str, Any]:
    """SonarQube scanner. The token file is mounted; the value is not in Env.

    Command-line properties outrank ``sonar-project.properties``. The pinned
    keys are the ones that choose the server, a proxy, a custom trust store,
    or JVM options that could point HTTPS at another host. The token is not
    one of those arguments.
    """

    spec = _base(
        image=SONAR_IMAGE,
        command=[
            _sonar_host_argument(host_url),
            f"-Dsonar.projectKey={project_key}",
            "-Dsonar.sources=.",
            "-Dsonar.qualitygate.wait=true",
            "-Dsonar.qualitygate.timeout=480",
            "-Dsonar.scm.disabled=true",
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
        ],
        entrypoint=["/bin/sh", "-c", _SONAR_BOOT, "sonar-wrapper"],
        volumes={
            host_path: {"bind": "/usr/src", "mode": "ro"},
            token_file: {"bind": "/run/secrets/sonar_token", "mode": "ro"},
        },
        environment={
            "SONAR_HOST_URL": host_url,
            "SONAR_TOKEN_FILE": "/run/secrets/sonar_token",
            "SONAR_SCANNER_JAVA_OPTS": "-Xmx384m",
            "HOME": "/tmp",
            "TMPDIR": "/tmp",
        },
        working_dir="/usr/src",
        mem_limit="896m",
        read_only=False,
        user=_user_for("sonar"),
    )
    spec["labels"] = {
        "security-console.role": "scanner",
        "security-console.tool": "sonar",
    }
    return spec


def _sonar_host_argument(host_url: str) -> str:
    """Return one Sonar property. The token is not part of this argument."""

    if any(character.isspace() for character in host_url):
        raise RuntimeError("The SonarQube URL is invalid.")
    parsed = urlparse(host_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("The SonarQube URL is invalid.")
    if parsed.username or parsed.password:
        raise RuntimeError("The SonarQube URL is invalid.")
    return f"-Dsonar.host.url={host_url}"


def _home_env() -> dict[str, str]:
    return {
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp",
        "XDG_CONFIG_HOME": "/tmp",
    }


def uses_docker_socket(spec: dict[str, Any]) -> bool:
    """Return whether a container spec mounts the Docker socket."""

    for source in spec.get("volumes") or {}:
        if "docker.sock" in str(source):
            return True
        bind = (spec["volumes"][source] or {}).get("bind", "")
        if "docker.sock" in str(bind):
            return True
    environment = spec.get("environment") or {}
    return any("docker.sock" in str(value) for value in environment.values())
