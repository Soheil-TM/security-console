"""Run approved scanners. This module is the only place that talks to Docker."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from security_console.images import valid_image_ref
from security_console.repos import (
    clone_pins,
    git_clone_args,
    git_env,
    git_fetch_sha_commands,
    git_rev_parse_args,
)
from security_console.runtime import (
    TRIVY_DB_WAIT_SECONDS,
    TRIVY_IMAGE_TMP_BYTES,
    filesystem_spec,
    sonar_spec,
    trivy_image_spec,
    uses_docker_socket,
)
from security_console.trivy import parse_report as parse_trivy_report
from security_console.trivy_db import refresh_trivy_databases

SCAN_TIMEOUT = 600
IMAGE_SCAN_TIMEOUT = 900
SONAR_TIMEOUT = 900
_MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_REPO_BYTES = 1024 * 1024 * 1024
Phase = Callable[[str], None]


class CloneError(RuntimeError):
    """The repository was not checked out at the requested commit."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def execute_job(job: dict[str, Any], on_phase: Phase | None = None) -> dict[str, Any]:
    """Run one scan and return findings. Docker errors become a failed result."""

    requested = str(job.get("requested_sha") or "")

    def phase(name: str) -> None:
        if on_phase is not None:
            on_phase(name)

    try:
        if job["target"] == "image":
            result = _image_scan(job, phase)
        else:
            result = _repo_scan(job, phase)
    except CloneError as exc:
        result = _failed(
            RuntimeError(_redact_job(str(exc), job)),
            reason=exc.reason,
        )
    except Exception as exc:
        result = _failed(RuntimeError(_redact_job(str(exc), job)))
    result["requested_sha"] = requested
    return result


def list_images() -> list[dict[str, Any]]:
    """Return tagged local images. The caller already checked permission."""

    from security_console.images import image_rows

    client = _client()
    raw = []
    for image in client.images.list():
        attrs = image.attrs or {}
        raw.append(
            {
                "tags": list(image.tags or []),
                "id": image.id or "",
                "size": int(attrs.get("Size") or 0),
                "created": attrs.get("Created") or "",
            }
        )
    return image_rows(raw)


def _repo_scan(job: dict[str, Any], phase: Phase) -> dict[str, Any]:
    local_path = _scan_path(job["id"])
    host_path = _host_path(job["id"])
    auth_dir = local_path.parent / (job["id"] + "-auth")
    auth_config = _git_auth_file(auth_dir, job)
    try:
        phase("clone")
        commit_sha = _clone(
            job["repo"],
            local_path,
            str(job.get("requested_sha") or ""),
            auth_config,
        )
        _reject_huge_tree(local_path)
        client = _client()
        findings: list[dict[str, Any]] = []
        notes: list[str] = []
        sonar: dict[str, Any] | None = None
        if "semgrep" in job["tools"]:
            phase("Semgrep")
            code, stdout, stderr = _run(
                client,
                filesystem_spec("semgrep", host_path),
                SCAN_TIMEOUT,
            )
            _record(findings, notes, "Semgrep", _parse_semgrep, code, stdout, stderr)
        if "checkov" in job["tools"]:
            phase("Checkov")
            code, stdout, stderr = _run(
                client,
                filesystem_spec("checkov", host_path),
                SCAN_TIMEOUT,
            )
            _record(findings, notes, "Checkov", _parse_checkov, code, stdout, stderr)
        if "trivy" in job["tools"]:
            phase("Trivy database")
            db_error = _refresh_trivy_databases(client)
            if db_error:
                notes.append(db_error)
            phase("Trivy")
            code, stdout, stderr = _run(
                client,
                filesystem_spec("trivy", host_path),
                SCAN_TIMEOUT,
            )
            _record(findings, notes, "Trivy", _parse_trivy, code, stdout, stderr)
        if "sonar" in job["tools"]:
            phase("SonarQube")
            sonar = _run_sonar(client, host_path, job["id"])
        result = _finish(job["tools"], findings, notes, sonar)
        result["commit_sha"] = commit_sha
        result["failure_reason"] = ""
        return result
    finally:
        if local_path.exists():
            shutil.rmtree(local_path, ignore_errors=True)
        if auth_dir.exists():
            shutil.rmtree(auth_dir, ignore_errors=True)


def _image_scan(job: dict[str, Any], phase: Phase) -> dict[str, Any]:
    image_ref = job["image"]
    if not valid_image_ref(image_ref):
        raise RuntimeError("Image name is invalid.")
    phase("Trivy")
    local_path = _scan_path(job["id"])
    local_path.mkdir(parents=True, exist_ok=True)
    tmp_dir = local_path / "tmp"
    tmp_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(tmp_dir, 0o700)
    archive: Path | None = None
    try:
        client = _client()
        archive_host: str | None = None
        try:
            image = client.images.get(image_ref)
        except _image_not_found():
            image = None
        password = str(job.get("registry_password") or "")
        if image is None and password:
            phase("Pull")
            _pull_image(
                client,
                image_ref,
                str(job.get("registry_username") or ""),
                password,
            )
            try:
                image = client.images.get(image_ref)
            except _image_not_found():
                image = None
            if image is None:
                raise RuntimeError("The registry did not return the image.")
        if image is not None:
            size = int((image.attrs or {}).get("Size") or 0)
            if size > _image_limit():
                raise RuntimeError("Image is larger than the scan limit.")
            local_path.mkdir(parents=True, exist_ok=True)
            archive = local_path / "image.tar"
            written = 0
            with archive.open("wb") as handle:
                for chunk in image.save(named=True):
                    written += len(chunk)
                    if written > _image_limit():
                        raise RuntimeError("Image is larger than the scan limit.")
                    handle.write(chunk)
            archive_host = _host_file(job["id"], "image.tar")
        findings: list[dict[str, Any]] = []
        notes: list[str] = []
        phase("Trivy database")
        db_error = _refresh_trivy_databases(client)
        if db_error:
            notes.append(db_error)
        phase("Trivy")
        spec = trivy_image_spec(
            image_ref,
            archive_host_path=archive_host,
            tmp_host_path=_host_file(job["id"], "tmp"),
        )
        code, stdout, stderr = _run(
            client,
            spec,
            IMAGE_SCAN_TIMEOUT,
            limit_path=tmp_dir,
            limit_bytes=TRIVY_IMAGE_TMP_BYTES,
        )
        _record(findings, notes, "Trivy", _parse_trivy, code, stdout, stderr)
        result = _finish(job["tools"], findings, notes, None)
        result["commit_sha"] = ""
        result["failure_reason"] = ""
        return result
    finally:
        if local_path.exists():
            shutil.rmtree(local_path, ignore_errors=True)


def _run_sonar(client: Any, host_path: str, scan_id: str) -> dict[str, Any]:
    key = ""
    try:
        key = _sonar_key()
        token = _sonar_token()
    except Exception as exc:
        # Semgrep and Checkov already ran. A missing token must not discard them.
        detail = str(exc).strip() or type(exc).__name__
        return _empty_sonar(key, detail)
    try:
        token_file = _prepare_sonar_token(scan_id, token)
        spec = sonar_spec(
            host_path,
            project_key=key,
            host_url=_sonar_url(),
            token_file=token_file,
        )
        try:
            code, stdout, stderr = _run(client, spec, SONAR_TIMEOUT)
        except Exception as exc:
            return _empty_sonar(key, _redact(str(exc), token))
        logs = _redact(stdout + "\n" + stderr, token)
        uploaded = "ANALYSIS SUCCESSFUL" in logs or "QUALITY GATE STATUS" in logs
        if not uploaded:
            tail = "\n".join(logs.splitlines()[-25:])[-1500:]
            return _empty_sonar(key, tail or f"SonarQube finished with code {code}.")
        try:
            return _fetch_sonar_summary(key, token)
        except Exception as exc:
            return _empty_sonar(key, _redact(str(exc), token)[:1500])
    finally:
        _remove_sonar_token(scan_id)


_SONAR_LIST_TEXT = 200
_SONAR_FILE_TEXT = 500
_SONAR_ISSUE_CAP = 500
_SONAR_HOTSPOT_CAP = 200


def _sonar_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value[:_SONAR_LIST_TEXT]


def _sonar_file(value: Any, key: str) -> str:
    if not isinstance(value, str):
        return ""
    return value.removeprefix(key + ":")[:_SONAR_FILE_TEXT]


def _sonar_line(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _sonar_issue_list(payload: Any, key: str) -> list[dict[str, Any]]:
    """Keep the open issues from one SonarQube search page."""

    rows = payload.get("issues") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    items: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "file": _sonar_file(item.get("component"), key),
                "line": _sonar_line(item.get("line")),
                "rule": _sonar_text(item.get("rule")),
                "type": _sonar_text(item.get("type")),
                "severity": _sonar_text(item.get("severity")),
                "message": _sonar_text(item.get("message")),
            }
        )
        if len(items) >= _SONAR_ISSUE_CAP:
            break
    return items


def _sonar_hotspot_list(payload: Any, key: str) -> list[dict[str, Any]]:
    """Keep the hotspots still waiting for review."""

    rows = payload.get("hotspots") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    items: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "file": _sonar_file(item.get("component"), key),
                "line": _sonar_line(item.get("line")),
                "rule": _sonar_text(item.get("ruleKey")),
                "message": _sonar_text(item.get("message")),
                "status": _sonar_text(item.get("status")),
                "vulnerabilityProbability": _sonar_text(
                    item.get("vulnerabilityProbability")
                ),
            }
        )
        if len(items) >= _SONAR_HOTSPOT_CAP:
            break
    return items


def _fetch_sonar_summary(key: str, token: str) -> dict[str, Any]:
    import urllib.error
    import urllib.parse
    import urllib.request

    def sonar_api(path: str, params: dict[str, str]) -> dict[str, Any]:
        url = _sonar_url().rstrip("/") + path + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer " + token},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"SonarQube returned {exc.code}: {detail}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("SonarQube returned an unexpected response.")
        return payload

    gate = sonar_api("/api/qualitygates/project_status", {"projectKey": key})
    measures = sonar_api(
        "/api/measures/component",
        {
            "component": key,
            "metricKeys": "bugs,vulnerabilities,code_smells,security_hotspots",
        },
    )
    values = {
        item.get("metric"): item.get("value")
        for item in measures.get("component", {}).get("measures", [])
        if isinstance(item, dict)
    }

    def number(metric: str) -> int:
        try:
            return int(values.get(metric) or 0)
        except (TypeError, ValueError):
            return 0

    # A failed list lookup must leave the quality gate and the four counts.
    issues: list[dict[str, Any]] = []
    try:
        issues_data = sonar_api(
            "/api/issues/search",
            {
                "componentKeys": key,
                "resolved": "false",
                "ps": "500",
                "p": "1",
            },
        )
        issues = _sonar_issue_list(issues_data, key)
    except Exception:
        issues = []

    hotspots: list[dict[str, Any]] = []
    try:
        hotspots_data = sonar_api(
            "/api/hotspots/search",
            {
                "projectKey": key,
                "status": "TO_REVIEW",
                "ps": "200",
                "p": "1",
            },
        )
        hotspots = _sonar_hotspot_list(hotspots_data, key)
    except Exception:
        hotspots = []

    return {
        "project_key": key,
        "quality_gate": (gate.get("projectStatus") or {}).get("status") or "",
        "bugs": number("bugs"),
        "vulnerabilities": number("vulnerabilities"),
        "code_smells": number("code_smells"),
        "security_hotspots": number("security_hotspots"),
        "issues": issues,
        "hotspot_list": hotspots,
        "url": _sonar_url().rstrip("/")
        + "/dashboard?id="
        + urllib.parse.quote(key),
        "error": "",
    }


def _empty_sonar(key: str, error: str) -> dict[str, Any]:
    import urllib.parse

    return {
        "project_key": key,
        "quality_gate": "",
        "bugs": 0,
        "vulnerabilities": 0,
        "code_smells": 0,
        "security_hotspots": 0,
        "issues": [],
        "hotspot_list": [],
        "url": _sonar_url().rstrip("/") + "/dashboard?id=" + urllib.parse.quote(key),
        "error": error[:1500],
    }


def _clone(
    repo: str,
    dest: Path,
    requested_sha: str,
    auth_config: str | None = None,
) -> str:
    pins = clone_pins(repo)
    if not pins:
        raise CloneError("Repository URL is not allowed.", "clone_failed")
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if requested_sha:
        commands = git_fetch_sha_commands(
            repo,
            str(dest),
            requested_sha,
            pins,
            auth_config,
        )
    else:
        commands = [git_clone_args(repo, str(dest), pins, auth_config)]
    for command in commands:
        timeout = 180 if "fetch" in command or "clone" in command else 30
        try:
            completed = _run_git(command, timeout)
        except subprocess.TimeoutExpired:
            raise CloneError("git timed out.", "clone_failed") from None
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "git failed").strip()
            raise CloneError(detail[-1500:] or "git clone failed", "clone_failed")
    return _require_head(dest, requested_sha)


def _run_git(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=git_env(os.environ.get("PATH", "")),
        check=False,
    )


def _require_head(dest: Path, requested_sha: str) -> str:
    completed = _run_git(git_rev_parse_args(str(dest)), 30)
    head = completed.stdout.strip().lower() if completed.returncode == 0 else ""
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise CloneError("The cloned revision could not be read.", "clone_failed")
    if requested_sha and head != requested_sha:
        raise CloneError(
            f"SHA mismatch: requested={requested_sha} got={head}",
            "sha_mismatch",
        )
    return head


def _refresh_trivy_databases(client: Any) -> str:
    """Fill the shared cache. A failed mirror does not remove what is there."""

    def run(spec: dict[str, Any]) -> tuple[int, str, str]:
        return _run(client, spec, TRIVY_DB_WAIT_SECONDS)

    return refresh_trivy_databases(run)


def _directory_bytes(path: Path) -> int:
    """Byte size of one directory. Links are not followed."""

    total = 0
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


def _enforce_directory_limit(
    container: Any,
    path: Path,
    limit: int,
    stop: threading.Event,
    exceeded: threading.Event,
    interval: float = 2,
) -> None:
    """Stop the container when its temporary directory grows past the cap."""

    while not stop.wait(interval):
        if _directory_bytes(path) <= limit:
            continue
        exceeded.set()
        with suppress(Exception):
            container.kill()
        return


def _run(
    client: Any,
    spec: dict[str, Any],
    timeout: int,
    *,
    limit_path: Path | None = None,
    limit_bytes: int = 0,
) -> tuple[int, str, str]:
    unsafe = (
        uses_docker_socket(spec)
        or spec.get("privileged")
        or spec.get("network_mode") == "host"
    )
    if unsafe:
        raise RuntimeError("scanner container was rejected")
    client.images.pull(spec["image"])
    kwargs = dict(spec)
    image = kwargs.pop("image")
    container = client.containers.run(image, **kwargs)
    stop = threading.Event()
    exceeded = threading.Event()
    watcher = None
    if limit_path is not None and limit_bytes > 0:
        watcher = threading.Thread(
            target=_enforce_directory_limit,
            args=(container, limit_path, limit_bytes, stop, exceeded),
            daemon=True,
        )
        watcher.start()
    try:
        result = container.wait(timeout=timeout)
        if exceeded.is_set():
            raise RuntimeError(
                "Image scan temporary files exceeded the size limit."
            )
        stdout = container.logs(stdout=True, stderr=False)
        stderr = container.logs(stdout=False, stderr=True)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        return (
            int(code),
            stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"),
        )
    finally:
        stop.set()
        if watcher is not None:
            watcher.join(timeout=3)
        with suppress(Exception):
            container.remove(force=True)


def _record(
    findings: list[dict[str, Any]],
    notes: list[str],
    name: str,
    parser: Callable[[str], list[dict[str, Any]]],
    code: int,
    stdout: str,
    stderr: str,
) -> None:
    try:
        findings.extend(parser(stdout))
    except json.JSONDecodeError:
        notes.append(f"{name} output was not JSON:\n" + (stdout or stderr)[-1500:])
    if code not in (0, 1):
        notes.append(stderr[-1500:])


def _finish(
    tools: list[str],
    findings: list[dict[str, Any]],
    notes: list[str],
    sonar: dict[str, Any] | None,
) -> dict[str, Any]:
    sonar_error = (sonar or {}).get("error") or ""
    if tools == ["sonar"] and sonar_error:
        return {
            "findings": findings,
            "notes": notes,
            "sonar": sonar,
            "status": "failed",
            "error": sonar_error,
            "phase": "",
        }
    return {
        "findings": findings,
        "notes": notes,
        "sonar": sonar,
        "status": "done",
        "error": _public_error(notes),
        "phase": "",
    }


def _public_error(notes: list[str]) -> str:
    """Notes the scan page can show. A stale database is not a failed scan."""

    kept = [
        note
        for note in notes
        if note and "Could not refresh the Trivy" not in note
    ]
    return "\n".join(kept)[:2000]


def _git_auth_file(directory: Path, job: dict[str, Any]) -> str | None:
    """Write a git config the clone includes. The token stays out of argv."""

    token = str(job.get("clone_token") or "")
    ca_cert = str(job.get("ca_cert") or "")
    if not token and not ca_cert:
        return None
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    lines = ["[http]"]
    if token and job.get("clone_style") == "basic":
        pair = base64.b64encode(("x-access-token:" + token).encode()).decode()
        lines.append("\textraHeader = Authorization: Basic " + pair)
    elif token:
        lines.append("\textraHeader = PRIVATE-TOKEN: " + token)
    if ca_cert:
        ca_path = directory / "ca.pem"
        ca_path.write_text(ca_cert, encoding="utf-8")
        os.chmod(ca_path, 0o600)
        lines.append("\tsslCAInfo = " + str(ca_path))
    path = directory / "auth.config"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return str(path)


def _pull_image(client: Any, ref: str, username: str, password: str) -> None:
    """Pull one private image through the Docker API. Trivy never sees the password."""

    try:
        stream = client.api.pull(
            ref,
            stream=True,
            decode=True,
            auth_config={"username": username, "password": password},
        )
    except Exception as exc:
        raise RuntimeError(_hide_secret(str(exc), password)) from None
    message = ""
    for item in stream:
        if isinstance(item, dict) and item.get("error"):
            message = _hide_secret(str(item["error"]), password)
    if message:
        raise RuntimeError(message)


def _redact_job(text: str, job: dict[str, Any]) -> str:
    hidden = text
    for key in ("clone_token", "registry_password"):
        hidden = _hide_secret(hidden, str(job.get(key) or ""))
    return hidden


def _hide_secret(text: str, secret: str) -> str:
    if secret and secret in text:
        return text.replace(secret, "***")
    return text


def _failed(exc: Exception, *, reason: str = "") -> dict[str, Any]:
    text = str(exc).strip() or type(exc).__name__
    return {
        "findings": [],
        "notes": [],
        "sonar": None,
        "status": "failed",
        "error": text[-2000:],
        "phase": "",
        "requested_sha": "",
        "commit_sha": "",
        "failure_reason": reason,
    }


def _client() -> Any:
    import docker

    return docker.from_env()


def _image_not_found() -> type[BaseException]:
    from docker.errors import ImageNotFound

    return cast("type[BaseException]", ImageNotFound)


def _scan_path(scan_id: str) -> Path:
    import re

    if not re.fullmatch(r"[a-f0-9]{12}", scan_id):
        raise RuntimeError("Invalid scan.")
    return Path(os.environ.get("SCAN_DIR", "/scans")) / scan_id


def _host_path(scan_id: str) -> str:
    _scan_path(scan_id)
    root = os.environ.get("HOST_SCAN_DIR", "/var/lib/security-scans")
    return os.path.join(root, scan_id)


def _host_file(scan_id: str, name: str) -> str:
    return os.path.join(_host_path(scan_id), name)


def _sonar_token_dir(scan_id: str) -> Path:
    _scan_path(scan_id)
    return Path(os.environ.get("SCAN_DIR", "/scans")) / f".{scan_id}-sonar"


def _prepare_sonar_token(scan_id: str, token: str) -> str:
    """Write the token where only root on the host can traverse to it.

    The file itself is mode 0444 so the scanner image user can read the bind
    mount. The parent directory is mode 0700. Docker records the path, not
    the file contents, in the container inspect payload.
    """

    directory = _sonar_token_dir(scan_id)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / "token"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    try:
        os.write(descriptor, token.encode())
    finally:
        os.close(descriptor)
    os.chmod(path, 0o444)
    root = os.environ.get("HOST_SCAN_DIR", "/var/lib/security-scans")
    return os.path.join(root, f".{scan_id}-sonar", "token")


def _remove_sonar_token(scan_id: str) -> None:
    shutil.rmtree(_sonar_token_dir(scan_id), ignore_errors=True)


def _reject_huge_tree(path: Path) -> None:
    total = 0
    limit = _repo_limit()
    for dirpath, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                continue
            if total > limit:
                raise RuntimeError("Repository is larger than the scan limit.")


def _repo_limit() -> int:
    override = os.environ.get("SCANNER_MAX_REPO_MB", "").strip()
    if override.isdigit() and 32 <= int(override) <= 8192:
        return int(override) * 1024 * 1024
    return _MAX_REPO_BYTES


def _image_limit() -> int:
    override = os.environ.get("SCANNER_MAX_IMAGE_MB", "").strip()
    if override.isdigit() and 32 <= int(override) <= 8192:
        return int(override) * 1024 * 1024
    return _MAX_IMAGE_BYTES


def _sonar_url() -> str:
    return os.environ.get("SONAR_URL", "http://sonarqube:9000/sonar").strip()


def _sonar_key() -> str:
    import re

    key = os.environ.get("SONAR_PROJECT_KEY", "security-console")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", key):
        raise RuntimeError("The SonarQube project key is invalid.")
    return key


def _sonar_token() -> str:
    from security_console.secrets import read_secret

    token = read_secret("SONAR_TOKEN", "SONAR_TOKEN_FILE")
    if not token:
        raise RuntimeError("The SonarQube token is not configured.")
    return token


def _redact(text: str, token: str) -> str:
    if token and token in text:
        return text.replace(token, "***")
    return text


def _parse_json_blob(raw: str) -> Any:
    text = raw.strip()
    starts = [pos for pos in (text.find("{"), text.find("[")) if pos >= 0]
    if not starts:
        raise json.JSONDecodeError("no json", text, 0)
    return json.loads(text[min(starts) :])


def _parse_semgrep(raw: str) -> list[dict[str, Any]]:
    data = _parse_json_blob(raw)
    if not isinstance(data, dict):
        return []
    findings = []
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {}
        start = item.get("start") or {}
        findings.append(
            {
                "tool": "semgrep",
                "severity": extra.get("severity") or "INFO",
                "check": item.get("check_id") or "",
                "path": item.get("path") or "",
                "line": start.get("line") if isinstance(start, dict) else None,
                "message": extra.get("message") or "",
            }
        )
    return findings


def _parse_checkov(raw: str) -> list[dict[str, Any]]:
    data = _parse_json_blob(raw)
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return []
    findings = []
    failed = (data.get("results") or {}).get("failed_checks") or []
    for item in failed:
        if not isinstance(item, dict):
            continue
        line_range = item.get("file_line_range") or [None]
        findings.append(
            {
                "tool": "checkov",
                "severity": item.get("severity") or "UNKNOWN",
                "check": item.get("check_id") or "",
                "path": item.get("file_path") or "",
                "line": line_range[0]
                if isinstance(line_range, list) and line_range
                else None,
                "message": item.get("check_name") or "",
            }
        )
    return findings


def _parse_trivy(raw: str) -> list[dict[str, Any]]:
    data = _parse_json_blob(raw)
    if not isinstance(data, dict):
        return []
    return parse_trivy_report(data)
