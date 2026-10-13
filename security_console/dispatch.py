"""Send a scan to the isolated worker, or run it in this process.

``SCANNER_URL`` selects the worker. The web process does not open the Docker
socket on that path. Leaving the variable empty keeps the previous
single-process mode for a host that has not deployed the worker yet.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from security_console.jobs import JobError, parse_job
from security_console.secrets import read_secret, same_secret

log = logging.getLogger("security_console")
_warned = False
Phase = Callable[[str], None]


def scanner_url() -> str:
    """Return the worker base URL, or an empty string for in-process scans."""

    return os.environ.get("SCANNER_URL", "").strip().rstrip("/")


def scanner_token() -> str:
    """Return the shared token used to call the worker."""

    return read_secret("SCANNER_TOKEN", "SCANNER_TOKEN_FILE")


def dispatch_scan(job: dict[str, Any], on_phase: Phase | None = None) -> dict[str, Any]:
    """Run a scan and always return a status dict."""

    try:
        approved = parse_job(job)
        if scanner_url():
            return _remote_scan(approved, on_phase or (lambda _phase: None))
        _warn_local()
        from security_console.runner import execute_job

        return execute_job(approved, on_phase)
    except JobError as exc:
        return _failed(str(exc))
    except Exception as exc:
        log.error("scan failed: %s", type(exc).__name__)
        return _failed(str(exc) or type(exc).__name__)


def dispatch_images() -> list[dict[str, Any]]:
    """List local images through the worker when one is configured."""

    if scanner_url():
        payload = _request("GET", "/v1/images", None, timeout=30)
        if not isinstance(payload, list):
            raise RuntimeError("The scanner returned an unexpected image list.")
        return payload
    _warn_local()
    from security_console.runner import list_images

    return list_images()


def _remote_scan(job: dict[str, Any], on_phase: Phase) -> dict[str, Any]:
    _request("POST", "/v1/jobs", job, timeout=30)
    deadline = time.monotonic() + _deadline()
    while True:
        if time.monotonic() > deadline:
            raise RuntimeError("The scan timed out.")
        payload = _request("GET", "/v1/jobs/" + job["id"], None, timeout=30)
        if not isinstance(payload, dict):
            raise RuntimeError("The scanner returned an unexpected result.")
        phase = payload.get("phase") or ""
        if isinstance(phase, str) and phase:
            on_phase(phase)
        if payload.get("status") in {"done", "failed"}:
            return {
                "findings": payload.get("findings") or [],
                "notes": payload.get("notes") or [],
                "sonar": payload.get("sonar"),
                "status": payload.get("status"),
                "error": _redact(str(payload.get("error") or "")),
                "phase": "",
                "requested_sha": str(payload.get("requested_sha") or ""),
                "commit_sha": str(payload.get("commit_sha") or ""),
                "failure_reason": str(payload.get("failure_reason") or ""),
            }
        time.sleep(2)


def _request(method: str, path: str, body: dict[str, Any] | None, timeout: int) -> Any:
    token = scanner_token()
    if len(token) < 16:
        raise RuntimeError("The scanner token is not configured.")
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        scanner_url() + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(
            f"The scanner rejected the scan ({exc.code}). {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("The scanner is unavailable.") from exc
    if not raw:
        return {}
    return json.loads(raw)


def _deadline() -> int:
    override = os.environ.get("SCANNER_DEADLINE", "").strip()
    if override.isdigit() and 60 <= int(override) <= 7200:
        return int(override)
    return 1200


def _warn_local() -> None:
    global _warned
    if _warned:
        return
    _warned = True
    log.warning(
        "SCANNER_URL is unset; this process talks to the Docker socket directly"
    )


def _failed(message: str) -> dict[str, Any]:
    return {
        "findings": [],
        "notes": [],
        "sonar": None,
        "status": "failed",
        "error": _redact(message)[-2000:],
        "phase": "",
        "requested_sha": "",
        "commit_sha": "",
        "failure_reason": "",
    }


def _redact(text: str) -> str:
    token = scanner_token()
    if token and token in text:
        return text.replace(token, "***")
    return text


def token_matches(presented: str) -> bool:
    """Return whether this bearer token is the configured scanner token."""

    return same_secret(presented, scanner_token())
