"""Scans started from the public page without signing in.

A guest scan never uses a saved connection. A private repository or image
works only with a token the guest types for that one scan, and the token is
kept in memory until the scanner has it. Guest scans stay out of group
reports, and a guest reads only the scans of their own browser session.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from security_console.access import severity_counts
from security_console.images import registry_host, valid_image_ref
from security_console.repos import valid_repo

COOKIE = "guest_session"
COOKIE_DAYS = 7
KEEP_DAYS = 7
HOURLY_LIMIT = 6
REPO_TOOLS = ("semgrep", "checkov", "trivy")


def session_key(cookie: str) -> str:
    """Return the stored form of a guest cookie. The cookie itself is not kept."""

    return hashlib.sha256(cookie.encode("utf-8")).hexdigest()


def parse_guest_scan(
    body: Any,
) -> tuple[dict[str, Any] | None, dict[str, str], str]:
    """Return the scan fields, the one-time credentials, and an error."""

    if not isinstance(body, dict):
        return None, {}, "Invalid scan."
    target = body.get("target") or "repo"
    if target not in {"repo", "image"}:
        return None, {}, "Invalid scan type."
    raw_tools = body.get("tools")
    tools = [tool for tool in REPO_TOOLS if tool in (raw_tools or [])]
    if target == "image":
        image = str(body.get("image") or "").strip()
        if not valid_image_ref(image) or image.startswith("sha256:"):
            return None, {}, "Image name is invalid. Use a name like nginx:1.27."
        if not _image_host_ok(image):
            return None, {}, "Use a full registry name like registry.example.com/app:1."
        secrets, error = _registry_secrets(body)
        if error:
            return None, {}, error
        fields = {"target": "image", "repo": "", "image": image, "tools": ["trivy"]}
        return fields, secrets, ""
    repo = str(body.get("repo") or "").strip()
    if not valid_repo(repo) or "." not in (urlparse(repo).hostname or ""):
        return None, {}, "Repository URL must be a full http or https address."
    if not tools:
        return None, {}, "Select at least one tool."
    secrets, error = _repo_secrets(body, repo)
    if error:
        return None, {}, error
    fields = {"target": "repo", "repo": repo, "image": "", "tools": tools}
    return fields, secrets, ""


def _image_host_ok(image: str) -> bool:
    """Docker Hub names pass. A registry host must look like a real domain."""

    host = registry_host(image)
    return host is None or "." in host


def _token(value: Any, limit: int) -> tuple[str, str]:
    if value is None or value == "":
        return "", ""
    if not isinstance(value, str) or len(value) > limit:
        return "", "The token is too long."
    text = value.strip()
    if any(ord(ch) < 33 for ch in text):
        return "", "The token cannot contain spaces."
    return text, ""


def _repo_secrets(body: dict[str, Any], repo: str) -> tuple[dict[str, str], str]:
    token, error = _token(body.get("token"), 256)
    if error or not token:
        return {}, error
    host = (urlparse(repo).hostname or "").lower()
    style = "basic" if host in {"github.com", "www.github.com"} else "header"
    return {"clone_token": token, "clone_style": style}, ""


def _registry_secrets(body: dict[str, Any]) -> tuple[dict[str, str], str]:
    username, error = _token(body.get("registry_username"), 128)
    if error:
        return {}, "The registry username cannot contain spaces."
    password, error = _token(body.get("registry_password"), 256)
    if error:
        return {}, error
    if bool(username) != bool(password):
        return {}, "Enter both the registry username and the token."
    if not password:
        return {}, ""
    return {"registry_username": username, "registry_password": password}, ""


def _when(scan: dict[str, Any]) -> datetime | None:
    raw = str(scan.get("created_at") or "").replace(" UTC", "").strip()
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def recent_count(
    items: list[dict[str, Any]],
    guest: str,
    ip: str,
    now: datetime | None = None,
) -> int:
    """Count guest scans from this session or this address in the last hour."""

    clock = now or datetime.now(UTC)
    total = 0
    for item in items:
        if not item.get("guest"):
            continue
        if item.get("guest") != guest and item.get("guest_ip") != ip:
            continue
        when = _when(item)
        if when is not None and clock - when <= timedelta(hours=1):
            total += 1
    return total


def expired(scan: dict[str, Any], now: datetime | None = None) -> bool:
    """Return whether a guest scan is older than ``KEEP_DAYS``."""

    if not scan.get("guest"):
        return False
    when = _when(scan)
    if when is None:
        return False
    return (now or datetime.now(UTC)) - when > timedelta(days=KEEP_DAYS)


def present_guest_scan(scan: dict[str, Any], *, summary: bool) -> dict[str, Any]:
    """Return what the guest who started the scan may read."""

    from security_console.tool_results import normalize_tool_results

    findings = list(scan.get("findings") or [])
    tools = list(scan.get("tools") or [])
    shown: dict[str, Any] = {
        "id": scan.get("id"),
        "target": scan.get("target") or "repo",
        "repo": scan.get("repo") or "",
        "image": scan.get("image") or "",
        "tools": tools,
        "status": scan.get("status") or "",
        "phase": scan.get("phase") or "",
        "error": scan.get("error") or "",
        "created_at": scan.get("created_at") or "",
        "finished_at": scan.get("finished_at") or "",
        "private": bool(scan.get("private")),
        "finding_count": len(findings),
        "severity": severity_counts(findings),
        "tool_results": normalize_tool_results(
            tools,
            scan.get("tool_results"),
            str(scan.get("error") or ""),
            findings,
            str(scan.get("status") or ""),
        ),
    }
    position = scan.get("queue_position")
    if position is not None:
        shown["queue_position"] = position
    if not summary:
        shown["findings"] = findings
    return shown
