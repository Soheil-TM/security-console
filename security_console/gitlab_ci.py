"""Resolve GitLab project identity for CI auto-provisioning.

Client-supplied repository URLs are never used as the clone source. The
Console looks up the project through an allowlisted Integration and the
GitLab Projects API, then verifies the requested commit belongs there.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote, urlparse

from security_console import db
from security_console.repos import clone_pins, normalize_commit_sha, valid_repo

log = logging.getLogger("security_console")

# Opaque client-facing message for host / token / project availability failures.
UNAVAILABLE = "Project not available for scanning."

_CACHE_TTL_SECONDS = 45.0
_CACHE_MAX = 256
_cache_lock = threading.Lock()
_resolve_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class GitLabCiError(Exception):
    """Mapped to an HTTP status for the CI scan API."""

    def __init__(self, message: str, status: int, *, reason: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.reason = reason or message


def _unavailable(reason: str) -> GitLabCiError:
    log.info("ci gitlab unavailable reason=%s", reason)
    return GitLabCiError(UNAVAILABLE, 403, reason=reason)


def normalize_gitlab_base_url(value: str) -> str | None:
    """Return scheme://host[:port] with no trailing slash, or None if invalid."""

    text = str(value or "").strip()
    if not text or len(text) > 300:
        return None
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    if port is None:
        origin = f"{parsed.scheme}://{host}"
    else:
        origin = f"{parsed.scheme}://{host}:{port}"
    # Structural allow only; DNS / clone_pins run when calling GitLab or cloning.
    if not valid_repo(origin + "/group/project.git"):
        return None
    return origin


def slug_for_gitlab(base_url: str, gitlab_project_id: int) -> str:
    """Stable console slug from instance fingerprint + GitLab project id."""

    digest = hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:8]
    return f"gl-{digest}-{int(gitlab_project_id)}"


def find_gitlab_integration(base_url: str) -> dict[str, Any] | None:
    """Return the Integration whose normalized base_url matches."""

    want = normalize_gitlab_base_url(base_url)
    if want is None:
        return None
    for row in db.integration_secrets():
        if row.get("kind") != "gitlab":
            continue
        have = normalize_gitlab_base_url(str(row.get("base_url") or ""))
        if have == want and str(row.get("secret") or "").strip():
            return row
    return None


def resolve_gitlab_project(
    *,
    gitlab_base_url: str,
    gitlab_project_id: int,
    requested_sha: str,
) -> dict[str, Any]:
    """Verify allowlist + project + commit; return canonical fields for upsert.

    Returns keys: base_url, gitlab_project_id, path, name, repo_url, sha
    """

    base = normalize_gitlab_base_url(gitlab_base_url)
    if base is None:
        raise _unavailable("gitlab_base_url_invalid")
    if not isinstance(gitlab_project_id, int) or gitlab_project_id < 1:
        raise GitLabCiError("gitlab_project_id is invalid.", 400)
    sha = normalize_commit_sha(requested_sha)
    if not sha:
        raise GitLabCiError("Commit SHA is invalid.", 400)

    integration = find_gitlab_integration(base)
    if integration is None:
        raise _unavailable("gitlab_instance_not_allowlisted")

    cache_key = f"{base}|{gitlab_project_id}|{sha}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    token = str(integration.get("secret") or "")
    ca_pem = str(integration.get("ca_cert") or "")
    try:
        project = _gitlab_get_json(
            f"{base}/api/v4/projects/{int(gitlab_project_id)}",
            token=token,
            ca_pem=ca_pem,
        )
    except GitLabCiError as exc:
        if exc.status == 403 and exc.message == UNAVAILABLE:
            raise
        raise _unavailable(exc.reason) from None
    if project is None:
        raise _unavailable("gitlab_project_not_found")
    path = str(project.get("path_with_namespace") or "").strip()
    name = str(project.get("name_with_namespace") or project.get("name") or path).strip()
    repo_url = str(project.get("http_url_to_repo") or "").strip()
    if not path or not repo_url:
        raise _unavailable("gitlab_project_incomplete")
    if not valid_repo(repo_url):
        log.info("ci gitlab clone url not http(s) project_id=%s", gitlab_project_id)
        raise GitLabCiError(
            "GitLab project has no usable http(s) clone URL.",
            400,
            reason="gitlab_clone_url_not_https",
        )
    # Commit must exist on this project (fork/MR SHAs from other projects fail).
    try:
        commit = _gitlab_get_json(
            f"{base}/api/v4/projects/{int(gitlab_project_id)}"
            f"/repository/commits/{quote(sha, safe='')}",
            token=token,
            ca_pem=ca_pem,
        )
    except GitLabCiError as exc:
        if exc.status == 403 and exc.message == UNAVAILABLE:
            raise
        raise _unavailable(exc.reason) from None
    if commit is None:
        raise GitLabCiError("Commit SHA is invalid.", 400, reason="commit_not_in_project")

    resolved = {
        "base_url": base,
        "gitlab_project_id": int(gitlab_project_id),
        "path": path,
        "name": name[:80] or path[:80],
        "repo_url": repo_url,
        "sha": sha,
    }
    _cache_put(cache_key, resolved)
    return resolved


def clear_resolve_cache() -> None:
    """Test helper: drop the in-process GitLab resolve cache."""

    with _cache_lock:
        _resolve_cache.clear()


def _cache_get(key: str) -> dict[str, Any] | None:
    now = time.monotonic()
    with _cache_lock:
        row = _resolve_cache.get(key)
        if row is None:
            return None
        expires, payload = row
        if expires < now:
            _resolve_cache.pop(key, None)
            return None
        return dict(payload)


def _cache_put(key: str, payload: dict[str, Any]) -> None:
    now = time.monotonic()
    with _cache_lock:
        if len(_resolve_cache) >= _CACHE_MAX:
            stale = [k for k, (exp, _) in _resolve_cache.items() if exp < now]
            for k in stale:
                _resolve_cache.pop(k, None)
            while len(_resolve_cache) >= _CACHE_MAX:
                _resolve_cache.pop(next(iter(_resolve_cache)))
        _resolve_cache[key] = (now + _CACHE_TTL_SECONDS, dict(payload))


def _gitlab_get_json(
    url: str,
    *,
    token: str,
    ca_pem: str,
) -> dict[str, Any] | None:
    """GET JSON from GitLab. 404 → None. Auth/network failures → opaque 403."""

    if clone_pins(_origin(url)) is None:
        raise _unavailable("gitlab_dns_or_ssrf_blocked")
    context = _ssl_context(ca_pem)
    headers = {
        "Accept": "application/json",
        "User-Agent": "security-console",
        "PRIVATE-TOKEN": token,
    }
    outgoing = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(outgoing, context=context, timeout=20) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            raw = resp.read(2_000_000)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in {401, 403}:
            raise _unavailable("gitlab_token_rejected") from None
        raise _unavailable(f"gitlab_http_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise _unavailable("gitlab_unreachable") from None
    if status == 404:
        return None
    if status >= 400:
        raise _unavailable(f"gitlab_http_{status}")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _unavailable("gitlab_invalid_json") from None
    if not isinstance(body, dict):
        raise _unavailable("gitlab_invalid_json")
    return body


def _origin(url: str) -> str:
    parsed = urlparse(url)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{(parsed.hostname or '').lower()}{port}/"


def _ssl_context(ca_pem: str) -> Any:
    import ssl
    import tempfile

    if not ca_pem.strip():
        return ssl.create_default_context()
    context = ssl.create_default_context()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as handle:
        handle.write(ca_pem)
        path = handle.name
    context.load_verify_locations(cafile=path)
    return context
