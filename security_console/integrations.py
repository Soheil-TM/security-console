"""Admin-configured GitLab and private-registry connections.

The browser receives the address and whether a token is saved. The token
and CA certificate stay in the database and are sent only to the scanner.
"""

from __future__ import annotations

import base64
import json
import ssl
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import re

import psycopg
from flask import Flask, Response, g, jsonify, request
from psycopg.errors import UniqueViolation

from security_console import db
from security_console.access import project_key
from security_console.images import valid_image_ref
from security_console.repos import clone_pins, valid_repo

Reply = Response | tuple[Response, int]
_KINDS = {"gitlab", "registry"}
_MAX_NAME = 80
_MAX_SECRET = 256
_MAX_CA = 12000
_MAX_CONNECTIONS = 10


def install_integrations(app: Flask) -> None:
    """Attach connection routes. Mutations require an admin."""

    @app.get("/api/integrations")
    def list_connections() -> Reply:
        return _call(app, _list_connections)

    @app.post("/api/integrations")
    def create_connection() -> Reply:
        return _call(app, lambda: _create_connection(app))

    @app.patch("/api/integrations/<int:integration_id>")
    def update_connection(integration_id: int) -> Reply:
        return _call(app, lambda: _update_connection(app, integration_id))

    @app.delete("/api/integrations/<int:integration_id>")
    def delete_connection(integration_id: int) -> Reply:
        return _call(app, lambda: _delete_connection(app, integration_id))

    @app.post("/api/integrations/<int:integration_id>/test")
    def test_connection(integration_id: int) -> Reply:
        return _call(app, lambda: _test_connection(integration_id))

    @app.get("/api/integrations/<int:integration_id>/projects")
    def list_projects(integration_id: int) -> Reply:
        return _call(app, lambda: _list_projects(integration_id))


def parse_integration(
    body: Any,
    *,
    secret_required: bool,
) -> tuple[dict[str, Any] | None, str]:
    """Validate a connection form. The error is empty when the form is valid."""

    if not isinstance(body, dict):
        return None, "The connection details are incomplete."
    kind = body.get("kind")
    name = body.get("name")
    base = body.get("base_url")
    username = body.get("username") or ""
    secret = body.get("secret") or ""
    ca_cert = body.get("ca_cert") or ""
    if not isinstance(name, str) or not isinstance(base, str):
        return None, "The connection details are incomplete."
    if not isinstance(username, str) or not isinstance(secret, str):
        return None, "The connection details are incomplete."
    if not isinstance(ca_cert, str):
        return None, "The connection details are incomplete."
    if kind not in _KINDS:
        return None, "Connection type is invalid."
    name = " ".join(name.split())
    if not name or len(name) > _MAX_NAME or _has_control(name):
        return None, "Connection name is invalid."
    address = _address(kind, base)
    if address is None:
        return None, "Address is invalid."
    if kind == "registry":
        username = username.strip()
        if not username or len(username) > 128 or _has_control(username):
            return None, "Username is invalid."
    else:
        username = ""
    if secret and not _valid_secret(secret):
        return None, "Token is invalid."
    if secret_required and not secret:
        return None, "Token is required."
    certificate = _certificate(ca_cert)
    if certificate is None:
        return None, "Certificate is invalid."
    return {
        "kind": kind,
        "name": name,
        "base_url": address,
        "username": username,
        "secret": secret,
        "ca_cert": certificate,
        "clear_ca": bool(body.get("clear_ca")),
    }, ""


def public_integration(row: dict[str, Any]) -> dict[str, Any]:
    """Return one connection without its token or certificate."""

    return {
        "id": int(row["id"]),
        "kind": row["kind"],
        "name": row["name"],
        "base_url": row["base_url"],
        "username": row.get("username") or "",
        "has_secret": bool(row.get("has_secret")),
        "has_ca": bool(row.get("has_ca")),
    }


def credentials_for(scan: dict[str, Any]) -> dict[str, str]:
    """Return scanner secrets when the target belongs to a saved connection."""

    rows = db.integration_secrets()
    if scan.get("target") == "image":
        match = matching_registry(str(scan.get("image") or ""), rows)
        if match is None or not match.get("secret"):
            return {}
        found = {
            "registry_username": str(match.get("username") or ""),
            "registry_password": str(match["secret"]),
        }
    else:
        match = matching_gitlab(str(scan.get("repo") or ""), rows)
        if match is None or not match.get("secret"):
            return {}
        found = {"clone_token": str(match["secret"])}
    ca_cert = str(match.get("ca_cert") or "")
    if ca_cert:
        found["ca_cert"] = ca_cert
    return found


def matching_gitlab(repo: str, rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the GitLab connection whose address contains this repository."""

    found = None
    best = -1
    for row in rows:
        if row.get("kind") != "gitlab":
            continue
        base = str(row.get("base_url") or "").rstrip("/")
        if repo == base or repo.startswith(base + "/"):
            if len(base) > best:
                found = row
                best = len(base)
    return found


def matching_registry(
    image: str,
    rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the registry connection whose host prefixes this image."""

    found = None
    best = -1
    for row in rows:
        if row.get("kind") != "registry":
            continue
        prefix = registry_prefix(str(row.get("base_url") or ""))
        if prefix and (image == prefix or image.startswith(prefix + "/")):
            if len(prefix) > best:
                found = row
                best = len(prefix)
    return found


def registry_prefix(base: str) -> str:
    """Return the host and optional path used in an image name."""

    text = base.strip().rstrip("/")
    if text.startswith("https://"):
        text = text[len("https://") :]
    elif text.startswith("http://"):
        text = text[len("http://") :]
    return text


def join_registry_image(base: str, name: str) -> str | None:
    """Prefix a short image name with the registry. A full name stays whole."""

    prefix = registry_prefix(base)
    text = name.strip()
    if not prefix or not text:
        return None
    full = text if text.startswith(prefix + "/") else prefix + "/" + text.lstrip("/")
    if not valid_image_ref(full):
        return None
    return full


def _call(app: Flask, action: Callable[[], Reply]) -> Reply:
    try:
        return action()
    except psycopg.Error:
        app.logger.error("integration database unavailable")
        return jsonify({"error": "Sign-in is unavailable."}), 503


def _list_connections() -> Reply:
    rows = [public_integration(row) for row in db.list_integrations()]
    if not _admin():
        for row in rows:
            row["username"] = ""
    return jsonify(rows)


def _create_connection(app: Flask) -> Reply:
    if not _admin():
        return jsonify({"error": "You do not have permission."}), 403
    parsed, error = parse_integration(
        request.get_json(silent=True),
        secret_required=True,
    )
    if parsed is None:
        return jsonify({"error": error}), 400
    if not _reachable(parsed["base_url"], parsed["kind"]):
        return jsonify({"error": "That address cannot be used."}), 400
    if db.count_integrations() >= _MAX_CONNECTIONS:
        return jsonify({"error": "Too many connections."}), 409
    try:
        integration_id = db.insert_integration(
            parsed["kind"],
            parsed["name"],
            parsed["base_url"],
            parsed["username"],
            parsed["secret"],
            parsed["ca_cert"],
        )
    except UniqueViolation:
        return jsonify({"error": "That name is already used."}), 409
    app.logger.info("integration created id=%s", integration_id)
    created = _public_by_id(integration_id)
    if created is None:
        return jsonify({"error": "Could not save the connection."}), 500
    return jsonify(created), 201


def _update_connection(app: Flask, integration_id: int) -> Reply:
    if not _admin():
        return jsonify({"error": "You do not have permission."}), 403
    current = db.get_integration(integration_id)
    if current is None:
        return jsonify({"error": "Connection not found."}), 404
    parsed, error = parse_integration(
        request.get_json(silent=True),
        secret_required=False,
    )
    if parsed is None:
        return jsonify({"error": error}), 400
    if not _reachable(parsed["base_url"], parsed["kind"]):
        return jsonify({"error": "That address cannot be used."}), 400
    secret = parsed["secret"] or None
    ca_cert: str | None
    if parsed["clear_ca"]:
        ca_cert = ""
    elif parsed["ca_cert"]:
        ca_cert = parsed["ca_cert"]
    else:
        ca_cert = None
    try:
        db.update_integration(
            integration_id,
            parsed["kind"],
            parsed["name"],
            parsed["base_url"],
            parsed["username"],
            secret,
            ca_cert,
        )
    except UniqueViolation:
        return jsonify({"error": "That name is already used."}), 409
    app.logger.info("integration updated id=%s", integration_id)
    updated = _public_by_id(integration_id)
    if updated is None:
        return jsonify({"error": "Connection not found."}), 404
    return jsonify(updated)


def _delete_connection(app: Flask, integration_id: int) -> Reply:
    if not _admin():
        return jsonify({"error": "You do not have permission."}), 403
    db.delete_integration(integration_id)
    app.logger.info("integration deleted id=%s", integration_id)
    return jsonify({"ok": True})


def _test_connection(integration_id: int) -> Reply:
    if not _admin():
        return jsonify({"error": "You do not have permission."}), 403
    current = db.get_integration(integration_id)
    if current is None:
        return jsonify({"error": "Connection not found."}), 404
    try:
        detail = _probe(current)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"ok": True, "detail": detail})


def _list_projects(integration_id: int) -> Reply:
    user = g.user
    purpose = request.args.get("purpose") or "scan"
    if purpose not in {"scan", "edit"}:
        return jsonify({"error": "Request rejected."}), 400
    if purpose == "edit" and user.get("role") not in {"admin", "developer"}:
        return jsonify({"error": "You do not have permission."}), 403
    current = db.get_integration(integration_id)
    if current is None:
        return jsonify({"error": "Connection not found."}), 404
    try:
        if current["kind"] == "gitlab":
            projects = _gitlab_projects(current)
        else:
            projects = _registry_names(current)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502
    if purpose == "scan" and user.get("role") != "admin":
        keys = db.group_project_keys(int(user["id"]))
        projects = [
            item
            for item in projects
            if _project_key(current["kind"], item) in keys
        ]
    return jsonify(projects)


def _probe(current: dict[str, Any]) -> str:
    if current["kind"] == "gitlab":
        status, _body = _http(
            current["base_url"].rstrip("/") + "/api/v4/projects?simple=true&per_page=1",
            headers={"PRIVATE-TOKEN": str(current["secret"])},
            ca_pem=str(current.get("ca_cert") or ""),
        )
        if status != 200:
            raise RuntimeError("GitLab rejected the token.")
        return "GitLab accepted the token."
    return _probe_registry(current)


def _probe_registry(current: dict[str, Any]) -> str:
    """Accept Basic /v2/ or GitLab-style Bearer challenge."""

    ca_pem = str(current.get("ca_cert") or "")
    username = str(current.get("username") or "")
    secret = str(current.get("secret") or "")
    url = _registry_url(str(current.get("base_url") or ""))
    status, _body, challenge = _http_detail(
        url,
        headers=_basic(username, secret),
        ca_pem=ca_pem,
    )
    if status == 200:
        return "Registry accepted the account."
    if status == 401 and challenge:
        token = _registry_bearer_token(challenge, username, secret, ca_pem)
        if token:
            status, _body, _chal = _http_detail(
                url,
                headers={"Authorization": "Bearer " + token},
                ca_pem=ca_pem,
            )
            if status == 200:
                return "Registry accepted the account."
    raise RuntimeError("The registry rejected the account.")


def _registry_bearer_token(
    challenge: str,
    username: str,
    password: str,
    ca_pem: str,
) -> str:
    params = {
        key: value
        for key, value in re.findall(r'(\w+)="([^"]*)"', challenge)
    }
    realm = params.get("realm") or ""
    if not realm.startswith("https://") and not realm.startswith("http://"):
        return ""
    if clone_pins(_origin(realm)) is None:
        return ""
    query = dict(parse_qsl(urlparse(realm).query, keep_blank_values=True))
    if params.get("service"):
        query["service"] = params["service"]
    if params.get("scope"):
        query["scope"] = params["scope"]
    elif "scope" not in query:
        query["scope"] = "registry:catalog:*"
    if username:
        query["account"] = username
    parsed = urlparse(realm)
    token_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urlencode(query),
            "",
        )
    )
    status, body = _http(
        token_url,
        headers=_basic(username, password),
        ca_pem=ca_pem,
    )
    if status != 200 or not isinstance(body, dict):
        return ""
    token = str(body.get("token") or body.get("access_token") or "")
    return token.strip()


def _gitlab_projects(current: dict[str, Any]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    base = current["base_url"].rstrip("/")
    for page in range(1, 6):
        status, body = _http(
            base + "/api/v4/projects?simple=true&archived=false&per_page=100&page="
            + str(page),
            headers={"PRIVATE-TOKEN": str(current["secret"])},
            ca_pem=str(current.get("ca_cert") or ""),
        )
        if status != 200 or not isinstance(body, list):
            raise RuntimeError("GitLab rejected the token.")
        if not body:
            break
        for item in body:
            if not isinstance(item, dict):
                continue
            url = str(item.get("http_url_to_repo") or "")
            path = str(item.get("path_with_namespace") or "")
            if not url.startswith(base + "/") or not path:
                continue
            found.append({"path": path, "url": url})
        if len(body) < 100:
            break
    return found


def _registry_names(current: dict[str, Any]) -> list[dict[str, str]]:
    try:
        status, body = _http(
            _registry_url(current["base_url"]).rstrip("/") + "/_catalog",
            headers=_basic(
                str(current.get("username") or ""),
                str(current["secret"]),
            ),
            ca_pem=str(current.get("ca_cert") or ""),
        )
    except RuntimeError:
        return []
    if status != 200 or not isinstance(body, dict):
        return []
    names = body.get("repositories")
    if not isinstance(names, list):
        return []
    prefix = registry_prefix(current["base_url"])
    rows: list[dict[str, str]] = []
    for name in names[:100]:
        if not isinstance(name, str) or not name:
            continue
        rows.append({"path": name, "url": prefix + "/" + name})
    return rows


def _http(
    url: str,
    *,
    headers: dict[str, str],
    ca_pem: str,
) -> tuple[int, Any]:
    status, body, _challenge = _http_detail(url, headers=headers, ca_pem=ca_pem)
    return status, body


def _http_detail(
    url: str,
    *,
    headers: dict[str, str],
    ca_pem: str,
) -> tuple[int, Any, str]:
    if clone_pins(_origin(url)) is None:
        raise RuntimeError("That address cannot be used.")
    context = _ssl_context(ca_pem)
    request_headers = {"Accept": "application/json", "User-Agent": "security-console"}
    request_headers.update(headers)
    outgoing = urllib.request.Request(url, headers=request_headers, method="GET")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _RefuseRedirect(),
    )
    try:
        with opener.open(outgoing, timeout=15) as response:
            raw = response.read(500_000)
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        challenge = str(exc.headers.get("Www-Authenticate") or "")
        exc.read(2000)
        return int(exc.code), None, challenge
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = str(
            exc.reason if isinstance(exc, urllib.error.URLError) else exc
        )
        if "CERTIFICATE_VERIFY_FAILED" in reason or "certificate verify failed" in reason.lower():
            raise RuntimeError(
                "TLS certificate could not be verified. "
                "Paste the registry CA certificate in the connection form."
            ) from exc
        raise RuntimeError("The connection failed.") from exc
    if not raw:
        return status, None, ""
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return status, None, ""
    return status, parsed, ""


def _ssl_context(ca_pem: str) -> ssl.SSLContext:
    if not ca_pem:
        return ssl.create_default_context()
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(ca_pem)
        handle.flush()
        return ssl.create_default_context(cafile=handle.name)


def _origin(url: str) -> str:
    parsed = urlparse(url)
    port = ""
    if parsed.port:
        port = ":" + str(parsed.port)
    return parsed.scheme + "://" + (parsed.hostname or "") + port + "/"


def _registry_url(base: str) -> str:
    raw = base.strip().rstrip("/")
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw + "/v2/"
    return "https://" + raw + "/v2/"


def _basic(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode((username + ":" + password).encode()).decode("ascii")
    return {"Authorization": "Basic " + token}


def _address(kind: str, value: str) -> str | None:
    text = value.strip().rstrip("/")
    if not text or len(text) > 300 or _has_control(text):
        return None
    if kind == "gitlab":
        if not valid_repo(text + "/group/project.git"):
            return None
        return text
    prefix = registry_prefix(text)
    if not valid_image_ref(prefix + "/name:1"):
        return None
    return text


def _reachable(base: str, kind: str) -> bool:
    if kind == "gitlab":
        return clone_pins(base + "/group/project.git") is not None
    probe = _registry_url(base)
    return clone_pins(_origin(probe)) is not None


def _project_key(kind: str, item: dict[str, str]) -> str:
    if kind == "registry":
        return project_key({"target": "image", "image": item["url"], "repo": ""})
    return project_key({"target": "repo", "repo": item["url"], "image": ""})


def _public_by_id(integration_id: int) -> dict[str, Any] | None:
    for row in db.list_integrations():
        if int(row["id"]) == integration_id:
            return public_integration(row)
    return None


def _admin() -> bool:
    user = getattr(g, "user", None)
    return isinstance(user, dict) and user.get("role") == "admin"


def _valid_secret(value: str) -> bool:
    if len(value) < 8 or len(value) > _MAX_SECRET:
        return False
    return not any(ord(ch) < 32 or ch.isspace() for ch in value)


def _certificate(value: str) -> str | None:
    text = value.strip()
    if not text:
        return ""
    if len(text) > _MAX_CA or "PRIVATE KEY" in text:
        return None
    if "BEGIN CERTIFICATE" not in text or "END CERTIFICATE" not in text:
        return None
    if any(ord(ch) < 9 or (13 < ord(ch) < 32) for ch in text):
        return None
    return text + "\n"


def _has_control(value: str) -> bool:
    return any(ord(ch) < 32 for ch in value)


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Stop before a token can be sent to another host."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise RuntimeError("The server redirected the request.")
