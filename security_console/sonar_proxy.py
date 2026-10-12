"""Open SonarQube through the console for accounts that are allowed in.

The SonarQube port stays on the Compose network. A browser reaches it only
as ``/sonar/`` on the console, and only after the session is checked.
"""

from __future__ import annotations

import gzip
import os
import urllib.error
import urllib.request
import zlib
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, Response, request

from security_console.auth import sonar_page_user

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}
_LOCAL_HOSTS = {"sonarqube", "localhost", "127.0.0.1"}


def install_sonar_proxy(app: Flask) -> None:
    """Attach the SonarQube reverse proxy."""

    methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

    @app.before_request
    def _sonar_body_limit() -> None:
        path = request.path
        if path == "/sonar" or path.startswith("/sonar/"):
            request.max_content_length = 32 * 1024 * 1024

    @app.route("/sonar", defaults={"subpath": ""}, methods=methods)
    @app.route("/sonar/", defaults={"subpath": ""}, methods=methods)
    @app.route("/sonar/<path:subpath>", methods=methods)
    def sonar_proxy(subpath: str) -> Response:
        gated = sonar_page_user()
        if isinstance(gated, Response):
            return gated
        if ".." in subpath.split("/"):
            return Response("Request rejected.", status=400)
        return _forward(subpath)


def browser_sonar_path(value: str) -> str:
    """Return a same-site SonarQube path for a stored or upstream URL."""

    text = (value or "").strip()
    if not text:
        return "/sonar/"
    if text.startswith("/") and not text.startswith("//"):
        if text == "/sonar" or text.startswith("/sonar/"):
            return text
        return "/sonar" + text
    parts = urlsplit(text)
    if parts.hostname not in _LOCAL_HOSTS:
        return text
    path = parts.path or "/"
    if path == "/sonar" or path.startswith("/sonar/"):
        rewritten = path
    else:
        rewritten = "/sonar" + (path if path.startswith("/") else "/" + path)
    return urlunsplit(("", "", rewritten, parts.query, parts.fragment))


def _forward(subpath: str) -> Response:
    upstream = os.environ.get("SONAR_UPSTREAM", "http://sonarqube:9000").rstrip("/")
    path = "/sonar/" + subpath if subpath else "/sonar/"
    query = request.query_string.decode("ascii", "replace")
    target = upstream + path + (("?" + query) if query else "")
    headers = {
        "Host": request.host,
        "Accept-Encoding": "identity",
        "X-Forwarded-Proto": request.scheme,
        "X-Forwarded-Host": request.host,
        "X-Forwarded-Prefix": "/sonar",
    }
    for name, value in request.headers.items():
        if name.lower() in _HOP or name.lower() in {
            "host",
            "authorization",
            "accept-encoding",
        }:
            continue
        headers[name] = value
    body = request.get_data() if request.method not in {"GET", "HEAD"} else None
    opener = urllib.request.build_opener(_NoRedirect())
    call = urllib.request.Request(
        target,
        data=body,
        headers=headers,
        method=request.method,
    )
    try:
        received = opener.open(call, timeout=60)
        status = int(received.status)
    except urllib.error.HTTPError as exc:
        received = exc
        status = int(exc.code)
    except urllib.error.URLError:
        return Response("SonarQube is not available.", status=502)
    payload, dropped = _unwrap(received.read(), received.headers)
    response = Response(payload, status=status)
    for key, value in received.headers.items():
        lowered = key.lower()
        if lowered in _HOP or lowered in dropped:
            continue
        if lowered == "location":
            response.headers[key] = browser_sonar_path(value)
            continue
        if lowered == "set-cookie":
            response.headers.add(key, _cookie(value))
            continue
        response.headers[key] = value
    return response


def _unwrap(payload: bytes, headers: object) -> tuple[bytes, set[str]]:
    """Return a body the browser can read without a second decompression."""

    getter = getattr(headers, "get", None)
    encoding = ""
    if callable(getter):
        encoding = str(getter("Content-Encoding", "") or "").lower()
    if encoding == "gzip":
        return gzip.decompress(payload), {"content-encoding"}
    if encoding == "deflate":
        return zlib.decompress(payload), {"content-encoding"}
    return payload, set()


def _cookie(value: str) -> str:
    parts = []
    for item in value.split(";"):
        name = item.strip().split("=", 1)[0].lower()
        if name == "domain":
            continue
        parts.append(item.strip())
    return "; ".join(parts)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None
