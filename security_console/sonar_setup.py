"""Create the SonarQube scanner token once, and again only when an admin asks.

The token file stays on the host. A full file is checked, not replaced.
Revoking the named token is the admin rotate action.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

TOKEN_NAME = "security-console-scanner"
_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
_STATUSES = frozenset(
    {
        "ready",
        "waiting",
        "admin_password_unknown",
        "token_name_taken",
        "token_rejected",
    }
)
_WAITING = "SonarQube setup has not finished."
_NOT_READY = "SonarQube is not ready."
_PASSWORD = "The SonarQube admin password in the secrets file was rejected."
_PASSWORD_DB = "SonarQube could not replace the admin password."
_ITERATIONS = 100000
_NAME_TAKEN = (
    "A scanner token already exists in SonarQube. "
    "Rotate it to replace the empty file."
)
_REJECTED = "The saved token was rejected. Rotate it to issue a new one."
_READY = "SonarQube is ready."
_PROJECT = "The SonarQube project key was rejected."
_TOKEN = "SonarQube rejected the new token."

Exchange = Callable[
    [str, str, dict[str, str], bytes | None],
    tuple[int, list[tuple[str, str]], bytes],
]


class SetupDown(Exception):
    """SonarQube did not answer."""


def read_public_status() -> dict[str, str]:
    """Return the setup state an admin may see. Secrets stay in their files."""

    path = _status_path()
    if not path.is_file():
        return {"status": "waiting", "detail": _WAITING, "expires_at": ""}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "waiting", "detail": _WAITING, "expires_at": ""}
    if not isinstance(payload, dict):
        return {"status": "waiting", "detail": _WAITING, "expires_at": ""}
    status = payload.get("status")
    if not isinstance(status, str) or status not in _STATUSES:
        status = "waiting"
    detail = payload.get("detail")
    expires = payload.get("expires_at")
    return {
        "status": status,
        "detail": detail if isinstance(detail, str) else "",
        "expires_at": expires if isinstance(expires, str) else "",
    }


def run_setup(
    *,
    rotate: bool = False,
    exchange: Exchange | None = None,
    sleep: Callable[[float], None] = time.sleep,
    attempts: int = 36,
    reset_admin: Callable[[str], bool] | None = None,
) -> str:
    """Leave a usable token and project, or a status the admin page can show."""

    with _lock() as handle:
        return _setup(
            rotate,
            exchange or _urllib_exchange,
            sleep,
            attempts,
            handle,
            reset_admin or _reset_admin_password,
        )


def main() -> None:
    """Run one setup. Exit after the status file is written."""

    try:
        status = run_setup(rotate=os.environ.get("SONAR_INIT_ROTATE") == "1")
    except Exception:
        print("sonar setup error", file=sys.stderr)
        _write_status("waiting", _WAITING)
        status = "waiting"
    print(f"sonar setup {status}", flush=True)
    if status == "waiting":
        raise SystemExit(1)


class _Client:
    def __init__(self, base: str, exchange: Exchange) -> None:
        self.base = base.rstrip("/")
        self.exchange = exchange
        self.cookies: dict[str, str] = {}

    def call(
        self,
        method: str,
        path: str,
        fields: dict[str, str] | None = None,
        bearer: str = "",
    ) -> tuple[int, dict[str, Any]]:
        headers = {"Accept": "application/json"}
        body = None
        if fields is not None:
            body = urllib.parse.urlencode(fields).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self.cookies.items()
            )
        xsrf = self.cookies.get("XSRF-TOKEN", "")
        if xsrf and method != "GET":
            headers["X-XSRF-TOKEN"] = xsrf
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        try:
            status, response_headers, raw = self.exchange(
                method,
                self.base + path,
                headers,
                body,
            )
        except (OSError, TimeoutError) as exc:
            raise SetupDown from exc
        for name, value in response_headers:
            if name.lower() == "set-cookie":
                _keep_cookie(self.cookies, value)
        if not raw:
            return status, {}
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            return status, {}
        return status, payload


def _setup(
    rotate: bool,
    exchange: Exchange,
    sleep: Callable[[float], None],
    attempts: int,
    handle: Any,
    reset_admin: Callable[[str], bool],
) -> str:
    key = _project_key()
    if key is None:
        return _write_status("waiting", _PROJECT, handle=handle)
    client = _Client(_base_url(), exchange)
    if not _wait_until_up(client, sleep, attempts):
        return _write_status("waiting", _NOT_READY, handle=handle)
    signed_in = _sign_in(client, reset_admin)
    if signed_in != "ok":
        if signed_in == "down":
            return _write_status("waiting", _NOT_READY, handle=handle)
        detail = _PASSWORD_DB if signed_in == "denied_empty" else _PASSWORD
        return _write_status("admin_password_unknown", detail, handle=handle)
    if rotate:
        _revoke(client)
        return _issue(client, key, handle)
    token = _read_secret(_token_path())
    if not token:
        return _issue(client, key, handle)
    try:
        valid = _token_valid(client, token)
    except SetupDown:
        return _write_status("waiting", _NOT_READY, handle=handle)
    if not valid:
        return _write_status("token_rejected", _REJECTED, handle=handle)
    return _finish_project(client, key, "", handle)


def _sign_in(client: _Client, reset_admin: Callable[[str], bool]) -> str:
    password = _read_secret(_password_path())
    if password:
        saved = _sign_in_with_saved(client, password)
        if saved != "denied":
            return saved
        return _replace_unknown_password(client, reset_admin)
    admin = _login(client, "admin")
    if admin == "ok":
        generated = _new_password()
        _write_private(_password_path(), generated)
        changed = _change_from_admin(client, generated)
        if changed == "down":
            return "down"
        if changed != "ok":
            _write_private(_password_path(), "")
            return "denied_empty"
        return "ok"
    if admin != "denied":
        return admin
    return _replace_unknown_password(client, reset_admin)


def _replace_unknown_password(
    client: _Client,
    reset_admin: Callable[[str], bool],
) -> str:
    """Set a new admin password in SonarQube's database, then sign in with it."""

    previous = _read_secret(_password_path())
    generated = _new_password()
    _write_private(_password_path(), generated)
    if not reset_admin(generated):
        if previous:
            _write_private(_password_path(), previous)
        else:
            _write_private(_password_path(), "")
        return "denied_empty" if not previous else "denied"
    logged_in = _login(client, generated)
    if logged_in == "ok":
        return "ok"
    return logged_in


def _sign_in_with_saved(client: _Client, password: str) -> str:
    result = _login(client, password)
    if result == "ok" or result == "down" or password == "admin":
        return result
    result = _login(client, "admin")
    if result != "ok":
        return result
    return _change_from_admin(client, password)


def _change_from_admin(client: _Client, password: str) -> str:
    try:
        changed = client.call(
            "POST",
            "/api/users/change_password",
            {
                "login": "admin",
                "previousPassword": "admin",
                "password": password,
            },
        )
    except SetupDown:
        return "down"
    if changed[0] not in {200, 204}:
        return "denied"
    return _login(client, password)


def _login(client: _Client, password: str) -> str:
    try:
        status, _payload = client.call(
            "POST",
            "/api/authentication/login",
            {"login": "admin", "password": password},
        )
    except SetupDown:
        return "down"
    if status == 200:
        return "ok"
    if status == 401:
        return "denied"
    return "down"


def _issue(client: _Client, key: str, handle: Any) -> str:
    try:
        status, payload = client.call(
            "POST",
            "/api/user_tokens/generate",
            {"name": TOKEN_NAME, "type": "USER_TOKEN"},
        )
    except SetupDown:
        return _write_status("waiting", _NOT_READY, handle=handle)
    if status == 400 and _name_taken(payload):
        return _write_status("token_name_taken", _NAME_TAKEN, handle=handle)
    token = payload.get("token")
    if status not in {200, 201} or not isinstance(token, str) or len(token) < 16:
        return _write_status("waiting", _TOKEN, handle=handle)
    _write_private(_token_path(), token)
    expires = payload.get("expirationDate")
    when = expires if isinstance(expires, str) else ""
    return _finish_project(client, key, when, handle)


def _finish_project(
    client: _Client,
    key: str,
    expires: str,
    handle: Any,
) -> str:
    try:
        if not _project_ready(client, key):
            return _write_status("waiting", _PROJECT, handle=handle)
    except SetupDown:
        return _write_status("waiting", _NOT_READY, handle=handle)
    return _write_status("ready", _READY, expires, handle=handle)


def _project_ready(client: _Client, key: str) -> bool:
    status, payload = client.call(
        "GET",
        "/api/projects/search?" + urllib.parse.urlencode({"projects": key}),
    )
    if status == 200 and _contains_project(payload, key):
        return True
    created, body = client.call(
        "POST",
        "/api/projects/create",
        {"project": key, "name": key},
    )
    if created in {200, 201}:
        return True
    if created == 400 and _name_taken(body):
        return True
    return False


def _contains_project(payload: dict[str, Any], key: str) -> bool:
    components = payload.get("components")
    if not isinstance(components, list):
        return False
    return any(
        isinstance(item, dict) and item.get("key") == key for item in components
    )


def _token_valid(client: _Client, token: str) -> bool:
    status, payload = client.call(
        "GET",
        "/api/authentication/validate",
        bearer=token,
    )
    return status == 200 and payload.get("valid") is True


def _revoke(client: _Client) -> None:
    with contextlib.suppress(SetupDown):
        client.call("POST", "/api/user_tokens/revoke", {"name": TOKEN_NAME})


def _name_taken(payload: dict[str, Any]) -> bool:
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return False
    for item in errors:
        if not isinstance(item, dict):
            continue
        message = item.get("msg")
        if isinstance(message, str) and "already exists" in message.lower():
            return True
    return False


def _wait_until_up(
    client: _Client,
    sleep: Callable[[float], None],
    attempts: int,
) -> bool:
    for attempt in range(max(1, attempts)):
        try:
            status, payload = client.call("GET", "/api/system/status")
        except SetupDown:
            status, payload = 0, {}
        if status == 200 and payload.get("status") == "UP":
            return True
        if attempt + 1 < attempts:
            sleep(5)
    return False


def _hash_password(password: str) -> tuple[str, str]:
    """Match SonarQube 26 PBKDF2: 100000 rounds, SHA-512, 20-byte salt."""

    salt = os.urandom(20)
    digest = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode("utf-8"),
        salt,
        _ITERATIONS,
        dklen=64,
    )
    stored = f"{_ITERATIONS}${base64.b64encode(digest).decode('ascii')}"
    return stored, base64.b64encode(salt).decode("ascii")


def _reset_admin_password(password: str) -> bool:
    db_password = _read_secret(_db_password_path())
    if not db_password:
        return False
    stored, salt = _hash_password(password)
    try:
        import psycopg

        with psycopg.connect(
            host=os.environ.get("SONAR_DB_HOST", "sonar-db"),
            port=int(os.environ.get("SONAR_DB_PORT", "5432")),
            dbname=os.environ.get("SONAR_DB_NAME", "sonar"),
            user=os.environ.get("SONAR_DB_USER", "sonar"),
            password=db_password,
            connect_timeout=5,
        ) as connection:
            cursor = connection.execute(
                """
                UPDATE users
                SET crypted_password = %s,
                    salt = %s,
                    hash_method = 'PBKDF2',
                    reset_password = false,
                    user_local = true,
                    updated_at = %s
                WHERE login = 'admin'
                """,
                (stored, salt, int(time.time() * 1000)),
            )
            updated = cursor.rowcount
        return updated == 1
    except Exception:
        # The database error can contain the connection password.
        return False


def _db_password_path() -> Path:
    return Path(
        os.environ.get("SONAR_DB_PASSWORD_FILE", "/run/sonar/db_password")
    )


def _new_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%+-"
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#%+-"),
    ]
    extra = [secrets.choice(alphabet) for _ in range(28)]
    pieces = required + extra
    secrets.SystemRandom().shuffle(pieces)
    return "".join(pieces)


def _project_key() -> str | None:
    key = os.environ.get("SONAR_PROJECT_KEY", "security-console").strip()
    if not _KEY.fullmatch(key):
        return None
    return key


def _base_url() -> str:
    return os.environ.get("SONAR_URL", "http://sonarqube:9000/sonar").strip()


def _password_path() -> Path:
    return Path(
        os.environ.get(
            "SONAR_ADMIN_PASSWORD_FILE",
            "/run/sonar/admin_password",
        )
    )


def _token_path() -> Path:
    return Path(os.environ.get("SONAR_TOKEN_FILE", "/run/sonar/token"))


def _status_path() -> Path:
    return Path(os.environ.get("SONAR_INIT_STATUS_FILE", "/run/sonar/status"))


def _read_secret(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _write_private(path: Path, text: str) -> None:
    """Write through the existing inode so a bind-mounted file stays mounted."""

    data = text.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    descriptor = os.open(path, os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, data)
        os.ftruncate(descriptor, len(data))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    _own(path)


def _write_status(
    status: str,
    detail: str,
    expires_at: str = "",
    handle: Any = None,
) -> str:
    text = (
        json.dumps(
            {"status": status, "detail": detail, "expires_at": expires_at},
            ensure_ascii=False,
        )
        + "\n"
    )
    if handle is None:
        _write_private(_status_path(), text.strip("\n"))
        return status
    handle.seek(0)
    handle.truncate()
    handle.write(text)
    handle.flush()
    os.fsync(handle.fileno())
    _own(_status_path())
    return status


def _own(path: Path) -> None:
    if os.geteuid() != 0:
        return
    uid = int(os.environ.get("SONAR_SETUP_UID", "10001"))
    gid = int(os.environ.get("SONAR_SETUP_GID", "10001"))
    os.chown(path, uid, gid)


@contextlib.contextmanager
def _lock() -> Iterator[Any]:
    path = _status_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        _write_private(
            path,
            json.dumps(
                {
                    "status": "waiting",
                    "detail": _WAITING,
                    "expires_at": "",
                },
                ensure_ascii=False,
            ),
        )
    handle = path.open("r+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield handle
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _keep_cookie(cookies: dict[str, str], header: str) -> None:
    pair = header.split(";", 1)[0]
    name, separator, value = pair.partition("=")
    if separator and name.strip():
        cookies[name.strip()] = value.strip()


def _urllib_exchange(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, _header_pairs(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, _header_pairs(exc.headers), exc.read()


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key in headers.keys():
        for value in headers.get_all(key) or []:
            pairs.append((str(key), str(value)))
    return pairs


if __name__ == "__main__":
    main()
