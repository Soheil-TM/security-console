"""SonarQube setup writes a token once and does not invent a second one."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from security_console.sonar_setup import read_public_status, run_setup

_COOKIES = [
    ("Set-Cookie", "JWT-SESSION=session-value; Path=/; HttpOnly"),
    ("Set-Cookie", "XSRF-TOKEN=xsrf-value; Path=/"),
]
_TOKEN = "squ_" + ("a" * 24)
_PASSWORD = "CorrectHorse!1battery"


class _Script:
    def __init__(self, steps: list[Any]) -> None:
        self.steps = list(steps)
        self.calls: list[tuple[str, str, str, bytes | None]] = []

    def exchange(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        self.calls.append((method, url, headers.get("Authorization", ""), body))
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        status, pairs, raw = step
        return status, pairs, raw


def _paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path]:
    password = tmp_path / "admin_password"
    token = tmp_path / "token"
    status = tmp_path / "status"
    monkeypatch.setenv("SONAR_ADMIN_PASSWORD_FILE", str(password))
    monkeypatch.setenv("SONAR_TOKEN_FILE", str(token))
    monkeypatch.setenv("SONAR_INIT_STATUS_FILE", str(status))
    monkeypatch.setenv("SONAR_URL", "http://sonarqube:9000/sonar")
    monkeypatch.setenv("SONAR_PROJECT_KEY", "payments-api")
    return password, token, status


def _up() -> tuple[int, list[tuple[str, str]], bytes]:
    return 200, [], b'{"status":"UP"}'


def _login_ok() -> tuple[int, list[tuple[str, str]], bytes]:
    return 200, _COOKIES, b"{}"


def _denied() -> tuple[int, list[tuple[str, str]], bytes]:
    return 401, [], b""


def test_first_run_changes_the_default_password_and_writes_a_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    script = _Script(
        [
            _up(),
            _denied(),
            _login_ok(),
            (204, [], b""),
            _login_ok(),
            (
                200,
                [],
                json.dumps(
                    {"token": _TOKEN, "expirationDate": "2027-04-01"}
                ).encode(),
            ),
            (200, [], b'{"components":[]}'),
            (200, [], b"{}"),
        ]
    )

    result = run_setup(exchange=script.exchange, sleep=lambda _seconds: None)

    assert result == "ready"
    assert token.read_text() == _TOKEN
    assert password.read_text() == _PASSWORD
    saved = json.loads(status.read_text())
    assert saved["status"] == "ready"
    assert saved["expires_at"] == "2027-04-01"
    assert _TOKEN not in status.read_text()
    assert _PASSWORD not in status.read_text()
    assert script.calls[5][1].endswith("/api/user_tokens/generate")
    assert script.calls[5][3] is not None
    assert b"type=USER_TOKEN" in script.calls[5][3]
    assert b"name=security-console-scanner" in script.calls[5][3]
    assert "Bearer" not in script.calls[5][2]
    assert not any(
        url.endswith("/api/user_tokens/revoke") for _m, url, _a, _b in script.calls
    )


def test_existing_token_is_kept_when_sonarqube_accepts_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, _status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    token.write_text("existing-token-value-ok")
    script = _Script(
        [
            _up(),
            _login_ok(),
            (200, [], b'{"valid":true}'),
            (
                200,
                [],
                b'{"components":[{"key":"payments-api"}]}',
            ),
        ]
    )

    result = run_setup(exchange=script.exchange, sleep=lambda _seconds: None)

    assert result == "ready"
    assert token.read_text() == "existing-token-value-ok"
    assert script.calls[2][2] == "Bearer existing-token-value-ok"
    assert not any(
        "generate" in url for _method, url, _auth, _body in script.calls
    )


def test_rejected_token_is_not_replaced_automatically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    token.write_text("existing-token-value-ok")
    script = _Script([_up(), _login_ok(), (401, [], b"")])

    result = run_setup(exchange=script.exchange, sleep=lambda _seconds: None)

    assert result == "token_rejected"
    assert token.read_text() == "existing-token-value-ok"
    assert json.loads(status.read_text())["status"] == "token_rejected"
    assert not any(
        "generate" in url for _method, url, _auth, _body in script.calls
    )


def test_empty_file_does_not_revoke_an_existing_token_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    token.write_text("")
    script = _Script(
        [
            _up(),
            _login_ok(),
            (
                400,
                [],
                b'{"errors":[{"msg":"A user token already exists"}]}',
            ),
        ]
    )

    result = run_setup(exchange=script.exchange, sleep=lambda _seconds: None)

    assert result == "token_name_taken"
    assert token.read_text() == ""
    assert json.loads(status.read_text())["status"] == "token_name_taken"
    assert not any(
        "revoke" in url for _method, url, _auth, _body in script.calls
    )


def test_unknown_admin_password_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    script = _Script([_up(), _denied(), _denied()])

    result = run_setup(
        exchange=script.exchange,
        sleep=lambda _seconds: None,
        reset_admin=lambda _password: False,
    )

    assert result == "admin_password_unknown"
    assert password.read_text() == _PASSWORD
    assert not token.exists()
    saved = json.loads(status.read_text())
    assert saved["status"] == "admin_password_unknown"
    assert "CorrectHorse" not in saved["detail"]


def test_rotate_revokes_the_named_token_and_writes_the_new_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, _status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    token.write_text("existing-token-value-ok")
    script = _Script(
        [
            _up(),
            _login_ok(),
            (204, [], b""),
            (200, [], json.dumps({"token": _TOKEN}).encode()),
            (200, [], b'{"components":[{"key":"payments-api"}]}'),
        ]
    )

    result = run_setup(
        rotate=True,
        exchange=script.exchange,
        sleep=lambda _seconds: None,
    )

    assert result == "ready"
    assert token.read_text() == _TOKEN
    assert script.calls[2][1].endswith("/api/user_tokens/revoke")
    assert script.calls[3][1].endswith("/api/user_tokens/generate")


def test_sonarqube_still_starting_does_not_burn_the_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, _token, status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    script = _Script([(200, [], b'{"status":"STARTING"}')] * 2)
    slept: list[float] = []

    result = run_setup(
        exchange=script.exchange,
        sleep=slept.append,
        attempts=2,
    )

    assert result == "waiting"
    assert slept == [5]
    assert password.read_text() == _PASSWORD
    assert json.loads(status.read_text())["detail"] == "SonarQube is not ready."


def test_validate_outage_does_not_mark_the_token_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, status = _paths(tmp_path, monkeypatch)
    password.write_text(_PASSWORD)
    token.write_text("existing-token-value-ok")
    script = _Script([_up(), _login_ok(), OSError("down")])

    result = run_setup(exchange=script.exchange, sleep=lambda _seconds: None)

    assert result == "waiting"
    assert token.read_text() == "existing-token-value-ok"
    assert json.loads(status.read_text())["status"] == "waiting"


def test_default_password_is_left_empty_when_reset_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, _token, status = _paths(tmp_path, monkeypatch)
    script = _Script([_up(), _denied()])

    result = run_setup(
        exchange=script.exchange,
        sleep=lambda _seconds: None,
        reset_admin=lambda _password: False,
    )

    assert result == "admin_password_unknown"
    assert password.read_text().strip() == ""
    detail = json.loads(status.read_text())["detail"]
    assert detail == "SonarQube could not replace the admin password."


def test_default_admin_login_stores_the_new_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, _status = _paths(tmp_path, monkeypatch)
    script = _Script(
        [
            _up(),
            _login_ok(),
            (204, [], b""),
            _login_ok(),
            (200, [], json.dumps({"token": _TOKEN}).encode()),
            (200, [], b'{"components":[{"key":"payments-api"}]}'),
        ]
    )

    result = run_setup(exchange=script.exchange, sleep=lambda _seconds: None)

    assert result == "ready"
    saved = password.read_text()
    assert saved != "admin"
    assert any(character.islower() for character in saved)
    assert any(character.isupper() for character in saved)
    assert any(character.isdigit() for character in saved)
    assert token.read_text() == _TOKEN


def test_replaced_admin_password_continues_to_a_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password, token, _status = _paths(tmp_path, monkeypatch)
    seen: list[str] = []

    def reset(value: str) -> bool:
        seen.append(value)
        return True

    script = _Script(
        [
            _up(),
            _denied(),
            _login_ok(),
            (200, [], json.dumps({"token": _TOKEN}).encode()),
            (200, [], b'{"components":[{"key":"payments-api"}]}'),
        ]
    )

    result = run_setup(
        exchange=script.exchange,
        sleep=lambda _seconds: None,
        reset_admin=reset,
    )

    assert result == "ready"
    assert seen
    assert password.read_text() == seen[0]
    assert seen[0] != "admin"
    assert token.read_text() == _TOKEN


def test_hash_uses_sonarqube_pbkdf2() -> None:
    import base64
    import hashlib

    from security_console.sonar_setup import _hash_password

    stored, salt = _hash_password("CorrectHorse!1battery")
    iterations, digest = stored.split("$", 1)
    raw_salt = base64.b64decode(salt)

    assert iterations == "100000"
    assert len(raw_salt) == 20
    expected = hashlib.pbkdf2_hmac(
        "sha512",
        b"CorrectHorse!1battery",
        raw_salt,
        100000,
        dklen=64,
    )
    assert base64.b64encode(expected).decode("ascii") == digest


def test_public_status_drops_anything_except_the_three_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _password, _token, status = _paths(tmp_path, monkeypatch)
    status.write_text(
        json.dumps(
            {
                "status": "ready",
                "detail": "SonarQube is ready.",
                "expires_at": "",
                "token": "secret-token",
            }
        )
    )

    assert read_public_status() == {
        "status": "ready",
        "detail": "SonarQube is ready.",
        "expires_at": "",
    }
