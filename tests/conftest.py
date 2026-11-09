"""Shared pytest fixtures.

Destructive DB helpers refuse to run unless CONSOLE_ALLOW_TEST_DB_WIPE=1 and
the target database is not the live ``security_console_db``.

This session fixture:
- enables the wipe flag for the process
- defaults missing ``CONSOLE_DB_NAME`` to ``security_console_test``
- refuses an explicit live DB name (fail closed; no remap to live)
- creates the disposable database when missing
- never falls back to ``security_console_db`` if the test DB is unreachable
"""

from __future__ import annotations

import os
import re

import pytest

_TEST_DB_NAME = "security_console_test"
_LIVE_DB_NAME = "security_console_db"
_SAFE_DB_RE = re.compile(r"^[a-z][a-z0-9_]*$")


@pytest.fixture(scope="session", autouse=True)
def _configure_isolated_test_database() -> None:
    os.environ["CONSOLE_ALLOW_TEST_DB_WIPE"] = "1"

    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url:
        _assert_not_live_url(database_url)
        return

    current = os.environ.get("CONSOLE_DB_NAME", "").strip()
    if current == _LIVE_DB_NAME:
        raise RuntimeError(
            "CONSOLE_DB_NAME points at the live security_console_db; "
            "refusing to run tests against production data. "
            f"Use CONSOLE_DB_NAME={_TEST_DB_NAME} (or omit it)."
        )
    if not current:
        os.environ["CONSOLE_DB_NAME"] = _TEST_DB_NAME
    _ensure_database_exists(os.environ["CONSOLE_DB_NAME"])


def _assert_not_live_url(database_url: str) -> None:
    from urllib.parse import urlparse

    name = urlparse(database_url).path.lstrip("/").split("?")[0].strip()
    if not name or name == _LIVE_DB_NAME:
        raise RuntimeError(
            "DATABASE_URL points at the live security_console_db (or is empty); "
            "use a disposable database such as security_console_test"
        )


def _ensure_database_exists(dbname: str) -> None:
    if not _SAFE_DB_RE.fullmatch(dbname):
        raise RuntimeError(f"refusing to create unsafe test database name {dbname!r}")

    import psycopg

    from security_console.db import load_settings

    settings = load_settings()
    if not settings.app_password:
        raise RuntimeError("console database password is not configured for tests")
    try:
        with psycopg.connect(
            host=settings.app_host,
            port=5432,
            user=settings.app_user,
            password=settings.app_password,
            dbname="postgres",
            connect_timeout=5,
            autocommit=True,
        ) as conn:
            row = conn.execute(
                "SELECT 1 AS found FROM pg_database WHERE datname = %s",
                (dbname,),
            ).fetchone()
            if row is None:
                conn.execute(
                    f'CREATE DATABASE "{dbname}" OWNER "{settings.app_user}"'
                )
    except Exception as exc:  # noqa: BLE001 — fail closed, never open live
        raise RuntimeError(
            f"could not ensure disposable test database {dbname!r}; "
            "refusing to fall back to the live console database"
        ) from exc
