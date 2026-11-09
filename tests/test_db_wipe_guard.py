"""Wipe/connect guards must refuse the live console database."""

from __future__ import annotations

import pytest

from security_console import db


def test_wipe_refuses_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONSOLE_ALLOW_TEST_DB_WIPE", raising=False)
    monkeypatch.setenv("CONSOLE_DB_NAME", "security_console_test")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="CONSOLE_ALLOW_TEST_DB_WIPE"):
        db._require_test_db_wipe()


def test_wipe_refuses_live_database_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_ALLOW_TEST_DB_WIPE", "1")
    monkeypatch.setenv("CONSOLE_DB_NAME", "security_console_db")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="live database"):
        db._require_test_db_wipe()


def test_wipe_refuses_default_live_when_name_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ALLOW_TEST_DB_WIPE", "1")
    monkeypatch.delenv("CONSOLE_DB_NAME", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # load_settings defaults app_name to security_console_db → refuse.
    with pytest.raises(RuntimeError, match="live database"):
        db._require_test_db_wipe()


def test_connect_refuses_live_in_test_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_ALLOW_TEST_DB_WIPE", "1")
    monkeypatch.setenv("CONSOLE_DB_NAME", "security_console_db")
    monkeypatch.setenv("CONSOLE_DB_PASSWORD", "unused-in-guard")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="refuses the live database"):
        db.connect()


def test_connect_refuses_live_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_ALLOW_TEST_DB_WIPE", "1")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://console:x@db:5432/security_console_db",
    )
    with pytest.raises(RuntimeError, match="refuses the live database"):
        db.connect()


def test_all_reset_helpers_call_wipe_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every TRUNCATE helper must invoke the shared live-DB guard."""

    called: list[str] = []

    def boom() -> None:
        called.append("guard")
        raise RuntimeError("guarded")

    monkeypatch.setattr(db, "_require_test_db_wipe", boom)
    for name in ("reset_auth_tables", "reset_scan_table", "reset_schedule_table"):
        called.clear()
        fn = getattr(db, name)
        with pytest.raises(RuntimeError, match="guarded"):
            fn()
        assert called == ["guard"], name


@pytest.mark.skipif(
    not (
        __import__("os").environ.get("DATABASE_URL", "").strip()
        or __import__("os").environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or __import__("os").environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    ),
    reason="database required",
)
def test_suite_targets_non_live_database() -> None:
    name = db.connected_database_name()
    assert name
    assert name != "security_console_db"
