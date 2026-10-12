"""Production startup refuses plain-HTTP cookies. Development may use them."""

from __future__ import annotations

import pytest

from security_console.auth import ConfigError, validate_runtime_config


def test_development_allows_http_cookies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "0")

    validate_runtime_config()


def test_unset_mode_is_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONSOLE_ENV", raising=False)
    monkeypatch.setenv("COOKIE_SECURE", "0")

    validate_runtime_config()


def test_production_requires_secure_cookies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSOLE_ENV", "production")
    monkeypatch.setenv("COOKIE_SECURE", "0")

    with pytest.raises(ConfigError, match="COOKIE_SECURE"):
        validate_runtime_config()


def test_production_accepts_secure_cookies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_ENV", "production")
    monkeypatch.setenv("COOKIE_SECURE", "1")

    validate_runtime_config()


def test_unknown_mode_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSOLE_ENV", "staging")

    with pytest.raises(ConfigError, match="CONSOLE_ENV"):
        validate_runtime_config()
