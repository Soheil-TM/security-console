"""Escaping for the role password, which Postgres will not bind."""

from __future__ import annotations

import pytest

from security_console.db import _sql_literal


def test_sql_literal_doubles_quotes() -> None:
    """A quote inside the password stays inside the literal."""

    assert _sql_literal("a'b") == "'a''b'"


def test_sql_literal_rejects_control_characters() -> None:
    """Control characters are refused before they reach the server."""

    with pytest.raises(RuntimeError):
        _sql_literal("bad\npassword")
