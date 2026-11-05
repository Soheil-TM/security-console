"""Shared pytest fixtures.

Destructive DB helpers refuse to run unless CONSOLE_ALLOW_TEST_DB_WIPE=1.
Tests set that flag here; never point them at a production console database.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _allow_test_db_wipe() -> None:
    os.environ["CONSOLE_ALLOW_TEST_DB_WIPE"] = "1"
