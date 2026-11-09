"""P1: CI API token generate/hash/verify helpers."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta

import pytest

from security_console.ci_api_tokens import (
    create_token,
    generate_ci_token,
    hash_token,
    hashes_match,
    parse_token_prefix,
    revoke_token,
    token_status,
    verify_presented_token,
)
from security_console.db import prepare_database, reset_auth_tables


def _db_ready() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    return bool(
        os.environ.get("CONSOLE_DB_PASSWORD", "").strip()
        or os.environ.get("CONSOLE_DB_PASSWORD_FILE", "").strip()
    )


def test_generate_uses_urlsafe_32_and_prefix_shape() -> None:
    token, prefix, digest = generate_ci_token()
    assert re.fullmatch(r"csc_[0-9a-f]{8}_[A-Za-z0-9_-]+", token)
    assert prefix == token.rsplit("_", 1)[0] or token.startswith(prefix + "_")
    assert prefix.startswith("csc_") and len(prefix) == 12
    secret = token[len(prefix) + 1 :]
    # token_urlsafe(32) yields >= 43 chars typically; ensure substantial secret.
    assert len(secret) >= 40
    assert digest == hash_token(token)
    assert " " not in token


def test_parse_prefix_and_hashes_match() -> None:
    token, prefix, digest = generate_ci_token()
    assert parse_token_prefix(token) == prefix
    assert parse_token_prefix("csc_bad") is None
    assert parse_token_prefix("not-a-token") is None
    assert hashes_match(token, digest) is True
    assert hashes_match(token + "x", digest) is False


def test_token_status_expired_revoked() -> None:
    now = datetime(2026, 11, 9, tzinfo=UTC)
    assert (
        token_status({"revoked_at": now, "expires_at": None}, now=now) == "revoked"
    )
    assert (
        token_status(
            {"revoked_at": None, "expires_at": now - timedelta(seconds=1)},
            now=now,
        )
        == "expired"
    )
    assert token_status({"revoked_at": None, "expires_at": None}, now=now) == "active"


@pytest.mark.skipif(not _db_ready(), reason="database required")
def test_create_stores_hash_only_and_verify() -> None:
    os.environ.setdefault("CONSOLE_ALLOW_TEST_DB_WIPE", "1")
    prepare_database()
    reset_auth_tables()
    token, public = create_token(
        name="runner-a",
        created_by=None,
        expires_at=datetime.now(UTC) + timedelta(days=90),
    )
    assert public["prefix"] in token
    assert "token_hash" not in public
    assert public["status"] == "active"
    row = verify_presented_token(token)
    assert row is not None
    assert row["token_hash"] == hash_token(token)
    assert token not in str(row["token_hash"])
    assert verify_presented_token(token + "nope") is None
    revoked = revoke_token(int(public["id"]))
    assert revoked is not None
    assert revoked["status"] == "revoked"
    assert verify_presented_token(token) is None
