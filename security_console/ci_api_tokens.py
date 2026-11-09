"""Managed CI API tokens: generate, hash, verify (hash-only storage)."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from security_console import db

_PREFIX_RE = re.compile(r"^csc_[0-9a-f]{8}$")
_TOKEN_RE = re.compile(r"^csc_[0-9a-f]{8}_[A-Za-z0-9_-]+$")
_DUMMY_HASH = hashlib.sha256(b"ci-api-token-dummy").hexdigest()


def hash_token(token: str) -> str:
    """Return hex SHA-256 of the full token string."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_ci_token() -> tuple[str, str, str]:
    """Return (full_token, prefix, token_hash). Secret is token_urlsafe(32)."""

    for _ in range(16):
        prefix = "csc_" + secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        token = prefix + "_" + secret
        if not _TOKEN_RE.fullmatch(token):
            continue
        return token, prefix, hash_token(token)
    raise RuntimeError("could not generate CI API token")


def parse_token_prefix(presented: str) -> str | None:
    """Return ``csc_<8hex>`` prefix or None if malformed."""

    text = str(presented or "").strip()
    if not text.startswith("csc_"):
        return None
    parts = text.split("_", 2)
    if len(parts) < 3:
        return None
    prefix = parts[0] + "_" + parts[1]
    if not _PREFIX_RE.fullmatch(prefix):
        return None
    if not _TOKEN_RE.fullmatch(text):
        return None
    return prefix


def dummy_hash_compare(presented: str) -> None:
    """Burn a compare_digest against a dummy hash (timing uniformity)."""

    hmac.compare_digest(hash_token(presented or "x"), _DUMMY_HASH)


def hashes_match(presented: str, token_hash: str) -> bool:
    """Constant-time compare of SHA-256(presented) to stored hex hash."""

    if not presented or not token_hash or len(token_hash) != 64:
        dummy_hash_compare(presented or "x")
        return False
    return hmac.compare_digest(hash_token(presented), token_hash)


def default_expires_at(days: int = 90) -> datetime:
    """UTC expiry used when the UI does not choose Never."""

    return datetime.now(UTC) + timedelta(days=days)


def token_status(row: dict[str, Any], *, now: datetime | None = None) -> str:
    """Return active, expired, or revoked for list/API display."""

    if row.get("revoked_at"):
        return "revoked"
    expires = row.get("expires_at")
    if expires is not None:
        stamp = expires
        if isinstance(stamp, str):
            stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        if stamp <= current:
            return "expired"
    return "active"


def public_token_row(row: dict[str, Any]) -> dict[str, Any]:
    """Metadata safe for clients (no hash, no secret)."""

    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "prefix": str(row["prefix"]),
        "created_at": row.get("created_at") or "",
        "expires_at": row.get("expires_at"),
        "last_used_at": row.get("last_used_at"),
        "revoked_at": row.get("revoked_at"),
        "status": token_status(row),
        "gitlab_path_prefix": str(row.get("gitlab_path_prefix") or ""),
    }


def create_token(
    *,
    name: str,
    created_by: int | None,
    expires_at: datetime | None,
    gitlab_path_prefix: str = "",
) -> tuple[str, dict[str, Any]]:
    """Insert a new token; return (plaintext_once, public_row)."""

    from psycopg.errors import UniqueViolation

    clean_name = " ".join(str(name or "").split())
    if not clean_name or len(clean_name) > 80:
        raise ValueError("name is invalid")
    prefix_scope = str(gitlab_path_prefix or "").strip()
    if len(prefix_scope) > 200:
        raise ValueError("gitlab_path_prefix is invalid")

    for _ in range(8):
        token, prefix, digest = generate_ci_token()
        try:
            row = db.insert_ci_api_token(
                name=clean_name,
                prefix=prefix,
                token_hash=digest,
                created_by=created_by,
                expires_at=expires_at,
                gitlab_path_prefix=prefix_scope,
            )
            return token, public_token_row(row)
        except UniqueViolation:
            continue
    raise RuntimeError("could not allocate a unique CI token prefix")


def list_tokens() -> list[dict[str, Any]]:
    """Return public metadata for all tokens, newest first."""

    return [public_token_row(row) for row in db.list_ci_api_tokens()]


def revoke_token(token_id: int) -> dict[str, Any] | None:
    """Revoke by id; return public row or None if missing."""

    row = db.revoke_ci_api_token(token_id)
    if row is None:
        return None
    return public_token_row(row)


def delete_token(token_id: int) -> dict[str, Any] | None:
    """Permanently delete a revoked token; return public row or None."""

    row = db.delete_ci_api_token(token_id)
    if row is None:
        return None
    return public_token_row(row)


def verify_presented_token(presented: str) -> dict[str, Any] | None:
    """Validate a Bearer token against DB.

    Returns the active token row on success, otherwise None after a dummy
    compare when appropriate.
    """

    prefix = parse_token_prefix(presented)
    if prefix is None:
        dummy_hash_compare(presented or "x")
        return None
    row = db.get_ci_api_token_by_prefix(prefix)
    if row is None:
        dummy_hash_compare(presented)
        return None
    if row.get("revoked_at"):
        dummy_hash_compare(presented)
        return None
    if token_status(row) == "expired":
        dummy_hash_compare(presented)
        return None
    if not hashes_match(presented, str(row.get("token_hash") or "")):
        return None
    return row


def touch_last_used(token_id: int) -> None:
    """Best-effort last_used_at bump; never raises to callers."""

    try:
        db.touch_ci_api_token_last_used(token_id)
    except Exception:  # noqa: BLE001 — must not reject authenticated CI
        return


def count_usable_tokens() -> int:
    """Active (non-revoked, non-expired) token count for config warnings."""

    return db.count_usable_ci_api_tokens()
