"""Shared helpers for secrets that stay out of source control."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def read_secret(env_name: str, file_env: str) -> str:
    """Return a secret from a file when configured, otherwise from the env."""

    file_path = os.environ.get(file_env, "").strip()
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.environ.get(env_name, "").strip()


def same_secret(presented: str, expected: str) -> bool:
    """Compare two secrets without leaking which one is longer."""

    if not presented or not expected:
        return False
    return hmac.compare_digest(
        hashlib.sha256(presented.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )
