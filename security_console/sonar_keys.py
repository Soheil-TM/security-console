"""Deterministic SonarQube project keys per repository URL."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,200}")


def normalize_repo_key(repo: str) -> str:
    """Stable identity for a git URL (lowercase, strip .git / trailing slash)."""

    text = str(repo or "").strip().rstrip("/").lower()
    if text.endswith(".git"):
        text = text[:-4]
    return text.rstrip("/")


def derive_sonar_project_key(repo: str) -> str:
    """Return a Sonar-safe key unique to this repository URL.

    Format: ``sc-`` + first 40 hex chars of SHA-256(normalized repo key).
    """

    identity = normalize_repo_key(repo)
    if not identity:
        raise RuntimeError("Repository URL is required for SonarQube.")
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:40]
    key = "sc-" + digest
    if not _KEY.fullmatch(key):
        raise RuntimeError("The SonarQube project key is invalid.")
    return key


def sonar_key_for_job(job: dict[str, Any]) -> str:
    """Resolve the Sonar project key for one scan job."""

    explicit = str(job.get("sonar_project_key") or "").strip()
    if explicit:
        if not _KEY.fullmatch(explicit):
            raise RuntimeError("The SonarQube project key is invalid.")
        return explicit
    repo = str(job.get("repo") or "").strip()
    if repo:
        return derive_sonar_project_key(repo)
    # Bootstrap / legacy fallback when no repo is in the job.
    import os

    key = os.environ.get("SONAR_PROJECT_KEY", "security-console").strip()
    if not _KEY.fullmatch(key):
        raise RuntimeError("The SonarQube project key is invalid.")
    return key
