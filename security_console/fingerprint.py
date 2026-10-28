"""Stable risk / push-gate fingerprints (no secrets)."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def finding_disposition_parts(
    finding_key: str,
    disposition: dict[str, Any] | None,
) -> dict[str, str]:
    status = str((disposition or {}).get("status") or "")
    reason = str((disposition or {}).get("reason") or "")
    reason_hash = ""
    if status in {"false_positive", "accepted_risk"} and reason:
        reason_hash = hashlib.sha256(reason.encode("utf-8")).hexdigest()[:16]
    return {
        "key": finding_key,
        "status": status,
        "reason_hash": reason_hash,
    }


def compute_risk_fingerprint(
    *,
    project_key: str,
    commit_sha: str,
    finding_keys: list[str],
    dispositions: dict[str, dict[str, Any]] | list[dict[str, Any]],
) -> str:
    """Hash project + commit + sorted finding dispositions in scope."""

    by_key: dict[str, dict[str, Any]] = {}
    if isinstance(dispositions, dict):
        by_key = {str(k): v for k, v in dispositions.items() if isinstance(v, dict)}
    else:
        for row in dispositions:
            if not isinstance(row, dict):
                continue
            key = str(row.get("finding_key") or "")
            if key:
                by_key[key] = row
    rows = [
        finding_disposition_parts(key, by_key.get(key))
        for key in sorted({str(item) for item in finding_keys if item})
    ]
    payload = {
        "project_key": str(project_key or "").strip().lower(),
        "commit_sha": str(commit_sha or "").strip().lower(),
        "findings": rows,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprints_match(left: str, right: str) -> bool:
    a = str(left or "").strip().lower()
    b = str(right or "").strip().lower()
    return bool(a) and a == b
