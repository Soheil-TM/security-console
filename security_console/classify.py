"""Auto-classify findings into security / quality / operational."""

from __future__ import annotations

from typing import Any

import psycopg

from security_console.risk import finding_key

CLASSIFIER_VERSION = 1

FINDING_CLASSES = frozenset({"security", "quality", "operational"})
CLASSIFICATION_SOURCES = frozenset({"auto", "manual"})


class ClassOverridesUnavailable(RuntimeError):
    """Raised when project class overrides cannot be loaded for a security path."""


class ClassOverrideConflict(RuntimeError):
    """Raised when an optimistic concurrency check on an override fails."""


def load_class_overrides(project_key: str) -> dict[str, dict[str, Any]]:
    """Load overrides for a project. Fail closed on database errors."""

    from security_console import db

    try:
        return db.list_class_overrides(project_key)
    except psycopg.Error as exc:
        raise ClassOverridesUnavailable(
            "class overrides unavailable"
        ) from exc


def enrich_findings(
    rows: list[dict[str, Any]],
    overrides: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Classify findings, then apply project overrides when provided."""

    classified = [classify_finding(row) for row in rows]
    if not overrides:
        return classified
    return apply_overrides(classified, overrides)


def classify_finding(row: dict[str, Any]) -> dict[str, Any]:
    """Attach finding_class fields; never overwrite a valid manual class."""

    out = dict(row)
    if _keep_manual(out):
        return out
    out["finding_class"] = _auto_class(out)
    out["classification_source"] = "auto"
    out["classifier_version"] = CLASSIFIER_VERSION
    return out


def apply_overrides(
    rows: list[dict[str, Any]],
    overrides_by_key: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Force manual class from project overrides onto classified rows."""

    result: list[dict[str, Any]] = []
    for row in rows:
        key = finding_key(row)
        override = overrides_by_key.get(key) if key else None
        if not isinstance(override, dict):
            result.append(row)
            continue
        finding_class = str(override.get("finding_class") or "").strip().lower()
        if finding_class not in FINDING_CLASSES:
            result.append(row)
            continue
        updated = dict(row)
        updated["finding_class"] = finding_class
        updated["classification_source"] = "manual"
        updated["classifier_version"] = CLASSIFIER_VERSION
        updated["classification_reason"] = str(override.get("reason") or "")
        updated["classification_updated_by"] = str(override.get("updated_by") or "")
        result.append(updated)
    return result


def _keep_manual(row: dict[str, Any]) -> bool:
    source = str(row.get("classification_source") or "").strip().lower()
    finding_class = str(row.get("finding_class") or "").strip().lower()
    return source == "manual" and finding_class in FINDING_CLASSES


def _auto_class(row: dict[str, Any]) -> str:
    tool = str(row.get("tool") or "").strip().lower()
    if tool == "sonar":
        return _sonar_class(row)
    if tool == "trivy":
        return _trivy_class(row)
    if tool in {"semgrep", "checkov"}:
        return "security"
    return "security"


def _sonar_class(row: dict[str, Any]) -> str:
    sonar_type = str(row.get("sonar_type") or "").strip().upper()
    security_review = row.get("security_review") is True
    if sonar_type == "VULNERABILITY":
        return "security"
    if sonar_type == "SECURITY_HOTSPOT" and security_review:
        return "security"
    if sonar_type in {"BUG", "CODE_SMELL"} or sonar_type:
        return "quality"
    return "security"


def _trivy_class(row: dict[str, Any]) -> str:
    kind = str(row.get("trivy_kind") or "").strip().lower()
    if kind == "misconfiguration":
        return "operational"
    if kind in {"vulnerability", "secret"}:
        return "security"
    return "security"
