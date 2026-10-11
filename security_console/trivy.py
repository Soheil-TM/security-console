"""Turn a Trivy filesystem report into console findings."""

from __future__ import annotations

from typing import Any


def parse_report(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Read vulnerabilities, misconfigurations, and secrets from one report."""

    findings: list[dict[str, Any]] = []
    for result in data.get("Results") or []:
        target = result.get("Target") or ""
        for item in result.get("Vulnerabilities") or []:
            findings.append(_finding(
                item.get("VulnerabilityID") or "",
                item.get("Severity") or "UNKNOWN",
                target,
                None,
                _text(item.get("Title"), item.get("PkgName")),
            ))
        for item in result.get("Misconfigurations") or []:
            cause = item.get("CauseMetadata") or {}
            findings.append(_finding(
                item.get("ID") or item.get("AVDID") or "",
                item.get("Severity") or "UNKNOWN",
                target,
                cause.get("StartLine"),
                item.get("Title") or item.get("Message") or "",
            ))
        for item in result.get("Secrets") or []:
            findings.append(_finding(
                item.get("RuleID") or item.get("Title") or "",
                item.get("Severity") or "UNKNOWN",
                target,
                item.get("StartLine"),
                item.get("Title") or "",
            ))
    return findings


def _finding(
    check: str,
    severity: str,
    path: str,
    line: Any,
    message: str,
) -> dict[str, Any]:
    return {
        "tool": "trivy",
        "severity": severity or "UNKNOWN",
        "check": check,
        "path": path,
        "line": line,
        "message": message,
    }


def _text(title: Any, package: Any) -> str:
    name = str(title or "").strip()
    pkg = str(package or "").strip()
    if name and pkg:
        return f"{name} ({pkg})"
    return name or pkg
