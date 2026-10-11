"""Who may start a scan and which findings they may read."""

from __future__ import annotations

from typing import Any

TOOLS = ("semgrep", "checkov", "sonar", "trivy")
ROLES = ("admin", "developer", "viewer")


def access_map(user: dict[str, Any]) -> dict[str, bool]:
    """Return the tools this account may see. Admins see every tool."""

    if user.get("role") == "admin":
        return {tool: True for tool in TOOLS}
    return {tool: bool(user.get(f"allow_{tool}")) for tool in TOOLS}


def can_start_scan(user: dict[str, Any], tools: list[str]) -> bool:
    """Return whether this account may launch exactly these tools."""

    if user.get("role") not in {"admin", "developer"}:
        return False
    if not tools:
        return False
    allowed = access_map(user)
    return all(allowed.get(tool, False) for tool in tools)


def can_view_scan(user: dict[str, Any], scan: dict[str, Any]) -> bool:
    """Admins see every scan. Others see their own scans for allowed tools."""

    if user.get("role") != "admin":
        owner = scan.get("owner") or ""
        if owner != user.get("username"):
            return False
    allowed = access_map(user)
    tools = [tool for tool in scan.get("tools") or [] if tool in TOOLS]
    if not tools:
        return True
    return any(allowed.get(tool, False) for tool in tools)


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Bucket finding severities for the dashboard cards."""

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in findings:
        severity = str(row.get("severity") or "").upper()
        if severity in {"CRITICAL", "ERROR"}:
            counts["critical"] += 1
        elif severity == "HIGH":
            counts["high"] += 1
        elif severity in {"MEDIUM", "WARNING"}:
            counts["medium"] += 1
        elif severity == "LOW":
            counts["low"] += 1
        else:
            counts["info"] += 1
    return counts


def present_scan(
    user: dict[str, Any],
    scan: dict[str, Any],
    *,
    summary: bool,
) -> dict[str, Any] | None:
    """Return the scan fields this account is allowed to read."""

    if not can_view_scan(user, scan):
        return None
    allowed = access_map(user)
    findings = [
        row
        for row in scan.get("findings") or []
        if allowed.get(str(row.get("tool") or ""))
    ]
    shown: dict[str, Any] = {
        "id": scan.get("id"),
        "target": scan.get("target") or "repo",
        "repo": scan.get("repo") or "",
        "image": scan.get("image") or "",
        "owner": scan.get("owner") or "",
        "tools": [
            tool for tool in scan.get("tools") or [] if allowed.get(tool)
        ],
        "status": scan.get("status") or "",
        "phase": scan.get("phase") or "",
        "error": scan.get("error") or "",
        "created_at": scan.get("created_at") or "",
        "finished_at": scan.get("finished_at") or "",
        "finding_count": len(findings),
        "severity": severity_counts(findings),
        "sonar": scan.get("sonar") if allowed.get("sonar") else None,
    }
    if not summary:
        shown["findings"] = findings
    return shown
