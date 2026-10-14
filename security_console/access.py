"""Who may start a scan and which findings they may read."""

from __future__ import annotations

from typing import Any

TOOLS = ("semgrep", "checkov", "sonar", "trivy")
ROLES = ("admin", "developer", "viewer")


def access_map(user: dict[str, Any]) -> dict[str, bool]:
    """Return the tools this account may see. Admins see every tool."""

    if user.get("role") == "admin":
        allowed = {tool: True for tool in TOOLS}
    else:
        allowed = {tool: bool(user.get(f"allow_{tool}")) for tool in TOOLS}
    allowed["sonar_ui"] = can_open_sonar_ui(user)
    return allowed


def can_open_sonar_ui(user: dict[str, Any]) -> bool:
    """Return whether this account may open the SonarQube site."""

    if user.get("role") == "admin":
        return True
    return bool(user.get("allow_sonar_ui"))


def can_start_scan(user: dict[str, Any], tools: list[str]) -> bool:
    """Return whether this account may launch exactly these tools."""

    if user.get("role") not in {"admin", "developer"}:
        return False
    if not tools:
        return False
    allowed = access_map(user)
    return all(allowed.get(tool, False) for tool in tools)


def can_scan_project(
    user: dict[str, Any],
    tools: list[str],
    project: str,
    group_keys: set[str],
) -> bool:
    """Return whether this account may scan one group project.

    Admins may scan any accepted target. A developer may scan it only when
    that project belongs to one of their groups and every requested tool is
    allowed.
    """

    if not can_start_scan(user, tools):
        return False
    if user.get("role") == "admin":
        return True
    return project in group_keys


def project_key(scan: dict[str, Any]) -> str:
    """Group scans the same way the reports list groups them.

    An image scan keys on the image name. A repository scan keys on the Git
    URL with a trailing ``.git`` and slashes removed.
    """

    image = str(scan.get("image") or "")
    repo = str(scan.get("repo") or "")
    if scan.get("target") == "image" or (image and not repo):
        return "image:" + image.lower()
    key = repo[:-4] if repo.lower().endswith(".git") else repo
    return key.rstrip("/").lower()


def can_view_scan(
    user: dict[str, Any],
    scan: dict[str, Any],
    *,
    group_keys: set[str] | None = None,
) -> bool:
    """Return whether this account may read the scan.

    Admins see every scan. Everyone else sees a scan only when its project
    is in one of their groups and at least one of its tools is allowed.
    The owner records who started it and does not grant access.
    """

    if user.get("role") != "admin":
        if project_key(scan) not in (group_keys or set()):
            return False
    allowed = access_map(user)
    tools = [tool for tool in scan.get("tools") or [] if tool in TOOLS]
    if not tools:
        return True
    return any(allowed.get(tool, False) for tool in tools)


def recent_per_project(
    user: dict[str, Any],
    items: list[dict[str, Any]],
    *,
    summary: bool,
    group_keys: set[str] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Keep the newest scans for each repository or image."""

    ordered = sorted(
        items,
        key=lambda item: str(item.get("created_at") or ""),
        reverse=True,
    )
    counts: dict[str, int] = {}
    visible: list[dict[str, Any]] = []
    for item in ordered:
        shown = present_scan(
            user,
            item,
            summary=summary,
            group_keys=group_keys,
        )
        if shown is None:
            continue
        key = project_key(item)
        taken = counts.get(key, 0)
        if taken >= limit:
            continue
        counts[key] = taken + 1
        visible.append(shown)
    return visible


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
    group_keys: set[str] | None = None,
) -> dict[str, Any] | None:
    """Return the scan fields this account is allowed to read."""

    if not can_view_scan(user, scan, group_keys=group_keys):
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
        "requested_sha": scan.get("requested_sha") or "",
        "commit_sha": scan.get("commit_sha") or "",
        "failure_reason": scan.get("failure_reason") or "",
        "created_at": scan.get("created_at") or "",
        "finished_at": scan.get("finished_at") or "",
        "finding_count": len(findings),
        "severity": severity_counts(findings),
        "sonar": scan.get("sonar") if allowed.get("sonar") else None,
    }
    if not summary:
        shown["findings"] = findings
    return shown
