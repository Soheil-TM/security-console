"""Per-tool ok/failed status for a finished scan."""

from __future__ import annotations

from typing import Any

_LABELS = {
    "semgrep": "Semgrep",
    "checkov": "Checkov",
    "trivy": "Trivy",
    "sonar": "SonarQube",
}


def normalize_tool_results(
    tools: list[str],
    raw: object,
    error: str = "",
    findings: object = None,
    status: str = "",
) -> list[dict[str, str]]:
    """Return one row per requested tool. Derive from error/findings when missing."""

    active = str(status or "").strip().lower() in {"running", "queued"}
    by_tool: dict[str, dict[str, str]] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool") or "").strip().lower()
            if not tool:
                continue
            row_status = str(item.get("status") or "").strip().lower()
            if row_status not in {"ok", "failed"}:
                row_status = "failed" if item.get("error") else "ok"
            by_tool[tool] = {
                "tool": tool,
                "status": row_status,
                "error": str(item.get("error") or "")[:500],
                "label": _LABELS.get(tool, tool),
            }
    # In-flight scans only expose tools the worker has already recorded.
    if active:
        ordered = [
            str(tool).strip().lower()
            for tool in tools
            if str(tool).strip()
        ]
        return [by_tool[key] for key in ordered if key in by_tool]

    failed_names = _failed_tools_from_error(error)
    finding_tools = _tools_from_findings(findings)
    ordered = [
        str(tool).strip().lower()
        for tool in tools
        if str(tool).strip()
    ]
    first_failed = next(
        (index for index, key in enumerate(ordered) if key in failed_names),
        None,
    )
    rows: list[dict[str, str]] = []
    for index, key in enumerate(ordered):
        if key in by_tool:
            rows.append(by_tool[key])
            continue
        if key in failed_names:
            rows.append(
                {
                    "tool": key,
                    "status": "failed",
                    "error": failed_names[key][:500],
                    "label": _LABELS.get(key, key),
                }
            )
            continue
        if (
            key in finding_tools
            or by_tool
            or not error
            or (
                first_failed is not None
                and index < first_failed
            )
        ):
            rows.append(
                {
                    "tool": key,
                    "status": "ok",
                    "error": "",
                    "label": _LABELS.get(key, key),
                }
            )
    # Pre-tool failures (clone, scanner down, deadline before any tool) would
    # otherwise leave the UI blank. Mark every requested tool failed.
    if not rows and error and ordered:
        detail = str(error).strip()[:500]
        for key in ordered:
            rows.append(
                {
                    "tool": key,
                    "status": "failed",
                    "error": detail,
                    "label": _LABELS.get(key, key),
                }
            )
    return rows


def _tools_from_findings(findings: object) -> set[str]:
    found: set[str] = set()
    if not isinstance(findings, list):
        return found
    for item in findings:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool") or "").strip().lower()
        if tool:
            found.add(tool)
    return found


def _failed_tools_from_error(error: str) -> dict[str, str]:
    """Parse lines like ``Checkov: timed out`` from the scan error field."""

    found: dict[str, str] = {}
    for line in str(error or "").splitlines():
        text = line.strip()
        if ":" not in text:
            continue
        head, _, rest = text.partition(":")
        key = head.strip().lower()
        if key == "sonarqube":
            key = "sonar"
        if key in _LABELS:
            found[key] = rest.strip() or text
    return found
