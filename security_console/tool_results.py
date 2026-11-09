"""Per-tool ok/failed status for a finished scan."""

from __future__ import annotations

from typing import Any

_LABELS: dict[str, str] = {
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
) -> list[dict[str, Any]]:
    """Return one row per requested tool. Derive from error/findings when missing."""

    active = str(status or "").strip().lower() in {"running", "queued"}
    failed_scan = str(status or "").strip().lower() == "failed"
    by_tool: dict[str, dict[str, Any]] = {}
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
            row: dict[str, Any] = {
                "tool": tool,
                "status": row_status,
                "error": str(item.get("error") or "")[:500],
                "label": _LABELS.get(tool, tool),
            }
            coverage = str(item.get("coverage") or "").strip().lower()
            if coverage in {"with_findings", "no_findings", "no_targets"}:
                row["coverage"] = coverage
            summary = item.get("summary")
            if isinstance(summary, dict):
                row["summary"] = summary
            by_tool[tool] = row
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
    last_recorded = -1
    for index, key in enumerate(ordered):
        if key in by_tool:
            last_recorded = index
    detail = str(error or "").strip()[:500]
    rows: list[dict[str, Any]] = []
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
        if key in finding_tools:
            rows.append(
                {
                    "tool": key,
                    "status": "ok",
                    "error": "",
                    "label": _LABELS.get(key, key),
                }
            )
            continue
        # Failed scans: tools that never recorded a result did not finish.
        if failed_scan and detail and index > last_recorded:
            rows.append(
                {
                    "tool": key,
                    "status": "failed",
                    "error": detail,
                    "label": _LABELS.get(key, key),
                }
            )
            continue
        # Invent OK only for gaps at/before the last recorded tool, or
        # tools that finished before a tool-prefixed failure line.
        if (
            (last_recorded >= 0 and index <= last_recorded)
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
