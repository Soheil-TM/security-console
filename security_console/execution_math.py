"""Stage-based scan progress and elapsed helpers (Execution Center).

Keep formulas in sync with ``static/execution_math.js``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def _parse_stamp(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    text = raw
    if text.endswith(" UTC"):
        text = text[: -len(" UTC")].strip()
        try:
            return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    try:
        if " " in text and "T" not in text and not text.endswith("Z"):
            text = text.replace(" ", "T") + "Z"
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _ok_tools(scan: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for row in scan.get("tool_results") or []:
        if not isinstance(row, dict):
            continue
        tool = str(row.get("tool") or "").strip().lower()
        if tool and str(row.get("status") or "").strip().lower() == "ok":
            found.add(tool)
    return found


def scan_progress(scan: dict[str, Any] | None) -> dict[str, Any]:
    """Return stage-based pipeline progress from real tool_results only.

    Running / Waiting / Failed never count as successful completion.
    ``status == failed`` never yields 100. ``status == done`` yields 100 only
    when every requested tool has ``status == ok``.
    """

    if not isinstance(scan, dict):
        return {
            "percent": 0,
            "ok": 0,
            "total": 0,
            "complete_success": False,
            "label": "queued",
        }
    tools = [
        str(tool).strip().lower()
        for tool in (scan.get("tools") or [])
        if str(tool).strip()
    ]
    total = len(tools)
    ok_set = _ok_tools(scan)
    ok = sum(1 for tool in tools if tool in ok_set)
    status = str(scan.get("status") or "").strip().lower()
    if total == 0:
        percent = 0
    else:
        percent = int((ok * 100) // total)
    complete_success = status == "done" and total > 0 and ok == total
    if status == "failed":
        percent = min(percent, 99)
        complete_success = False
    elif status == "done" and complete_success:
        percent = 100
    elif status == "done":
        # Finished run with gaps/failures: show ratio, never claim full success.
        percent = min(percent, 99) if ok < total else percent
        complete_success = False
    if status == "queued":
        label = "queued"
    elif status == "running":
        label = "running"
    elif status == "failed":
        label = "failed"
    elif complete_success:
        label = "completed"
    elif status == "done":
        label = "done_partial"
    else:
        label = status or "unknown"
    return {
        "percent": percent,
        "ok": ok,
        "total": total,
        "complete_success": complete_success,
        "label": label,
    }


def format_duration(seconds: float) -> str:
    if seconds < 0 or not (seconds == seconds):  # NaN
        seconds = 0
    whole = int(seconds)
    hours, rem = divmod(whole, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def scan_elapsed(
    scan: dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Elapsed execution time from ``started_at`` (not queue wait)."""

    if not isinstance(scan, dict):
        return {"kind": "waiting", "seconds": 0, "text": ""}
    started = _parse_stamp(scan.get("started_at"))
    if started is None:
        return {"kind": "waiting", "seconds": 0, "text": ""}
    finished = _parse_stamp(scan.get("finished_at"))
    end = finished if finished is not None else (now or datetime.now(UTC))
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    seconds = max(0.0, (end - started).total_seconds())
    kind = "frozen" if finished is not None else "running"
    return {
        "kind": kind,
        "seconds": seconds,
        "text": format_duration(seconds),
    }
