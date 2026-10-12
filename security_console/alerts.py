"""Falco webhook rows stored by the console."""

from __future__ import annotations

from typing import Any

_LIMITS = {
    "time": 80,
    "priority": 40,
    "rule": 300,
    "output": 2000,
    "source": 200,
}


def alert_from_payload(payload: dict[str, Any], now: str) -> dict[str, str]:
    """Keep one alert and drop oversized or non-text fields."""

    fields = payload.get("output_fields")
    source = ""
    if isinstance(payload.get("hostname"), str):
        source = payload["hostname"]
    elif isinstance(fields, dict) and isinstance(fields.get("host.name"), str):
        source = fields["host.name"]
    moment = payload.get("time")
    if not isinstance(moment, str) or not moment:
        moment = now
    priority = payload.get("priority")
    if not isinstance(priority, str) or not priority:
        priority = "Notice"
    return {
        "time": _clip(moment, _LIMITS["time"]),
        "priority": _clip(priority, _LIMITS["priority"]),
        "rule": _clip(payload.get("rule"), _LIMITS["rule"]),
        "output": _clip(payload.get("output"), _LIMITS["output"]),
        "source": _clip(source, _LIMITS["source"]),
    }


def _clip(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]
