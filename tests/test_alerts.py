"""Falco alerts are stored as short text, not as nested caller data."""

from __future__ import annotations

from security_console.alerts import alert_from_payload


def test_alert_clips_text_and_ignores_nested_objects() -> None:
    alert = alert_from_payload(
        {
            "time": "x" * 200,
            "priority": "Warning",
            "rule": "shell",
            "output": "y" * 5000,
            "output_fields": {"host.name": "work-01", "cmd": {"nested": True}},
        },
        "2026-10-12 00:00:00 UTC",
    )

    assert len(alert["time"]) == 80
    assert len(alert["output"]) == 2000
    assert alert["source"] == "work-01"
    assert set(alert) == {"time", "priority", "rule", "output", "source"}
