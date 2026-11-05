"""Stage-based progress and elapsed for the Execution Center."""

from __future__ import annotations

from datetime import UTC, datetime

from security_console.execution_math import scan_elapsed, scan_progress


def test_progress_queued_is_zero_without_ok() -> None:
    result = scan_progress(
        {
            "status": "queued",
            "tools": ["semgrep", "checkov", "sonar"],
            "tool_results": [],
        }
    )
    assert result["percent"] == 0
    assert result["label"] == "queued"
    assert result["complete_success"] is False


def test_progress_running_counts_only_ok() -> None:
    result = scan_progress(
        {
            "status": "running",
            "phase": "Checkov",
            "tools": ["semgrep", "checkov", "sonar"],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
        }
    )
    assert result["percent"] == 33
    assert result["ok"] == 1
    assert result["total"] == 3
    assert result["complete_success"] is False


def test_progress_done_all_ok_is_100() -> None:
    result = scan_progress(
        {
            "status": "done",
            "tools": ["semgrep", "checkov"],
            "tool_results": [
                {"tool": "semgrep", "status": "ok"},
                {"tool": "checkov", "status": "ok"},
            ],
        }
    )
    assert result["percent"] == 100
    assert result["complete_success"] is True
    assert result["label"] == "completed"


def test_progress_failed_never_100() -> None:
    result = scan_progress(
        {
            "status": "failed",
            "tools": ["semgrep", "checkov", "sonar"],
            "tool_results": [
                {"tool": "semgrep", "status": "ok"},
                {"tool": "checkov", "status": "ok"},
                {"tool": "sonar", "status": "ok"},
            ],
        }
    )
    assert result["percent"] < 100
    assert result["complete_success"] is False
    assert result["label"] == "failed"


def test_progress_done_partial_not_full_success() -> None:
    result = scan_progress(
        {
            "status": "done",
            "tools": ["semgrep", "checkov", "sonar"],
            "tool_results": [
                {"tool": "semgrep", "status": "ok"},
                {"tool": "checkov", "status": "ok"},
                {"tool": "sonar", "status": "failed", "error": "timeout"},
            ],
        }
    )
    assert result["percent"] == 66
    assert result["complete_success"] is False
    assert result["label"] == "done_partial"


def test_progress_image_only_trivy() -> None:
    result = scan_progress(
        {
            "status": "done",
            "tools": ["trivy"],
            "tool_results": [{"tool": "trivy", "status": "ok"}],
        }
    )
    assert result["percent"] == 100
    assert result["total"] == 1


def test_progress_subset_tools() -> None:
    result = scan_progress(
        {
            "status": "running",
            "tools": ["semgrep"],
            "tool_results": [{"tool": "semgrep", "status": "ok"}],
        }
    )
    assert result["percent"] == 100
    assert result["complete_success"] is False
    assert result["label"] == "running"


def test_progress_ignores_unrequested_ok() -> None:
    result = scan_progress(
        {
            "status": "running",
            "tools": ["semgrep"],
            "tool_results": [
                {"tool": "semgrep", "status": "ok"},
                {"tool": "trivy", "status": "ok"},
            ],
        }
    )
    assert result["ok"] == 1
    assert result["total"] == 1


def test_elapsed_waiting_without_started_at() -> None:
    result = scan_elapsed({"status": "queued", "tools": ["semgrep"]})
    assert result["kind"] == "waiting"
    assert result["text"] == ""


def test_elapsed_running_and_frozen() -> None:
    start = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)
    now = datetime(2026, 11, 3, 12, 0, 45, tzinfo=UTC)
    running = scan_elapsed(
        {
            "started_at": "2026-11-03 12:00:00 UTC",
            "finished_at": "",
        },
        now=now,
    )
    assert running["kind"] == "running"
    assert running["text"] == "00:45"

    frozen = scan_elapsed(
        {
            "started_at": "2026-11-03 12:00:00 UTC",
            "finished_at": "2026-11-03 12:01:30 UTC",
        },
        now=now,
    )
    assert frozen["kind"] == "frozen"
    assert frozen["text"] == "01:30"
    assert start  # silence lint about unused in some runners
