"""Per-tool ok/failed rows for the scan report."""

from __future__ import annotations

from security_console.tool_results import normalize_tool_results


def test_normalize_keeps_stored_rows() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [
            {"tool": "semgrep", "status": "ok"},
            {"tool": "checkov", "status": "failed", "error": "timed out"},
            {"tool": "trivy", "status": "ok"},
        ],
    )
    assert [(row["tool"], row["status"], row["label"]) for row in rows] == [
        ("semgrep", "ok", "Semgrep"),
        ("checkov", "failed", "Checkov"),
        ("trivy", "ok", "Trivy"),
    ]
    assert rows[1]["error"] == "timed out"


def test_normalize_derives_failed_tool_from_error() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [],
        "Checkov: Checkov timed out after 1200 seconds.",
        [{"tool": "semgrep"}, {"tool": "trivy"}],
    )
    assert [row["status"] for row in rows] == ["ok", "failed", "ok"]
    assert "timed out" in rows[1]["error"]


def test_normalize_marks_earlier_tools_ok_when_later_fails() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [],
        "Checkov: Checkov timed out after 1200 seconds.",
        [],
    )
    assert [(row["tool"], row["status"]) for row in rows] == [
        ("semgrep", "ok"),
        ("checkov", "failed"),
    ]


def test_normalize_marks_all_failed_when_clone_failed() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [],
        "git timed out.",
    )
    assert [row["status"] for row in rows] == ["failed", "failed", "failed"]
    assert rows[0]["error"] == "git timed out."


def test_normalize_marks_all_failed_when_scanner_unavailable() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [],
        "The scanner is unavailable.",
    )
    assert [(row["tool"], row["status"]) for row in rows] == [
        ("semgrep", "failed"),
        ("checkov", "failed"),
        ("trivy", "failed"),
    ]


def test_normalize_does_not_invent_ok_while_running() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [],
        "",
        status="running",
    )
    assert rows == []


def test_normalize_keeps_recorded_rows_while_running() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "trivy"],
        [{"tool": "semgrep", "status": "ok"}],
        "",
        status="running",
    )
    assert [(row["tool"], row["status"]) for row in rows] == [("semgrep", "ok")]


def test_normalize_marks_unfinished_tools_failed_after_restart() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov", "sonar"],
        [{"tool": "semgrep", "status": "ok"}],
        "The console restarted during the scan.",
        [{"tool": "semgrep"}],
        status="failed",
    )
    assert [(row["tool"], row["status"]) for row in rows] == [
        ("semgrep", "ok"),
        ("checkov", "failed"),
        ("sonar", "failed"),
    ]
    assert "restarted" in rows[2]["error"]


def test_normalize_keeps_checkov_coverage_and_summary() -> None:
    rows = normalize_tool_results(
        ["checkov", "semgrep"],
        [
            {
                "tool": "checkov",
                "status": "ok",
                "coverage": "no_findings",
                "summary": {
                    "passed": 4,
                    "failed": 0,
                    "skipped": 0,
                    "resource_count": 2,
                    "frameworks": ["terraform"],
                },
            },
            {"tool": "semgrep", "status": "ok"},
        ],
    )
    assert rows[0]["coverage"] == "no_findings"
    assert rows[0]["summary"]["frameworks"] == ["terraform"]
    assert "coverage" not in rows[1]


def test_normalize_ignores_unknown_checkov_coverage() -> None:
    rows = normalize_tool_results(
        ["checkov"],
        [{"tool": "checkov", "status": "ok", "coverage": "weird"}],
    )
    assert "coverage" not in rows[0]
