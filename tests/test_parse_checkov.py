"""Checkov multi-framework parsing and coverage metadata."""

from __future__ import annotations

import json

import pytest

from security_console.runner import (
    _parse_checkov,
    _record_checkov,
    analyze_checkov,
)
from security_console.tool_results import normalize_tool_results


def _failed_check(
    check_id: str,
    path: str,
    line: int,
    *,
    name: str = "policy",
    severity: str = "HIGH",
) -> dict:
    return {
        "check_id": check_id,
        "file_path": path,
        "file_line_range": [line, line],
        "check_name": name,
        "severity": severity,
    }


def test_single_object_with_findings() -> None:
    payload = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                _failed_check("CKV_AWS_1", "/src/main.tf", 3, name="Encrypt bucket"),
            ],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 0,
            "failed": 1,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 1,
        },
        "checkov_version": "3.3.26",
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert len(findings) == 1
    assert findings[0]["tool"] == "checkov"
    assert findings[0]["check"] == "CKV_AWS_1"
    assert findings[0]["path"] == "/src/main.tf"
    assert findings[0]["line"] == 3
    assert findings[0]["check_type"] == "terraform"
    assert findings[0]["framework"] == "terraform"
    assert summary["failed"] == 1
    assert summary["resource_count"] == 1
    assert summary["frameworks"] == ["terraform"]
    assert summary["checkov_version"] == "3.3.26"
    assert _parse_checkov(json.dumps(payload)) == findings


def test_single_object_zero_findings_with_resources() -> None:
    payload = {
        "check_type": "dockerfile",
        "results": {
            "passed_checks": [{"check_id": "CKV_DOCKER_1"}],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 2,
        },
        "checkov_version": "3.3.26",
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "no_findings"
    assert findings == []
    assert summary["passed"] == 1
    assert summary["resource_count"] == 2
    assert summary["frameworks"] == ["dockerfile"]


def test_zero_resource_flat_summary() -> None:
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
        "checkov_version": "3.3.26",
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "no_targets"
    assert findings == []
    assert summary["resource_count"] == 0
    assert summary["passed"] == 0
    assert summary["frameworks"] == []
    assert summary["checkov_version"] == "3.3.26"


def test_multi_framework_array_aggregates_and_keeps_later_findings() -> None:
    payload = [
        {
            "check_type": "terraform",
            "results": {
                "passed_checks": [{"check_id": "CKV_AWS_OK"}],
                "failed_checks": [],
                "skipped_checks": [],
            },
            "summary": {
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "parsing_errors": 0,
                "resource_count": 1,
            },
        },
        {
            "check_type": "dockerfile",
            "results": {
                "passed_checks": [],
                "failed_checks": [
                    _failed_check(
                        "CKV_DOCKER_3",
                        "/src/Dockerfile",
                        2,
                        name="Ensure USER",
                    ),
                ],
                "skipped_checks": [{"check_id": "CKV_DOCKER_SKIP"}],
            },
            "summary": {
                "passed": 0,
                "failed": 1,
                "skipped": 1,
                "parsing_errors": 0,
                "resource_count": 1,
            },
            "checkov_version": "3.3.26",
        },
    ]
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert len(findings) == 1
    assert findings[0]["check"] == "CKV_DOCKER_3"
    assert findings[0]["check_type"] == "dockerfile"
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["skipped"] == 1
    assert summary["resource_count"] == 2
    assert summary["frameworks"] == ["terraform", "dockerfile"]
    assert summary["checkov_version"] == "3.3.26"


def test_findings_only_in_second_array_element() -> None:
    """Regression: parser must not keep only data[0]."""

    payload = [
        {
            "check_type": "terraform",
            "results": {"failed_checks": [], "passed_checks": [], "skipped_checks": []},
            "summary": {
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "resource_count": 0,
            },
        },
        {
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [
                    _failed_check("CKV_K8S_1", "deploy.yaml", 10),
                    _failed_check("CKV_K8S_2", "deploy.yaml", 20),
                ],
                "passed_checks": [],
                "skipped_checks": [],
            },
            "summary": {
                "passed": 0,
                "failed": 2,
                "skipped": 0,
                "resource_count": 1,
            },
        },
    ]
    findings, _summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert [row["check"] for row in findings] == ["CKV_K8S_1", "CKV_K8S_2"]


def test_empty_json_array() -> None:
    findings, summary, coverage = analyze_checkov("[]")
    assert coverage == "no_targets"
    assert findings == []
    assert summary["resource_count"] == 0
    assert summary["frameworks"] == []


def test_missing_optional_fields() -> None:
    payload = {
        "check_type": "arm",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AZURE_1",
                    "file_path": "template.json",
                }
            ]
        },
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert findings[0]["line"] is None
    assert findings[0]["message"] == ""
    assert findings[0]["severity"] == "UNKNOWN"
    assert "checkov_version" not in summary


def test_malformed_json_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        analyze_checkov("not-json-at-all")


def test_record_checkov_marks_malformed_failed() -> None:
    findings: list[dict] = []
    notes: list[str] = []
    failures: list[str] = []
    tool_results: list[dict] = []
    _record_checkov(findings, notes, failures, tool_results, 0, "nope", "")
    assert findings == []
    assert tool_results == [
        {
            "tool": "checkov",
            "status": "failed",
            "error": "Checkov output was not usable JSON",
        }
    ]
    assert failures[0].startswith("Checkov:")


def test_resource_count_alone_is_no_targets() -> None:
    payload = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 5,
        },
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert findings == []
    assert summary["resource_count"] == 5
    assert coverage == "no_targets"


def test_resource_count_with_passed_checks_is_no_findings() -> None:
    payload = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [{"check_id": "CKV_AWS_OK"}],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "resource_count": 3,
        },
    }
    findings, _summary, coverage = analyze_checkov(json.dumps(payload))
    assert findings == []
    assert coverage == "no_findings"


def test_resource_count_with_failed_checks_is_with_findings() -> None:
    payload = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [_failed_check("CKV_AWS_9", "main.tf", 1)],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 0,
            "failed": 1,
            "skipped": 0,
            "resource_count": 2,
        },
    }
    findings, _summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert findings[0]["check"] == "CKV_AWS_9"


def test_missing_summary_uses_check_lists_for_no_findings() -> None:
    payload = {
        "check_type": "dockerfile",
        "results": {
            "passed_checks": [{"check_id": "CKV_DOCKER_1"}],
            "failed_checks": [],
            "skipped_checks": [],
        },
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "no_findings"
    assert findings == []
    assert summary["passed"] == 1


def test_exit_code_1_with_findings_is_ok() -> None:
    findings: list[dict] = []
    notes: list[str] = []
    failures: list[str] = []
    tool_results: list[dict] = []
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [_failed_check("CKV_AWS_1", "main.tf", 2)],
            "passed_checks": [],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 0,
            "failed": 1,
            "skipped": 0,
            "resource_count": 1,
        },
    }
    _record_checkov(
        findings,
        notes,
        failures,
        tool_results,
        1,
        json.dumps(payload),
        "",
    )
    assert failures == []
    assert tool_results[0]["status"] == "ok"
    assert tool_results[0]["coverage"] == "with_findings"
    assert len(findings) == 1


def test_parsing_errors_only_fails_record() -> None:
    findings: list[dict] = []
    notes: list[str] = []
    failures: list[str] = []
    tool_results: list[dict] = []
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 3,
        "resource_count": 0,
    }
    _record_checkov(
        findings,
        notes,
        failures,
        tool_results,
        0,
        json.dumps(payload),
        "",
    )
    assert tool_results[0]["status"] == "failed"
    assert "coverage" not in tool_results[0]
    assert "parsing errors" in tool_results[0]["error"].lower()


def test_structurally_invalid_json_values_fail() -> None:
    for raw in ("null", "true", '"unexpected"', "123"):
        with pytest.raises(json.JSONDecodeError):
            analyze_checkov(raw)
        findings: list[dict] = []
        notes: list[str] = []
        failures: list[str] = []
        tool_results: list[dict] = []
        _record_checkov(findings, notes, failures, tool_results, 0, raw, "")
        assert tool_results[0]["status"] == "failed"
        assert "coverage" not in tool_results[0]


def test_mixed_findings_across_first_and_later_frameworks() -> None:
    payload = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [_failed_check("CKV_AWS_1", "a.tf", 1)],
                "passed_checks": [],
                "skipped_checks": [],
            },
            "summary": {
                "passed": 0,
                "failed": 1,
                "skipped": 0,
                "resource_count": 1,
            },
        },
        {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [_failed_check("CKV_DOCKER_1", "Dockerfile", 1)],
                "passed_checks": [],
                "skipped_checks": [],
            },
            "summary": {
                "passed": 0,
                "failed": 1,
                "skipped": 0,
                "resource_count": 1,
            },
        },
    ]
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert [row["check"] for row in findings] == ["CKV_AWS_1", "CKV_DOCKER_1"]
    assert summary["frameworks"] == ["terraform", "dockerfile"]
    assert summary["failed"] == 2


def test_record_checkov_bad_exit_failed() -> None:
    findings: list[dict] = []
    notes: list[str] = []
    failures: list[str] = []
    tool_results: list[dict] = []
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
    }
    _record_checkov(
        findings,
        notes,
        failures,
        tool_results,
        2,
        json.dumps(payload),
        "boom",
    )
    assert tool_results[0]["status"] == "failed"
    assert "coverage" not in tool_results[0]


def test_record_checkov_ok_with_coverage() -> None:
    findings: list[dict] = []
    notes: list[str] = []
    failures: list[str] = []
    tool_results: list[dict] = []
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
        "checkov_version": "3.3.26",
    }
    _record_checkov(
        findings,
        notes,
        failures,
        tool_results,
        0,
        json.dumps(payload),
        "",
    )
    assert failures == []
    assert tool_results[0]["status"] == "ok"
    assert tool_results[0]["coverage"] == "no_targets"
    assert tool_results[0]["summary"]["checkov_version"] == "3.3.26"


def test_duplicate_findings_deduped() -> None:
    dup = _failed_check("CKV_AWS_1", "main.tf", 4)
    payload = {
        "check_type": "terraform",
        "results": {"failed_checks": [dup, dict(dup), dict(dup)]},
        "summary": {
            "passed": 0,
            "failed": 3,
            "skipped": 0,
            "resource_count": 1,
        },
    }
    findings, summary, coverage = analyze_checkov(json.dumps(payload))
    assert coverage == "with_findings"
    assert len(findings) == 1
    # Counter comes from Checkov summary, not deduped finding count.
    assert summary["failed"] == 3


def test_normalize_preserves_checkov_metadata() -> None:
    rows = normalize_tool_results(
        ["semgrep", "checkov"],
        [
            {"tool": "semgrep", "status": "ok"},
            {
                "tool": "checkov",
                "status": "ok",
                "coverage": "no_targets",
                "summary": {"resource_count": 0, "passed": 0, "failed": 0},
            },
        ],
    )
    assert rows[0]["status"] == "ok"
    assert "coverage" not in rows[0]
    assert rows[1]["status"] == "ok"
    assert rows[1]["coverage"] == "no_targets"
    assert rows[1]["summary"]["resource_count"] == 0


def test_normalize_legacy_checkov_without_coverage() -> None:
    rows = normalize_tool_results(
        ["checkov"],
        [{"tool": "checkov", "status": "ok"}],
    )
    assert rows == [
        {
            "tool": "checkov",
            "status": "ok",
            "error": "",
            "label": "Checkov",
        }
    ]


def test_no_findings_not_inferred_from_empty_findings_alone() -> None:
    """Empty findings without counters/resources stay no_targets, not no_findings."""

    findings, _summary, coverage = analyze_checkov("{}")
    assert findings == []
    assert coverage == "no_targets"
