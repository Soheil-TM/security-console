"""Finding class auto-classifier."""

from __future__ import annotations

from security_console.classify import CLASSIFIER_VERSION, classify_finding, enrich_findings


def test_semgrep_and_checkov_are_security() -> None:
    for tool in ("semgrep", "checkov"):
        row = classify_finding({"tool": tool, "check": "x", "path": "a", "line": 1})
        assert row["finding_class"] == "security"
        assert row["classification_source"] == "auto"
        assert row["classifier_version"] == CLASSIFIER_VERSION


def test_sonar_types() -> None:
    vuln = classify_finding(
        {"tool": "sonar", "sonar_type": "VULNERABILITY", "check": "r"}
    )
    assert vuln["finding_class"] == "security"
    hotspot = classify_finding(
        {
            "tool": "sonar",
            "sonar_type": "SECURITY_HOTSPOT",
            "security_review": True,
            "check": "h",
        }
    )
    assert hotspot["finding_class"] == "security"
    smell = classify_finding(
        {"tool": "sonar", "sonar_type": "CODE_SMELL", "check": "s"}
    )
    assert smell["finding_class"] == "quality"
    bug = classify_finding({"tool": "sonar", "sonar_type": "BUG", "check": "b"})
    assert bug["finding_class"] == "quality"


def test_sonar_hotspot_without_review_is_quality() -> None:
    row = classify_finding(
        {
            "tool": "sonar",
            "sonar_type": "SECURITY_HOTSPOT",
            "security_review": False,
            "check": "h",
        }
    )
    assert row["finding_class"] == "quality"


def test_trivy_kinds() -> None:
    vuln = classify_finding(
        {"tool": "trivy", "trivy_kind": "vulnerability", "check": "CVE-1"}
    )
    secret = classify_finding(
        {"tool": "trivy", "trivy_kind": "secret", "check": "key"}
    )
    misconfig = classify_finding(
        {"tool": "trivy", "trivy_kind": "misconfiguration", "check": "DS002"}
    )
    assert vuln["finding_class"] == "security"
    assert secret["finding_class"] == "security"
    assert misconfig["finding_class"] == "operational"


def test_trivy_without_kind_defaults_security() -> None:
    row = classify_finding({"tool": "trivy", "check": "CVE-1"})
    assert row["finding_class"] == "security"


def test_unknown_tool_defaults_security() -> None:
    row = classify_finding({"tool": "other", "check": "x"})
    assert row["finding_class"] == "security"


def test_manual_class_is_preserved() -> None:
    row = classify_finding(
        {
            "tool": "semgrep",
            "check": "x",
            "finding_class": "quality",
            "classification_source": "manual",
            "classifier_version": 9,
        }
    )
    assert row["finding_class"] == "quality"
    assert row["classification_source"] == "manual"
    assert row["classifier_version"] == 9


def test_manual_without_valid_class_is_overwritten() -> None:
    row = classify_finding(
        {
            "tool": "semgrep",
            "check": "x",
            "finding_class": "nope",
            "classification_source": "manual",
        }
    )
    assert row["finding_class"] == "security"
    assert row["classification_source"] == "auto"


def test_enrich_findings_returns_new_list() -> None:
    original = [{"tool": "semgrep", "check": "a"}]
    out = enrich_findings(original)
    assert out is not original
    assert original[0].get("finding_class") is None
    assert out[0]["finding_class"] == "security"


def test_enrich_applies_project_override() -> None:
    from security_console.risk import finding_key

    row = {"tool": "semgrep", "check": "a", "path": "a.py", "line": 1}
    key = finding_key(row)
    out = enrich_findings(
        [row],
        overrides={
            key: {
                "finding_class": "quality",
                "reason": "Style rule tracked in Sonar backlog.",
                "updated_by": "boss",
            }
        },
    )
    assert out[0]["finding_class"] == "quality"
    assert out[0]["classification_source"] == "manual"
    assert out[0]["classification_updated_by"] == "boss"


def test_gate_respects_manual_quality_and_security() -> None:
    from security_console.investigate import gate_readiness
    from security_console.risk import finding_key

    security = {"tool": "semgrep", "check": "sec", "path": "a.py", "line": 1}
    quality = {
        "tool": "semgrep",
        "check": "q",
        "path": "b.py",
        "line": 2,
        "finding_class": "quality",
        "classification_source": "manual",
    }
    sec_key = finding_key(security)
    ready = gate_readiness(
        [security, quality],
        {
            sec_key: {
                "status": "false_positive",
                "reason": "Not reachable in production path.",
            }
        },
    )
    assert ready["ready_for_gate"] is True
    assert ready["excluded_quality"] == 1

    blocked = gate_readiness(
        [
            {
                "tool": "sonar",
                "check": "python:S1",
                "path": "c.py",
                "line": 3,
                "sonar_type": "CODE_SMELL",
                "finding_class": "security",
                "classification_source": "manual",
            }
        ],
        {},
    )
    assert blocked["ready_for_gate"] is False
    assert blocked["gate_finding_count"] == 1
