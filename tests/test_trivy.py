"""Trivy report rows become the same finding shape as the other tools."""

from __future__ import annotations

from security_console.trivy import parse_report


def test_parse_report_keeps_vuln_misconfig_and_secret() -> None:
    findings = parse_report(
        {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-1",
                            "Severity": "HIGH",
                            "PkgName": "left-pad",
                            "Title": "Prototype issue",
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Severity": "CRITICAL",
                            "Title": "Image user should not be root",
                            "CauseMetadata": {"StartLine": 4},
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "private-key",
                            "Severity": "CRITICAL",
                            "Title": "Private key",
                            "StartLine": 2,
                        }
                    ],
                }
            ]
        }
    )

    assert [row["check"] for row in findings] == [
        "CVE-2026-1",
        "DS002",
        "private-key",
    ]
    assert findings[0]["message"] == "Prototype issue (left-pad)"
    assert findings[1]["line"] == 4
    assert {row["tool"] for row in findings} == {"trivy"}
