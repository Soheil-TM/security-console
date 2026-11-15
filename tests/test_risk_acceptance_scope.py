"""Risk acceptance must not approve after gate scope changes (C1/C2)."""

from __future__ import annotations

from security_console.classify import enrich_findings
from security_console.fingerprint import (
    compute_risk_fingerprint,
    risk_acceptance_still_valid,
)
from security_console.investigate import gate_scoped_findings, triage_snapshot
from security_console.risk import finding_key

PROJECT = "payments-api"
COMMIT = "abc123def"


def _disp(
    status: str = "false_positive",
    reason: str = "Not reachable in prod.",
) -> dict:
    return {"status": status, "reason": reason}


def _accept_bundle(
    findings: list[dict],
    dispositions: dict[str, dict],
) -> tuple[dict, str]:
    enriched = enrich_findings(findings)
    snapshot = triage_snapshot(enriched, dispositions)
    keys = [finding_key(row) for row in gate_scoped_findings(enriched)]
    fingerprint = compute_risk_fingerprint(
        project_key=PROJECT,
        commit_sha=COMMIT,
        finding_keys=keys,
        dispositions=dispositions,
    )
    return snapshot, fingerprint


def test_quality_to_security_override_invalidates_acceptance() -> None:
    quality = {
        "tool": "sonar",
        "check": "python:S125",
        "path": "a.py",
        "line": 1,
        "sonar_type": "CODE_SMELL",
    }
    security = {
        "tool": "semgrep",
        "check": "sec.rule",
        "path": "b.py",
        "line": 2,
    }
    sec_key = finding_key(security)
    q_key = finding_key(quality)
    dispositions = {
        sec_key: _disp(),
        q_key: _disp("accepted_risk", "Tracked as style debt only."),
    }
    snapshot, fingerprint = _accept_bundle([quality, security], dispositions)

    overridden = enrich_findings(
        [quality, security],
        overrides={
            q_key: {
                "finding_class": "security",
                "reason": "Actually a security smell.",
                "updated_by": "lead",
            }
        },
    )
    assert not risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=overridden,
        dispositions=dispositions,
    )


def test_security_to_quality_override_invalidates_acceptance() -> None:
    security = {
        "tool": "semgrep",
        "check": "sec.rule",
        "path": "b.py",
        "line": 2,
    }
    sec_key = finding_key(security)
    dispositions = {sec_key: _disp()}
    snapshot, fingerprint = _accept_bundle([security], dispositions)

    overridden = enrich_findings(
        [security],
        overrides={
            sec_key: {
                "finding_class": "quality",
                "reason": "Reclassified as style only.",
                "updated_by": "lead",
            }
        },
    )
    assert not risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=overridden,
        dispositions=dispositions,
    )


def test_empty_acceptance_then_quality_to_security_invalidates() -> None:
    quality = {
        "tool": "sonar",
        "check": "python:S125",
        "path": "a.py",
        "line": 1,
        "sonar_type": "CODE_SMELL",
    }
    q_key = finding_key(quality)
    dispositions: dict[str, dict] = {}
    snapshot, fingerprint = _accept_bundle([quality], dispositions)
    assert snapshot == {}
    assert fingerprint  # empty-scope acceptances still get a fingerprint

    overridden = enrich_findings(
        [quality],
        overrides={
            q_key: {
                "finding_class": "security",
                "reason": "Hotspot promoted after accept.",
                "updated_by": "lead",
            }
        },
    )
    assert not risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=overridden,
        dispositions={
            q_key: _disp("accepted_risk", "Accepted after reclass."),
        },
    )


def test_new_finding_entering_gate_scope_invalidates() -> None:
    first = {
        "tool": "semgrep",
        "check": "sec.one",
        "path": "a.py",
        "line": 1,
    }
    second = {
        "tool": "semgrep",
        "check": "sec.two",
        "path": "b.py",
        "line": 2,
    }
    first_key = finding_key(first)
    dispositions = {first_key: _disp()}
    snapshot, fingerprint = _accept_bundle([first], dispositions)

    both = enrich_findings([first, second])
    assert not risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=both,
        dispositions={
            **dispositions,
            finding_key(second): _disp(),
        },
    )


def test_finding_leaving_gate_scope_invalidates() -> None:
    keep = {
        "tool": "semgrep",
        "check": "sec.keep",
        "path": "a.py",
        "line": 1,
    }
    leave = {
        "tool": "semgrep",
        "check": "sec.leave",
        "path": "b.py",
        "line": 2,
    }
    dispositions = {
        finding_key(keep): _disp(),
        finding_key(leave): _disp(),
    }
    snapshot, fingerprint = _accept_bundle([keep, leave], dispositions)

    # Finding removed from the scan (left gate scope).
    remaining = enrich_findings([keep])
    assert not risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=remaining,
        dispositions=dispositions,
    )


def test_unchanged_scope_and_dispositions_still_allow() -> None:
    quality = {
        "tool": "sonar",
        "check": "python:S125",
        "path": "a.py",
        "line": 1,
        "sonar_type": "CODE_SMELL",
    }
    security = {
        "tool": "semgrep",
        "check": "sec.rule",
        "path": "b.py",
        "line": 2,
    }
    dispositions = {finding_key(security): _disp()}
    snapshot, fingerprint = _accept_bundle([quality, security], dispositions)

    current = enrich_findings([quality, security])
    assert risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=current,
        dispositions=dispositions,
    )


def test_legacy_acceptance_without_fingerprint_is_not_trusted() -> None:
    security = {
        "tool": "semgrep",
        "check": "sec.rule",
        "path": "b.py",
        "line": 2,
    }
    dispositions = {finding_key(security): _disp()}
    snapshot, _ = _accept_bundle([security], dispositions)
    assert not risk_acceptance_still_valid(
        stored_fingerprint="",
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=enrich_findings([security]),
        dispositions=dispositions,
    )


def test_raw_finding_without_override_enrichment_mis_scopes_gate() -> None:
    """Raw CODE_SMELL stays quality; only enriched override puts it in gate scope."""

    from security_console.fingerprint import current_gate_scope_keys
    from security_console.investigate import gate_readiness

    smell = {
        "tool": "sonar",
        "check": "python:S125",
        "path": "a.py",
        "line": 1,
        "sonar_type": "CODE_SMELL",
    }
    key = finding_key(smell)
    raw_keys = current_gate_scope_keys([smell])
    assert key not in raw_keys
    assert gate_readiness([smell], {})["ready_for_gate"] is True

    overridden = enrich_findings(
        [smell],
        overrides={
            key: {
                "finding_class": "security",
                "reason": "Actually a security smell.",
                "updated_by": "lead",
            }
        },
    )
    enriched_keys = current_gate_scope_keys(overridden)
    assert key in enriched_keys
    assert gate_readiness(overridden, {})["ready_for_gate"] is False
    assert raw_keys != enriched_keys


def test_resolved_reason_change_invalidates_acceptance() -> None:
    security = {
        "tool": "semgrep",
        "check": "sec.rule",
        "path": "b.py",
        "line": 2,
    }
    key = finding_key(security)
    dispositions = {
        key: {"status": "resolved", "reason": "Patched in hotfix branch."}
    }
    snapshot, fingerprint = _accept_bundle([security], dispositions)
    changed = {
        key: {"status": "resolved", "reason": "Different remediation write-up."}
    }
    assert not risk_acceptance_still_valid(
        stored_fingerprint=fingerprint,
        project_key=PROJECT,
        commit_sha=COMMIT,
        snapshot=snapshot,
        current_findings=enrich_findings([security]),
        dispositions=changed,
    )
