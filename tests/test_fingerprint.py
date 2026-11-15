"""Risk fingerprint stability."""

from __future__ import annotations

from security_console.fingerprint import (
    compute_risk_fingerprint,
    finding_disposition_parts,
    fingerprints_match,
)


def test_fingerprint_stable_and_sensitive_to_disposition() -> None:
    keys = ["semgrep|a|a.py|1", "trivy|CVE-1|pkg|"]
    base = {
        "semgrep|a|a.py|1": {"status": "false_positive", "reason": "test reason x"},
        "trivy|CVE-1|pkg|": {"status": "accepted_risk", "reason": "accepted now"},
    }
    left = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=keys,
        dispositions=base,
    )
    right = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=list(reversed(keys)),
        dispositions=base,
    )
    assert fingerprints_match(left, right)
    changed = dict(base)
    changed["semgrep|a|a.py|1"] = {
        "status": "true_positive",
        "reason": "test reason x",
    }
    other = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=keys,
        dispositions=changed,
    )
    assert not fingerprints_match(left, other)


def test_proposed_risk_reason_is_not_a_closed_disposition() -> None:
    key = "semgrep|proposal|a.py|1"
    parts = finding_disposition_parts(
        key,
        {
            "status": "risk_proposed",
            "reason": "Developer wants the lead to accept this.",
        },
    )
    assert parts["status"] == "risk_proposed"
    assert parts["reason_hash"] == ""
    left = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=[key],
        dispositions={key: {"status": "risk_proposed", "reason": "First rationale."}},
    )
    right = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=[key],
        dispositions={
            key: {"status": "risk_proposed", "reason": "Rewritten rationale."}
        },
    )
    assert fingerprints_match(left, right)


def test_fingerprint_sensitive_to_resolved_reason_change() -> None:
    key = "semgrep|a|a.py|1"
    base = {key: {"status": "resolved", "reason": "Fixed in release train."}}
    left = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=[key],
        dispositions=base,
    )
    changed = {key: {"status": "resolved", "reason": "Different fix rationale."}}
    right = compute_risk_fingerprint(
        project_key="payments",
        commit_sha="abc",
        finding_keys=[key],
        dispositions=changed,
    )
    assert not fingerprints_match(left, right)
