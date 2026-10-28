"""Risk fingerprint stability."""

from __future__ import annotations

from security_console.fingerprint import (
    compute_risk_fingerprint,
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
