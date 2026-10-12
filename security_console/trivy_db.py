"""Refresh the shared Trivy databases from official mirrors.

Each refresh starts at the first repository. A later mirror is used only
when the earlier one fails for a reason another mirror might survive, such
as a timeout or a blocked registry. The cache volume is never deleted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from security_console.runtime import (
    TRIVY_JAVA_REPOSITORIES,
    TRIVY_VULN_REPOSITORIES,
    trivy_db_update_spec,
)

Attempt = Callable[[dict[str, Any]], tuple[int, str, str]]

# Another mirror cannot repair a bad invocation or a cache that is not writable.
_LOCAL_FAILURES = (
    "unknown flag",
    "unknown command",
    "unknown shorthand",
    "permission denied",
)
_LABEL = {"vuln": "vulnerability", "java": "Java"}


def refresh_trivy_databases(run: Attempt) -> str:
    """Download both databases. Return an empty string when both succeed.

    The returned text is safe to show on a scan. It does not remove the
    cache, so a later scan can still use the last database that landed.
    """

    notes = [
        _refresh_one(run, "vuln", TRIVY_VULN_REPOSITORIES),
        _refresh_one(run, "java", TRIVY_JAVA_REPOSITORIES),
    ]
    return "\n".join(note for note in notes if note)


def _refresh_one(run: Attempt, kind: str, repositories: tuple[str, ...]) -> str:
    tried: list[str] = []
    for repository in repositories:
        try:
            code, stdout, stderr = run(trivy_db_update_spec(kind, repository))
        except Exception as exc:
            detail = str(exc).strip() or type(exc).__name__
            tried.append(_attempt(repository, detail))
            if _try_next(detail):
                continue
            break
        if code == 0:
            return ""
        detail = (stderr or stdout).strip() or f"exit {code}"
        tried.append(_attempt(repository, detail))
        if not _try_next(detail):
            break
    label = _LABEL[kind]
    summary = " | ".join(tried)[:700]
    return (
        f"Could not refresh the Trivy {label} database. "
        f"The scan will use the cached database. {summary}"
    ).strip()


def _try_next(detail: str) -> bool:
    """Return whether the next official mirror is worth trying."""

    lowered = detail.lower()
    return not any(marker in lowered for marker in _LOCAL_FAILURES)


def _attempt(repository: str, detail: str) -> str:
    compact = " ".join(detail.split())
    return f"{repository}: {compact[:160]}"
