"""Queued scans wait in Postgres and are claimed one at a time."""

from __future__ import annotations

import os

import pytest

from security_console import db
from security_console.access import queue_position

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL", "").strip(),
    reason="DATABASE_URL is required for queue storage tests",
)


def _item(scan_id: str, *, status: str = "queued", created_at: str) -> dict:
    return {
        "id": scan_id,
        "target": "repo",
        "repo": "https://example.com/app.git",
        "image": "",
        "tools": ["semgrep"],
        "status": status,
        "phase": "",
        "error": "",
        "failure_reason": "",
        "owner": "ada",
        "requested_sha": "",
        "commit_sha": "",
        "findings": [],
        "sonar": None,
        "priority": 0,
        "created_at": created_at,
        "finished_at": "",
    }


@pytest.fixture(autouse=True)
def _clean_scans() -> None:
    db.prepare_database()
    db.reset_scan_table()
    yield
    db.reset_scan_table()


def test_claim_takes_the_oldest_queued_when_idle() -> None:
    db.upsert_scan(_item("aaaaaaaaaaaa", created_at="2026-10-15 10:00:00 UTC"))
    db.upsert_scan(_item("bbbbbbbbbbbb", created_at="2026-10-15 10:01:00 UTC"))

    first = db.claim_next_queued()
    second = db.claim_next_queued()

    assert first is not None
    assert first["id"] == "aaaaaaaaaaaa"
    assert first["status"] == "running"
    assert first["phase"] == "clone"
    assert second is None


def test_claim_waits_while_another_scan_is_running() -> None:
    db.upsert_scan(
        _item(
            "cccccccccccc",
            status="running",
            created_at="2026-10-15 09:00:00 UTC",
        )
    )
    db.upsert_scan(_item("dddddddddddd", created_at="2026-10-15 10:00:00 UTC"))

    assert db.claim_next_queued() is None


def test_queue_position_follows_created_order() -> None:
    first = _item("eeeeeeeeeeee", created_at="2026-10-15 10:00:00 UTC")
    second = _item("ffffffffffff", created_at="2026-10-15 10:02:00 UTC")
    items = [first, second]

    assert queue_position(first, items) == 1
    assert queue_position(second, items) == 2
    assert queue_position({**first, "status": "running"}, items) is None


def test_upsert_round_trips_findings_and_tools() -> None:
    item = _item("121212121212", created_at="2026-10-15 10:00:00 UTC")
    item["tools"] = ["semgrep", "trivy"]
    item["findings"] = [
        {
            "tool": "semgrep",
            "severity": "HIGH",
            "check": "x",
            "path": "a.py",
            "line": 1,
            "message": "n",
        }
    ]
    item["status"] = "done"
    item["finished_at"] = "2026-10-15 10:05:00 UTC"
    db.upsert_scan(item)

    loaded = db.get_scan_row("121212121212")
    assert loaded is not None
    assert loaded["tools"] == ["semgrep", "trivy"]
    assert loaded["findings"][0]["check"] == "x"
    assert loaded["status"] == "done"
