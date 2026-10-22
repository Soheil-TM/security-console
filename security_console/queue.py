"""Claim queued scans and run them one at a time through the existing scanner."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from security_console import db

log = logging.getLogger("security_console")

QUEUE_CAP = 20
_POLL_SECONDS = 1.5
_stop = threading.Event()
_thread: threading.Thread | None = None


def start_dispatcher(run_scan: Callable[[str], None]) -> None:
    """Start the background loop that claims queued scans. Idempotent."""

    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()

    def loop() -> None:
        while not _stop.is_set():
            try:
                claimed = _claim_into_memory()
                if claimed is None:
                    _stop.wait(_POLL_SECONDS)
                    continue
                run_scan(str(claimed["id"]))
            except Exception:
                log.exception("scan queue dispatcher failed")
                _stop.wait(_POLL_SECONDS)

    _thread = threading.Thread(target=loop, name="scan-queue", daemon=True)
    _thread.start()


def stop_dispatcher() -> None:
    """Stop the background loop. Used by tests."""

    _stop.set()
    global _thread
    if _thread is not None:
        _thread.join(timeout=5)
        _thread = None


def _claim_into_memory() -> dict[str, Any] | None:
    """Claim the next queued row and sync the in-memory map in app."""

    # Imported late so tests can set app.scans before the loop runs.
    import app as console

    claimed = db.claim_next_queued()
    if claimed is None:
        return None
    with console.lock:
        current = console.scans.get(claimed["id"]) or {}
        merged = {**current, **claimed}
        console.scans[claimed["id"]] = merged
        console.save_scan(merged)
    return merged


def attach_queue_position(
    item: dict[str, Any], items: list[dict[str, Any]]
) -> dict[str, Any]:
    """Copy ``queue_position`` onto a scan dict when it is queued."""

    from security_console.access import queue_position

    position = queue_position(item, items)
    if position is None:
        return item
    shown = dict(item)
    shown["queue_position"] = position
    return shown
