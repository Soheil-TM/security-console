"""Scanner worker.

The web console calls this process over HTTP. It is the only process that
should have the Docker socket, and it accepts only approved scan jobs.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Any

from flask import Flask, Response, jsonify, request

from security_console.dispatch import scanner_token, token_matches
from security_console.jobs import JobError, parse_job

Reply = Response | tuple[Response, int]

_jobs: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


class Busy(Exception):
    """A scan is already running inside this worker."""


def create_app() -> Flask:
    """Build the worker API. Nothing is published except health and jobs."""

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    @app.get("/health")
    def health() -> Reply:
        return jsonify({"ok": True})

    @app.post("/v1/jobs")
    def create() -> Reply:
        if not _authorized():
            return jsonify({"error": "Not authorized."}), 401
        try:
            job = parse_job(request.get_json(silent=True))
        except JobError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            start_job(job)
        except Busy:
            return jsonify({"error": "A scan is already running."}), 409
        return jsonify({"id": job["id"]}), 202

    @app.get("/v1/jobs/<scan_id>")
    def show(scan_id: str) -> Reply:
        if not _authorized():
            return jsonify({"error": "Not authorized."}), 401
        with _lock:
            item = _jobs.get(scan_id)
        if item is None:
            return jsonify({"error": "Not found."}), 404
        return jsonify(item)

    @app.get("/v1/images")
    def images() -> Reply:
        if not _authorized():
            return jsonify({"error": "Not authorized."}), 401
        try:
            from security_console.runner import list_images

            return jsonify(list_images())
        except Exception:
            app.logger.error("image list failed")
            return jsonify({"error": "Could not list local images."}), 503

    @app.errorhandler(413)
    def too_large(_exc: Exception) -> Reply:
        return jsonify({"error": "Request is too large."}), 413

    return app


def start_job(job: dict[str, Any]) -> None:
    """Record the job and run it on a background thread."""

    with _lock:
        if any(item.get("status") == "running" for item in _jobs.values()):
            raise Busy()
        _jobs[job["id"]] = {
            "status": "running",
            "phase": "clone" if job["target"] == "repo" else "Trivy",
            "findings": [],
            "notes": [],
            "tool_results": [],
            "sonar": None,
            "error": "",
        }
        _trim()

    thread = threading.Thread(target=_run, args=(job,), daemon=True)
    thread.start()


def _run(job: dict[str, Any]) -> None:
    from security_console.runner import execute_job

    def on_phase(phase: str) -> None:
        with _lock:
            current = _jobs.get(job["id"])
            if current is not None and current.get("status") == "running":
                current["phase"] = phase

    def on_progress(
        findings: list[dict[str, Any]],
        notes: list[str],
        failures: list[str],
        tool_results: list[dict[str, Any]],
    ) -> None:
        """Publish each tool's results so a console deadline can keep them."""

        with _lock:
            current = _jobs.get(job["id"])
            if current is None or current.get("status") != "running":
                return
            current["findings"] = list(findings)
            current["notes"] = list(notes)
            current["tool_results"] = list(tool_results)
            if failures:
                current["error"] = "\n".join(failures)[:2000]

    outcome = execute_job(job, on_phase, on_progress)
    with _lock:
        _jobs[job["id"]] = {
            "status": outcome.get("status") or "failed",
            "phase": "",
            "findings": outcome.get("findings") or [],
            "notes": outcome.get("notes") or [],
            "tool_results": outcome.get("tool_results") or [],
            "sonar": outcome.get("sonar"),
            "error": str(outcome.get("error") or "")[:2000],
            "requested_sha": str(outcome.get("requested_sha") or ""),
            "commit_sha": str(outcome.get("commit_sha") or ""),
            "failure_reason": str(outcome.get("failure_reason") or ""),
        }


def _trim() -> None:
    finished = [
        key for key, item in _jobs.items() if item.get("status") != "running"
    ]
    while len(_jobs) > 20 and finished:
        _jobs.pop(finished.pop(0), None)


def _authorized() -> bool:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer ") or not scanner_token():
        return False
    return token_matches(header[7:].strip())


def main() -> None:
    """Serve the worker. Exit if the shared token is missing."""

    if len(scanner_token()) < 16:
        print("scanner token is not configured", file=sys.stderr)
        raise SystemExit(1)
    port = int(os.environ.get("SCANNER_PORT", "8092"))
    create_app().run(host="0.0.0.0", port=port, threaded=True)


if __name__ == "__main__":
    main()
