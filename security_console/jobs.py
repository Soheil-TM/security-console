"""Scan jobs accepted by the scanner worker.

Extra fields such as mounts, privileges, and network mode are ignored.
The worker builds those itself from the approved tool list.
"""

from __future__ import annotations

import re
from typing import Any

from security_console.images import valid_image_ref
from security_console.repos import normalize_commit_sha, valid_repo

_ID = re.compile(r"^[a-f0-9]{12}$")
TOOLS = frozenset({"semgrep", "checkov", "sonar", "trivy"})


class JobError(ValueError):
    """The job body is not one of the approved scan shapes."""


def parse_job(body: Any) -> dict[str, Any]:
    """Return the fields the worker will run. Reject anything else."""

    if not isinstance(body, dict):
        raise JobError("Invalid scan.")
    scan_id = body.get("id")
    if not isinstance(scan_id, str) or not _ID.fullmatch(scan_id):
        raise JobError("Invalid scan.")
    target = body.get("target")
    if target not in {"repo", "image"}:
        raise JobError("Invalid scan type.")
    requested = body.get("tools")
    if not isinstance(requested, list) or not requested:
        raise JobError("Select at least one tool.")
    if any(not isinstance(tool, str) or tool not in TOOLS for tool in requested):
        raise JobError("Invalid scan type.")
    tools = list(requested)
    if target == "image":
        image = body.get("image")
        if not isinstance(image, str) or not valid_image_ref(image.strip()):
            raise JobError("Image name is invalid. Use a name like nginx:1.27.")
        if tools != ["trivy"]:
            raise JobError("Image scans run with Trivy only.")
        image_sha = normalize_commit_sha(body.get("requested_sha"))
        if image_sha is None:
            raise JobError("Commit SHA is invalid.")
        if image_sha:
            raise JobError("Image scans do not take a commit.")
        return _with_secrets(
            body,
            {
                "id": scan_id,
                "target": "image",
                "repo": "",
                "image": image.strip(),
                "tools": ["trivy"],
                "requested_sha": "",
            },
        )
    repo = body.get("repo")
    if not isinstance(repo, str) or not valid_repo(repo.strip()):
        raise JobError("Repository URL must start with http or https.")
    requested_sha = normalize_commit_sha(body.get("requested_sha"))
    if requested_sha is None:
        raise JobError("Commit SHA is invalid.")
    return _with_secrets(
        body,
        {
            "id": scan_id,
            "target": "repo",
            "repo": repo.strip(),
            "image": "",
            "tools": tools,
            "requested_sha": requested_sha,
        },
    )


def _with_secrets(body: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    """Keep a credential only when the console attached one for this scan."""

    token = _secret(body, "clone_token", 256)
    username = _secret(body, "registry_username", 128)
    password = _secret(body, "registry_password", 256)
    certificate = _secret(body, "ca_cert", 12000, pem=True)
    if token:
        job["clone_token"] = token
        style = body.get("clone_style") or "header"
        if style not in {"header", "basic"}:
            raise JobError("Invalid scan.")
        job["clone_style"] = style
    if username:
        job["registry_username"] = username
    if password:
        job["registry_password"] = password
    if certificate:
        job["ca_cert"] = certificate
    return job


def _secret(body: dict[str, Any], key: str, limit: int, *, pem: bool = False) -> str:
    value = body.get(key) or ""
    if value == "":
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise JobError("Invalid scan.")
    if pem:
        if "PRIVATE KEY" in value:
            raise JobError("Invalid scan.")
        if any(ord(ch) < 9 or (13 < ord(ch) < 32) for ch in value):
            raise JobError("Invalid scan.")
        return value
    if any(ord(ch) < 32 or ch.isspace() for ch in value):
        raise JobError("Invalid scan.")
    return value
