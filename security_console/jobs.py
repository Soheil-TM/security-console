"""Scan jobs accepted by the scanner worker.

Extra fields such as mounts, privileges, and network mode are ignored.
The worker builds those itself from the approved tool list.
"""

from __future__ import annotations

import re
from typing import Any

from security_console.images import valid_image_ref
from security_console.repos import valid_repo

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
        return {
            "id": scan_id,
            "target": "image",
            "repo": "",
            "image": image.strip(),
            "tools": ["trivy"],
        }
    repo = body.get("repo")
    if not isinstance(repo, str) or not valid_repo(repo.strip()):
        raise JobError("Repository URL must start with http or https.")
    return {
        "id": scan_id,
        "target": "repo",
        "repo": repo.strip(),
        "image": "",
        "tools": tools,
    }
