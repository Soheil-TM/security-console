"""Image names the console may hand to Trivy.

A name without a registry host, such as ``nginx:1.27``, is a Docker Hub
reference and stays allowed. An internal registry on an RFC1918 address
stays allowed. Loopback, link-local, ``100.64.0.0/10``, metadata hostnames,
and ``localhost`` are rejected, including when they carry a registry port.
"""

from __future__ import annotations

import re
from typing import Any

from security_console.repos import host_is_blocked

_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST = r"sha256:[a-f0-9]{64}"
_HOST = (
    r"(?:localhost|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"
    r"(?::[0-9]{1,5})?"
)
_REF = re.compile(
    rf"^(?:{_HOST}/)?{_COMPONENT}(?:/{_COMPONENT})*"
    rf"(?::{_TAG})?(?:@{_DIGEST})?$"
)
_ID = re.compile(rf"^{_DIGEST}$")


def valid_image_ref(value: str) -> bool:
    """Accept a Docker image name, tag, or digest. Reject anything else."""

    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or len(text) > 255 or ".." in text or "//" in text:
        return False
    if _ID.fullmatch(text) is not None:
        return True
    if _REF.fullmatch(text) is None:
        return False
    host = _registry_host(text)
    return host is None or not host_is_blocked(host)


def _registry_host(text: str) -> str | None:
    """Return the registry host, or None for a Docker Hub short name."""

    slash = text.find("/")
    if slash <= 0:
        return None
    first = text[:slash]
    if first.startswith("[") and "]" in first:
        return first[1 : first.index("]")]
    if ":" in first:
        host, port = first.rsplit(":", 1)
        if port.isdigit() and host:
            return host
    if "." in first or first.lower() == "localhost":
        return first
    return None


def image_rows(images: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep tagged local images, newest first."""

    rows: list[dict[str, Any]] = []
    for image in images:
        created = str(image.get("created") or "")
        short = str(image.get("id") or "").removeprefix("sha256:")[:12]
        size = int(image.get("size") or 0)
        for ref in image.get("tags") or []:
            if not isinstance(ref, str) or "<none>" in ref:
                continue
            if not valid_image_ref(ref):
                continue
            rows.append(
                {"ref": ref, "id": short, "size": size, "created": created}
            )
    rows.sort(key=lambda row: row["created"], reverse=True)
    return rows[:100]
