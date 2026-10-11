"""Image names the console may hand to Trivy."""

from __future__ import annotations

import re
from typing import Any

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
    return _REF.fullmatch(text) is not None or _ID.fullmatch(text) is not None


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
