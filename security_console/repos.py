"""Repository URLs a scan is allowed to clone."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse

_BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google",
    "metadata.google.internal",
    "metadata.internal",
}
_SHARED = ipaddress.ip_network("100.64.0.0/10")
_METADATA_V6 = {ipaddress.ip_address("fd00:ec2::254")}
_DOTTED = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def valid_repo(url: str) -> bool:
    """Accept an http(s) git URL and reject credentials, loopback, and metadata.

    Private network addresses stay allowed so an internal git server can be
    scanned. Loopback, link-local, the shared range 100.64.0.0/10, and known
    metadata addresses are rejected.
    """

    if not isinstance(url, str):
        return False
    if not url or url != url.strip() or len(url) > 500:
        return False
    if any(ch in url for ch in "\n\r\x00\t \\@"):
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return False
    if parsed.username or parsed.password:
        return False
    if ".." in parsed.path:
        return False
    host = parsed.hostname.lower().rstrip(".")
    if host_is_blocked(host):
        return False
    return not (host.isascii() and host.isdigit())


def host_is_blocked(host: str) -> bool:
    """Return whether this registry or git hostname is a metadata destination."""

    name = host.lower().rstrip(".")
    if not name or name in _BLOCKED_HOSTS or name.endswith(".localhost"):
        return True
    if _ambiguous_ipv4(name):
        return True
    return ip_is_blocked(name)


def _ambiguous_ipv4(host: str) -> bool:
    """Reject dotted quads whose leading zeros can be read as octal."""

    match = _DOTTED.fullmatch(host)
    if match is None:
        return False
    return any(len(part) > 1 and part.startswith("0") for part in match.groups())


def ip_is_blocked(value: str) -> bool:
    """Return whether this address must not be cloned or connected to.

    RFC1918 addresses stay allowed. Loopback, link-local, multicast,
    reserved, unspecified, 100.64.0.0/10, and the AWS IPv6 metadata address
    are rejected. An IPv4-mapped IPv6 address is judged as its IPv4 form.
    """

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return ip_is_blocked(str(mapped))
    if ip in _METADATA_V6:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED:
        return True
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def clone_pins(url: str) -> list[str] | None:
    """Return curl resolve entries for one allowed git URL.

    Each entry is ``host:port:address``. Libcurl-based Git uses them instead
    of a second DNS lookup. ``None`` means the URL must not be cloned. A Git
    build that ignores ``http.curloptResolve`` can still resolve the name
    again, so this does not by itself close DNS rebinding.
    """

    if not valid_repo(url):
        return None
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    addresses: list[str] = []
    for item in answers:
        sockaddr = item[4] if len(item) > 4 else ()
        if (
            isinstance(sockaddr, tuple)
            and sockaddr
            and isinstance(sockaddr[0], str)
            and sockaddr[0] not in addresses
        ):
            addresses.append(sockaddr[0])
    if not addresses or any(ip_is_blocked(address) for address in addresses):
        return None
    pins: list[str] = []
    for address in addresses:
        rendered = f"[{address}]" if ":" in address else address
        pins.append(f"{host}:{port}:{rendered}")
    return pins


def repo_targets_blocked_address(url: str) -> bool:
    """Resolve the git host and reject answers that point at a blocked address.

    The name check in ``valid_repo`` does not see DNS that resolves to the
    metadata service. ``clone_pins`` is the same lookup and is what the clone
    command pins when Git honors it.
    """

    return clone_pins(url) is None


def git_clone_args(
    repo: str,
    dest: str,
    resolve: list[str] | None = None,
) -> list[str]:
    """Build a git clone command that does not read host credentials or hooks.

    HTTP redirects are disabled. ``resolve`` pins the addresses from
    ``clone_pins`` for libcurl-based Git.
    """

    command = [
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "http.followRedirects=false",
    ]
    for item in resolve or []:
        command.extend(["-c", f"http.curloptResolve={item}"])
    command.extend(["clone", "--depth", "1", "--", repo, dest])
    return command


def git_env(path: str) -> dict[str, str]:
    """Environment for git. Secrets in the process environment are not copied.

    Proxy and CA variables are copied when set, because a clone on a network
    that requires them would otherwise fail.
    """

    env = {
        "PATH": path or "/usr/bin",
        "HOME": "/tmp",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "LC_ALL": "C",
    }
    for name in (
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ):
        value = os.environ.get(name, "").strip()
        if value:
            env[name] = value
    return env
