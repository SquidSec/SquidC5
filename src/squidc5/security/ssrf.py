"""SSRF guards for outbound server HTTP (LLM base_url, etc.)."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

# Allow only simple API path prefixes (e.g. /v1, /openai/v1)
_SAFE_PATH = re.compile(r"^(/[A-Za-z0-9._-]+)+$")


def validate_llm_base_url(url: str, *, allow_private: bool = False) -> str:
    """Return normalized base URL (scheme://host[:port][/path]) or raise ValueError.

    Path is preserved when it is a simple API root (OpenAI-compatible /v1 etc.).
    Query strings and fragments are rejected. Callers append /chat/completions or /models.
    """
    u = (url or "").strip()
    if not u:
        raise ValueError("base_url required")
    p = urlparse(u)
    if p.scheme not in ("https", "http"):
        raise ValueError("base_url scheme must be http or https")
    if p.query or p.fragment or p.username or p.password:
        raise ValueError("base_url must not include credentials, query, or fragment")
    host = p.hostname
    if not host:
        raise ValueError("base_url host required")
    host_l = host.lower().strip("[]")
    loopback = host_l in ("127.0.0.1", "localhost", "::1")
    if p.scheme == "http":
        # http only for explicit loopback lab (Ollama etc.)
        if not loopback and not allow_private:
            raise ValueError("base_url must use https (http only for localhost lab)")
    if not allow_private and not loopback:
        _assert_public_host(host)
    elif not allow_private and loopback and p.scheme != "http":
        # https://localhost still blocked (avoid confusing TLS-to-loopback)
        raise ValueError("base_url host not allowed")

    path = (p.path or "").rstrip("/")
    if path in ("", "/"):
        path = ""
    elif not _SAFE_PATH.fullmatch(path):
        raise ValueError("base_url path not allowed")

    port = f":{p.port}" if p.port else ""
    host_out = host_l if loopback else host
    return f"{p.scheme}://{host_out}{port}{path}"


def _assert_public_host(host: str) -> None:
    h = host.lower().strip("[]")
    if h in ("localhost", "metadata.google.internal"):
        raise ValueError("base_url host not allowed")
    # block obvious metadata
    if h.startswith("169.254.") or h == "metadata":
        raise ValueError("base_url host not allowed")
    try:
        ip = ipaddress.ip_address(h)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError("base_url must not target private/link-local addresses")
        return
    except ValueError as e:
        if "must not" in str(e) or "not allowed" in str(e):
            raise
    # resolve DNS and check all A/AAAA
    try:
        infos = socket.getaddrinfo(h, None)
    except socket.gaierror as e:
        raise ValueError(f"base_url host unresolvable: {h}") from e
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError("base_url resolves to private/link-local address")
