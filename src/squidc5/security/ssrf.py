"""SSRF guards for outbound server HTTP (LLM base_url, etc.)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_llm_base_url(url: str, *, allow_private: bool = False) -> str:
    """Return normalized base URL or raise ValueError."""
    u = (url or "").strip()
    if not u:
        raise ValueError("base_url required")
    p = urlparse(u)
    if p.scheme not in ("https", "http"):
        raise ValueError("base_url scheme must be http or https")
    if p.scheme == "http" and not allow_private:
        # allow http only for explicit loopback lab
        host = (p.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("base_url must use https (http only for localhost lab)")
    host = p.hostname
    if not host:
        raise ValueError("base_url host required")
    if not allow_private:
        _assert_public_host(host)
    # strip path noise; callers append /chat/completions
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{host}{port}"


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
