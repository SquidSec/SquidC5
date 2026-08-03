"""Assets host graph: which sessions count as real assets."""

from __future__ import annotations

import json
import re
from typing import Any

SHELL_KINDS = frozenset({"reverse_shell", "tcp"})
IMPLANT_KINDS = frozenset({"beacon"})

# Strip :port from IPv4/IPv6 host:port peer strings
_HOSTPORT_V4 = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")
_HOSTPORT_V6 = re.compile(r"^\[([0-9a-fA-F:]+)\]:\d+$")


def _meta(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    return meta if isinstance(meta, dict) else {}


def _truthy(v: Any) -> bool:
    if v is True or v == 1:
        return True
    if isinstance(v, str) and v.strip().lower() in ("1", "true", "yes"):
        return True
    return False


def shell_was_real(row: dict[str, Any]) -> bool:
    """True only when exec-verified / stage-2 / operator-grade shell evidence exists."""
    meta = _meta(row)
    if _truthy(row.get("verified")):
        return True
    for k in (
        "verified",
        "exec_ok",
        "exec_probe_ok",
        "shell_verified",
        "was_verified",
        "stage2",
        "stabilized",
        "stage2_injected",
    ):
        if _truthy(meta.get(k)):
            return True
    # username+os together is strong (stage-2 / probe filled both)
    if row.get("username") and row.get("os_info"):
        return True
    return False


def is_asset_session(row: dict[str, Any]) -> bool:
    """True if session belongs on the Assets graph.

    Strict default: reverse shells must have been exec-verified (or stage-2).
    Unverified TCP connects and scanner noise never qualify. Beacons need a
    real hostname (not empty / not bare peer sockname).
    """
    kind = (row.get("kind") or "").strip()
    meta = _meta(row)

    if meta.get("rejected") or meta.get("false_positive") or meta.get("session_rejected"):
        return False
    if meta.get("host_graph_exclude"):
        return False

    if kind in SHELL_KINDS:
        # Live interactive channel counts (operator is on it even if probe flags lag)
        if (row.get("status") or "") == "active" and (
            _truthy(row.get("interactive")) or _truthy(row.get("verified"))
        ):
            return True
        return shell_was_real(row)

    if kind in IMPLANT_KINDS:
        host = (row.get("hostname") or "").strip()
        if not host:
            return False
        # reject placeholder / peer socknames used as hostname
        if _HOSTPORT_V4.match(host) or _HOSTPORT_V6.match(host):
            return False
        if host.lower() in ("unknown", "localhost", "none", "-"):
            return False
        return True

    return False


def normalize_peer(addr: str | None) -> str | None:
    """Return host portion of remote_addr (drop ephemeral source port)."""
    if addr is None:
        return None
    s = str(addr).strip()
    if not s:
        return None
    m = _HOSTPORT_V4.match(s)
    if m:
        return m.group(1)
    m = _HOSTPORT_V6.match(s)
    if m:
        return m.group(1)
    # bare IPv6 with port sometimes without brackets: skip exotic forms
    if s.count(":") == 1 and not s.startswith("["):
        # host:port
        host, _, port = s.partition(":")
        if port.isdigit():
            return host
    return s


def host_key_for_session(row: dict[str, Any]) -> str:
    """Stable host node id: hostname, else peer IP (no port), else session id."""
    hn = (row.get("hostname") or "").strip()
    if hn and not _HOSTPORT_V4.match(hn) and not _HOSTPORT_V6.match(hn):
        return hn
    peer = normalize_peer(row.get("remote_addr"))
    if peer:
        return peer
    sid = row.get("id")
    if sid:
        return str(sid).strip()
    return "unknown"


def host_is_live(node: dict[str, Any]) -> bool:
    return int(node.get("active_sessions") or 0) > 0
