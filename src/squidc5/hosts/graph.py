"""Assets host graph: which sessions count as real assets."""

from __future__ import annotations

import json
from typing import Any

SHELL_KINDS = frozenset({"reverse_shell", "tcp"})
IMPLANT_KINDS = frozenset({"beacon"})


def _meta(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    return meta if isinstance(meta, dict) else {}


def is_asset_session(row: dict[str, Any]) -> bool:
    """True if session is a real shell/implant worth putting on the Assets graph.

    Excludes scanner noise, false shells, and bare TCP connects that never
    verified or went interactive. Closed shells that once verified (or were
    interactive / stage-2) still count as historical assets.
    """
    kind = (row.get("kind") or "").strip()
    status = (row.get("status") or "").strip()
    verified = bool(row.get("verified"))
    interactive = bool(row.get("interactive"))
    meta = _meta(row)

    if meta.get("rejected") or meta.get("false_positive") or meta.get("session_rejected"):
        return False
    if meta.get("host_graph_exclude"):
        return False

    if kind in SHELL_KINDS:
        if verified or interactive:
            return True
        # Historical: closed shell that had real access markers
        if status == "closed":
            if meta.get("was_verified") or meta.get("stage2") or meta.get("stabilized"):
                return True
            if meta.get("exec_probe_ok") or meta.get("shell_verified"):
                return True
            # Closed + known user/os from a real session is enough
            if row.get("username") or row.get("os_info") or row.get("hostname"):
                return True
        return False

    if kind in IMPLANT_KINDS:
        # Real implant callback needs some identity (not empty probe)
        if row.get("hostname") or row.get("username") or row.get("os_info"):
            return True
        # still allow if verified flag or implant id in meta
        if verified or meta.get("implant_id") or meta.get("agent_id"):
            return True
        return False

    return False


def host_key_for_session(row: dict[str, Any]) -> str:
    """Stable host node id: prefer hostname, else remote addr, else session id."""
    for k in ("hostname", "remote_addr", "id"):
        v = row.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return "unknown"
