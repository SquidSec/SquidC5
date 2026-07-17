"""Observability: timeline + lightweight MITRE ATT&CK mapping."""

from __future__ import annotations

from typing import Any

from squidc5.db.store import Database

# action prefix / event type -> ATT&CK technique ids (illustrative)
ATTACK_MAP: dict[str, list[str]] = {
    "shell.interact": ["T1059"],
    "shell.broadcast": ["T1059"],
    "payloads.generate": ["T1587", "T1608"],
    "listeners.create": ["T1090", "T1571"],
    "listeners.start": ["T1090"],
    "session.handoff": ["T1078"],
    "tokens.create": ["T1136"],
    "ai.admin": ["T1588"],
    "implant.beacon": ["T1071.001"],
    "mcp.call": ["T1106"],
    "features.update": ["T1562"],
    "profile.activate": ["T1071"],
}


class TimelineService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def map_attack(self, action: str) -> list[str]:
        if action in ATTACK_MAP:
            return list(ATTACK_MAP[action])
        for prefix, techs in ATTACK_MAP.items():
            if action.startswith(prefix.split(".")[0]):
                return list(techs)
        return []

    async def timeline(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        rows = await self.db.list_audit(limit=limit, offset=offset)
        out = []
        for r in rows:
            action = r.get("action") or ""
            out.append(
                {
                    "ts": r.get("ts"),
                    "actor": r.get("actor"),
                    "action": action,
                    "resource": r.get("resource"),
                    "allowed": bool(r.get("allowed", 1)),
                    "risk_score": r.get("risk_score", 0),
                    "attack": self.map_attack(action),
                }
            )
        return out

    async def heatmap(self) -> dict[str, Any]:
        sessions = await self.db.list_sessions(status="active")
        by_host: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for s in sessions:
            host = s.get("hostname") or s.get("remote_addr") or "unknown"
            by_host[host] = by_host.get(host, 0) + 1
            kind = s.get("kind") or "unknown"
            by_kind[kind] = by_kind.get(kind, 0) + 1
        return {
            "active_sessions": len(sessions),
            "by_host": by_host,
            "by_kind": by_kind,
        }
