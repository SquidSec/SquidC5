"""Multi-operator collaboration: teams, session ownership, handoff notes."""

from __future__ import annotations

import json
import time
from typing import Any

from squidc5.db.store import Database


class TeamService:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def list_teams(self) -> list[dict[str, Any]]:
        return await self.db.list_teams()

    async def create_team(self, name: str, created_by: str) -> dict[str, Any]:
        tid = await self.db.create_team(name, created_by)
        return {"id": tid, "name": name, "created_by": created_by}

    async def handoff(
        self,
        session_id: str,
        from_actor: str,
        to_actor: str,
        note: str = "",
    ) -> dict[str, Any]:
        entry = {
            "ts": time.time(),
            "from": from_actor,
            "to": to_actor,
            "note": (note or "")[:2000],
            "session_id": session_id,
        }
        await self.db.add_session_handoff(session_id, entry)
        await self.db.audit(
            actor=from_actor,
            actor_type="operator",
            action="session.handoff",
            resource=session_id,
            details={"to": to_actor, "note_len": len(note or "")},
            risk_score=2,
        )
        return entry

    async def session_notes(self, session_id: str) -> list[dict[str, Any]]:
        return await self.db.get_session_handoffs(session_id)

    async def set_owner(self, session_id: str, owner: str) -> None:
        await self.db.set_session_owner(session_id, owner)

    async def spectator_view(self, session_id: str) -> dict[str, Any]:
        """Read-only snapshot for spectator mode (no shell interact)."""
        row = await self.db.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        meta = row.get("metadata") or {}
        if isinstance(meta, str):
            meta = json.loads(meta)
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "remote_addr": row.get("remote_addr"),
            "hostname": row.get("hostname"),
            "owner": meta.get("owner"),
            "handoffs": await self.session_notes(session_id),
            "mode": "spectator",
        }
