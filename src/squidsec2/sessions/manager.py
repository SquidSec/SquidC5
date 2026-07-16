"""Beacon and reverse-shell session management."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from squidsec2.db.store import Database
from squidsec2.metrics.collector import MetricsCollector


class SessionManager:
    def __init__(self, db: Database, metrics: MetricsCollector) -> None:
        self.db = db
        self.metrics = metrics
        self._live: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        kind: str,
        remote_addr: str | None = None,
        user_agent: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        os_info: str | None = None,
        listener_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        sid = await self.db.create_session(
            kind=kind,
            remote_addr=remote_addr,
            user_agent=user_agent,
            hostname=hostname,
            username=username,
            os_info=os_info,
            listener_id=listener_id,
            metadata=metadata,
        )
        async with self._lock:
            self._live[sid] = {"kind": kind, "connected": True}
        await self.metrics.incr("sessions.created")
        await self.metrics.emit(
            "session.created",
            {"id": sid, "kind": kind, "remote_addr": remote_addr},
        )
        return sid

    async def get(self, session_id: str) -> dict[str, Any] | None:
        row = await self.db.get_session(session_id)
        if not row:
            return None
        return self._normalize(row)

    async def list(self, status: str | None = None) -> list[dict[str, Any]]:
        rows = await self.db.list_sessions(status=status)
        return [self._normalize(r) for r in rows]

    async def heartbeat(self, session_id: str, **fields: Any) -> None:
        fields["last_seen_at"] = __import__("time").time()
        await self.db.update_session(session_id, **fields)
        await self.metrics.emit("session.heartbeat", {"id": session_id})

    async def close(self, session_id: str) -> None:
        await self.db.update_session(session_id, status="closed")
        async with self._lock:
            self._live.pop(session_id, None)
        await self.metrics.emit("session.closed", {"id": session_id})

    def _normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        meta = out.get("metadata")
        if isinstance(meta, str):
            try:
                out["metadata"] = json.loads(meta)
            except json.JSONDecodeError:
                out["metadata"] = {}
        return out
