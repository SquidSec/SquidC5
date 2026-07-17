"""Beacon and reverse-shell session management."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

from squidc5.db.store import Database
from squidc5.metrics.collector import MetricsCollector


class SessionManager:
    def __init__(self, db: Database, metrics: MetricsCollector) -> None:
        self.db = db
        self.metrics = metrics
        self._live: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        # Optional: ListenerManager.is_live(session_id) for reverse shells
        self.interactive_check: Callable[[str], bool] | None = None
        self.verified_check: Callable[[str], bool] | None = None
        # Optional async probe: prove remote executes commands
        self.exec_probe: Callable[[str], Any] | None = None
        # Optional async drop of TCP channel
        self.drop_channel: Callable[[str], Any] | None = None

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
        return self._enrich(self._normalize(row))

    async def list(self, status: str | None = None) -> list[dict[str, Any]]:
        rows = await self.db.list_sessions(status=status)
        return [self._enrich(self._normalize(r)) for r in rows]

    async def heartbeat(self, session_id: str, **fields: Any) -> None:
        fields["last_seen_at"] = time.time()
        await self.db.update_session(session_id, **fields)
        await self.metrics.emit("session.heartbeat", {"id": session_id})

    async def close(self, session_id: str) -> None:
        await self.db.update_session(session_id, status="closed")
        async with self._lock:
            self._live.pop(session_id, None)
        await self.metrics.emit("session.closed", {"id": session_id})

    async def reject(self, session_id: str, reason: str) -> None:
        """Remove false-positive / scanner sessions entirely."""
        async with self._lock:
            self._live.pop(session_id, None)
        await self.db.delete_session(session_id)
        await self.metrics.incr("sessions.rejected")
        await self.metrics.emit(
            "session.rejected",
            {"id": session_id, "reason": reason},
        )

    async def close_orphaned_shells(self, *, probe: bool = False) -> int:
        """
        Mark reverse_shell/tcp sessions closed when no live TCP channel exists.

        Required after process restart: SQLite still says 'active' but sockets are gone.
        If probe=True and a probe_exec callback is set, also drop echo-only / non-executing shells.
        Probes run concurrently (capped) so large zombie storms do not block the API.
        """
        rows = await self.db.list_sessions(status="active")
        closed = 0
        to_probe: list[str] = []
        for row in rows:
            kind = row.get("kind")
            if kind not in ("reverse_shell", "tcp"):
                continue
            sid = row["id"]
            live = bool(self.interactive_check(sid)) if self.interactive_check else False
            if not live:
                await self.db.update_session(sid, status="closed")
                async with self._lock:
                    self._live.pop(sid, None)
                closed += 1
                await self.metrics.emit(
                    "session.orphaned_closed",
                    {"id": sid, "kind": kind, "reason": "no_live_channel"},
                )
                continue
            if probe and self.exec_probe is not None:
                to_probe.append(sid)

        if to_probe and probe and self.exec_probe is not None:
            sem = asyncio.Semaphore(8)

            async def _one(sid: str) -> tuple[str, bool]:
                async with sem:
                    try:
                        ok = await asyncio.wait_for(self.exec_probe(sid), timeout=2.0)
                    except Exception:
                        ok = False
                    return sid, bool(ok)

            results = await asyncio.gather(*[_one(s) for s in to_probe])
            for sid, ok in results:
                if ok:
                    continue
                if self.drop_channel is not None:
                    try:
                        await self.drop_channel(sid)
                    except Exception:
                        pass
                await self.db.update_session(sid, status="closed")
                async with self._lock:
                    self._live.pop(sid, None)
                closed += 1
                await self.metrics.emit(
                    "session.orphaned_closed",
                    {"id": sid, "kind": "reverse_shell", "reason": "exec_probe_failed"},
                )

        if closed:
            await self.metrics.incr("sessions.orphaned_closed", float(closed))
        return closed

    def _enrich(self, row: dict[str, Any]) -> dict[str, Any]:
        """Attach interactive/live flags so operators know if shell commands will work."""
        kind = row.get("kind")
        status = row.get("status")
        interactive = False
        verified = False
        if kind in ("reverse_shell", "tcp") and status == "active":
            if self.interactive_check is not None:
                interactive = bool(self.interactive_check(row["id"]))
            else:
                interactive = row["id"] in self._live
            if self.verified_check is not None:
                verified = bool(self.verified_check(row["id"]))
            meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            if meta.get("verified") or meta.get("exec_ok"):
                verified = verified or True
        elif kind == "beacon" and status == "active":
            interactive = False
            row["taskable"] = True
        row["interactive"] = interactive
        row["verified"] = verified
        if kind in ("reverse_shell", "tcp") and status == "active" and not interactive:
            row["dead"] = True
            row["note"] = "TCP channel gone — session is stale (use a live reconnect)"
        elif kind in ("reverse_shell", "tcp") and status == "active" and interactive and not verified:
            row["note"] = "connected but not yet verified (exec probe pending/failed)"
        return row

    def _normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        meta = out.get("metadata")
        if isinstance(meta, str):
            try:
                out["metadata"] = json.loads(meta)
            except json.JSONDecodeError:
                out["metadata"] = {}
        return out
