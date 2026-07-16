"""Multi-type listeners. Port-flexible — no default 80/443 requirement."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from squidsec2.db.store import Database
from squidsec2.metrics.collector import MetricsCollector

log = logging.getLogger("squidsec2.listeners")

SessionFactory = Callable[..., Awaitable[str]]


class ListenerManager:
    def __init__(
        self,
        db: Database,
        metrics: MetricsCollector,
        session_factory: SessionFactory | None = None,
    ) -> None:
        self.db = db
        self.metrics = metrics
        self.session_factory = session_factory
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._shell_queues: dict[str, asyncio.Queue[str]] = {}

    async def create(
        self,
        name: str,
        kind: str,
        port: int,
        host: str = "0.0.0.0",
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if kind not in ("http", "tcp", "reverse_shell"):
            raise ValueError(f"Unsupported listener kind: {kind}")
        if port < 1 or port > 65535:
            raise ValueError("Port must be 1-65535")
        lid = await self.db.create_listener(name, kind, port, host, config)
        await self.metrics.emit("listener.created", {"id": lid, "kind": kind, "port": port})
        row = await self.db.get_listener(lid)
        return self._norm(row)  # type: ignore[arg-type]

    async def list(self) -> list[dict[str, Any]]:
        return [self._norm(r) for r in await self.db.list_listeners()]

    async def get(self, listener_id: str) -> dict[str, Any] | None:
        row = await self.db.get_listener(listener_id)
        return self._norm(row) if row else None

    async def start(self, listener_id: str) -> dict[str, Any]:
        row = await self.db.get_listener(listener_id)
        if not row:
            raise KeyError("listener not found")
        async with self._lock:
            if listener_id in self._servers:
                return self._norm(row)
            kind = row["kind"]
            host = row["host"]
            port = int(row["port"])
            if kind == "http":
                # HTTP listeners are handled by FastAPI implant routes; mark running.
                await self.db.set_listener_status(listener_id, "running")
            elif kind in ("tcp", "reverse_shell"):
                server = await asyncio.start_server(
                    lambda r, w: self._handle_tcp(listener_id, kind, r, w),
                    host=host,
                    port=port,
                )
                self._servers[listener_id] = server
                task = asyncio.create_task(server.serve_forever(), name=f"listener-{listener_id}")
                self._tasks[listener_id] = task
                await self.db.set_listener_status(listener_id, "running")
                log.info("Started %s listener %s on %s:%s", kind, listener_id, host, port)
            else:
                raise ValueError(f"Cannot start kind {kind}")
        await self.metrics.incr("listeners.started")
        await self.metrics.emit("listener.started", {"id": listener_id})
        updated = await self.db.get_listener(listener_id)
        return self._norm(updated)  # type: ignore[arg-type]

    async def stop(self, listener_id: str) -> dict[str, Any]:
        async with self._lock:
            task = self._tasks.pop(listener_id, None)
            server = self._servers.pop(listener_id, None)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            if server:
                server.close()
                await server.wait_closed()
            await self.db.set_listener_status(listener_id, "stopped")
        await self.metrics.emit("listener.stopped", {"id": listener_id})
        row = await self.db.get_listener(listener_id)
        return self._norm(row)  # type: ignore[arg-type]

    async def delete(self, listener_id: str) -> bool:
        if listener_id in self._servers:
            await self.stop(listener_id)
        return await self.db.delete_listener(listener_id)

    async def stop_all(self) -> None:
        ids = list(self._servers.keys())
        for lid in ids:
            try:
                await self.stop(lid)
            except Exception:
                log.exception("Error stopping listener %s", lid)

    async def _handle_tcp(
        self,
        listener_id: str,
        kind: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        sid = None
        try:
            if self.session_factory:
                sid = await self.session_factory(
                    kind="reverse_shell" if kind == "reverse_shell" else "tcp",
                    remote_addr=remote,
                    listener_id=listener_id,
                )
            else:
                sid = await self.db.create_session(
                    kind="reverse_shell" if kind == "reverse_shell" else "tcp",
                    remote_addr=remote,
                    listener_id=listener_id,
                )
            q: asyncio.Queue[str] = asyncio.Queue()
            self._shell_queues[sid] = q
            await self.metrics.emit(
                "shell.connected",
                {"session_id": sid, "remote": remote, "listener_id": listener_id},
            )

            async def pump_out() -> None:
                while True:
                    cmd = await q.get()
                    if cmd is None:  # type: ignore[comparison-overlap]
                        break
                    writer.write((cmd if cmd.endswith("\n") else cmd + "\n").encode())
                    await writer.drain()

            out_task = asyncio.create_task(pump_out())
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    await self.db.execute(
                        "UPDATE sessions SET last_seen_at = ? WHERE id = ?",
                        (__import__("time").time(), sid),
                    )
                    await self.metrics.emit(
                        "shell.output",
                        {"session_id": sid, "data": text[:2000]},
                    )
            finally:
                out_task.cancel()
                try:
                    await out_task
                except asyncio.CancelledError:
                    pass
        except Exception:
            log.exception("TCP handler error for %s", remote)
        finally:
            if sid:
                self._shell_queues.pop(sid, None)
                await self.db.update_session(sid, status="closed")
                await self.metrics.emit("shell.disconnected", {"session_id": sid})
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def send_shell(self, session_id: str, command: str) -> bool:
        q = self._shell_queues.get(session_id)
        if not q:
            return False
        await q.put(command)
        return True

    def _norm(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        cfg = out.get("config")
        if isinstance(cfg, str):
            try:
                out["config"] = json.loads(cfg)
            except json.JSONDecodeError:
                out["config"] = {}
        return out
