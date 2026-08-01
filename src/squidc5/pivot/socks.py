"""SOCKS5 pivot tasking helpers (teamserver side)."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SocksPivot:
    id: str
    session_id: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    status: str = "pending"
    server: asyncio.AbstractServer | None = field(default=None, repr=False)


class SocksBroker:
    """In-memory registry of SOCKS pivots bound to sessions."""

    def __init__(self) -> None:
        self._pivots: dict[str, SocksPivot] = {}

    def list(self) -> list[dict[str, Any]]:
        return [
            {
                "id": p.id,
                "session_id": p.session_id,
                "listen_host": p.listen_host,
                "listen_port": p.listen_port,
                "status": p.status,
            }
            for p in self._pivots.values()
        ]

    async def start(
        self,
        session_id: str,
        *,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
    ) -> dict[str, Any]:
        """Bind a local SOCKS5 placeholder that accepts then closes (lab stub).

        Full relay requires implant SOCKS agent; this registers the pivot and
        port for operators while implant task `socks:start` is delivered.
        """
        pid = f"socks_{secrets.token_hex(6)}"

        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                # Minimal SOCKS5 greeting consume then close (no relay yet)
                await asyncio.wait_for(reader.read(262), timeout=5.0)
                # reply: ver=5 method=no-auth not available
                writer.write(b"\x05\xff")
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(_handler, host=listen_host, port=listen_port)
        socks = list(server.sockets or [])
        port = int(socks[0].getsockname()[1]) if socks else listen_port
        pivot = SocksPivot(
            id=pid,
            session_id=session_id,
            listen_host=listen_host,
            listen_port=port,
            status="listening",
            server=server,
        )
        self._pivots[pid] = pivot
        asyncio.create_task(server.serve_forever(), name=f"socks-{pid}")
        return {
            "id": pid,
            "session_id": session_id,
            "listen_host": listen_host,
            "listen_port": port,
            "status": "listening",
            "task_hint": {"command": "socks:start", "args": {"pivot_id": pid, "port": port}},
        }

    async def stop(self, pivot_id: str) -> bool:
        p = self._pivots.pop(pivot_id, None)
        if not p:
            return False
        if p.server:
            p.server.close()
            await p.server.wait_closed()
        return True
