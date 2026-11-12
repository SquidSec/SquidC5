"""Shared helpers for socket-level C2 tests.

These helpers drive the real listener code over real TCP sockets. They exist so
tests assert protocol behavior instead of mocking the handler under test.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Callable
from typing import Any

# ---------------------------------------------------------------------------
# Ports and timing
# ---------------------------------------------------------------------------


def free_port(host: str = "127.0.0.1") -> int:
    """Reserve an ephemeral port by binding and releasing it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


async def wait_until(
    predicate: Callable[[], Any],
    *,
    timeout: float = 5.0,
    interval: float = 0.02,
    message: str = "condition not met",
) -> Any:
    """Poll ``predicate`` until it is truthy. Returns the truthy value."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        value = predicate()
        if asyncio.iscoroutine(value):
            value = await value
        if value:
            return value
        await asyncio.sleep(interval)
    raise AssertionError(f"{message} (waited {timeout}s)")


# ---------------------------------------------------------------------------
# Listener setup
# ---------------------------------------------------------------------------


async def start_listener(
    app: Any,
    *,
    name: str,
    kind: str = "reverse_shell",
    host: str = "127.0.0.1",
    port: int | None = None,
    config: dict[str, Any] | None = None,
) -> tuple[str, int]:
    """Create and start a listener on an ephemeral port. Returns (id, port)."""
    manager = app.state.app_state.listeners
    port = port or free_port(host)
    row = await manager.create(name, kind, port, host=host, config=config)
    listener_id = row["id"]
    await manager.start(listener_id)
    return listener_id, port


async def stop_listener(app: Any, listener_id: str) -> None:
    with contextlib.suppress(Exception):
        await app.state.app_state.listeners.stop(listener_id)


# ---------------------------------------------------------------------------
# Scripted reverse-shell peer
# ---------------------------------------------------------------------------

TLS_CLIENT_HELLO = bytes.fromhex("16030100a5010000a10303") + b"\x00" * 40
HTTP_PROBE = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"
BINARY_NOISE = bytes(range(0, 32)) * 4


class FakeShell:
    """A scripted TCP peer that behaves like a reverse shell.

    Modes:
        real       answers SC5_PING / echo probes with SC5_PONG, runs commands
        echo_only  echoes each command back verbatim (a zombie)
        silent     connects and never sends or answers
        tls        sends a TLS ClientHello then idles
        http       sends an HTTP probe then idles
        binary     sends binary noise then idles
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        mode: str = "real",
        banner: str | None = "bash-5.1$ ",
        command_output: str = "uid=0(root) gid=0(root) groups=0(root)\n",
        close_after: float | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.mode = mode
        self.banner = banner
        self.command_output = command_output
        self.close_after = close_after
        self.received: list[str] = []
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()

    async def __aenter__(self) -> FakeShell:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
        if self.mode == "tls":
            self._writer.write(TLS_CLIENT_HELLO)
            await self._writer.drain()
        elif self.mode == "http":
            self._writer.write(HTTP_PROBE)
            await self._writer.drain()
        elif self.mode == "binary":
            self._writer.write(BINARY_NOISE)
            await self._writer.drain()
        elif self.mode == "real" and self.banner:
            self._writer.write(self.banner.encode())
            await self._writer.drain()
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        assert self._reader is not None
        try:
            if self.close_after is not None:
                await asyncio.sleep(self.close_after)
                return
            if self.mode in ("silent", "tls", "http", "binary"):
                # Hold the socket open without answering.
                await self._closed.wait()
                return
            while True:
                line = await self._reader.readline()
                if not line:
                    return
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                self.received.append(text)
                await self._respond(text)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return

    async def _respond(self, text: str) -> None:
        assert self._writer is not None
        if self.mode == "echo_only":
            self._writer.write((text + "\n").encode())
            await self._writer.drain()
            return
        if text.startswith("SC5_PING "):
            token = text.split(" ", 1)[1].strip()
            self._writer.write(f"SC5_PONG {token}\n".encode())
        elif text.startswith("echo SC5_PONG "):
            token = text.split("SC5_PONG ", 1)[1].strip()
            self._writer.write(f"SC5_PONG {token}\n".encode())
        elif "SC5_DIE" in text:
            await self.close()
            return
        else:
            self._writer.write(self.command_output.encode())
        await self._writer.drain()

    async def send(self, data: str | bytes) -> None:
        assert self._writer is not None
        payload = data.encode() if isinstance(data, str) else data
        self._writer.write(payload)
        await self._writer.drain()

    async def close(self) -> None:
        self._closed.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()
            self._writer = None


# ---------------------------------------------------------------------------
# Raw request helpers
# ---------------------------------------------------------------------------


async def raw_http(
    host: str,
    port: int,
    request: bytes,
    *,
    timeout: float = 5.0,
) -> bytes:
    """Send raw bytes to a listener and return everything it sends back."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(request)
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


def http_request(
    method: str,
    path: str,
    *,
    host: str = "127.0.0.1",
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    head = "\r\n".join(lines).encode() + b"\r\n\r\n"
    return head + body


async def wait_for_session(
    app: Any,
    *,
    kind: str = "reverse_shell",
    listener_id: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Wait for a session row to appear, optionally filtered by listener."""

    async def _find() -> dict[str, Any] | None:
        rows = await app.state.app_state.db.list_sessions(status=None)
        for row in rows:
            if row.get("kind") != kind:
                continue
            if listener_id and row.get("listener_id") != listener_id:
                continue
            return row
        return None

    return await wait_until(_find, timeout=timeout, message=f"no {kind} session appeared")


async def wait_for_verified(app: Any, session_id: str, *, timeout: float = 8.0) -> bool:
    """Wait until the listener marks a session exec-verified."""

    def _check() -> bool:
        return app.state.app_state.listeners.is_verified(session_id)

    return await wait_until(_check, timeout=timeout, message=f"session {session_id} never verified")


async def wait_for_closed(app: Any, session_id: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Wait until a session row is no longer active."""

    async def _check() -> dict[str, Any] | None:
        row = await app.state.app_state.db.get_session(session_id)
        if row and row.get("status") != "active":
            return row
        return None

    return await wait_until(_check, timeout=timeout, message=f"session {session_id} stayed active")


async def wait_for_gone(app: Any, session_id: str, *, timeout: float = 8.0) -> None:
    """Wait until a session row is deleted."""

    async def _check() -> bool:
        return await app.state.app_state.db.get_session(session_id) is None

    await wait_until(_check, timeout=timeout, message=f"session {session_id} was not deleted")


def collect_events(app: Any, event_type: str) -> list[dict[str, Any]]:
    """Return buffered metric events matching an event type."""
    events = list(app.state.app_state.metrics._events)
    return [e for e in events if e.get("type") == event_type]


__all__ = [
    "BINARY_NOISE",
    "FakeShell",
    "HTTP_PROBE",
    "TLS_CLIENT_HELLO",
    "collect_events",
    "free_port",
    "http_request",
    "raw_http",
    "start_listener",
    "stop_listener",
    "wait_for_closed",
    "wait_for_gone",
    "wait_for_session",
    "wait_for_verified",
    "wait_until",
]
