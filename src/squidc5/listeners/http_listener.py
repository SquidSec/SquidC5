"""Lightweight per-port HTTP listener (beacon + OAST catch-all)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlparse

if TYPE_CHECKING:
    from squidc5.listeners.manager import ListenerManager

log = logging.getLogger("squidc5.listeners.http")


async def handle_http_client(
    manager: ListenerManager,
    listener_id: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
    try:
        req = await _read_request(reader)
        if req is None:
            await _respond(writer, 400, {"error": "bad request"})
            return

        method = req["method"]
        path = req["path"]
        body = req["body"]
        headers = req["headers"]
        query = req["query"]

        # Normalize path
        path_only = path.split("?", 1)[0]

        if method == "GET" and path_only in ("/", "/health", "/api/v1/health"):
            await _respond(
                writer,
                200,
                {
                    "status": "ok",
                    "listener_id": listener_id,
                    "kind": "http",
                    "service": "squidc5-http-listener",
                },
            )
            return

        # Beacon endpoints: legacy paths + active/known profile URIs
        pe = getattr(manager, "profile_engine", None)
        kind = ""
        prof = None
        if pe is not None and method == "POST":
            kind, prof = pe.match_beacon_path(path_only)
        elif method == "POST" and path_only in (
            "/api/v1/implant/beacon",
            "/implant/beacon",
            "/beacon",
        ):
            kind = "beacon"
        elif method == "POST" and path_only in (
            "/api/v1/implant/beacon/result",
            "/implant/beacon/result",
            "/beacon/result",
        ):
            kind = "result"

        if method == "POST" and kind == "beacon":
            data = pe.unwrap_request_body(prof, body) if pe else _json_body(body)
            result = await manager.handle_beacon(
                listener_id=listener_id,
                remote_addr=peer[0] if peer else remote,
                payload=data,
                user_agent=headers.get("user-agent"),
            )
            if pe:
                await _respond_text(writer, 200, pe.wrap_response(prof, result), "application/json")
            else:
                await _respond(writer, 200, result)
            return

        if method == "POST" and kind == "result":
            data = pe.unwrap_request_body(prof, body) if pe else _json_body(body)
            result = await manager.handle_beacon_result(data)
            if pe:
                await _respond_text(writer, 200, pe.wrap_response(prof, result), "application/json")
            else:
                await _respond(writer, 200, result)
            return

        # OAST / catch-all: log hit, optional lightweight session note
        hit = {
            "listener_id": listener_id,
            "remote": remote,
            "method": method,
            "path": path,
            "query": query,
            "headers": {k: v for k, v in headers.items() if k.lower() not in ("authorization", "cookie")},
            "body_preview": body[:500].decode("utf-8", errors="replace") if body else "",
            "ts": time.time(),
        }
        await manager.record_http_hit(listener_id, hit)
        await _respond(
            writer,
            200,
            {"status": "ok", "listener_id": listener_id, "received": True},
        )
    except Exception:
        log.exception("HTTP handler error from %s", remote)
        try:
            await _respond(writer, 500, {"error": "internal"})
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _read_request(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=15.0)
    except TimeoutError:
        return None
    if not line:
        return None
    try:
        parts = line.decode("latin-1", errors="replace").strip().split()
        if len(parts) < 2:
            return None
        method, target = parts[0].upper(), parts[1]
    except Exception:
        return None

    headers: dict[str, str] = {}
    while True:
        hline = await asyncio.wait_for(reader.readline(), timeout=15.0)
        if hline in (b"\r\n", b"\n", b""):
            break
        try:
            text = hline.decode("latin-1", errors="replace")
            if ":" in text:
                k, v = text.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        except Exception:
            continue

    length = int(headers.get("content-length", "0") or "0")
    body = b""
    if length > 0:
        length = min(length, 1_048_576)
        body = await asyncio.wait_for(reader.readexactly(length), timeout=30.0)

    parsed = urlparse(target)
    query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
    return {
        "method": method,
        "path": unquote(target),
        "query": query,
        "headers": headers,
        "body": body,
    }


def _json_body(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    try:
        data = json.loads(body.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


async def _respond(writer: asyncio.StreamWriter, status: int, payload: dict[str, Any]) -> None:
    await _respond_text(writer, status, json.dumps(payload), "application/json")


async def _respond_text(
    writer: asyncio.StreamWriter,
    status: int,
    text: str,
    content_type: str = "application/json",
) -> None:
    body = text.encode("utf-8")
    reason = {200: "OK", 400: "Bad Request", 500: "Internal Server Error"}.get(status, "OK")
    header = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"Server: SquidC5\r\n"
        f"\r\n"
    ).encode("latin-1")
    writer.write(header + body)
    await writer.drain()
