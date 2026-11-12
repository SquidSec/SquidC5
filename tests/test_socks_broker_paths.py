"""SOCKS5 broker: mode guards, implant relay failure paths, teardown."""

from __future__ import annotations

import asyncio
import struct

import pytest

from squidc5.pivot.socks import SocksBroker


async def _socks_greeting(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    return reader, writer


async def _socks_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
) -> bytes:
    req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", port)
    writer.write(req)
    await writer.drain()
    return await reader.readexactly(10)


def test_list_is_empty_initially():
    assert SocksBroker().list() == []


@pytest.mark.asyncio
async def test_direct_mode_requires_allow_direct():
    broker = SocksBroker()
    with pytest.raises(PermissionError, match="allow_direct"):
        await broker.start("ses_1", mode="direct")


@pytest.mark.asyncio
async def test_non_loopback_bind_requires_allow():
    broker = SocksBroker()
    with pytest.raises(PermissionError, match="loopback"):
        await broker.start("ses_1", listen_host="0.0.0.0")


@pytest.mark.asyncio
async def test_unknown_mode_falls_back_to_implant():
    broker = SocksBroker()
    out = await broker.start("ses_1", mode="carrier-pigeon")
    try:
        assert out["mode"] == "implant"
        assert out["status"] == "listening"
        assert out["data_port"] > 0
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_list_reports_started_pivot():
    broker = SocksBroker()
    out = await broker.start("ses_1")
    try:
        rows = broker.list()
        assert len(rows) == 1
        assert rows[0]["id"] == out["id"]
        assert rows[0]["session_id"] == "ses_1"
        assert rows[0]["mode"] == "implant"
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_implant_enqueue_failure_returns_error_reply():
    broker = SocksBroker()

    async def _boom(*_args, **_kwargs) -> None:
        raise RuntimeError("task queue down")

    broker.enqueue_task = _boom
    out = await broker.start("ses_1")
    try:
        reader, writer = await _socks_greeting("127.0.0.1", out["listen_port"])
        try:
            reply = await _socks_connect(reader, writer, "example.test", 80)
            assert reply[1] == 0x01  # general failure
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_implant_relay_failure_returns_error_reply():
    """The implant never dials back and the relay future fails."""
    broker = SocksBroker()
    pivot_holder: dict[str, object] = {}

    async def _fail_relay(session_id: str, command: str, args: dict) -> None:
        pivot = pivot_holder["pivot"]
        fut = pivot.pending.get(args["conn_id"])  # type: ignore[attr-defined]
        if fut is not None and not fut.done():
            fut.set_exception(RuntimeError("implant never dialed back"))

    broker.enqueue_task = _fail_relay
    out = await broker.start("ses_1")
    pivot_holder["pivot"] = broker._pivots[out["id"]]
    try:
        reader, writer = await _socks_greeting("127.0.0.1", out["listen_port"])
        try:
            reply = await asyncio.wait_for(_socks_connect(reader, writer, "example.test", 80), 10.0)
            assert reply[1] == 0x05  # connection refused
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_implant_relay_success_bridges_bytes():
    broker = SocksBroker()
    out = await broker.start("ses_1")
    try:
        reader, writer = await _socks_greeting("127.0.0.1", out["listen_port"])
        try:
            req = b"\x05\x01\x00\x03" + bytes([len("target.test")]) + b"target.test" + struct.pack("!H", 80)
            writer.write(req)
            await writer.drain()

            # Simulate the implant opening the data channel for this conn.
            await asyncio.sleep(0.2)
            data_reader, data_writer = await asyncio.open_connection(
                "127.0.0.1", out["data_port"]
            )
            # The broker generated a conn_id; read it from the pending map.
            pivot = broker._pivots[out["id"]]
            conn_id = next(iter(pivot.pending))
            data_writer.write((conn_id + "\n").encode())
            await data_writer.drain()

            reply = await reader.readexactly(10)
            assert reply[1] == 0x00

            writer.write(b"ping")
            await writer.drain()
            assert await asyncio.wait_for(data_reader.read(4), 5.0) == b"ping"

            data_writer.write(b"pong")
            await data_writer.drain()
            assert await asyncio.wait_for(reader.read(4), 5.0) == b"pong"
        finally:
            writer.close()
            await writer.wait_closed()
            data_writer.close()
            await data_writer.wait_closed()
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_data_channel_with_unknown_conn_id_is_closed():
    broker = SocksBroker()
    out = await broker.start("ses_1")
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", out["data_port"])
        try:
            writer.write(b"not-a-real-conn-id\n")
            await writer.drain()
            # Server closes the socket for unknown ids.
            assert await asyncio.wait_for(reader.read(1), 5.0) == b""
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_stop_cancels_pending_futures():
    broker = SocksBroker()

    async def _noop(*_args, **_kwargs) -> None:
        return None

    broker.enqueue_task = _noop
    out = await broker.start("ses_1")
    reader, writer = await _socks_greeting("127.0.0.1", out["listen_port"])
    try:
        req = b"\x05\x01\x00\x03" + bytes([len("slow.test")]) + b"slow.test" + struct.pack("!H", 80)
        writer.write(req)
        await writer.drain()
        await asyncio.sleep(0.2)
        pivot = broker._pivots[out["id"]]
        assert pivot.pending
        assert await broker.stop(out["id"]) is True
        assert broker.list() == []
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_stop_unknown_pivot_returns_false():
    assert await SocksBroker().stop("socks_missing") is False


@pytest.mark.asyncio
async def test_non_connect_command_is_rejected():
    broker = SocksBroker()
    out = await broker.start("ses_1")
    try:
        reader, writer = await _socks_greeting("127.0.0.1", out["listen_port"])
        try:
            # BIND (0x02) is not supported.
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            reply = await reader.readexactly(10)
            assert reply[1] == 0x07
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_unsupported_address_type_is_rejected():
    broker = SocksBroker()
    out = await broker.start("ses_1")
    try:
        reader, writer = await _socks_greeting("127.0.0.1", out["listen_port"])
        try:
            writer.write(b"\x05\x01\x00\x09")
            await writer.drain()
            reply = await reader.readexactly(10)
            assert reply[1] == 0x08
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await broker.stop(out["id"])


@pytest.mark.asyncio
async def test_non_socks5_greeting_is_dropped():
    broker = SocksBroker()
    out = await broker.start("ses_1")
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", out["listen_port"])
        try:
            writer.write(b"\x04\x01")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(1), 5.0) == b""
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await broker.stop(out["id"])
