"""SOCKS5 direct mode + broker registration (implant mode wiring)."""

from __future__ import annotations

import asyncio
import struct

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_socks2"


async def _socks5_connect(host: str, port: int, dest_host: str, dest_port: int) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    greet = await reader.readexactly(2)
    assert greet == b"\x05\x00"
    # CONNECT domain
    req = b"\x05\x01\x00\x03" + bytes([len(dest_host)]) + dest_host.encode() + struct.pack(
        "!H", dest_port
    )
    writer.write(req)
    await writer.drain()
    resp = await reader.readexactly(10)
    writer.close()
    await writer.wait_closed()
    return resp


@pytest.mark.asyncio
async def test_socks_direct_connect_localhost(tmp_path):
    """Direct mode: C2 dials target (echo server)."""
    # tiny echo server
    async def echo(r, w):
        data = await r.read(100)
        w.write(data)
        await w.drain()
        w.close()

    echo_srv = await asyncio.start_server(echo, "127.0.0.1", 0)
    echo_port = echo_srv.sockets[0].getsockname()[1]

    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=3000,
        public_host="127.0.0.1",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "s"})
            sid = b.json()["session_id"]
            r = await client.post(
                "/api/v1/pivot/socks",
                headers=h,
                json={
                    "session_id": sid,
                    "listen_host": "127.0.0.1",
                    "listen_port": 0,
                    "mode": "direct",
                },
            )
            assert r.status_code == 200, r.text
            sport = r.json()["listen_port"]
            assert r.json()["mode"] == "direct"
            resp = await _socks5_connect("127.0.0.1", sport, "127.0.0.1", echo_port)
            assert resp[0] == 5 and resp[1] == 0  # success
            await client.delete(f"/api/v1/pivot/socks/{r.json()['id']}", headers=h)
    echo_srv.close()
    await echo_srv.wait_closed()


@pytest.mark.asyncio
async def test_socks_implant_mode_registers_data_port(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN + "b",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=3000,
        public_host="127.0.0.1",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}b"}
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "s2"})
            sid = b.json()["session_id"]
            r = await client.post(
                "/api/v1/pivot/socks",
                headers=h,
                json={"session_id": sid, "mode": "implant"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["data_port"] > 0
            assert r.json()["task_hint"]["args"]["data_port"] > 0
