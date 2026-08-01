"""Parity: transforms, file ops, SOCKS, profile switch fields."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.deploy.helpers import caddy_redirector_config, nginx_redirector_config
from squidc5.main import create_app
from squidc5.profiles.transforms import apply_decode, apply_encode

ADMIN = "sc5_test_admin_token_bootstrap_parity01"


def test_transform_roundtrip():
    pipe = [
        {"name": "prepend", "value": "X"},
        {"name": "base64"},
        {"name": "append", "value": "Y"},
    ]
    raw = b'{"hostname":"h"}'
    enc = apply_encode(pipe, raw)
    dec = apply_decode(pipe, enc)
    assert dec == raw


def test_xor_netbios_roundtrip():
    pipe = [{"name": "xor", "key": "ab"}, {"name": "netbios"}]
    raw = b"hello-squid"
    assert apply_decode(pipe, apply_encode(pipe, raw)) == raw


def test_caddy_redirector_snippet():
    s = caddy_redirector_config(server_name="cdn.lab", upstream="10.0.0.2:8443")
    assert "cdn.lab" in s
    assert "reverse_proxy" in s
    assert "proxy_pass" in nginx_redirector_config(server_name="x")


@pytest.mark.asyncio
async def test_file_op_task_and_profile_id(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "f1"})
            assert b.status_code == 200
            body = b.json()
            assert body.get("profile_id")
            sid = body["session_id"]
            r = await client.post(
                "/api/v1/files/op",
                headers=h,
                json={"session_id": sid, "op": "list", "path": "/tmp"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["command"] == "file:list"
            bad = await client.post(
                "/api/v1/files/op",
                headers=h,
                json={"session_id": sid, "op": "read"},
            )
            assert bad.status_code == 400


@pytest.mark.asyncio
async def test_socks_pivot(tmp_path):
    tok = "sc5_test_admin_token_bootstrap_socks01"
    settings = Settings(
        data_dir=tmp_path / "d2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=tok,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {tok}"}
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "s1"})
            sid = b.json()["session_id"]
            r = await client.post(
                "/api/v1/pivot/socks",
                headers=h,
                json={"session_id": sid, "listen_host": "127.0.0.1", "listen_port": 0},
            )
            assert r.status_code == 200, r.text
            assert r.json()["listen_port"] > 0
            pid = r.json()["id"]
            lst = await client.get("/api/v1/pivot/socks", headers=h)
            assert any(x["id"] == pid for x in lst.json()["pivots"])
            d = await client.delete(f"/api/v1/pivot/socks/{pid}", headers=h)
            assert d.status_code == 200
