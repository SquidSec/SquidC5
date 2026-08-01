"""Implant AEAD channel (A11)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.implants.crypto import is_envelope, open_envelope, seal
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_impcr01"
PSK = "unit-test-implant-psk-xyz"


def test_seal_open_roundtrip():
    env = seal(PSK, {"session_id": None, "hostname": "h1"})
    assert is_envelope(env)
    plain = open_envelope(PSK, env)
    assert plain["hostname"] == "h1"


def test_wrong_psk_fails():
    env = seal(PSK, {"a": 1})
    with pytest.raises(Exception):
        open_envelope("wrong-psk", env)


@pytest.mark.asyncio
async def test_require_auth_rejects_plain(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=True,
        implant_psk=PSK,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.post(
                "/api/v1/implant/beacon",
                json={"hostname": "no-auth"},
            )
            assert r.status_code == 403


@pytest.mark.asyncio
async def test_sealed_checkin_and_task(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=True,
        implant_psk=PSK,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = seal(PSK, {"hostname": "lab-host", "session_id": None})
            r = await client.post("/api/v1/implant/beacon", json=body)
            assert r.status_code == 200, r.text
            env = r.json()
            assert is_envelope(env)
            data = open_envelope(PSK, env)
            assert data.get("session_id")
            sid = data["session_id"]
            # create task as admin
            headers = {"Authorization": f"Bearer {ADMIN}"}
            tr = await client.post(
                "/api/v1/tasks",
                headers=headers,
                json={"session_id": sid, "command": "id"},
            )
            assert tr.status_code == 200
            # poll via sealed beacon
            body2 = seal(PSK, {"session_id": sid, "hostname": "lab-host"})
            r2 = await client.post("/api/v1/implant/beacon", json=body2)
            assert r2.status_code == 200
            data2 = open_envelope(PSK, r2.json())
            assert data2.get("task") is not None
            tid = data2["task"]["id"]
            # complete
            done = seal(PSK, {"task_id": tid, "result": "uid=0", "status": "completed"})
            r3 = await client.post("/api/v1/implant/beacon/result", json=done)
            assert r3.status_code == 200
            assert open_envelope(PSK, r3.json())["status"] == "ok"
