"""Admin AI operator chat — railed tools + offline intents."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_aichat01"


def _settings(tmp_path, **kw):
    base = dict(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=5000,
    )
    base.update(kw)
    return Settings(**base)


@pytest.mark.asyncio
async def test_ai_chat_offline_create_listener(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/ai/chat",
                headers=h,
                json={"message": "Setup a reverse shell listener on 4444"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["mode"] == "offline"
            assert body.get("tool_trace")
            assert any(t.get("tool") == "create_listener" and t.get("ok") for t in body["tool_trace"])
            # listener exists and started
            lis = await client.get("/api/v1/listeners", headers=h)
            assert lis.status_code == 200
            rows = lis.json()
            assert any(int(x.get("port") or 0) == 4444 for x in rows)


@pytest.mark.asyncio
async def test_ai_chat_offline_list_sessions(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/ai/chat",
                headers=h,
                json={"message": "list sessions please"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["mode"] == "offline"
            assert any(t.get("tool") == "list_sessions" for t in body.get("tool_trace") or [])


@pytest.mark.asyncio
async def test_ai_tools_catalog(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.get("/api/v1/ai/tools", headers=h)
            assert r.status_code == 200
            names = {t["name"] for t in r.json()["tools"]}
            assert "create_listener" in names
            assert "list_sessions" in names
            assert "generate_payload" in names


@pytest.mark.asyncio
async def test_ai_chat_requires_scope(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            t = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={"name": "noscope", "scopes": ["sessions:read"]},
            )
            tok = t.json()["token"]
            r = await client.post(
                "/api/v1/ai/chat",
                headers={"Authorization": f"Bearer {tok}"},
                json={"message": "hi"},
            )
            assert r.status_code == 403
