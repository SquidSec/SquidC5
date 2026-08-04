"""MCP dual-gate status on meta/features + clear 403 when settings off."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_mcpstat01"


@pytest.mark.asyncio
async def test_meta_reports_mcp_blocked_when_setting_off(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "mcp_off",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        await app.state.app_state.features.set_many({"mcp_enabled": True}, actor="test")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            meta = (await client.get("/api/v1/meta", headers=h)).json()
            mcp = meta.get("mcp") or {}
            assert mcp.get("setting") is False
            assert mcp.get("feature") is True
            assert mcp.get("active") is False
            assert "settings" in (mcp.get("blocked_by") or [])

            feats = (await client.get("/api/v1/features", headers=h)).json()
            assert feats.get("mcp", {}).get("active") is False

            r = await client.get("/mcp/tools", headers=h)
            assert r.status_code == 403
            detail = r.json().get("detail") or ""
            assert "SQUIDC5_MCP_ENABLED" in detail or "server settings" in detail.lower()


@pytest.mark.asyncio
async def test_meta_reports_mcp_active_when_both_on(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "mcp_on",
        debug=True,
        mcp_enabled=True,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        await app.state.app_state.features.set_many({"mcp_enabled": True}, actor="test")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            mcp = (await client.get("/api/v1/meta", headers=h)).json().get("mcp") or {}
            assert mcp.get("active") is True
            assert mcp.get("setting") is True
            assert mcp.get("feature") is True
            assert (mcp.get("blocked_by") or []) == []

            tools = await client.get("/mcp/tools", headers=h)
            assert tools.status_code == 200
            assert "tools" in tools.json()
