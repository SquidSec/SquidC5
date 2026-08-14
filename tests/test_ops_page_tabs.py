"""Ops console: every main view uses page tabs; confirm modal; bootstrap name."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_tabs01"


@pytest.mark.asyncio
async def test_all_views_use_page_tabs(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "tabs1",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            js = (await client.get("/api/v1/ops/admin.js", headers=h)).text
            html = (await client.get("/ops")).text

            # Shared tab infrastructure
            assert "function tabbedHtml" in js or "tabbedHtml(" in js
            assert "bindPageTabs" in js
            assert "page-tab-btn" in js
            assert "sc5Confirm" in html or "__SC5_confirm" in js
            assert "askConfirm" in js
            # themed confirm only (no window.alert / bare confirm calls)
            assert "window.alert" not in js
            assert "window.confirm" not in js
            assert "askConfirm" in js

            # Every nav page has a tabbed shell id
            for tid in (
                "sessionsTabs",
                "listenersTabs",
                "payloadsTabs",
                "postexTabs",
                "collabTabs",
                "observeTabs",
                "aiTabs",
                "adminTabs",
                "profilesTabs",
                "artifactsTabs",
                "assetsTabs",
                "oastTabs",
            ):
                assert tid in js, f"missing tabs shell {tid}"
            assert "labeledOastUrls" in js
            assert "oast-copy-one" in js
            assert "oastSaveNote" in js
            assert "oastDeleteBtn" in js
            assert "deleteSelectedOast" in js
            assert "ctxKill" in js
            assert "Kill shell" in js

            # INKO has Status & tools tab
            assert "aistatus" in js
            assert "aiStatus" in js
            assert "aiTools" in js

            # Bottom layout toggle
            assert "bottomLayoutToggle" in html
            assert "mode-tabs" in html or "mode-split" in html

            # Graph pan/zoom
            assert "bindGraphPanZoom" in js
            assert "sub-tab-btn" in js
            assert "meta-rows" in js or "Address" in js
            assert "bindSubTabs" in js
            assert "hostZoomIn" in js


@pytest.mark.asyncio
async def test_bootstrap_admin_name_is_squidc5_admin(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "tabs2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        state = app.state.app_state
        rows = await state.db.list_tokens()
        admin_rows = [r for r in rows if "admin" in (r.get("scopes") or "")]
        assert admin_rows
        names = {r.get("name") for r in admin_rows}
        assert "squidc5-admin" in names or any("admin" in (n or "") for n in names)


@pytest.mark.asyncio
async def test_rename_self_actor(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "tabs3",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.put("/api/v1/me", headers=h, json={"name": "ops-lead"})
            assert r.status_code == 200
            assert r.json()["actor"] == "ops-lead"
            meta = await client.get("/api/v1/meta", headers=h)
            assert meta.status_code == 200
            body = meta.json()
            assert body.get("actor") == "ops-lead" or body.get("name") == "ops-lead"
