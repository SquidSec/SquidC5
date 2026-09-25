"""Ops header browser notifications for shells and OAST hits."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app
from squidc5.paths import web_file


def test_ops_html_notify_toggle():
    html = Path(web_file("phone-dashboard.html")).read_text(encoding="utf-8")
    assert 'id="btnNotify"' in html
    assert "sc5_ops_notify" in html
    assert "shell.connected" in html
    assert "oast.hit" in html
    assert "/api/v1/events/stream" in html
    assert "Notification.requestPermission" in html
    sw = Path(web_file("notify-sw.js")).read_text(encoding="utf-8")
    assert "showNotification" in sw


@pytest.mark.asyncio
async def test_ops_serves_notify_sw(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap="sc5_test_admin_token_bootstrap_notify01",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/ops/notify-sw.js")
            assert r.status_code == 200
            assert "showNotification" in r.text
            assert r.headers.get("service-worker-allowed") == "/ops"
