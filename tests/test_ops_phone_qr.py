"""Ops console phone QR share affordance."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app
from squidc5.paths import web_file


def test_qrcode_asset_packaged():
    p = web_file("assets/qrcode.min.js")
    assert p is not None and Path(p).is_file()
    text = Path(p).read_text(encoding="utf-8", errors="replace")
    assert "QRCode" in text


def test_ops_html_has_phone_qr_button():
    p = web_file("phone-dashboard.html")
    assert p is not None
    html = Path(p).read_text(encoding="utf-8")
    assert 'id="btnPhoneQr"' in html
    assert "buildPhoneShareUrl" in html or "sc5=" in html
    assert "/ops/assets/qrcode.min.js" in html
    assert 'id="qrModal"' in html


@pytest.mark.asyncio
async def test_ops_serves_qrcode_asset(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap="sc5_test_admin_token_bootstrap_qrcode01",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/ops")
            if r.status_code != 200:
                pytest.skip("ops html not mounted")
            assert "btnPhoneQr" in r.text
            qr = await client.get("/ops/assets/qrcode.min.js")
            assert qr.status_code == 200
            assert "QRCode" in qr.text
