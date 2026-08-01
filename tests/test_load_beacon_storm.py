"""Beacon storm load smoke (D04) — lab only."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_storm01"


@pytest.mark.asyncio
async def test_beacon_burst_sequential(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=5000,
        auth_fail_limit_per_minute=5000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            ok = 0
            for i in range(50):
                r = await client.post(
                    "/api/v1/implant/beacon",
                    json={"hostname": f"h{i}"},
                )
                if r.status_code == 200:
                    ok += 1
            assert ok >= 45
