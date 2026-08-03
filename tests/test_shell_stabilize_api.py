"""Manual shell stabilize API + auto-stabilize default OFF."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.features import DEFAULT_FEATURES
from squidc5.main import create_app
from squidc5.shells.stabilize import ShellStabilizer, detect_os

ADMIN = "sc5_test_admin_token_bootstrap_stab01"


def test_defaults_auto_stabilize_off(tmp_path):
    assert DEFAULT_FEATURES.get("shell_auto_stabilize") is False
    s = Settings(
        data_dir=tmp_path / "sc5-stab-cfg",
        debug=True,
        mcp_enabled=False,
        plugin_signing_secret="x" * 32,
    )
    assert s.shell_auto_stabilize is False


def test_detect_os_and_plans():
    assert detect_os("Linux ubuntu 5.15") == "linux"
    assert detect_os("Microsoft Windows [Version 10.0]") == "windows"
    st = ShellStabilizer("10.0.0.1", 443)
    assert "python" in st.plan("linux").method.lower() or "stage2" in st.plan("linux").method.lower()
    assert "power" in st.plan("windows").method.lower() or "stage2" in st.plan("windows").method.lower()
    assert st.plan("linux").commands
    assert st.plan("windows").commands


@pytest.mark.asyncio
async def test_stabilize_requires_live_channel(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "stab1",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=2000,
        shell_auto_stabilize=False,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            # default feature flag off
            feat = await client.get("/api/v1/features", headers=h)
            assert feat.status_code == 200
            assert feat.json()["features"]["shell_auto_stabilize"] is False

            sid = await app.state.app_state.sessions.register(
                kind="reverse_shell",
                remote_addr="10.1.2.3:4444",
            )
            r = await client.post(
                f"/api/v1/sessions/{sid}/stabilize",
                headers=h,
                json={"os": "auto"},
            )
            assert r.status_code == 404
            assert "live" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_ops_ui_stabilize_marker(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "stab2",
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
            assert "ctxStabilize" in js
            assert "/stabilize" in js
            assert "adFeatSave" in js
