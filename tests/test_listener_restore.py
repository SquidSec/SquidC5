"""Listener restore on boot (B02)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_lrest01"


@pytest.mark.asyncio
async def test_restore_running_listeners_on_startup(tmp_path):
    data = tmp_path / "data_lr"
    settings = Settings(
        data_dir=data,
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    # First boot: create + start a reverse_shell listener on ephemeral port
    app1 = create_app(settings)
    lid = None
    port = 18765
    async with app1.router.lifespan_context(app1):
        transport = ASGITransport(app=app1)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {ADMIN}"}
            cr = await client.post(
                "/api/v1/listeners",
                headers=headers,
                json={
                    "name": "rev-restore",
                    "kind": "reverse_shell",
                    "host": "127.0.0.1",
                    "port": port,
                },
            )
            assert cr.status_code == 200, cr.text
            lid = cr.json()["id"]
            st = await client.post(f"/api/v1/listeners/{lid}/start", headers=headers)
            assert st.status_code == 200, st.text
            assert st.json()["status"] == "running"

    # Second boot: same DB - must restore running listener
    app2 = create_app(settings)
    async with app2.router.lifespan_context(app2):
        row = await app2.state.app_state.db.get_listener(lid)
        assert row is not None
        assert row["status"] == "running"
        # live server map should include it
        assert lid in app2.state.app_state.listeners._servers


@pytest.mark.asyncio
async def test_restore_bind_failure_marks_error(tmp_path):
    """If port cannot bind, status becomes error and app still starts."""
    data = tmp_path / "data_lr2"
    settings = Settings(
        data_dir=data,
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN + "b",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    # Occupy a port
    import asyncio

    async def _hold(reader, writer):
        await asyncio.sleep(3600)

    holder = await asyncio.start_server(_hold, host="127.0.0.1", port=0)
    sock = holder.sockets[0]
    port = sock.getsockname()[1]

    app1 = create_app(settings)
    lid = None
    async with app1.router.lifespan_context(app1):
        # Insert a fake running listener pointing at occupied port via DB
        lid = await app1.state.app_state.db.create_listener(
            "conflict", "reverse_shell", port, "127.0.0.1", {}
        )
        await app1.state.app_state.db.set_listener_status(lid, "running")

    app2 = create_app(settings)
    async with app2.router.lifespan_context(app2):
        row = await app2.state.app_state.db.get_listener(lid)
        assert row is not None
        assert row["status"] == "error"
        assert lid not in app2.state.app_state.listeners._servers

    holder.close()
    await holder.wait_closed()
