"""Listener crash supervision (B03)."""

from __future__ import annotations

import pytest

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_supv01"


@pytest.mark.asyncio
async def test_on_listener_crash_restarts(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_sup",
        debug=False,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        lm = app.state.app_state.listeners
        lm._max_restarts = 3
        lm._restart_counts.clear()
        row = await lm.create("sup-http", "http", 18767, host="127.0.0.1")
        lid = row["id"]
        await lm.start(lid)
        assert lid in lm._servers
        # Simulate crash cleanup + supervised restart
        await lm._on_listener_crash(lid, RuntimeError("simulated"))
        assert lm._restart_counts.get(lid, 0) >= 1
        row2 = await lm.db.get_listener(lid)
        assert row2["status"] == "running"
        assert lid in lm._servers


@pytest.mark.asyncio
async def test_max_restarts_marks_error(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_sup2",
        debug=False,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN + "b",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        lm = app.state.app_state.listeners
        lm._max_restarts = 1
        row = await lm.create("sup-lim", "http", 18768, host="127.0.0.1")
        lid = row["id"]
        await lm.db.set_listener_status(lid, "running")
        lm._restart_counts[lid] = 1  # next crash exceeds max of 1
        await lm._on_listener_crash(lid, RuntimeError("again"))
        row2 = await lm.db.get_listener(lid)
        assert row2["status"] == "error"
