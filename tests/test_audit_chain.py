"""Audit integrity chain (C08)."""

from __future__ import annotations

import pytest

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_achain01"


@pytest.mark.asyncio
async def test_audit_rows_have_chain_hash(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        db = app.state.app_state.db
        await db.audit("a", "operator", "test.one", details={"n": 1})
        await db.audit("a", "operator", "test.two", details={"n": 2})
        rows = await db.fetchall(
            "SELECT action, chain_hash, prev_hash FROM audit_log WHERE action LIKE 'test.%' ORDER BY id"
        )
        assert len(rows) >= 2
        assert rows[0]["chain_hash"]
        assert rows[1]["prev_hash"] == rows[0]["chain_hash"]
