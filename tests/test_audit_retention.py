"""Audit retention purge (B07)."""

from __future__ import annotations

import time

import pytest

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_audret01"


@pytest.mark.asyncio
async def test_purge_older_than_days(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_aud",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        audit_retention_days=30,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        db = app.state.app_state.db
        old_ts = time.time() - (60 * 86400)
        await db.execute(
            """INSERT INTO audit_log (ts, actor, actor_type, action, resource, details, risk_score, allowed)
               VALUES (?, 'x', 'system', 'old.event', null, '{}', 0, 1)""",
            (old_ts,),
        )
        await db.execute(
            """INSERT INTO audit_log (ts, actor, actor_type, action, resource, details, risk_score, allowed)
               VALUES (?, 'x', 'system', 'new.event', null, '{}', 0, 1)""",
            (time.time(),),
        )
        n = await app.state.app_state.audit.purge_older_than_days(30)
        assert n >= 1
        rows = await db.fetchall("SELECT action FROM audit_log WHERE action IN ('old.event','new.event')")
        actions = {r["action"] for r in rows}
        assert "old.event" not in actions
        assert "new.event" in actions


@pytest.mark.asyncio
async def test_startup_runs_purge(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_aud2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN + "b",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        audit_retention_days=7,
        rate_limit_per_minute=1000,
    )
    # Pre-seed DB with old row before app start
    from squidc5.db.store import Database

    db_path = settings.resolve_db_path()
    db = Database(db_path)
    await db.connect()
    await db.execute(
        """INSERT INTO audit_log (ts, actor, actor_type, action, resource, details, risk_score, allowed)
           VALUES (?, 'x', 'system', 'ancient', null, '{}', 0, 1)""",
        (time.time() - 40 * 86400,),
    )
    await db.close()

    app = create_app(settings)
    async with app.router.lifespan_context(app):
        rows = await app.state.app_state.db.fetchall(
            "SELECT action FROM audit_log WHERE action = 'ancient'"
        )
        assert rows == []
