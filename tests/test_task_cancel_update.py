"""Pending task cancel and modify APIs."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_tskcanc01"


@pytest.mark.asyncio
async def test_cancel_and_patch_pending_task(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "t1"})
            assert b.status_code == 200
            sid = b.json()["session_id"]
            t = await client.post(
                "/api/v1/tasks",
                headers=h,
                json={"session_id": sid, "command": "whoami"},
            )
            assert t.status_code == 200, t.text
            tid = t.json()["id"]
            assert t.json()["status"] == "pending"

            # list pending for session
            lst = await client.get(
                f"/api/v1/tasks?session_id={sid}&status=pending", headers=h
            )
            assert lst.status_code == 200
            assert any(x["id"] == tid for x in lst.json())

            # patch command
            p = await client.patch(
                f"/api/v1/tasks/{tid}",
                headers=h,
                json={"command": "id"},
            )
            assert p.status_code == 200, p.text
            assert p.json()["command"] == "id"
            assert p.json()["status"] == "pending"

            # cancel
            c = await client.post(f"/api/v1/tasks/{tid}/cancel", headers=h)
            assert c.status_code == 200, c.text
            assert c.json()["status"] == "cancelled"

            # cannot cancel again
            c2 = await client.post(f"/api/v1/tasks/{tid}/cancel", headers=h)
            assert c2.status_code == 404

            # cannot patch cancelled
            p2 = await client.patch(
                f"/api/v1/tasks/{tid}",
                headers=h,
                json={"command": "uname"},
            )
            assert p2.status_code == 404
