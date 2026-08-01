"""Lab e2e: profile activate -> sealed optional -> task cycle (C09)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_e2e01"


@pytest.mark.asyncio
async def test_lab_playbook_http_beacon_task(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "e2e",
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
            await client.post("/api/v1/profiles/prof_default_http/activate", headers=h)
            r1 = await client.post(
                "/api/v1/implant/beacon",
                json={"hostname": "victim-lab"},
            )
            assert r1.status_code == 200
            sid = r1.json()["session_id"]
            assert r1.json().get("profile_id")
            t = await client.post(
                "/api/v1/tasks",
                headers=h,
                json={"session_id": sid, "command": "echo lab-ok"},
            )
            assert t.status_code == 200
            r2 = await client.post(
                "/api/v1/implant/beacon",
                json={"session_id": sid, "hostname": "victim-lab"},
            )
            task = r2.json().get("task")
            assert task and task["command"] == "echo lab-ok"
            done = await client.post(
                "/api/v1/implant/beacon/result",
                json={"task_id": task["id"], "result": "lab-ok\n", "status": "completed"},
            )
            assert done.status_code == 200
            got = await client.get(f"/api/v1/tasks/{task['id']}", headers=h)
            assert got.json()["status"] == "completed"
            assert "lab-ok" in (got.json().get("result") or "")
