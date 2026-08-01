"""Five-star pack B/C: audit verify, profile push, file chunks."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.audit.verify import verify_rows
from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_5sbc01"


def test_verify_empty_ok():
    assert verify_rows([])["ok"] is True


@pytest.mark.asyncio
async def test_audit_verify_and_profile_push(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=3000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            v = await client.get("/api/v1/audit/verify", headers=h)
            assert v.status_code == 200
            assert "checked" in v.json()
            # beacon session
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "p1"})
            sid = b.json()["session_id"]
            r = await client.post(
                "/api/v1/profiles/prof_default_http/push",
                headers=h,
                params={"session_id": sid},
            )
            assert r.status_code == 200, r.text
            assert r.json()["count"] >= 1
            # chunked file read task
            t = await client.post(
                "/api/v1/tasks",
                headers=h,
                json={
                    "session_id": sid,
                    "command": "file:read",
                    "args": {"path": "/etc/hosts", "offset": 0, "length": 64},
                },
            )
            assert t.status_code == 200
