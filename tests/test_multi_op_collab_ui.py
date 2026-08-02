"""Multi-op collab M1-M6 + ops UI markers."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.collab.presence import PresenceService
from squidc5.collab.teams import TeamService
from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_collab01"
OP_A = "sc5_test_op_a_token_collab_aaaa01"
OP_B = "sc5_test_op_b_token_collab_bbbb01"


def test_presence_ttl():
    p = PresenceService(ttl_sec=0.01)
    p.heartbeat("alice", status="online")
    assert len(p.list_online()) == 1
    import time

    time.sleep(0.05)
    assert p.list_online() == []


@pytest.mark.asyncio
async def test_claim_lock_and_handoff_pack(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=5000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            # create two operator tokens
            ta = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={
                    "name": "op-a",
                    "scopes": [
                        "sessions:read",
                        "sessions:write",
                        "tasks:read",
                        "tasks:write",
                        "shell:interact",
                        "collab:use",
                        "audit:read",
                        "metrics:read",
                    ],
                },
            )
            assert ta.status_code == 200, ta.text
            token_a = ta.json()["token"]
            tb = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={
                    "name": "op-b",
                    "scopes": [
                        "sessions:read",
                        "sessions:write",
                        "tasks:read",
                        "tasks:write",
                        "shell:interact",
                        "collab:use",
                        "audit:read",
                    ],
                },
            )
            assert tb.status_code == 200
            token_b = tb.json()["token"]
            ha = {"Authorization": f"Bearer {token_a}"}
            hb = {"Authorization": f"Bearer {token_b}"}

            # beacon session
            b = await client.post("/api/v1/implant/beacon", json={"hostname": "collab-host"})
            assert b.status_code == 200
            sid = b.json()["session_id"]

            # A claims
            c = await client.post(f"/api/v1/sessions/{sid}/claim", headers=ha, json={})
            assert c.status_code == 200, c.text
            assert c.json()["claimed_by"]

            # B cannot task
            tdeny = await client.post(
                "/api/v1/tasks",
                headers=hb,
                json={"session_id": sid, "command": "id"},
            )
            assert tdeny.status_code == 403

            # A can task
            tok = await client.post(
                "/api/v1/tasks",
                headers=ha,
                json={"session_id": sid, "command": "id"},
            )
            assert tok.status_code == 200, tok.text

            # B cannot handoff while A holds claim
            hdeny = await client.post(
                f"/api/v1/sessions/{sid}/handoff",
                headers=hb,
                json={"to": "op-a", "note": "steal"},
            )
            assert hdeny.status_code == 403

            # handoff pack to B (A holds claim)
            ho = await client.post(
                f"/api/v1/sessions/{sid}/handoff",
                headers=ha,
                json={"to": "op-b", "note": "your turn", "include_pack": True},
            )
            assert ho.status_code == 200, ho.text
            body = ho.json()
            assert body["to"] == "op-b"
            assert "pack" in body
            assert body["pack"].get("session")

            # B now claimed - can task
            t2 = await client.post(
                "/api/v1/tasks",
                headers=hb,
                json={"session_id": sid, "command": "whoami"},
            )
            assert t2.status_code == 200, t2.text

            # spectator
            sp = await client.get(f"/api/v1/sessions/{sid}/spectator", headers=ha)
            assert sp.status_code == 200
            assert sp.json().get("watching") is True
            assert sp.json().get("can_interact") is False

            # presence
            pr = await client.post(
                "/api/v1/collab/presence",
                headers=ha,
                json={"status": "online", "viewing_session": sid},
            )
            assert pr.status_code == 200
            pl = await client.get("/api/v1/collab/presence", headers=ha)
            assert pl.status_code == 200
            assert pl.json()["count"] >= 1

            # team chat - creator is lead member; B not member -> denied
            team = await client.post("/api/v1/teams", headers=ha, json={"name": "red"})
            assert team.status_code == 200
            tid = team.json()["id"]
            ch = await client.post(
                "/api/v1/collab/chat",
                headers=ha,
                json={"message": "hello team", "team_id": tid},
            )
            assert ch.status_code == 200
            deny_ch = await client.post(
                "/api/v1/collab/chat",
                headers=hb,
                json={"message": "intrude", "team_id": tid},
            )
            assert deny_ch.status_code == 403
            cl = await client.get(f"/api/v1/collab/chat?team_id={tid}", headers=ha)
            assert cl.status_code == 200
            assert any("hello" in (m.get("message") or "") for m in cl.json()["messages"])

            # audit me
            me = await client.get("/api/v1/audit/me?limit=20", headers=ha)
            assert me.status_code == 200
            assert me.json()["actor"]
            filt = await client.get("/api/v1/audit?mine=true&limit=10", headers=ha)
            assert filt.status_code == 200

            # release
            rel = await client.post(f"/api/v1/sessions/{sid}/release", headers=hb)
            assert rel.status_code == 200


@pytest.mark.asyncio
async def test_ops_admin_collab_ui_markers(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d2",
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
            r = await client.get("/api/v1/ops/admin.js", headers=h)
            assert r.status_code == 200
            js = r.text
            for m in (
                "view-sessions",
                "view-collab",
                "ctxClaim",
                "/api/v1/sessions/",
                "claim",
                "handoff",
                "presence",
                "selectSession",
                "renderSessionsView",
            ):
                assert m in js, m


@pytest.mark.asyncio
async def test_team_service_claim_unit(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d3",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        state = app.state.app_state
        sid = await state.sessions.register(kind="beacon", hostname="u")
        ts: TeamService = state.teams
        await ts.claim(sid, "alice")
        with pytest.raises(PermissionError):
            await ts.assert_write_access(sid, "bob")
        await ts.assert_write_access(sid, "alice")
        await ts.release(sid, "alice")
        await ts.assert_write_access(sid, "bob")
