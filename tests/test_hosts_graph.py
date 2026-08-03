"""Assets host graph API + claim TTL + ops UI markers."""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.collab.teams import TeamService, claim_info
from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_hosts01"


@pytest.mark.asyncio
async def test_hosts_api_and_claim_ttl(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "hg2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=2000,
        session_claim_ttl_sec=120,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            b1 = await client.post(
                "/api/v1/implant/beacon",
                json={"hostname": "workstation-a", "username": "alice"},
            )
            assert b1.status_code == 200
            sid1 = b1.json()["session_id"]
            b2 = await client.post(
                "/api/v1/implant/beacon",
                json={"hostname": "workstation-a", "username": "bob"},
            )
            assert b2.status_code == 200
            sid2 = b2.json()["session_id"]
            b3 = await client.post(
                "/api/v1/implant/beacon",
                json={"hostname": "dc01", "username": "svc"},
            )
            assert b3.status_code == 200

            hosts = await client.get("/api/v1/hosts", headers=h)
            assert hosts.status_code == 200
            body = hosts.json()
            assert body["claim_ttl_sec"] == 120
            by_id = {x["id"]: x for x in body["hosts"]}
            assert "workstation-a" in by_id
            assert "dc01" in by_id
            wa = by_id["workstation-a"]
            assert wa["session_count"] == 2
            assert set(wa["usernames"]) == {"alice", "bob"}
            assert "beacon" in wa["kinds"]
            assert isinstance(body.get("edges"), list)
            assert isinstance(body.get("session_nodes"), list)
            pair = {sid1, sid2}
            assert any(
                {e["source"], e["target"]} == pair and e.get("rel") == "co-host"
                for e in body["edges"]
            )

            c = await client.post(f"/api/v1/sessions/{sid1}/claim", headers=h, json={})
            assert c.status_code == 200
            cj = c.json()
            assert cj["claimed_by"]
            assert cj.get("claim_expires_at") is not None

            sess = await client.get(f"/api/v1/sessions/{sid1}", headers=h)
            assert sess.status_code == 200
            claim = sess.json().get("claim") or {}
            assert claim.get("locked") is True
            assert claim.get("claim_remaining_sec") is not None

            hosts2 = await client.get("/api/v1/hosts", headers=h)
            wa2 = {x["id"]: x for x in hosts2.json()["hosts"]}["workstation-a"]
            assert wa2.get("claimed_by")

            c2 = await client.post(
                f"/api/v1/sessions/{sid2}/claim",
                headers=h,
                json={"ttl_sec": 1},
            )
            assert c2.status_code == 200
            time.sleep(1.2)
            ts: TeamService = app.state.app_state.teams
            await ts.assert_write_access(sid2, "other-op", is_admin=False)
            await ts.assert_write_access(sid2, "other-op")


def test_claim_info_unit():
    now = 1_000_000.0
    open_lock = claim_info(
        {"claimed_by": "alice", "claimed_at": now - 10, "claim_expires_at": now + 50},
        now=now,
    )
    assert open_lock["locked"] is True
    assert open_lock["claim_remaining_sec"] == 50
    dead = claim_info(
        {"claimed_by": "alice", "claim_expires_at": now - 1},
        now=now,
    )
    assert dead["locked"] is False
    assert dead["claim_expired"] is True
    forever = claim_info({"claimed_by": "bob", "claimed_at": now}, now=now)
    assert forever["locked"] is True
    assert forever["claim_expires_at"] is None


@pytest.mark.asyncio
async def test_hosts_ui_markers(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "hg3",
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
                "renderHostsView",
                "drawHostGraph",
                "/api/v1/hosts",
                "hostGraph",
                "ctxForceClaim",
                "claimChipHtml",
            ):
                assert m in js, m
            html = await client.get("/ops")
            assert html.status_code == 200
            assert 'data-view="hosts"' in html.text
            assert 'id="view-hosts"' in html.text
