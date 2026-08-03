"""Assets host graph API + claim TTL + ops UI markers."""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.collab.teams import TeamService, claim_info
from squidc5.config import Settings
from squidc5.hosts.graph import host_key_for_session, is_asset_session, normalize_peer
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_hosts01"


def test_is_asset_session_strict():
    # verified shell
    assert is_asset_session(
        {"kind": "reverse_shell", "status": "active", "verified": True, "hostname": "h1"}
    )
    assert is_asset_session(
        {
            "kind": "reverse_shell",
            "status": "closed",
            "metadata": {"exec_ok": True},
            "remote_addr": "10.0.0.5:4444",
        }
    )
    assert is_asset_session(
        {
            "kind": "reverse_shell",
            "status": "closed",
            "username": "root",
            "os_info": "Linux",
        }
    )
    # live interactive channel is an asset (operator is on it)
    assert is_asset_session(
        {"kind": "reverse_shell", "status": "active", "interactive": True, "verified": False}
    )
    # inactive interactive-looking flags without evidence are not assets
    assert not is_asset_session(
        {"kind": "reverse_shell", "status": "closed", "interactive": True, "verified": False}
    )
    # scanner closed shells
    assert not is_asset_session(
        {
            "kind": "reverse_shell",
            "status": "closed",
            "remote_addr": "45.79.145.53:61000",
        }
    )
    assert not is_asset_session(
        {"kind": "reverse_shell", "status": "closed", "hostname": "noise-box"}
    )
    # beacon needs real hostname
    assert is_asset_session(
        {"kind": "beacon", "status": "active", "hostname": "workstation-a", "username": "alice"}
    )
    assert not is_asset_session({"kind": "beacon", "status": "active"})
    assert not is_asset_session(
        {"kind": "beacon", "status": "active", "hostname": "1.2.3.4:9999"}
    )


def test_host_key_strips_port():
    assert normalize_peer("45.79.145.53:61000") == "45.79.145.53"
    assert host_key_for_session(
        {"kind": "reverse_shell", "remote_addr": "10.1.2.3:5555", "verified": True}
    ) == "10.1.2.3"
    assert host_key_for_session(
        {"hostname": "dc01", "remote_addr": "10.1.2.3:5555"}
    ) == "dc01"


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

            state = app.state.app_state
            # noise: unverified reverse_shell (scanner)
            noise = await state.sessions.register(
                kind="reverse_shell",
                remote_addr="45.79.145.53:61000",
                hostname=None,
            )
            # closed shell that only has a hostname still noise
            junk = await state.sessions.register(
                kind="reverse_shell",
                remote_addr="1.2.3.4:9",
                hostname="scanner-host",
            )
            await state.db.update_session(junk, status="closed")

            hosts = await client.get("/api/v1/hosts", headers=h)
            assert hosts.status_code == 200
            body = hosts.json()
            assert body["claim_ttl_sec"] == 120
            assert body.get("skipped_noise", 0) >= 2
            by_id = {x["id"]: x for x in body["hosts"]}
            assert "workstation-a" in by_id
            assert "dc01" in by_id
            assert noise not in by_id
            assert "45.79.145.53" not in by_id
            assert "45.79.145.53:61000" not in by_id
            assert "scanner-host" not in by_id
            wa = by_id["workstation-a"]
            assert wa["session_count"] == 2
            assert set(wa["usernames"]) == {"alice", "bob"}
            assert "beacon" in wa["kinds"]
            pair = {sid1, sid2}
            assert any(
                {e["source"], e["target"]} == pair and e.get("rel") == "co-host"
                for e in body["edges"]
            )

            # verified closed shell becomes asset, key strips port
            real = await state.sessions.register(
                kind="reverse_shell",
                remote_addr="10.9.8.7:4444",
                hostname=None,
                username="root",
                os_info="Linux",
            )
            await state.db.update_session(
                real,
                status="closed",
                metadata={"exec_ok": True, "verified": True},
            )
            hosts_r = await client.get("/api/v1/hosts", headers=h)
            assert "10.9.8.7" in {x["id"] for x in hosts_r.json()["hosts"]}

            # Historical-only host can be dismissed; live hosts auto-unhide
            hide = await client.post("/api/v1/hosts/10.9.8.7/hide", headers=h)
            assert hide.status_code == 200
            hosts2 = await client.get("/api/v1/hosts", headers=h)
            ids2 = {x["id"] for x in hosts2.json()["hosts"]}
            assert "10.9.8.7" not in ids2
            assert "dc01" in ids2
            assert "workstation-a" in ids2

            bulk = await client.post("/api/v1/hosts/hide-inactive", headers=h)
            assert bulk.status_code == 200
            assert bulk.json()["hidden"] >= 0

            # Live implant host reappears even if previously bulk-hidden
            await state.db.hide_host_graph("dc01", hidden_by="test", note="stale")
            hosts_live = await client.get("/api/v1/hosts", headers=h)
            assert "dc01" in {x["id"] for x in hosts_live.json()["hosts"]}

            # restore historical
            unhide = await client.delete("/api/v1/hosts/10.9.8.7/hide", headers=h)
            assert unhide.status_code in (200, 404)

            c = await client.post(f"/api/v1/sessions/{sid1}/claim", headers=h, json={})
            assert c.status_code == 200
            time.sleep(0.05)
            ts: TeamService = app.state.app_state.teams
            await ts.assert_write_access(sid1, c.json()["claimed_by"])


def test_claim_info_unit():
    now = 1_000_000.0
    open_lock = claim_info(
        {"claimed_by": "alice", "claimed_at": now - 10, "claim_expires_at": now + 50},
        now=now,
    )
    assert open_lock["locked"] is True
    dead = claim_info(
        {"claimed_by": "alice", "claim_expires_at": now - 1},
        now=now,
    )
    assert dead["locked"] is False


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
                "hostDropInactive",
                "hostActiveOnly",
                "hide-inactive",
            ):
                assert m in js, m
