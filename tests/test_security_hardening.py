"""Security hardening regression tests (Critical/High/Medium fixes)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.implants.crypto import open_envelope, seal
from squidc5.listeners.implant_auth import unwrap_implant_payload
from squidc5.main import create_app
from squidc5.security.ssrf import validate_llm_base_url
from squidc5.shells.stabilize import _safe_host, windows_stage2_script

ADMIN = "sc5_test_admin_token_bootstrap_sechard01"
PSK = "sec-hard-psk-unit-test-xyz"


def _settings(tmp_path, **kw):
    base = dict(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=True,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=True,
        implant_psk=PSK,
        rate_limit_per_minute=5000,
    )
    base.update(kw)
    return Settings(**base)


def test_ssrf_blocks_metadata_and_private():
    with pytest.raises(ValueError):
        validate_llm_base_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        validate_llm_base_url("http://10.0.0.1/v1")
    with pytest.raises(ValueError):
        validate_llm_base_url("http://evil.example/v1")  # http non-local
    with pytest.raises(ValueError):
        validate_llm_base_url("https://127.0.0.1/v1")  # loopback only via http lab
    ok = validate_llm_base_url("https://api.openai.com/v1")
    assert ok.startswith("https://")
    lab = validate_llm_base_url("http://127.0.0.1:11434/v1")
    assert lab == "http://127.0.0.1:11434"
    lab2 = validate_llm_base_url("http://localhost:11434/v1")
    assert lab2 == "http://localhost:11434"


def test_stage2_host_injection_blocked():
    with pytest.raises(ValueError):
        _safe_host("evil'; iex 'calc'")
    with pytest.raises(ValueError):
        windows_stage2_script("x';whoami", 443)
    s = windows_stage2_script("c2.lab.example", 443)
    assert "c2.lab.example" in s


def test_implant_auth_rejects_plain():
    with pytest.raises(PermissionError):
        unwrap_implant_payload({"hostname": "x"}, psk=PSK, require_auth=True)
    env = seal(PSK, {"hostname": "x"})
    plain = unwrap_implant_payload(env, psk=PSK, require_auth=True)
    assert plain["hostname"] == "x"


def test_aead_roundtrip_with_aad():
    env = seal(PSK, {"a": 1})
    assert open_envelope(PSK, env)["a"] == 1


@pytest.mark.asyncio
async def test_token_cannot_mint_admin(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            # admin creates tokens:manage only token
            r = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={"name": "tm", "scopes": ["tokens:manage", "sessions:read"]},
            )
            assert r.status_code == 200, r.text
            tm = r.json()["token"]
            ht = {"Authorization": f"Bearer {tm}"}
            # cannot mint admin
            bad = await client.post(
                "/api/v1/tokens",
                headers=ht,
                json={"name": "evil", "scopes": ["admin"]},
            )
            assert bad.status_code == 400
            # cannot grant scopes it lacks
            bad2 = await client.post(
                "/api/v1/tokens",
                headers=ht,
                json={"name": "evil2", "scopes": ["shell:interact"]},
            )
            assert bad2.status_code == 400


@pytest.mark.asyncio
async def test_policy_put_admin_only(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={"name": "pm", "scopes": ["policy:manage", "sessions:read"]},
            )
            tok = r.json()["token"]
            hp = {"Authorization": f"Bearer {tok}"}
            denied = await client.put(
                "/api/v1/policy",
                headers=hp,
                json={"rules": {"require_hitl": []}},
            )
            assert denied.status_code == 403
            ok = await client.put(
                "/api/v1/policy",
                headers=h,
                json={"rules": {"require_hitl": ["shell.interact"]}},
            )
            assert ok.status_code == 200


@pytest.mark.asyncio
async def test_hitl_single_use(tmp_path):
    app = create_app(_settings(tmp_path, mcp_enabled=False))
    async with app.router.lifespan_context(app):
        state = app.state.app_state
        hid = await state.db.create_hitl_request(
            action="shell.interact",
            resource="r",
            actor="op",
            actor_type="operator",
            details={},
            binding_hash="x",
            risk_score=8,
        )
        assert await state.db.resolve_hitl_request(hid, status="approved", resolved_by="admin")
        assert await state.db.consume_hitl_request(hid) is True
        assert await state.db.consume_hitl_request(hid) is False
        row = await state.db.get_hitl_request(hid)
        assert row["status"] == "consumed"


@pytest.mark.asyncio
async def test_task_complete_session_bound(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        state = app.state.app_state
        sid = await state.sessions.register(kind="beacon", hostname="t")
        t = await state.tasks.create(session_id=sid, command="id", created_by="admin")
        tid = t["id"]
        # wrong session fails
        ok = await state.db.complete_task(tid, "out", session_id="ses_wrong")
        assert ok is False
        ok = await state.db.complete_task(tid, "out", session_id=sid)
        assert ok is True
        # already done
        ok2 = await state.db.complete_task(tid, "out2", session_id=sid)
        assert ok2 is False


@pytest.mark.asyncio
async def test_mcp_shell_requires_scope_and_claim(tmp_path):
    app = create_app(_settings(tmp_path, mcp_enabled=True))
    async with app.router.lifespan_context(app):
        # enable feature
        state = app.state.app_state
        await state.features.set_many({"mcp_enabled": True}, actor="admin")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            # token with mcp but NO shell:interact
            r = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={
                    "name": "mcp-weak",
                    "scopes": ["mcp:connect", "sessions:read"],
                    "mcp_tools": ["interact_shell", "list_sessions"],
                },
            )
            assert r.status_code == 200, r.text
            tok = r.json()["token"]
            hm = {"Authorization": f"Bearer {tok}"}
            call = await client.post(
                "/mcp/call",
                headers=hm,
                json={"name": "interact_shell", "arguments": {"session_id": "x", "command": "id"}},
            )
            assert call.status_code == 200
            body = call.json()
            assert body.get("ok") is False
            assert "scope" in (body.get("error") or "").lower() or "Requires" in (body.get("error") or "")


@pytest.mark.asyncio
async def test_team_member_requires_lead(tmp_path):
    app = create_app(_settings(tmp_path, mcp_enabled=False))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            t1 = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={"name": "alice", "scopes": ["collab:use", "sessions:read"]},
            )
            t2 = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={"name": "bob", "scopes": ["collab:use", "sessions:read"]},
            )
            alice = t1.json()["token"]
            bob = t2.json()["token"]
            ha = {"Authorization": f"Bearer {alice}"}
            hb = {"Authorization": f"Bearer {bob}"}
            team = await client.post("/api/v1/teams", headers=ha, json={"name": "cell"})
            tid = team.json()["id"]
            # bob cannot add members
            denied = await client.post(
                f"/api/v1/teams/{tid}/members",
                headers=hb,
                json={"actor": "eve", "role": "operator"},
            )
            assert denied.status_code == 403
            # alice is lead (creator)
            ok = await client.post(
                f"/api/v1/teams/{tid}/members",
                headers=ha,
                json={"actor": "bob", "role": "operator"},
            )
            assert ok.status_code == 200


@pytest.mark.asyncio
async def test_llm_ssrf_on_configure(tmp_path):
    app = create_app(_settings(tmp_path, mcp_enabled=False))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            bad = await client.post(
                "/api/v1/llm",
                headers=h,
                json={
                    "name": "evil",
                    "model": "x",
                    "base_url": "http://169.254.169.254/",
                    "api_key": "k",
                },
            )
            assert bad.status_code in (400, 500, 422) or bad.status_code >= 400


@pytest.mark.asyncio
async def test_ops_console_sets_role_flag(tmp_path):
    app = create_app(_settings(tmp_path, mcp_enabled=False))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.get("/api/v1/ops/console.js", headers=h)
            assert r.status_code == 200
            assert "view-sessions" in r.text or "selectSession" in r.text
            assert "Claim" in r.text or "ctxClaim" in r.text
            # non-admin
            t = await client.post(
                "/api/v1/tokens",
                headers=h,
                json={"name": "op", "scopes": ["sessions:read", "shell:interact"]},
            )
            ho = {"Authorization": f"Bearer {t.json()['token']}"}
            r2 = await client.get("/api/v1/ops/console.js", headers=ho)
            assert r2.status_code == 200
            assert "view-sessions" in r2.text or "__SC5_UI_ROLE__" in r2.text or "selectSession" in r2.text


@pytest.mark.asyncio
async def test_socks_rejects_non_loopback(tmp_path):
    app = create_app(_settings(tmp_path, mcp_enabled=False))
    async with app.router.lifespan_context(app):
        state = app.state.app_state
        sid = await state.sessions.register(kind="beacon", hostname="s")
        with pytest.raises(PermissionError):
            await state.socks.start(sid, listen_host="0.0.0.0", mode="implant")
        with pytest.raises(PermissionError):
            await state.socks.start(sid, listen_host="127.0.0.1", mode="direct")
