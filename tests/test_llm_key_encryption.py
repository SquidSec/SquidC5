"""LLM API keys encrypted at rest (A06)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.crypto.secrets import ENC_PREFIX, SECRETS_KEY_FILENAME, SecretBox, resolve_secrets_key
from squidc5.main import create_app

ADMIN = "sc5_test_admin_token_bootstrap_llmenc01"


def test_secret_box_roundtrip():
    box = SecretBox(b"unit-test-master-key-material")
    enc = box.encrypt("sk-live-secret-value")
    assert enc is not None
    assert enc.startswith(ENC_PREFIX)
    assert "sk-live" not in enc
    assert box.decrypt(enc) == "sk-live-secret-value"


def test_legacy_plaintext_decrypt_passthrough():
    box = SecretBox(b"unit-test-master-key-material")
    assert box.decrypt("plain-legacy-key") == "plain-legacy-key"


def test_resolve_generates_secrets_key_file(tmp_path):
    m = resolve_secrets_key(explicit=None, data_dir=tmp_path)
    path = tmp_path / SECRETS_KEY_FILENAME
    assert path.is_file()
    assert path.read_bytes().strip() == m
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_configure_llm_stores_ciphertext(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_llm",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        secrets_key="test-secrets-master-for-ci",
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/llm",
                headers=headers,
                json={
                    "name": "lab",
                    "provider": "openai",
                    "model": "gpt-test",
                    "api_key": "sk-super-secret-should-not-be-plain",
                },
            )
            assert r.status_code == 200, r.text
            llm_id = r.json()["id"]
            row = await app.state.app_state.db.get_llm(llm_id)
            assert row is not None
            stored = row.get("api_key_enc") or ""
            assert stored.startswith(ENC_PREFIX)
            assert "sk-super-secret" not in stored
            # status must not leak key
            st = await client.get("/api/v1/ai/status", headers=headers)
            assert st.status_code == 200
            assert "sk-super-secret" not in st.text
