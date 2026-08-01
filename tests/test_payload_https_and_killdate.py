"""HTTPS beacon templates + kill date (C01/C02)."""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app
from squidc5.payloads.generator import PayloadGenerator

ADMIN = "sc5_test_admin_token_bootstrap_https01"


def test_http_beacon_python_defaults_https():
    g = PayloadGenerator()
    out = g.generate("http_beacon_python", "c2.example", 8443)
    assert "https://c2.example:8443" in out["content"]
    assert "CERT_NONE" in out["content"]  # lab insecure TLS


def test_http_beacon_bash_defaults_https():
    g = PayloadGenerator()
    out = g.generate("http_beacon_bash", "c2.example", 8443)
    assert 'C2="https://c2.example:8443' in out["content"]
    assert "curl -s -k " in out["content"] or "curl -s -k-" in out["content"] or "-k " in out["content"]


def test_http_scheme_override():
    g = PayloadGenerator()
    out = g.generate("http_beacon_python", "h", 80, extra={"scheme": "http"})
    assert "http://h:80" in out["content"]
    assert "https://h:80" not in out["content"]


@pytest.mark.asyncio
async def test_kill_date_closes_session(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            past = time.time() - 10
            r = await client.post(
                "/api/v1/implant/beacon",
                json={"hostname": "kd", "kill_date": past},
            )
            assert r.status_code == 200
            sid = r.json()["session_id"]
            r2 = await client.post(
                "/api/v1/implant/beacon",
                json={"session_id": sid, "hostname": "kd", "kill_date": past},
            )
            assert r2.status_code == 403
            sess = await app.state.app_state.sessions.get(sid)
            assert sess is None or sess.get("status") == "closed"
