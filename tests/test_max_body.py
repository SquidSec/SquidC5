"""Max request body size enforcement (A02)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN_BOOTSTRAP = "sc5_test_admin_token_bootstrap_0001"


@pytest.fixture
async def body_limited_app(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_body",
        port=8443,
        debug=True,
        mcp_enabled=False,
        max_body_bytes=256,
        rate_limit_per_minute=1000,
        admin_token_bootstrap=ADMIN_BOOTSTRAP,
        security_headers=True,
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def body_client(body_limited_app):
    transport = ASGITransport(app=body_limited_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_oversized_body_returns_413(body_client):
    headers = {
        "Authorization": f"Bearer {ADMIN_BOOTSTRAP}",
        "Content-Type": "application/json",
    }
    # well over 256 bytes
    payload = {"name": "x", "scopes": ["sessions:read"], "pad": "A" * 400}
    r = await body_client.post("/api/v1/tokens", headers=headers, json=payload)
    assert r.status_code == 413
    assert "body" in r.json().get("detail", "").lower() or "large" in r.json().get("detail", "").lower()


@pytest.mark.asyncio
async def test_normal_body_still_succeeds(body_client):
    headers = {
        "Authorization": f"Bearer {ADMIN_BOOTSTRAP}",
        "Content-Type": "application/json",
    }
    r = await body_client.post(
        "/api/v1/tokens",
        headers=headers,
        json={"name": "small", "scopes": ["sessions:read"]},
    )
    assert r.status_code == 200
    assert r.json()["token"].startswith("sc5_")


@pytest.mark.asyncio
async def test_get_without_body_unaffected(body_client):
    headers = {"Authorization": f"Bearer {ADMIN_BOOTSTRAP}"}
    r = await body_client.get("/api/v1/sessions", headers=headers)
    assert r.status_code == 200
