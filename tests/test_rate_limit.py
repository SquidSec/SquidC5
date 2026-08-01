"""API rate limit enforcement (A01)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN_BOOTSTRAP = "sc5_test_admin_token_bootstrap_0001"


@pytest.fixture
async def limited_app(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_rl",
        port=8443,
        debug=True,
        mcp_enabled=False,
        rate_limit_per_minute=5,
        auth_fail_limit_per_minute=3,
        admin_token_bootstrap=ADMIN_BOOTSTRAP,
        security_headers=True,
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def limited_client(limited_app):
    transport = ASGITransport(app=limited_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_burst_over_limit_returns_429(limited_client):
    headers = {"Authorization": f"Bearer {ADMIN_BOOTSTRAP}"}
    codes = []
    for _ in range(8):
        r = await limited_client.get("/api/v1/sessions", headers=headers)
        codes.append(r.status_code)
    assert 429 in codes
    assert codes.count(200) == 5
    r429 = await limited_client.get("/api/v1/sessions", headers=headers)
    assert r429.status_code == 429
    assert "Retry-After" in r429.headers
    body = r429.json()
    assert body.get("detail") == "Rate limit exceeded"


@pytest.mark.asyncio
async def test_health_exempt_from_rate_limit(limited_client):
    codes = []
    for _ in range(20):
        r = await limited_client.get("/api/v1/health")
        codes.append(r.status_code)
    assert all(c == 200 for c in codes)


@pytest.mark.asyncio
async def test_auth_failures_stricter_limit(limited_client):
    """Invalid tokens trip a stricter per-IP auth-fail bucket."""
    bad = {"Authorization": "Bearer sc5_definitely_invalid_token_xxx"}
    codes = []
    for _ in range(6):
        r = await limited_client.get("/api/v1/sessions", headers=bad)
        codes.append(r.status_code)
    assert 401 in codes
    assert 429 in codes
    # Once auth-fail limited, further bad auth stays 429
    r = await limited_client.get("/api/v1/sessions", headers=bad)
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_root_minimal_banner_not_rate_starved_early(limited_client):
    """A few root hits succeed under limit (still counted toward the cap)."""
    r = await limited_client.get("/")
    assert r.status_code == 200
