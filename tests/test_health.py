import pytest
from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_root(client):
    r = await client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert "docs" not in body


@pytest.mark.asyncio
async def test_docs_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        r = await client.get(path)
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    # secure default: no version/app fingerprint
    assert "version" not in body


@pytest.mark.asyncio
async def test_health_deep_requires_auth(client):
    assert (await client.get("/api/v1/health/deep")).status_code == 401


@pytest.mark.asyncio
async def test_health_deep_admin(client, admin_headers):
    r = await client.get("/api/v1/health/deep", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert body["db"]["ok"] is True
    assert body["disk"]["writable"] is True
    assert "listeners" in body
    assert "version" in body
    # no secrets
    blob = r.text.lower()
    assert "api_key" not in blob
    assert "sc5_" not in blob or "sc5_test" not in blob


@pytest.mark.asyncio
async def test_health_deep_metrics_scope(client, admin_headers):
    t = await mint_token(client, admin_headers, "metrics-health", ["metrics:read"])
    r = await client.get("/api/v1/health/deep", headers=bearer(t["token"]))
    assert r.status_code == 200
    assert r.json()["db"]["ok"] is True


@pytest.mark.asyncio
async def test_health_deep_denied_without_scope(client, admin_headers):
    t = await mint_token(client, admin_headers, "no-deep", ["sessions:read"])
    r = await client.get("/api/v1/health/deep", headers=bearer(t["token"]))
    assert r.status_code == 403
