import pytest


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
