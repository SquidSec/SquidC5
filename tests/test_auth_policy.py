import pytest


@pytest.mark.asyncio
async def test_admin_meta(client, admin_headers):
    r = await client.get("/api/v1/meta", headers=admin_headers)
    assert r.status_code == 200
    assert "admin" in r.json()["scopes"] or r.json()["actor_type"] == "admin"


@pytest.mark.asyncio
async def test_unauthorized(client):
    r = await client.get("/api/v1/sessions")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_scoped_token(client, admin_headers):
    r = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={
            "name": "reader",
            "scopes": ["sessions:read", "metrics:read"],
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["token"].startswith("ss2_")
    # reader cannot create tokens
    r2 = await client.post(
        "/api/v1/tokens",
        headers={"Authorization": f"Bearer {data['token']}"},
        json={"name": "x", "scopes": ["admin"]},
    )
    assert r2.status_code == 403


@pytest.mark.asyncio
async def test_policy_get(client, admin_headers):
    r = await client.get("/api/v1/policy", headers=admin_headers)
    assert r.status_code == 200
    assert "external_ai" in r.json()
