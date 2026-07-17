"""Feature flags: secure defaults, hard-locks, enforcement."""

from __future__ import annotations

import pytest

from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_public_docs_hard_locked_off(client, admin_headers):
    r = await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"public_docs": True}},
    )
    assert r.status_code == 200
    flags = r.json()["features"]
    assert flags["public_docs"] is False
    # still 404
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/openapi.json")).status_code == 404


@pytest.mark.asyncio
async def test_feature_toggle_denies_payloads(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"payloads_generate": False}},
    )
    r = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={"template": "http_beacon_python", "host": "1.1.1.1", "port": 8443},
    )
    assert r.status_code == 403
    # re-enable for isolation
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"payloads_generate": True}},
    )


@pytest.mark.asyncio
async def test_feature_toggle_denies_ai(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"ai_enabled": False}},
    )
    r = await client.post(
        "/api/v1/ai/run",
        headers=admin_headers,
        json={"capability": "recon_assist", "user_data": "test"},
    )
    assert r.status_code == 403
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"ai_enabled": True}},
    )


@pytest.mark.asyncio
async def test_feature_toggle_denies_beacon(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"implant_beacon": False}},
    )
    r = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "x", "username": "y"},
    )
    assert r.status_code == 403
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"implant_beacon": True}},
    )


@pytest.mark.asyncio
async def test_feature_toggle_denies_shell_broadcast(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"shell_broadcast": False}},
    )
    r = await client.post(
        "/api/v1/shell/broadcast",
        headers=admin_headers,
        json={"command": "id"},
    )
    assert r.status_code == 403
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"shell_broadcast": True}},
    )


@pytest.mark.asyncio
async def test_non_admin_cannot_set_features(client, admin_headers):
    t = await mint_token(client, admin_headers, "op", ["sessions:read", "policy:manage"])
    # policy:manage can GET features but PUT requires admin
    h = bearer(t["token"])
    get_r = await client.get("/api/v1/features", headers=h)
    # policy:manage is allowed on GET
    assert get_r.status_code == 200
    put_r = await client.put(
        "/api/v1/features",
        headers=h,
        json={"features": {"ai_enabled": False}},
    )
    assert put_r.status_code == 403


@pytest.mark.asyncio
async def test_mcp_disabled_by_settings_and_flag(client, admin_headers, app):
    # Turn feature flag off
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"mcp_enabled": False}},
    )
    t = await mint_token(
        client,
        admin_headers,
        "mcpbot",
        ["mcp:connect", "sessions:read"],
        mcp_tools=["list_sessions"],
    )
    h = bearer(t["token"])
    r = await client.get("/mcp/tools", headers=h)
    assert r.status_code == 403
    # restore for other tests in same app
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"mcp_enabled": True}},
    )


@pytest.mark.asyncio
async def test_default_features_secure(client, admin_headers):
    r = await client.get("/api/v1/features", headers=admin_headers)
    assert r.status_code == 200
    f = r.json()["features"]
    assert f["public_docs"] is False
    # mcp may be True in test fixture after setup — public_docs always false
    assert f["public_docs"] is False
