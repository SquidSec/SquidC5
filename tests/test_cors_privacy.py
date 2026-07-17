"""CORS policy: no wildcard; same-host / explicit only."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_cors_denies_foreign_origin(client, admin_headers):
    r = await client.get(
        "/api/v1/meta",
        headers={**admin_headers, "Origin": "https://evil.example"},
    )
    assert r.status_code == 200
    assert "access-control-allow-origin" not in {k.lower(): v for k, v in r.headers.items()} or (
        r.headers.get("access-control-allow-origin") not in ("*", "https://evil.example")
    )
    # Explicit: foreign origin must not be reflected
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"
    assert r.headers.get("access-control-allow-origin") != "*"


@pytest.mark.asyncio
async def test_cors_allows_same_host_origin(client, admin_headers):
    r = await client.get(
        "/api/v1/meta",
        headers={
            **admin_headers,
            "Origin": "http://test",
            "Host": "test",
        },
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://test"


@pytest.mark.asyncio
async def test_cors_preflight_same_host(client):
    r = await client.options(
        "/api/v1/meta",
        headers={
            "Origin": "http://test",
            "Host": "test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert r.status_code == 204
    assert r.headers.get("access-control-allow-origin") == "http://test"
    allow_h = (r.headers.get("access-control-allow-headers") or "").lower()
    assert "authorization" in allow_h


@pytest.mark.asyncio
async def test_cors_preflight_foreign_no_acao(client):
    r = await client.options(
        "/api/v1/meta",
        headers={
            "Origin": "https://attacker.tld",
            "Host": "test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert r.status_code == 204
    assert r.headers.get("access-control-allow-origin") is None


@pytest.mark.asyncio
async def test_cors_null_origin_denied_without_public_host(client):
    r = await client.options(
        "/api/v1/health",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code == 204
    assert r.headers.get("access-control-allow-origin") is None


@pytest.mark.asyncio
async def test_cors_null_origin_allowed_with_public_host(client_public_host):
    r = await client_public_host.options(
        "/api/v1/health",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code == 204
    assert r.headers.get("access-control-allow-origin") == "null"


@pytest.mark.asyncio
async def test_cors_public_host_origin(client_public_host, admin_headers):
    # bootstrap token is same string; app_with_public_host has its own bootstrap
    r = await client_public_host.get(
        "/api/v1/meta",
        headers={
            **admin_headers,
            "Origin": "https://c2.example.test",
            "Host": "other:8443",
        },
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "https://c2.example.test"
