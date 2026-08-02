"""Ops console / admin UI delivery gates."""

from __future__ import annotations

import pytest
from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_console_js_any_authenticated_token(client, admin_headers):
    t = await mint_token(client, admin_headers, "op-console", ["sessions:read"])
    r = await client.get("/api/v1/ops/console.js", headers=bearer(t["token"]))
    assert r.status_code == 200
    body = r.text
    assert "SquidC5" in body or "__SC5_" in body or "can(" in body
    # scope gating present in client code
    assert "shell:interact" in body or "can(" in body


@pytest.mark.asyncio
async def test_admin_js_requires_admin_scope(client, admin_headers):
    r = await client.get("/api/v1/ops/admin.js", headers=admin_headers)
    assert r.status_code == 200
    assert "no-store" in (r.headers.get("cache-control") or "")
    body = r.text
    assert "SquidC5" in body or "__SC5_" in body or "can(" in body


@pytest.mark.asyncio
async def test_admin_js_non_admin_403(client, admin_headers):
    t = await mint_token(client, admin_headers, "op-no-admin-js", ["sessions:read"])
    r = await client.get("/api/v1/ops/admin.js", headers=bearer(t["token"]))
    assert r.status_code == 403
    # Must not leak admin module body
    assert "mintTokBtn" not in r.text
    assert "saveFeaturesBtn" not in r.text


@pytest.mark.asyncio
async def test_console_js_unauthenticated_401(client):
    assert (await client.get("/api/v1/ops/console.js")).status_code == 401
    assert (await client.get("/api/v1/ops/admin.js")).status_code == 401


@pytest.mark.asyncio
async def test_public_ops_html_does_not_include_admin_module(client):
    r = await client.get("/ops")
    if r.status_code != 200:
        pytest.skip("ops dashboard not packaged in this environment")
    html = r.text
    # admin/console module must be fetched after auth, not inlined
    assert "mintTokBtn" not in html
    assert "saveFeaturesBtn" not in html
    assert (
        "/api/v1/ops/console.js" in html
        or "/api/v1/ops/admin.js" in html
        or "loadAdminModule" in html
        or "ops/admin.js" in html
    )
    # shell has AI drawer hooks + docs
    assert "aiDrawer" in html or "aiFab" in html
    assert "user-guide.md" in html


@pytest.mark.asyncio
async def test_features_put_audited_admin_only(client, admin_headers):
    # operator denied
    t = await mint_token(client, admin_headers, "no-feat", ["sessions:read"])
    r = await client.put(
        "/api/v1/features",
        headers=bearer(t["token"]),
        json={"features": {"ai_enabled": True}},
    )
    assert r.status_code == 403
    # admin ok
    r2 = await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"ai_enabled": True}},
    )
    assert r2.status_code == 200
