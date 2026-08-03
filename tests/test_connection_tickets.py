"""One-time connection tickets for existing tokens (no secret exposure to admin)."""

from __future__ import annotations

import pytest
from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_connection_link_and_redeem_rolls_secret(client, admin_headers):
    created = await mint_token(
        client, admin_headers, "handoff-op", ["sessions:read", "metrics:read"]
    )
    tid = created["id"]
    old = created["token"]
    old_h = bearer(old)
    assert (await client.get("/api/v1/sessions", headers=old_h)).status_code == 200

    r = await client.post(
        f"/api/v1/tokens/{tid}/connection-link",
        headers=admin_headers,
        json={"ttl_sec": 600, "note": "test"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "url" in body and "sc5ticket=" in body["url"]
    assert "token" not in body  # admin never sees secret
    ticket = body["url"].split("sc5ticket=", 1)[1]

    # Redeem without auth
    red = await client.post("/api/v1/auth/redeem-ticket", json={"ticket": ticket})
    assert red.status_code == 200, red.text
    out = red.json()
    assert out.get("token", "").startswith("sc5_")
    assert out["token"] != old
    assert out.get("rolled") is True

    # Old secret dead; new works
    assert (await client.get("/api/v1/sessions", headers=old_h)).status_code == 401
    assert (await client.get("/api/v1/sessions", headers=bearer(out["token"]))).status_code == 200

    # Ticket single-use
    again = await client.post("/api/v1/auth/redeem-ticket", json={"ticket": ticket})
    assert again.status_code == 400


@pytest.mark.asyncio
async def test_connection_link_rejects_invalid_ticket(client):
    r = await client.post("/api/v1/auth/redeem-ticket", json={"ticket": "sc5t_nope"})
    assert r.status_code in (400, 404)


@pytest.mark.asyncio
async def test_tokens_manage_cannot_link_privileged(client, admin_headers):
    mgr = await mint_token(
        client,
        admin_headers,
        "link-mgr",
        ["tokens:manage", "sessions:read"],
    )
    listed = await client.get("/api/v1/tokens", headers=admin_headers)
    admin_tok = next(
        (t for t in listed.json() if "admin" in (t.get("scopes") or []) and not t.get("revoked")),
        None,
    )
    assert admin_tok
    r = await client.post(
        f"/api/v1/tokens/{admin_tok['id']}/connection-link",
        headers=bearer(mgr["token"]),
        json={},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_connection_link_requires_auth(client, admin_headers):
    created = await mint_token(client, admin_headers, "x", ["sessions:read"])
    r = await client.post(f"/api/v1/tokens/{created['id']}/connection-link", json={})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_connection_link_uses_client_base_url_not_public_host(client, admin_headers, monkeypatch):
    """Ops links use admin-supplied base_url (ops header), not PUBLIC_HOST."""
    created = await mint_token(client, admin_headers, "host-check", ["sessions:read"])
    app = client._transport.app  # type: ignore[attr-defined]
    state = app.state.app_state
    monkeypatch.setattr(state.settings, "public_host", "oast.example.com")

    r = await client.post(
        f"/api/v1/tokens/{created['id']}/connection-link",
        headers=admin_headers,
        json={"base_url": "https://squidc5.example.com:8443"},
    )
    assert r.status_code == 200, r.text
    url = r.json()["url"]
    assert url.startswith("https://squidc5.example.com:8443/ops#sc5ticket=")
    assert "oast.example.com" not in url

    bad = await client.post(
        f"/api/v1/tokens/{created['id']}/connection-link",
        headers=admin_headers,
        json={"base_url": "https://evil.example/phish"},
    )
    assert bad.status_code == 400
