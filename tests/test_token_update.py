"""PATCH /api/v1/tokens/{id} - update scopes without rotating secret."""

from __future__ import annotations

import pytest
from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_meta_includes_scope_presets(client, admin_headers):
    r = await client.get("/api/v1/meta", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "scope_catalog" in body
    assert "scope_presets" in body
    ids = {p["id"] for p in body["scope_presets"]}
    assert "operator" in ids
    assert "read_only" in ids
    assert "full_admin" in ids
    assert any(s["id"] == "sessions:read" and s.get("description") for s in body["scope_catalog"])


@pytest.mark.asyncio
async def test_patch_token_scopes_preserves_auth(client, admin_headers):
    created = await mint_token(
        client, admin_headers, "patch-me", ["sessions:read", "metrics:read"]
    )
    tid = created["id"]
    raw = created["token"]
    h = bearer(raw)

    # works with original scopes
    assert (await client.get("/api/v1/sessions", headers=h)).status_code == 200
    assert (await client.get("/api/v1/listeners", headers=h)).status_code == 403

    r = await client.patch(
        f"/api/v1/tokens/{tid}",
        headers=admin_headers,
        json={"scopes": ["sessions:read", "listeners:read", "metrics:read"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["scopes"]) == {"sessions:read", "listeners:read", "metrics:read"}
    assert "token" not in body  # secret not re-issued

    # same raw secret still authenticates with new scopes
    assert (await client.get("/api/v1/listeners", headers=h)).status_code == 200
    meta = await client.get("/api/v1/meta", headers=h)
    assert meta.status_code == 200
    assert "listeners:read" in meta.json()["scopes"]


@pytest.mark.asyncio
async def test_patch_token_name(client, admin_headers):
    created = await mint_token(client, admin_headers, "old-name", ["sessions:read"])
    tid = created["id"]
    r = await client.patch(
        f"/api/v1/tokens/{tid}",
        headers=admin_headers,
        json={"name": "new-name"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "new-name"


@pytest.mark.asyncio
async def test_tokens_manage_cannot_grant_admin_via_patch(client, admin_headers):
    mgr = await mint_token(
        client,
        admin_headers,
        "tok-mgr",
        ["tokens:manage", "sessions:read", "metrics:read"],
    )
    target = await mint_token(client, admin_headers, "target", ["sessions:read"])
    mh = bearer(mgr["token"])
    r = await client.patch(
        f"/api/v1/tokens/{target['id']}",
        headers=mh,
        json={"scopes": ["admin"]},
    )
    assert r.status_code == 400
    assert "admin" in r.text.lower() or "privileged" in r.text.lower()


@pytest.mark.asyncio
async def test_tokens_manage_cannot_grant_missing_scope(client, admin_headers):
    mgr = await mint_token(
        client,
        admin_headers,
        "tok-mgr2",
        ["tokens:manage", "sessions:read"],
    )
    target = await mint_token(client, admin_headers, "target2", ["sessions:read"])
    mh = bearer(mgr["token"])
    r = await client.patch(
        f"/api/v1/tokens/{target['id']}",
        headers=mh,
        json={"scopes": ["sessions:read", "shell:interact"]},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_patch_revoked_token_404(client, admin_headers):
    created = await mint_token(client, admin_headers, "gone", ["sessions:read"])
    tid = created["id"]
    assert (await client.delete(f"/api/v1/tokens/{tid}", headers=admin_headers)).status_code == 200
    r = await client.patch(
        f"/api/v1/tokens/{tid}",
        headers=admin_headers,
        json={"scopes": ["metrics:read"]},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_patch_empty_body_400(client, admin_headers):
    created = await mint_token(client, admin_headers, "empty", ["sessions:read"])
    r = await client.patch(
        f"/api/v1/tokens/{created['id']}",
        headers=admin_headers,
        json={},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_tokens_manage_cannot_modify_privileged_token(client, admin_headers):
    """tokens:manage must not demote/edit tokens that already hold admin/etc."""
    mgr = await mint_token(
        client,
        admin_headers,
        "tok-mgr3",
        ["tokens:manage", "sessions:read", "metrics:read"],
    )
    # Find bootstrap/admin token id via list
    listed = await client.get("/api/v1/tokens", headers=admin_headers)
    assert listed.status_code == 200
    admin_tok = next(
        (t for t in listed.json() if "admin" in (t.get("scopes") or []) and not t.get("revoked")),
        None,
    )
    assert admin_tok is not None
    mh = bearer(mgr["token"])
    r = await client.patch(
        f"/api/v1/tokens/{admin_tok['id']}",
        headers=mh,
        json={"scopes": ["sessions:read"]},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_roll_token_rotates_secret(client, admin_headers):
    created = await mint_token(
        client, admin_headers, "roll-me", ["sessions:read", "metrics:read"]
    )
    tid = created["id"]
    old = created["token"]
    old_h = bearer(old)
    assert (await client.get("/api/v1/sessions", headers=old_h)).status_code == 200

    r = await client.post(f"/api/v1/tokens/{tid}/roll", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("rolled") is True
    assert body.get("token") and body["token"] != old
    assert body["token"].startswith("sc5_")

    # old secret dead
    assert (await client.get("/api/v1/sessions", headers=old_h)).status_code == 401
    # new secret works
    new_h = bearer(body["token"])
    assert (await client.get("/api/v1/sessions", headers=new_h)).status_code == 200


@pytest.mark.asyncio
async def test_tokens_manage_cannot_roll_privileged(client, admin_headers):
    mgr = await mint_token(
        client,
        admin_headers,
        "tok-mgr-roll",
        ["tokens:manage", "sessions:read"],
    )
    listed = await client.get("/api/v1/tokens", headers=admin_headers)
    admin_tok = next(
        (t for t in listed.json() if "admin" in (t.get("scopes") or []) and not t.get("revoked")),
        None,
    )
    assert admin_tok
    r = await client.post(
        f"/api/v1/tokens/{admin_tok['id']}/roll",
        headers=bearer(mgr["token"]),
    )
    assert r.status_code == 403


def test_presets_never_grant_admin_except_full_admin():
    from squidc5.auth.tokens import PRIVILEGED_SCOPES, scope_catalog

    cat = scope_catalog()
    assert "admin" not in cat["non_admin_scopes"]
    for p in cat["presets"]:
        if p["id"] == "full_admin":
            assert p["scopes"] == ["admin"]
            continue
        if p["id"] == "token_admin":
            assert "tokens:manage" in p["scopes"]
            assert "admin" not in p["scopes"]
            continue
        overlap = set(p["scopes"]) & PRIVILEGED_SCOPES
        assert not overlap, f"{p['id']} has privileged {overlap}"
    fo = next(x for x in cat["presets"] if x["id"] == "full_operator")
    assert "shell:interact" in fo["scopes"] and "ai:use" in fo["scopes"]
    roa = next(x for x in cat["presets"] if x["id"] == "read_only_ai")
    assert "ai:use" in roa["scopes"]
    assert "tasks:write" not in roa["scopes"]
