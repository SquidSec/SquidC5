"""Token auth edge cases and policy boundaries."""

from __future__ import annotations

import pytest

from squidc5.auth.tokens import generate_token, hash_token
from conftest import bearer, mint_token


def test_generate_token_prefix_and_entropy():
    a = generate_token()
    b = generate_token()
    assert a.startswith("sc5_")
    assert b.startswith("sc5_")
    assert a != b
    assert len(a) > 20


def test_hash_token_stable_and_not_raw():
    raw = "sc5_example_token_value_for_hash"
    h1 = hash_token(raw)
    h2 = hash_token(raw)
    assert h1 == h2
    assert h1 != raw
    assert len(h1) == 64  # sha256 hex


@pytest.mark.asyncio
async def test_legacy_ss2_prefix_accepted_if_stored(client, admin_headers, app):
    """Legacy ss2_ tokens still authenticate when present in DB."""
    from squidc5.auth.tokens import hash_token as ht

    state = app.state.app_state
    raw = "ss2_legacy_test_token_aaaaaaaaaaaaaaaaaaaa"
    await state.db.create_token(
        name="legacy",
        token_hash=ht(raw),
        scopes=["sessions:read"],
        mcp_tools=[],
        created_by="test",
    )
    r = await client.get("/api/v1/sessions", headers=bearer(raw))
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_policy_get_requires_scope(client, admin_headers):
    t = await mint_token(client, admin_headers, "no-pol", ["sessions:read"])
    assert (await client.get("/api/v1/policy", headers=bearer(t["token"]))).status_code == 403
    assert (await client.get("/api/v1/policy", headers=admin_headers)).status_code == 200


@pytest.mark.asyncio
async def test_audit_requires_scope(client, admin_headers):
    t = await mint_token(client, admin_headers, "no-aud", ["sessions:read"])
    assert (await client.get("/api/v1/audit", headers=bearer(t["token"]))).status_code == 403
    r = await client.get("/api/v1/audit?limit=5", headers=admin_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_create_token_rejects_unknown_scopes(client, admin_headers):
    r = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={"name": "badscopes", "scopes": ["admin", "superuser:all"]},
    )
    # should not create with invalid scopes
    assert r.status_code in (400, 422, 500)
    if r.status_code == 200:
        pytest.fail("invalid scopes accepted")


@pytest.mark.asyncio
async def test_admin_can_access_all_core_reads(client, admin_headers):
    for path in (
        "/api/v1/meta",
        "/api/v1/sessions",
        "/api/v1/tasks",
        "/api/v1/listeners",
        "/api/v1/metrics",
        "/api/v1/audit",
        "/api/v1/tokens",
        "/api/v1/features",
        "/api/v1/policy",
        "/api/v1/ai/status",
    ):
        r = await client.get(path, headers=admin_headers)
        assert r.status_code == 200, f"{path} -> {r.status_code}"
