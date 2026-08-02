"""Server-side HITL approval queue (A10)."""

from __future__ import annotations

import pytest
from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_client_hitl_approved_does_not_bypass(client, admin_headers):
    """Non-admin cannot spoof hitl_approved: true."""
    t = await mint_token(
        client,
        admin_headers,
        "op-hitl",
        ["shell:interact", "sessions:read", "sessions:write"],
    )
    headers = bearer(t["token"])
    # Create a fake reverse_shell session row won't be live; policy runs first
    r = await client.post(
        "/api/v1/shell/command",
        headers=headers,
        json={
            "session_id": "ses_nonexistent",
            "command": "id",
            "hitl_approved": True,
        },
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    if isinstance(detail, dict):
        assert detail.get("require_hitl") is True
        assert detail.get("hitl_request_id")
        rid = detail["hitl_request_id"]
    else:
        # string detail fallback
        assert "Human-in-the-loop" in str(detail)
        lst = await client.get("/api/v1/policy/hitl", headers=admin_headers)
        assert lst.status_code == 200
        reqs = lst.json()["requests"]
        assert reqs
        rid = reqs[0]["id"]

    # Approve as admin
    ap = await client.post(f"/api/v1/policy/hitl/{rid}/approve", headers=admin_headers)
    assert ap.status_code == 200
    assert ap.json()["request"]["status"] == "approved"

    # Wrong command must not reuse approval
    r_wrong = await client.post(
        "/api/v1/shell/command",
        headers=headers,
        json={
            "session_id": "ses_nonexistent",
            "command": "cat /etc/shadow",
            "hitl_request_id": rid,
        },
    )
    assert r_wrong.status_code == 403

    # Same command as original - gets past policy (then 404 no live shell)
    r2 = await client.post(
        "/api/v1/shell/command",
        headers=headers,
        json={
            "session_id": "ses_nonexistent",
            "command": "id",
            "hitl_request_id": rid,
        },
    )
    assert r2.status_code == 404  # policy passed; no live channel


@pytest.mark.asyncio
async def test_admin_bypasses_hitl(client, admin_headers):
    r = await client.post(
        "/api/v1/shell/command",
        headers=admin_headers,
        json={"session_id": "ses_x", "command": "whoami"},
    )
    # admin not blocked by HITL
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_hitl_list_and_deny(client, admin_headers):
    t = await mint_token(
        client, admin_headers, "op-hitl2", ["shell:interact", "sessions:read"]
    )
    r = await client.post(
        "/api/v1/shell/command",
        headers=bearer(t["token"]),
        json={"session_id": "ses_y", "command": "id", "hitl_approved": True},
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    rid = detail["hitl_request_id"] if isinstance(detail, dict) else None
    assert rid
    dn = await client.post(f"/api/v1/policy/hitl/{rid}/deny", headers=admin_headers)
    assert dn.status_code == 200
    # Denied grant cannot be used
    r2 = await client.post(
        "/api/v1/shell/command",
        headers=bearer(t["token"]),
        json={"session_id": "ses_y", "command": "id", "hitl_request_id": rid},
    )
    assert r2.status_code == 403


@pytest.mark.asyncio
async def test_migration_creates_hitl_table(client, app):
    row = await app.state.app_state.db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='hitl_requests'"
    )
    assert row is not None
