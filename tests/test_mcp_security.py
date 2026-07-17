"""MCP external AI restrictions."""

from __future__ import annotations

import pytest

from conftest import bearer, mint_token


@pytest.mark.asyncio
async def test_mcp_requires_connect_scope(client, admin_headers):
    t = await mint_token(client, admin_headers, "no-mcp", ["sessions:read"])
    r = await client.get("/mcp/tools", headers=bearer(t["token"]))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_mcp_allowlist_strict(client, admin_headers):
    t = await mint_token(
        client,
        admin_headers,
        "mcp-strict",
        ["mcp:connect", "sessions:read", "metrics:read"],
        mcp_tools=["list_sessions"],
    )
    h = bearer(t["token"])
    tools = await client.get("/mcp/tools", headers=h)
    assert tools.status_code == 200
    names = {x["name"] for x in tools.json()["tools"]}
    assert names == {"list_sessions"}
    assert "generate_payload" not in names
    assert "interact_shell" not in names

    denied = await client.post(
        "/mcp/call",
        headers=h,
        json={"name": "interact_shell", "arguments": {"command": "id"}},
    )
    assert denied.status_code == 200
    assert denied.json()["ok"] is False

    ok = await client.post(
        "/mcp/call",
        headers=h,
        json={"name": "list_sessions", "arguments": {}},
    )
    assert ok.status_code == 200
    assert ok.json()["ok"] is True


@pytest.mark.asyncio
async def test_mcp_empty_allowlist_gets_nothing_dangerous(client, admin_headers):
    t = await mint_token(
        client,
        admin_headers,
        "mcp-empty",
        ["mcp:connect"],
        mcp_tools=[],
    )
    h = bearer(t["token"])
    tools = await client.get("/mcp/tools", headers=h)
    assert tools.status_code == 200
    # empty allow-list: no tools (or only defaults if server applies DEFAULT — either way no shell)
    names = {x["name"] for x in tools.json().get("tools", [])}
    assert "interact_shell" not in names
    assert "generate_payload" not in names


@pytest.mark.asyncio
async def test_mcp_unauthenticated_401(client):
    assert (await client.get("/mcp/tools")).status_code == 401
