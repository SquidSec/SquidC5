"""MCP connection payload + JSON-RPC remote endpoint."""

from __future__ import annotations

import pytest
from conftest import bearer, mint_token

from squidc5.mcp.connection import build_mcp_connection, mcp_endpoint, normalize_api_base


def test_normalize_api_base():
    assert normalize_api_base("https://c2.example:8443/") == "https://c2.example:8443"
    assert normalize_api_base("https://c2.example:8443/api/v1") == "https://c2.example:8443"
    assert mcp_endpoint("https://c2.example:8443") == "https://c2.example:8443/mcp"


def test_build_mcp_connection_opencode_shape():
    p = build_mcp_connection(
        api_base="https://c2.example:8443",
        token="sc5_testtokenvalue",
        name="mcp-lab",
        scopes=["mcp:connect", "sessions:read"],
        mcp_tools=["list_sessions"],
        token_id="tok_abc",
    )
    assert p["mcp_url"] == "https://c2.example:8443/mcp"
    assert "sc5_testtokenvalue" in p["copy_text"]
    key = p["server_name"]
    assert key in p["opencode"]["mcp"]
    assert p["opencode"]["mcp"][key]["type"] == "remote"
    assert p["opencode"]["mcp"][key]["url"].endswith("/mcp")
    assert (
        p["opencode"]["mcp"][key]["headers"]["Authorization"]
        == "Bearer sc5_testtokenvalue"
    )
    assert "mcpServers" in p["cursor"]
    assert p["cli"].startswith("sc5 login")


@pytest.mark.asyncio
async def test_mint_mcp_token_includes_connection_payload(client, admin_headers):
    r = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={
            "name": "mcp-ext",
            "scopes": ["mcp:connect", "sessions:read", "metrics:read"],
            "mcp_tools": ["list_sessions", "get_metrics"],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("token", "").startswith("sc5_")
    mcp = body.get("mcp_connection")
    assert isinstance(mcp, dict)
    assert mcp.get("copy_text")
    assert "Bearer " + body["token"] in mcp["copy_text"]
    assert mcp["opencode"]["mcp"]
    assert mcp["formats"]["cursor_json"]


@pytest.mark.asyncio
async def test_mint_non_mcp_has_no_payload(client, admin_headers):
    r = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={"name": "plain", "scopes": ["sessions:read"]},
    )
    assert r.status_code == 200
    assert "mcp_connection" not in r.json() or not r.json().get("mcp_connection")


@pytest.mark.asyncio
async def test_mcp_jsonrpc_initialize_and_tools(client, admin_headers):
    t = await mint_token(
        client,
        admin_headers,
        "mcp-rpc",
        ["mcp:connect", "sessions:read", "metrics:read"],
        mcp_tools=["list_sessions", "get_metrics"],
    )
    h = bearer(t["token"])
    init = await client.post(
        "/mcp",
        headers=h,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init.status_code == 200, init.text
    assert init.json()["result"]["serverInfo"]["name"] == "squidc5"

    tools = await client.post(
        "/mcp",
        headers=h,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert tools.status_code == 200
    names = {x["name"] for x in tools.json()["result"]["tools"]}
    assert names == {"list_sessions", "get_metrics"}

    call = await client.post(
        "/mcp",
        headers=h,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list_sessions", "arguments": {}},
        },
    )
    assert call.status_code == 200
    body = call.json()["result"]
    assert body.get("isError") is False
    assert body["content"][0]["type"] == "text"


@pytest.mark.asyncio
async def test_mcp_jsonrpc_denied_tool(client, admin_headers):
    t = await mint_token(
        client,
        admin_headers,
        "mcp-rpc-deny",
        ["mcp:connect", "sessions:read"],
        mcp_tools=["list_sessions"],
    )
    h = bearer(t["token"])
    call = await client.post(
        "/mcp",
        headers=h,
        json={
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "interact_shell", "arguments": {"session_id": "x", "command": "id"}},
        },
    )
    assert call.status_code == 200
    assert call.json()["result"].get("isError") is True
