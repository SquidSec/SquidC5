import pytest


@pytest.mark.asyncio
async def test_mcp_tool_allowlist(client, admin_headers):
    r = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={
            "name": "ai-bot",
            "scopes": ["mcp:connect", "sessions:read", "metrics:read"],
            "mcp_tools": ["list_sessions", "get_metrics"],
        },
    )
    assert r.status_code == 200
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    tools = await client.get("/mcp/tools", headers=h)
    assert tools.status_code == 200
    names = {t["name"] for t in tools.json()["tools"]}
    assert names == {"list_sessions", "get_metrics"}

    denied = await client.post(
        "/mcp/call",
        headers=h,
        json={"name": "generate_payload", "arguments": {}},
    )
    assert denied.status_code == 200
    assert denied.json()["ok"] is False

    allowed = await client.post(
        "/mcp/call",
        headers=h,
        json={"name": "list_sessions", "arguments": {}},
    )
    assert allowed.status_code == 200
    assert allowed.json()["ok"] is True


@pytest.mark.asyncio
async def test_admin_ai_offline(client, admin_headers):
    r = await client.post(
        "/api/v1/ai/run",
        headers=admin_headers,
        json={"capability": "shell_classify", "user_data": "uid=0(root) whoami"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "offline"
    assert body["result"]["category"] in {"recon", "priv", "other", "file", "network"}


@pytest.mark.asyncio
async def test_admin_ai_bad_capability(client, admin_headers):
    r = await client.post(
        "/api/v1/ai/run",
        headers=admin_headers,
        json={"capability": "delete_everything", "user_data": ""},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_mcp_admin_has_oast_tools(client, admin_headers):
    tools = await client.get("/mcp/tools", headers=admin_headers)
    assert tools.status_code == 200
    names = {t["name"] for t in tools.json()["tools"]}
    for required in (
        "oast_mint",
        "oast_list_tokens",
        "oast_get_token",
        "oast_revoke",
        "oast_hits",
        "get_platform_status",
        "get_task",
        "close_session",
        "delete_listener",
        "whoami",
    ):
        assert required in names


@pytest.mark.asyncio
async def test_mcp_oast_mint_hits_revoke(client, admin_headers):
    minted = await client.post(
        "/mcp/call",
        headers=admin_headers,
        json={"name": "oast_mint", "arguments": {"note": "inko-canary"}},
    )
    assert minted.status_code == 200
    body = minted.json()
    assert body["ok"] is True
    token = body["result"]["token"]
    assert token
    assert body["result"]["http_url"]
    assert body["result"]["http_url_path"]
    cid = body["result"]["id"]

    listed = await client.post(
        "/mcp/call",
        headers=admin_headers,
        json={"name": "oast_list_tokens", "arguments": {}},
    )
    assert listed.json()["ok"] is True
    ids = {t["id"] for t in listed.json()["result"]}
    assert cid in ids

    got = await client.post(
        "/mcp/call",
        headers=admin_headers,
        json={"name": "oast_get_token", "arguments": {"token_id": cid}},
    )
    assert got.json()["ok"] is True
    assert got.json()["result"]["token"] == token

    hits = await client.post(
        "/mcp/call",
        headers=admin_headers,
        json={"name": "oast_hits", "arguments": {"token": token}},
    )
    assert hits.json()["ok"] is True
    assert hits.json()["result"]["count"] == 0
    assert hits.json()["result"]["hits"] == []

    revoked = await client.post(
        "/mcp/call",
        headers=admin_headers,
        json={"name": "oast_revoke", "arguments": {"token_id": cid}},
    )
    assert revoked.json()["ok"] is True
    assert revoked.json()["result"]["revoked"] is True

    missing = await client.post(
        "/mcp/call",
        headers=admin_headers,
        json={"name": "oast_get_token", "arguments": {"token_id": cid}},
    )
    assert missing.json()["ok"] is False


@pytest.mark.asyncio
async def test_mcp_oast_tools_not_in_default_allowlist(client, admin_headers):
    r = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={
            "name": "ai-limited",
            "scopes": ["mcp:connect"],
            "mcp_tools": ["list_sessions"],
        },
    )
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    denied = await client.post(
        "/mcp/call",
        headers=h,
        json={"name": "oast_mint", "arguments": {"note": "nope"}},
    )
    assert denied.json()["ok"] is False
    assert "allow-listed" in denied.json()["error"]
