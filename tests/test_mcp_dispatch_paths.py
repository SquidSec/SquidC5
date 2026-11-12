"""MCP dispatch: allow-list, scope gates, policy denial, JSON-RPC envelope."""

from __future__ import annotations

import pytest
from conftest import bearer, mint_token

from squidc5.mcp import server as mcp_server


@pytest.fixture(autouse=True)
def _clear_budget():
    mcp_server._MCP_BUDGET.clear()
    yield
    mcp_server._MCP_BUDGET.clear()


async def _mcp_token(client, admin_headers, name, scopes, tools):
    return await mint_token(
        client,
        admin_headers,
        name,
        ["mcp:connect", *scopes],
        mcp_tools=tools,
    )


@pytest.mark.asyncio
async def test_unknown_tool_is_rejected(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-unknown", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "definitely_not_a_tool", "arguments": {}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "allow-listed" in body["error"] or "Unknown tool" in body["error"]


@pytest.mark.asyncio
async def test_tool_outside_allowlist_is_denied_and_audited(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-deny", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "get_metrics", "arguments": {}},
    )
    assert r.json()["ok"] is False
    audit = await client.get("/api/v1/audit?limit=50", headers=admin_headers)
    actions = [row["action"] for row in audit.json()]
    assert "mcp.call.denied" in actions


@pytest.mark.asyncio
async def test_missing_scope_for_allowlisted_tool(client, admin_headers):
    # Allow-listed but the token lacks tasks:write.
    t = await _mcp_token(client, admin_headers, "mcp-noscope", ["sessions:read"], ["create_task"])
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "create_task", "arguments": {"session_id": "ses_x", "command": "id"}},
    )
    body = r.json()
    assert body["ok"] is False
    assert "Requires one of scopes" in body["error"]


@pytest.mark.asyncio
async def test_policy_denial_blocks_tool(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-policy",
        ["sessions:read", "sessions:write"],
        ["close_session"],
    )
    policy = await client.get("/api/v1/policy", headers=admin_headers)
    rules = policy.json()
    rules["deny_actions"] = ["sessions.close"]
    put = await client.put("/api/v1/policy", headers=admin_headers, json={"rules": rules})
    assert put.status_code == 200

    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "close_session", "arguments": {"session_id": "ses_x"}},
    )
    body = r.json()
    assert body["ok"] is False
    assert "denied" in body["error"].lower() or "policy" in body["error"].lower()


@pytest.mark.asyncio
async def test_get_session_not_found_returns_tool_error(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-missing", ["sessions:read"], ["get_session"])
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "get_session", "arguments": {"session_id": "ses_missing"}},
    )
    body = r.json()
    assert body["ok"] is False
    assert body["error"] == "tool error"


@pytest.mark.asyncio
async def test_get_task_not_found_returns_tool_error(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-task-missing", ["tasks:read"], ["get_task"])
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "get_task", "arguments": {"task_id": "tsk_missing"}},
    )
    assert r.json()["ok"] is False


@pytest.mark.asyncio
async def test_create_listener_respects_feature_flag(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-listener",
        ["listeners:write"],
        ["create_listener"],
    )
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"http_listeners": False}},
    )
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={
            "name": "create_listener",
            "arguments": {"name": "blocked", "kind": "http", "port": 19999},
        },
    )
    body = r.json()
    assert body["ok"] is False
    assert "disabled" in body["error"].lower()


@pytest.mark.asyncio
async def test_interact_shell_requires_hitl_by_default(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-shell-hitl",
        ["shell:interact", "sessions:read"],
        ["interact_shell"],
    )
    sid = await client.post("/api/v1/implant/beacon", json={"hostname": "mcp-hitl-host"})
    session_id = sid.json()["session_id"]
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "interact_shell", "arguments": {"session_id": session_id, "command": "id"}},
    )
    body = r.json()
    assert body["ok"] is False
    assert "Human-in-the-loop" in body["error"]


@pytest.mark.asyncio
async def test_interact_shell_without_live_channel(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-shell",
        ["shell:interact", "sessions:read"],
        ["interact_shell"],
    )
    # Drop the HITL requirement so the handler's own guard is reached. HITL also
    # fires on risk score (shell.interact is 8), so raise the threshold too.
    rules = (await client.get("/api/v1/policy", headers=admin_headers)).json()
    rules["require_hitl"] = [a for a in rules.get("require_hitl", []) if a != "shell.interactive"]
    rules.setdefault("risk_thresholds", {})["hitl_min"] = 99
    await client.put("/api/v1/policy", headers=admin_headers, json={"rules": rules})

    sid = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "mcp-shell-host"},
    )
    session_id = sid.json()["session_id"]
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "interact_shell", "arguments": {"session_id": session_id, "command": "id"}},
    )
    body = r.json()
    assert body["ok"] is False
    # The handler raises RuntimeError for a missing channel; dispatch maps any
    # unexpected handler exception to a generic error so internals do not leak.
    assert body["error"] == "tool error"


@pytest.mark.asyncio
async def test_rate_budget_exhausted(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-budget", ["sessions:read"], ["list_sessions"])
    h = bearer(t["token"])
    limit = mcp_server._MCP_MAX_PER_MIN
    for _ in range(limit):
        r = await client.post("/mcp/call", headers=h, json={"name": "list_sessions", "arguments": {}})
        assert r.json()["ok"] is True
    over = await client.post("/mcp/call", headers=h, json={"name": "list_sessions", "arguments": {}})
    body = over.json()
    assert body["ok"] is False
    assert "budget" in body["error"].lower()


@pytest.mark.asyncio
async def test_jsonrpc_initialize(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-init", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    body = r.json()
    assert body["result"]["serverInfo"]["name"] == "squidc5"
    assert body["result"]["protocolVersion"]


@pytest.mark.asyncio
async def test_jsonrpc_ping(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-ping", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    assert r.json()["result"] == {}


@pytest.mark.asyncio
async def test_jsonrpc_notification_returns_empty(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-notif", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert r.status_code == 200
    assert r.json() == {}


@pytest.mark.asyncio
async def test_jsonrpc_unknown_method(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-method", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/nope"},
    )
    assert r.json()["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_jsonrpc_tools_list_respects_allowlist(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-list", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
    )
    names = {x["name"] for x in r.json()["result"]["tools"]}
    assert names == {"list_sessions"}


@pytest.mark.asyncio
async def test_jsonrpc_tools_call_success(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-call-ok", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "list_sessions", "arguments": {}},
        },
    )
    result = r.json()["result"]
    assert result["isError"] is False
    assert result["content"][0]["type"] == "text"


@pytest.mark.asyncio
async def test_jsonrpc_tools_call_error_is_content(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-call-err", ["sessions:read"], ["get_session"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "get_session", "arguments": {"session_id": "ses_missing"}},
        },
    )
    result = r.json()["result"]
    assert result["isError"] is True


@pytest.mark.asyncio
async def test_jsonrpc_batch_mixed_messages(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-batch", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers=bearer(t["token"]),
        json=[
            {"jsonrpc": "2.0", "id": 7, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 8, "method": "tools/list"},
        ],
    )
    body = r.json()
    assert isinstance(body, list)
    ids = [item.get("id") for item in body]
    assert 7 in ids and 8 in ids
    assert None not in ids


@pytest.mark.asyncio
async def test_jsonrpc_invalid_body_type(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-badbody", ["sessions:read"], ["list_sessions"])
    r = await client.post("/mcp", headers=bearer(t["token"]), json="not-an-object")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_jsonrpc_invalid_json(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-badjson", ["sessions:read"], ["list_sessions"])
    r = await client.post(
        "/mcp",
        headers={**bearer(t["token"]), "Content-Type": "application/json"},
        content=b"{not json",
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_mcp_health_hides_when_disabled(client):
    r = await client.get("/mcp/health")
    assert r.status_code in (401, 404)


@pytest.mark.asyncio
async def test_mcp_disabled_by_feature_flag(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-off", ["sessions:read"], ["list_sessions"])
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"mcp_enabled": False}},
    )
    r = await client.get("/mcp/tools", headers=bearer(t["token"]))
    assert r.status_code == 403
    assert "feature flag" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Happy-path sweep: every allow-listed tool must dispatch to its handler.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_read_tools_dispatch(client, admin_headers):
    tools = [
        "list_sessions",
        "list_tasks",
        "list_listeners",
        "list_payload_templates",
        "get_metrics",
        "list_audit",
        "whoami",
        "get_platform_status",
    ]
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-read-sweep",
        ["sessions:read", "tasks:read", "listeners:read", "payloads:generate", "metrics:read", "audit:read"],
        tools,
    )
    h = bearer(t["token"])
    for name in tools:
        r = await client.post("/mcp/call", headers=h, json={"name": name, "arguments": {}})
        body = r.json()
        assert body["ok"] is True, f"{name}: {body.get('error')}"


@pytest.mark.asyncio
async def test_listener_lifecycle_tools(client, admin_headers):
    from support import free_port

    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-listener-sweep",
        ["listeners:write", "listeners:read"],
        ["create_listener", "start_listener", "stop_listener", "delete_listener"],
    )
    h = bearer(t["token"])
    port = free_port()
    created = await client.post(
        "/mcp/call",
        headers=h,
        json={
            "name": "create_listener",
            "arguments": {"name": "mcp-l", "kind": "http", "port": port, "host": "127.0.0.1"},
        },
    )
    assert created.json()["ok"] is True, created.json()
    lid = created.json()["result"]["id"]

    started = await client.post(
        "/mcp/call", headers=h, json={"name": "start_listener", "arguments": {"listener_id": lid}}
    )
    assert started.json()["ok"] is True
    assert started.json()["result"]["status"] == "running"

    stopped = await client.post(
        "/mcp/call", headers=h, json={"name": "stop_listener", "arguments": {"listener_id": lid}}
    )
    assert stopped.json()["ok"] is True

    deleted = await client.post(
        "/mcp/call", headers=h, json={"name": "delete_listener", "arguments": {"listener_id": lid}}
    )
    assert deleted.json()["ok"] is True
    assert deleted.json()["result"]["deleted"] is True


@pytest.mark.asyncio
async def test_delete_missing_listener_errors(client, admin_headers):
    t = await _mcp_token(
        client, admin_headers, "mcp-del-missing", ["listeners:write"], ["delete_listener"]
    )
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "delete_listener", "arguments": {"listener_id": "lis_missing"}},
    )
    assert r.json()["ok"] is False


@pytest.mark.asyncio
async def test_payload_generate_and_task_tools(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-payload-sweep",
        ["payloads:generate", "tasks:write", "tasks:read", "sessions:read"],
        ["generate_payload", "create_task", "list_tasks", "get_task"],
    )
    h = bearer(t["token"])
    gen = await client.post(
        "/mcp/call",
        headers=h,
        json={
            "name": "generate_payload",
            "arguments": {"template": "http_beacon_python", "host": "10.0.0.5", "port": 8443},
        },
    )
    assert gen.json()["ok"] is True
    assert "10.0.0.5" in gen.json()["result"]["content"]

    beacon = await client.post("/api/v1/implant/beacon", json={"hostname": "mcp-task-host"})
    sid = beacon.json()["session_id"]
    created = await client.post(
        "/mcp/call",
        headers=h,
        json={"name": "create_task", "arguments": {"session_id": sid, "command": "id"}},
    )
    assert created.json()["ok"] is True
    tid = created.json()["result"]["id"]

    got = await client.post(
        "/mcp/call", headers=h, json={"name": "get_task", "arguments": {"task_id": tid}}
    )
    assert got.json()["ok"] is True
    assert got.json()["result"]["id"] == tid


@pytest.mark.asyncio
async def test_oast_tools_dispatch(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-oast-sweep",
        ["oast:write", "oast:read"],
        ["oast_mint", "oast_list_tokens", "oast_get_token", "oast_hits", "oast_revoke"],
    )
    h = bearer(t["token"])
    minted = await client.post(
        "/mcp/call", headers=h, json={"name": "oast_mint", "arguments": {"note": "mcp"}}
    )
    assert minted.json()["ok"] is True
    token_id = minted.json()["result"]["id"]

    listed = await client.post("/mcp/call", headers=h, json={"name": "oast_list_tokens", "arguments": {}})
    assert listed.json()["ok"] is True

    got = await client.post(
        "/mcp/call", headers=h, json={"name": "oast_get_token", "arguments": {"token_id": token_id}}
    )
    assert got.json()["ok"] is True

    hits = await client.post(
        "/mcp/call", headers=h, json={"name": "oast_hits", "arguments": {"client_id": token_id}}
    )
    assert hits.json()["ok"] is True
    assert hits.json()["result"]["count"] == 0

    revoked = await client.post(
        "/mcp/call", headers=h, json={"name": "oast_revoke", "arguments": {"token_id": token_id}}
    )
    assert revoked.json()["ok"] is True


@pytest.mark.asyncio
async def test_oast_hits_requires_scope_for_non_admin(client, admin_headers):
    t = await _mcp_token(client, admin_headers, "mcp-oast-narrow", ["oast:read"], ["oast_hits"])
    r = await client.post(
        "/mcp/call", headers=bearer(t["token"]), json={"name": "oast_hits", "arguments": {}}
    )
    assert r.json()["ok"] is False


@pytest.mark.asyncio
async def test_close_session_tool(client, admin_headers):
    t = await _mcp_token(
        client,
        admin_headers,
        "mcp-close",
        ["sessions:write", "sessions:read"],
        ["close_session"],
    )
    beacon = await client.post("/api/v1/implant/beacon", json={"hostname": "mcp-close-host"})
    sid = beacon.json()["session_id"]
    r = await client.post(
        "/mcp/call",
        headers=bearer(t["token"]),
        json={"name": "close_session", "arguments": {"session_id": sid}},
    )
    assert r.json()["ok"] is True
    assert r.json()["result"]["closed"] is True
