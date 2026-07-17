"""Role / scope permission matrix — every sensitive route denied without scope."""

from __future__ import annotations

import pytest

from conftest import bearer, mint_token

# (method, path, body_or_none)
PROTECTED = [
    ("GET", "/api/v1/sessions", None),
    ("GET", "/api/v1/tasks", None),
    ("GET", "/api/v1/listeners", None),
    ("GET", "/api/v1/metrics", None),
    ("GET", "/api/v1/audit", None),
    ("GET", "/api/v1/tokens", None),
    ("GET", "/api/v1/policy", None),
    ("GET", "/api/v1/features", None),
    ("GET", "/api/v1/llm", None),
    ("GET", "/api/v1/ai/status", None),
    ("POST", "/api/v1/tokens", {"name": "x", "scopes": ["sessions:read"]}),
    ("POST", "/api/v1/tasks", {"session_id": "ses_x", "command": "id"}),
    ("POST", "/api/v1/listeners", {"name": "l", "kind": "http", "port": 19991}),
    ("POST", "/api/v1/payloads/generate", {"template": "http_beacon_python", "host": "1.1.1.1", "port": 8443}),
    ("POST", "/api/v1/shell/command", {"session_id": "ses_x", "command": "id"}),
    ("POST", "/api/v1/shell/broadcast", {"command": "id"}),
    ("POST", "/api/v1/ai/run", {"capability": "recon_assist", "user_data": "x"}),
    ("POST", "/api/v1/sessions/reap", {"probe": False}),
    ("PUT", "/api/v1/features", {"features": {"ai_enabled": True}}),
]


@pytest.mark.asyncio
async def test_all_protected_routes_require_auth(client):
    for method, path, body in PROTECTED:
        r = await client.request(method, path, json=body)
        assert r.status_code == 401, f"{method} {path} -> {r.status_code} (expected 401)"


@pytest.mark.asyncio
async def test_invalid_token_rejected(client):
    bad = bearer("sc5_this_token_does_not_exist_00000000000000000000")
    r = await client.get("/api/v1/meta", headers=bad)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_wrong_prefix_token_rejected(client):
    for tok in ("bearer_not_sc5", "ss3_nope", "admin", ""):
        r = await client.get("/api/v1/meta", headers=bearer(tok) if tok else {})
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_x_api_token_header_works(client, admin_headers):
    # extract raw from Authorization
    raw = admin_headers["Authorization"].split(" ", 1)[1]
    r = await client.get("/api/v1/meta", headers={"X-API-Token": raw})
    assert r.status_code == 200
    assert r.json()["actor_type"] == "admin"


@pytest.mark.asyncio
async def test_reader_cannot_write(client, admin_headers):
    t = await mint_token(client, admin_headers, "reader", ["sessions:read", "metrics:read"])
    h = bearer(t["token"])

    assert (await client.get("/api/v1/sessions", headers=h)).status_code == 200
    assert (await client.get("/api/v1/metrics", headers=h)).status_code == 200

    # writes denied
    assert (
        await client.post(
            "/api/v1/tasks",
            headers=h,
            json={"session_id": "ses_x", "command": "id"},
        )
    ).status_code == 403
    assert (
        await client.post(
            "/api/v1/listeners",
            headers=h,
            json={"name": "nope", "kind": "http", "port": 19992},
        )
    ).status_code == 403
    assert (
        await client.post(
            "/api/v1/shell/command",
            headers=h,
            json={"session_id": "ses_x", "command": "id"},
        )
    ).status_code == 403
    assert (await client.get("/api/v1/tokens", headers=h)).status_code == 403
    assert (await client.get("/api/v1/policy", headers=h)).status_code == 403
    assert (await client.get("/api/v1/features", headers=h)).status_code == 403
    assert (await client.get("/api/v1/audit", headers=h)).status_code == 403


@pytest.mark.asyncio
async def test_shell_operator_scope(client, admin_headers):
    t = await mint_token(
        client,
        admin_headers,
        "shell-op",
        ["shell:interact", "sessions:read", "sessions:write"],
    )
    h = bearer(t["token"])
    # can list sessions
    assert (await client.get("/api/v1/sessions", headers=h)).status_code == 200
    # shell command: not a scope denial (missing session / policy / not found OK)
    r = await client.post(
        "/api/v1/shell/command",
        headers=h,
        json={"session_id": "ses_missing", "command": "id"},
    )
    detail = str(r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text)
    assert "Requires one of scopes" not in detail
    assert r.status_code != 401
    # cannot mint tokens
    assert (
        await client.post(
            "/api/v1/tokens",
            headers=h,
            json={"name": "evil", "scopes": ["admin"]},
        )
    ).status_code == 403


@pytest.mark.asyncio
async def test_listener_operator_cannot_payloads(client, admin_headers):
    t = await mint_token(
        client, admin_headers, "lis-op", ["listeners:read", "listeners:write"]
    )
    h = bearer(t["token"])
    assert (await client.get("/api/v1/listeners", headers=h)).status_code == 200
    r = await client.post(
        "/api/v1/payloads/generate",
        headers=h,
        json={"template": "http_beacon_python", "host": "1.2.3.4", "port": 8443},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_ai_user_cannot_manage_llm(client, admin_headers):
    t = await mint_token(client, admin_headers, "ai-user", ["ai:use", "metrics:read"])
    h = bearer(t["token"])
    assert (await client.get("/api/v1/ai/status", headers=h)).status_code == 200
    r = await client.post(
        "/api/v1/llm",
        headers=h,
        json={"name": "x", "model": "m", "provider": "openai", "api_key": "sk-secret"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_meta_returns_only_token_scopes(client, admin_headers):
    t = await mint_token(client, admin_headers, "scoped", ["sessions:read", "metrics:read"])
    h = bearer(t["token"])
    r = await client.get("/api/v1/meta", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert set(body["scopes"]) == {"sessions:read", "metrics:read"}
    assert "admin" not in body["scopes"]
    assert body["actor_type"] == "operator"
    # catalog of all scopes is separate and not confused with grants
    assert "all_scopes" in body
    assert "admin" in body["all_scopes"]


@pytest.mark.asyncio
async def test_admin_meta_has_admin_scope(client, admin_headers):
    r = await client.get("/api/v1/meta", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "admin" in body["scopes"]
    assert body["actor_type"] == "admin"


@pytest.mark.asyncio
async def test_cannot_privilege_escalate_via_token_create(client, admin_headers):
    t = await mint_token(client, admin_headers, "tm", ["tokens:manage"])
    h = bearer(t["token"])
    # tokens:manage can create, but invalid scopes rejected
    r = await client.post(
        "/api/v1/tokens",
        headers=h,
        json={"name": "bad", "scopes": ["not:a:real:scope"]},
    )
    assert r.status_code in (400, 422, 500) or (
        r.status_code == 200 and False
    )  # must not succeed with invalid scope
    # Prefer explicit: ValueError becomes 400/500 depending on handler
    if r.status_code == 200:
        pytest.fail("invalid scope accepted")


@pytest.mark.asyncio
async def test_token_revoke_blocks_use(client, admin_headers):
    t = await mint_token(client, admin_headers, "temp", ["sessions:read"])
    h = bearer(t["token"])
    assert (await client.get("/api/v1/sessions", headers=h)).status_code == 200
    rev = await client.delete(f"/api/v1/tokens/{t['id']}", headers=admin_headers)
    assert rev.status_code == 200
    assert (await client.get("/api/v1/sessions", headers=h)).status_code == 401


@pytest.mark.asyncio
async def test_reader_cannot_load_features_or_mint(client, admin_headers):
    t = await mint_token(client, admin_headers, "r2", ["sessions:read"])
    h = bearer(t["token"])
    # console.js is allowed for any auth
    cons = await client.get("/api/v1/ops/console.js", headers=h)
    assert cons.status_code == 200
    assert "application/javascript" in (cons.headers.get("content-type") or "")
    # but features API still admin
    assert (await client.get("/api/v1/features", headers=h)).status_code == 403
