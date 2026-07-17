"""Privacy: no secret leakage in API responses or status endpoints."""

from __future__ import annotations

import json
import re

import pytest
from conftest import ADMIN_BOOTSTRAP, bearer, mint_token

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{10,}"),
    re.compile(r"xai-[A-Za-z0-9]{10,}"),
    re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.I),
]


def _assert_no_secrets(obj, path: str = "$") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            # allowed boolean flags
            if kl in ("has_api_key", "api_key_enc"):
                if kl == "api_key_enc":
                    pytest.fail(f"raw api_key_enc leaked at {path}.{k}")
                continue
            if "api_key" in kl or kl in ("password", "secret", "token_hash", "private_key"):
                # values must not look like live secrets
                if isinstance(v, str) and len(v) > 8 and not v.startswith("sc5_"):
                    # token fields in mint response are intentional — skip named checks elsewhere
                    if kl == "token":
                        continue
                    pytest.fail(f"suspicious secret field {path}.{k}={v!r}")
            _assert_no_secrets(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _assert_no_secrets(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        for pat in SECRET_PATTERNS:
            assert not pat.search(obj), f"secret pattern in {path}: {obj[:40]}"


@pytest.mark.asyncio
async def test_ai_status_never_returns_api_keys(client, admin_headers):
    # configure LLM with a fake key
    r = await client.post(
        "/api/v1/llm",
        headers=admin_headers,
        json={
            "name": "test-llm",
            "provider": "xai",
            "model": "grok-test",
            "base_url": "https://api.x.ai/v1",
            "api_key": "xai-SUPER_SECRET_KEY_DO_NOT_LEAK_12345",
        },
    )
    assert r.status_code == 200

    for path in ("/api/v1/ai/status", "/api/v1/ai/status?debug=true", "/api/v1/llm"):
        s = await client.get(path, headers=admin_headers)
        assert s.status_code == 200
        body = s.json()
        raw = json.dumps(body)
        assert "SUPER_SECRET" not in raw
        assert "xai-SUPER" not in raw
        _assert_no_secrets(body)
        if path.startswith("/api/v1/ai/status"):
            llms = body.get("llms") or []
            if llms:
                assert llms[0].get("has_api_key") is True
                assert "api_key" not in llms[0]


@pytest.mark.asyncio
async def test_token_list_does_not_return_raw_secrets(client, admin_headers):
    await mint_token(client, admin_headers, "listed", ["sessions:read"])
    r = await client.get("/api/v1/tokens", headers=admin_headers)
    assert r.status_code == 200
    rows = r.json()
    assert isinstance(rows, list)
    for row in rows:
        assert "token" not in row or not str(row.get("token", "")).startswith("sc5_")
        assert "token_hash" not in row
        raw = json.dumps(row)
        assert ADMIN_BOOTSTRAP not in raw


@pytest.mark.asyncio
async def test_mint_returns_token_once_only_in_create(client, admin_headers):
    t = await mint_token(client, admin_headers, "once", ["metrics:read"])
    assert t["token"].startswith("sc5_")
    # subsequent list must not include raw token
    rows = (await client.get("/api/v1/tokens", headers=admin_headers)).json()
    for row in rows:
        if row.get("id") == t["id"]:
            assert "token" not in row or row.get("token") is None


@pytest.mark.asyncio
async def test_metrics_and_audit_no_tokens(client, admin_headers):
    for path in ("/api/v1/metrics", "/api/v1/audit?limit=20"):
        r = await client.get(path, headers=admin_headers)
        assert r.status_code == 200
        raw = r.text
        assert ADMIN_BOOTSTRAP not in raw
        assert "xai-SUPER" not in raw


@pytest.mark.asyncio
async def test_console_js_no_store_and_no_embedded_secrets(client, admin_headers):
    r = await client.get("/api/v1/ops/console.js", headers=admin_headers)
    assert r.status_code == 200
    assert "no-store" in (r.headers.get("cache-control") or "")
    assert ADMIN_BOOTSTRAP not in r.text
    assert "xai-SUPER" not in r.text
    assert "sk-live" not in r.text


@pytest.mark.asyncio
async def test_operator_cannot_read_admin_token_file_via_api(client, admin_headers):
    t = await mint_token(client, admin_headers, "op", ["sessions:read", "metrics:read", "audit:read"])
    h = bearer(t["token"])
    # no path traversal / data dir endpoints
    for path in (
        "/data/admin_token.txt",
        "/api/v1/admin_token",
        "/admin_token.txt",
        "/../data/admin_token.txt",
    ):
        r = await client.get(path, headers=h)
        assert r.status_code in (404, 401, 405, 403)
