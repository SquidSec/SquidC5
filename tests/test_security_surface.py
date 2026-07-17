"""Public surface hardening: docs off, headers, minimal fingerprint."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_root_minimal_banner(client):
    r = await client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body == {"service": "sc5", "status": "ok"} or (
        body.get("status") == "ok" and "docs" not in body and "openapi" not in body
    )
    for leak in ("docs", "redoc", "openapi", "swagger", "token", "admin"):
        assert leak not in body


@pytest.mark.asyncio
async def test_public_docs_always_404(client):
    for path in (
        "/docs",
        "/docs/",
        "/redoc",
        "/redoc/",
        "/openapi.json",
        "/swagger",
        "/api/docs",
    ):
        r = await client.get(path)
        assert r.status_code in (404, 405), f"{path} -> {r.status_code}"


@pytest.mark.asyncio
async def test_health_no_fingerprint_by_default(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body == {"status": "ok"}
    for key in ("version", "app", "host", "port", "debug", "token"):
        assert key not in body


@pytest.mark.asyncio
async def test_security_headers_present(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("x-content-type-options") == "nosniff"
    assert h.get("x-frame-options") == "DENY"
    assert h.get("referrer-policy") == "no-referrer"
    assert "no-store" in (h.get("cache-control") or "")
    csp = h.get("content-security-policy") or ""
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'self'" in csp
    pp = h.get("permissions-policy") or ""
    assert "camera=()" in pp
    assert "microphone=()" in pp


@pytest.mark.asyncio
async def test_ops_html_no_store(client):
    r = await client.get("/ops")
    # dashboard may be present in repo layout
    if r.status_code == 200:
        assert "no-store" in (r.headers.get("cache-control") or "")
        text = r.text
        # public shell must not embed admin token or mint UI
        assert "mintTokBtn" not in text
        assert "sc5_test_admin" not in text
        assert "api_key" not in text.lower() or "placeholder" in text.lower()


@pytest.mark.asyncio
async def test_ops_console_requires_auth(client):
    r = await client.get("/api/v1/ops/console.js")
    assert r.status_code == 401
    r2 = await client.get("/api/v1/ops/admin.js")
    assert r2.status_code == 401
