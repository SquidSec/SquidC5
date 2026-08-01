"""Shared pytest fixtures and auth helpers."""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN_BOOTSTRAP = "sc5_test_admin_token_bootstrap_0001"


@pytest.fixture
async def app(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        port=8443,
        debug=True,
        mcp_enabled=True,  # tests cover MCP allow-lists
        expose_health_details=False,
        security_headers=True,
        public_host="",  # default: Origin null denied
        cors_origins=[],
        admin_token_bootstrap=ADMIN_BOOTSTRAP,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        await application.state.app_state.features.set_many(
            {"mcp_enabled": True}, actor="test"
        )
        yield application


@pytest.fixture
async def app_with_public_host(tmp_path):
    """App that allows Origin: null when public_host is set."""
    settings = Settings(
        data_dir=tmp_path / "data_ph",
        port=8443,
        debug=True,
        mcp_enabled=False,
        expose_health_details=False,
        security_headers=True,
        public_host="c2.example.test",
        cors_origins=[],
        admin_token_bootstrap=ADMIN_BOOTSTRAP,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def client_public_host(app_with_public_host):
    transport = ASGITransport(app=app_with_public_host)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def admin_headers():
    return {"Authorization": f"Bearer {ADMIN_BOOTSTRAP}"}


@pytest.fixture
def admin_token():
    return ADMIN_BOOTSTRAP


async def mint_token(
    client: AsyncClient,
    admin_headers: dict[str, str],
    name: str,
    scopes: list[str],
    mcp_tools: list[str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"name": name, "scopes": scopes}
    if mcp_tools is not None:
        body["mcp_tools"] = mcp_tools
    r = await client.post("/api/v1/tokens", headers=admin_headers, json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["token"].startswith("sc5_")
    return data


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
