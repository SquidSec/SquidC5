"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app


@pytest.fixture
async def app(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        port=8443,
        debug=True,
        mcp_enabled=True,  # tests cover MCP allow-lists
        expose_health_details=False,
        admin_token_bootstrap="sc5_test_admin_token_bootstrap_0001",
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        # Enable MCP feature flag for allow-list tests (default is off)
        await application.state.app_state.features.set_many(
            {"mcp_enabled": True}, actor="test"
        )
        yield application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def admin_headers():
    return {"Authorization": "Bearer sc5_test_admin_token_bootstrap_0001"}
