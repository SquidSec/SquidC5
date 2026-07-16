"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from squidsec2.config import Settings
from squidsec2.main import create_app


@pytest.fixture
async def app(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        port=8443,
        debug=True,
        admin_token_bootstrap="ss2_test_admin_token_bootstrap_0001",
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
def admin_headers():
    return {"Authorization": "Bearer ss2_test_admin_token_bootstrap_0001"}
