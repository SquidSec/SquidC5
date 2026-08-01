"""Bootstrap admin_token.txt permissions (A04)."""

from __future__ import annotations

import stat

import pytest

from squidc5.config import Settings
from squidc5.main import create_app

ADMIN_BOOTSTRAP = "sc5_test_admin_token_bootstrap_perms_01"


@pytest.mark.asyncio
async def test_admin_token_file_mode_0600(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_tok",
        port=8443,
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN_BOOTSTRAP,
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        token_file = settings.data_dir / "admin_token.txt"
        assert token_file.is_file()
        mode = stat.S_IMODE(token_file.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
        assert token_file.read_text(encoding="utf-8").strip() == ADMIN_BOOTSTRAP
