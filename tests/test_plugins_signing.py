"""Plugin signing secret resolution (A05)."""

from __future__ import annotations

import pytest

from squidc5.config import Settings
from squidc5.main import create_app
from squidc5.plugins.registry import (
    LEGACY_DEV_PLUGIN_SECRET,
    PLUGIN_SECRET_FILENAME,
    PluginRegistry,
    resolve_plugin_signing_secret,
)


def test_resolve_explicit_secret(tmp_path):
    s = resolve_plugin_signing_secret(
        explicit="my-explicit-secret",
        data_dir=tmp_path,
        debug=False,
    )
    assert s == b"my-explicit-secret"


def test_resolve_generates_file_mode(tmp_path):
    s = resolve_plugin_signing_secret(explicit=None, data_dir=tmp_path, debug=False)
    path = tmp_path / PLUGIN_SECRET_FILENAME
    assert path.is_file()
    assert path.read_bytes().strip() == s
    assert path.stat().st_mode & 0o777 == 0o600
    # second resolve reads same
    s2 = resolve_plugin_signing_secret(explicit=None, data_dir=tmp_path, debug=False)
    assert s2 == s


def test_refuse_legacy_default_outside_debug(tmp_path):
    with pytest.raises(RuntimeError, match="legacy default"):
        resolve_plugin_signing_secret(
            explicit=LEGACY_DEV_PLUGIN_SECRET.decode(),
            data_dir=tmp_path,
            debug=False,
        )


def test_legacy_default_allowed_in_debug(tmp_path):
    s = resolve_plugin_signing_secret(
        explicit=LEGACY_DEV_PLUGIN_SECRET.decode(),
        data_dir=tmp_path,
        debug=True,
    )
    assert s == LEGACY_DEV_PLUGIN_SECRET


def test_sign_verify_roundtrip():
    reg = PluginRegistry(signing_secret=b"unit-test-secret")
    man = {"name": "x", "version": "1", "capabilities": []}
    sig = reg.sign_manifest(man)
    assert reg.verify(man, sig)
    assert not reg.verify(man, "00" * 32)


@pytest.mark.asyncio
async def test_app_boots_with_generated_secret(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data_plug",
        debug=False,
        mcp_enabled=False,
        admin_token_bootstrap="sc5_test_admin_token_bootstrap_plug1",
        plugin_signing_secret=None,
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        secret_path = settings.data_dir / PLUGIN_SECRET_FILENAME
        assert secret_path.is_file()
        assert application.state.app_state.plugins._signing_secret == secret_path.read_bytes().strip()
