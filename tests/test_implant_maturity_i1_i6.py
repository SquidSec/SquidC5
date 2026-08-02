"""Implant maturity I1-I6: factory config blob, stagers, BOF catalog, build API."""

from __future__ import annotations

import base64
import json

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.implants.factory import (
    build_config_blob,
    build_plan,
    generate_stage0_bash,
    generate_stage0_ps1,
)
from squidc5.implants.generators import generate_implant
from squidc5.implants.registry import ImplantRegistry
from squidc5.main import create_app
from squidc5.modules.catalog import list_bof_modules
from squidc5.modules.coff_loader import parse_coff_header

ADMIN = "sc5_test_admin_token_bootstrap_maturi01"


def test_config_blob_roundtrip():
    blob = build_config_blob(
        url="https://c2:8443/api/v1/implant/beacon",
        psk="",
        sleep=7,
        channel="ws",
        sleep_mask="timer",
    )
    assert blob["config"]["channel"] == "ws"
    assert "wss://" in blob["config"]["ws_url"]
    raw = base64.b64decode(blob["config_b64"])
    cfg = json.loads(raw)
    assert cfg["sleep"] == 7
    assert cfg["sleep_mask"] == "timer"


def test_build_plan_has_stagers_and_blob():
    p = build_plan(
        os_name="linux",
        arch="amd64",
        host="c2.lab",
        port=8443,
        channel="http",
        sleep_mask="ekko",
    )
    assert p["config_blob_b64"]
    assert "SC5_CONFIG_B64" in p["run_script"]
    assert "stage0" in p["stager_bash"].lower() or "SC5_STAGE1" in p["stager_bash"]
    assert "SC5_PSK" in p["stager_ps1"]
    assert p["agent_version"] == "3.0.0"


def test_stage0_generators():
    b = generate_stage0_bash(host="h", port=8443, scheme="https")
    assert "SC5_PSK" in b
    ps = generate_stage0_ps1(host="h", port=443, scheme="https")
    assert "sc5beacon" in ps.lower() or "SC5_STAGE1" in ps


def test_bof_catalog_five_modules():
    mods = {m["id"] for m in list_bof_modules()}
    for name in ("whoami", "env", "dir", "net", "screenshot"):
        assert name in mods, name


def test_coff_header():
    import struct

    hdr = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0, 0)
    meta = parse_coff_header(hdr + b"\x00" * 40)
    assert meta["arch"] == "amd64"


def test_registry_native_and_windows_stager():
    r = ImplantRegistry()
    names = {f["name"] for f in r.list_families()}
    assert "native_sc5beacon" in names
    assert "windows_stager" in names
    out = generate_implant("windows_stager", "windows", "x64", "c2", 8443, scheme="https")
    assert "SC5_URL" in out["content"] or "SC5_PSK" in out["content"]


@pytest.mark.asyncio
async def test_api_build_channel_ws(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=2000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.post(
                "/api/v1/implants/build",
                headers=h,
                json={
                    "os": "linux",
                    "arch": "amd64",
                    "host": "c2.example",
                    "port": 8443,
                    "channel": "ws",
                    "sleep_mask": "timer",
                },
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body.get("channel") == "ws"
            assert body.get("config_blob_b64")
            assert "stager_bash" in body
