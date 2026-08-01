"""Modules catalog, inject/BOF task queue, COFF header parse."""

from __future__ import annotations

import struct

import pytest
from httpx import ASGITransport, AsyncClient

from squidc5.config import Settings
from squidc5.main import create_app
from squidc5.modules.catalog import list_bof_modules, list_inject_techniques, sleep_mask_catalog
from squidc5.modules.coff_loader import parse_coff_header, plan_bof_run

ADMIN = "sc5_test_admin_token_bootstrap_modinj01"


def test_catalog_lists():
    inj = list_inject_techniques()
    assert any(t["id"] == "create_remote_thread" for t in inj)
    assert sleep_mask_catalog()
    bofs = list_bof_modules()
    assert any(m["id"] == "whoami" for m in bofs)


def test_coff_header_amd64():
    # Minimal IMAGE_FILE_HEADER: Machine=0x8664, 1 section, rest zeros
    hdr = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    meta = parse_coff_header(hdr + b"\x00" * 40)
    assert meta["arch"] == "amd64"
    assert meta["sections"] == 1
    assert meta["valid_header"] is True


def test_plan_bof_run_metadata():
    plan = plan_bof_run(module_id="whoami")
    assert plan["command"] == "bof:run"
    assert plan["args"]["module_id"] == "whoami"
    assert "SC5_ALLOW_BOF" in plan["args"]["requires_env"]


@pytest.mark.asyncio
async def test_modules_api_and_queue(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        implant_require_auth=False,
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            cat = await client.get("/api/v1/modules", headers=h)
            assert cat.status_code == 200, cat.text
            body = cat.json()
            assert "inject" in body and "bof" in body and "sleep_mask" in body

            b = await client.post("/api/v1/implant/beacon", json={"hostname": "mod-host"})
            assert b.status_code == 200
            sid = b.json()["session_id"]

            inj = await client.post(
                "/api/v1/modules/inject",
                headers=h,
                json={"session_id": sid, "technique": "create_remote_thread", "pid": 1},
            )
            assert inj.status_code == 200, inj.text
            assert inj.json()["command"].startswith("inject:")

            bof = await client.post(
                "/api/v1/modules/bof/run",
                headers=h,
                json={"session_id": sid, "module_id": "whoami"},
            )
            assert bof.status_code == 200, bof.text
            assert bof.json()["command"] == "bof:run"

            bad = await client.post(
                "/api/v1/modules/bof/run",
                headers=h,
                json={"session_id": sid, "module_id": "../etc/passwd"},
            )
            assert bad.status_code == 400


@pytest.mark.asyncio
async def test_ops_admin_has_new_panels(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "d2",
        debug=True,
        mcp_enabled=False,
        admin_token_bootstrap=ADMIN,
        plugin_signing_secret="test-plugin-signing-secret-for-ci",
        rate_limit_per_minute=1000,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": f"Bearer {ADMIN}"}
            r = await client.get("/api/v1/ops/admin.js", headers=h)
            assert r.status_code == 200
            js = r.text
            for marker in (
                "filesPanel",
                "socksPanel",
                "modulesPanel",
                "hitlPanel",
                "engagementPanel",
                "/api/v1/modules",
            ):
                assert marker in js, marker
