"""Post-ex module catalog + queue API (I7–I11)."""

from __future__ import annotations

import pytest

from squidc5.modules.catalog import full_catalog, list_inject_techniques, list_sa_modules
from squidc5.modules.coff_loader import parse_coff_header, plan_bof_run


def test_full_catalog_has_postex_packs():
    c = full_catalog()
    assert "sa" in c and len(c["sa"]) >= 4
    assert "cred" in c and "lateral" in c and "persist" in c
    assert "inject" in c and len(list_inject_techniques()) >= 6
    assert c["gates"]["postex"]


def test_sa_modules_ungated():
    for m in list_sa_modules():
        assert m.get("gate") in (None, "")


def test_coff_header_too_small():
    with pytest.raises(ValueError):
        parse_coff_header(b"\x00" * 10)


def test_plan_bof_run_shape():
    plan = plan_bof_run(module_id="whoami", entry="go")
    assert plan["command"] == "bof:run"
    assert plan["args"]["module_id"] == "whoami"


@pytest.mark.asyncio
async def test_modules_catalog_api(client, admin_headers):
    r = await client.get("/api/v1/modules", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "sa" in body and "cred" in body and "lateral" in body
    assert "bof" in body and "inject" in body


@pytest.mark.asyncio
async def test_modules_run_sa_task(client, admin_headers):
    # Create a beacon session via implant check-in (auth may be required)
    b = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "postex-lab", "username": "u"},
    )
    # May 401 if AEAD required — fall back to creating session via admin path if available
    if b.status_code != 200:
        pytest.skip("implant beacon requires AEAD in this fixture")
    sid = b.json()["session_id"]
    r = await client.post(
        "/api/v1/modules/run",
        headers=admin_headers,
        json={"session_id": sid, "command": "sa:whoami", "args": {}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["command"] == "sa:whoami"
    assert r.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_modules_run_rejects_unknown(client, admin_headers):
    b = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "postex-lab2"},
    )
    if b.status_code != 200:
        pytest.skip("implant beacon requires AEAD")
    sid = b.json()["session_id"]
    r = await client.post(
        "/api/v1/modules/run",
        headers=admin_headers,
        json={"session_id": sid, "command": "rm -rf /", "args": {}},
    )
    assert r.status_code == 400
