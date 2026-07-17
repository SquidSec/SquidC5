"""Implants, evasion, collab, plugins, observability foundations."""

from __future__ import annotations

import pytest

from squidc5.evasion.checks import anti_analysis_checklist, sleep_obfuscation_plan
from squidc5.implants.registry import ImplantRegistry
from squidc5.observability.timeline import ATTACK_MAP
from squidc5.plugins.registry import PluginRegistry


def test_implant_registry_resolve():
    reg = ImplantRegistry()
    fams = reg.list_families()
    assert any(f["name"] == "http_beacon" for f in fams)
    plan = reg.stager_plan("http_beacon", "linux", "x64", "1.2.3.4", 8443, {"channel": "http"})
    assert plan["callback_host"] == "1.2.3.4"
    assert "stage0_stager" in plan["stages"]
    with pytest.raises(ValueError):
        reg.resolve("http_beacon", "freebsd")


def test_evasion_checklist_platform_specific():
    lin = anti_analysis_checklist("linux")
    win = anti_analysis_checklist("windows")
    assert any(c["id"] == "sleep_jitter" for c in lin)
    assert any(c["id"] == "vm_check" for c in win)
    sleep = sleep_obfuscation_plan(5.0, 30.0)
    assert sleep["base_sec"] == 5.0


def test_plugin_signature_allowlist():
    reg = PluginRegistry(signing_secret=b"test-secret")
    manifest = {
        "name": "lab_recon",
        "version": "1.0.0",
        "capabilities": ["recon.list"],
        "description": "lab only",
    }
    sig = reg.sign_manifest(manifest)
    entry = reg.register(manifest, sig, enable=True)
    assert entry["enabled"] is True
    assert reg.is_allowed("lab_recon", "recon.list")
    assert not reg.is_allowed("lab_recon", "shell.exec")
    with pytest.raises(ValueError):
        reg.register(manifest, "deadbeef" * 8)


def test_attack_map_covers_shell():
    assert "T1059" in ATTACK_MAP["shell.interact"]


@pytest.mark.asyncio
async def test_implants_and_evasion_api(client, admin_headers):
    fams = await client.get("/api/v1/implants/families", headers=admin_headers)
    assert fams.status_code == 200
    assert len(fams.json()["families"]) >= 3

    plan = await client.post(
        "/api/v1/implants/plan",
        headers=admin_headers,
        json={"family": "memory_beacon_python", "platform": "linux", "arch": "x64", "host": "10.0.0.1", "port": 8443},
    )
    assert plan.status_code == 200
    assert plan.json()["memory_only"] is True
    assert plan.json()["profile"]["channel"] in ("http", "dns", "ws")

    ev = await client.get("/api/v1/evasion/checklist?platform=windows", headers=admin_headers)
    assert ev.status_code == 200
    assert ev.json()["checklist"]


@pytest.mark.asyncio
async def test_collab_team_and_handoff(client, admin_headers):
    # create beacon session
    b = await client.post("/api/v1/implant/beacon", json={"hostname": "collab-host"})
    sid = b.json()["session_id"]

    team = await client.post(
        "/api/v1/teams", headers=admin_headers, json={"name": "red-cell-a"}
    )
    assert team.status_code == 200
    assert team.json()["id"].startswith("team_")

    teams = await client.get("/api/v1/teams", headers=admin_headers)
    assert any(t["name"] == "red-cell-a" for t in teams.json())

    ho = await client.post(
        f"/api/v1/sessions/{sid}/handoff",
        headers=admin_headers,
        json={"to": "operator-b", "note": "taking over recon"},
    )
    assert ho.status_code == 200
    assert ho.json()["to"] == "operator-b"

    spec = await client.get(f"/api/v1/sessions/{sid}/spectator", headers=admin_headers)
    assert spec.status_code == 200
    assert spec.json()["mode"] == "spectator"
    assert len(spec.json()["handoffs"]) >= 1


@pytest.mark.asyncio
async def test_plugins_disabled_by_default(client, admin_headers):
    r = await client.get("/api/v1/plugins", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["enabled_feature"] is False

    # enable feature then register signed plugin
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"plugins_enabled": True}},
    )

    # API uses server's secret - bad sig fails
    bad = await client.post(
        "/api/v1/plugins/register",
        headers=admin_headers,
        json={
            "manifest": {"name": "x", "version": "1", "capabilities": []},
            "signature": "00" * 32,
        },
    )
    assert bad.status_code == 400


@pytest.mark.asyncio
async def test_observability_timeline_and_heatmap(client, admin_headers):
    # generate audit via token list
    await client.get("/api/v1/tokens", headers=admin_headers)
    tl = await client.get("/api/v1/observability/timeline?limit=20", headers=admin_headers)
    assert tl.status_code == 200
    events = tl.json()["events"]
    assert isinstance(events, list)
    if events:
        assert "attack" in events[0]

    hm = await client.get("/api/v1/observability/heatmap", headers=admin_headers)
    assert hm.status_code == 200
    assert "active_sessions" in hm.json()
    assert "by_kind" in hm.json()
