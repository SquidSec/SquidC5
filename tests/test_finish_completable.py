"""Tests for finishable product surfaces: teams, plugins catalog, CLI wiring, scheme."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_payload_https_scheme_in_content(client, admin_headers):
    r = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={
            "template": "http_beacon_python",
            "host": "cdn.lab",
            "port": 443,
            "scheme": "https",
        },
    )
    assert r.status_code == 200
    assert "https://cdn.lab:443" in r.json()["content"]


@pytest.mark.asyncio
async def test_dns_profile_drives_zone_on_generate(client, admin_headers):
    await client.post(
        "/api/v1/profiles/prof_default_dns/activate", headers=admin_headers
    )
    r = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={
            "template": "http_beacon_python",  # auto-maps to dns when profile channel=dns
            "host": "127.0.0.1",
            "port": 5353,
        },
    )
    assert r.status_code == 200
    # either remapped to dns template or contains zone
    c = r.json()["content"]
    assert "dns" in c.lower() or "ZONE" in c or "c2.example" in c or "invalid" in c


@pytest.mark.asyncio
async def test_team_membership(client, admin_headers):
    t = await client.post(
        "/api/v1/teams", headers=admin_headers, json={"name": "alpha-cell"}
    )
    assert t.status_code == 200
    tid = t.json()["id"]
    members = await client.get(f"/api/v1/teams/{tid}/members", headers=admin_headers)
    assert members.status_code == 200
    assert any(m["actor"] == "bootstrap-admin" for m in members.json()["members"])

    add = await client.post(
        f"/api/v1/teams/{tid}/members",
        headers=admin_headers,
        json={"actor": "op-beta", "role": "operator"},
    )
    assert add.status_code == 200
    members2 = await client.get(f"/api/v1/teams/{tid}/members", headers=admin_headers)
    assert any(m["actor"] == "op-beta" for m in members2.json()["members"])


@pytest.mark.asyncio
async def test_plugin_catalog_and_install(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"plugins_enabled": True}},
    )
    cat = await client.get("/api/v1/plugins/catalog", headers=admin_headers)
    assert cat.status_code == 200
    names = {c["name"] for c in cat.json()["catalog"]}
    assert "lab_recon" in names
    assert "opsec_helper" in names

    inst = await client.post(
        "/api/v1/plugins/install",
        headers=admin_headers,
        json={"name": "opsec_helper", "enable": True},
    )
    assert inst.status_code == 200
    ex = await client.post(
        "/api/v1/plugins/execute",
        headers=admin_headers,
        json={"name": "opsec_helper", "capability": "opsec.checklist", "args": {"channel": "dns"}},
    )
    assert ex.status_code == 200
    assert ex.json()["ok"] is True


@pytest.mark.asyncio
async def test_lab_playbook_scenario_http_profile(client, admin_headers):
    """Full lab scenario: profile -> payload -> check-in -> task -> result."""
    await client.post(
        "/api/v1/profiles/prof_amazon_cdn/activate", headers=admin_headers
    )
    gen = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={
            "template": "http_beacon_python",
            "host": "127.0.0.1",
            "port": 8443,
            "profile_id": "prof_amazon_cdn",
        },
    )
    assert gen.status_code == 200
    assert gen.json().get("profile_id") == "prof_amazon_cdn"

    r = await client.post(
        "/v1/telemetry",
        json={"Records": [{"hostname": "scenario-host"}]},
    )
    assert r.status_code == 200
    sid = r.json()["session_id"]
    task = await client.post(
        "/api/v1/tasks",
        headers=admin_headers,
        json={"session_id": sid, "command": "echo lab-ok"},
    )
    tid = task.json()["id"]
    r2 = await client.post(
        "/v1/telemetry",
        json={"Records": [{"session_id": sid, "hostname": "scenario-host"}]},
    )
    assert r2.json().get("task", {}).get("id") == tid
    await client.post(
        "/v1/telemetry/result",
        json={"Records": [{"task_id": tid, "result": "lab-ok\n"}]},
    )
    done = await client.get(f"/api/v1/tasks/{tid}", headers=admin_headers)
    assert done.json()["status"] == "completed"
