"""Coverage for remaining roadmap modules (AI chain, plugins, deploy, implants, collab)."""

from __future__ import annotations

import pytest

from squidc5.ai.anomaly import analyze_beacon_behavior
from squidc5.ai.chain import PLAYBOOKS
from squidc5.deploy.helpers import cert_rotation_plan, nginx_redirector_config
from squidc5.implants.generators import generate_implant
from squidc5.plugins.registry import PluginRegistry


def test_playbooks_defined():
    assert "recon_then_classify" in PLAYBOOKS
    assert all(s["capability"] for steps in PLAYBOOKS.values() for s in steps)


def test_anomaly_heuristics():
    sessions = [
        {"status": "active", "kind": "beacon", "hostname": "a"},
        {"status": "active", "kind": "reverse_shell", "verified": False},
    ]
    out = analyze_beacon_behavior(sessions, {"shell.false_positive": 25})
    codes = {f["code"] for f in out["findings"]}
    assert "unverified_shells" in codes
    assert "noise_listeners" in codes


def test_nginx_redirector_and_cert_plan():
    cfg = nginx_redirector_config(
        server_name="edge.lab",
        beacon_uris=["/v1/telemetry", "/api/v1/implant/beacon"],
    )
    assert "location /v1/telemetry" in cfg
    assert "proxy_pass" in cfg
    plan = cert_rotation_plan(["a.example", "b.example"], days=30)
    assert plan["interval_days"] == 30
    assert len(plan["steps"]) >= 4


def test_memory_implant_generator():
    out = generate_implant("memory_beacon_python", "linux", "x64", "10.0.0.1", 8443, evasion=True)
    assert "10.0.0.1" in out["content"]
    assert "sandbox" in out["content"].lower() or "docker" in out["content"]


def test_plugin_execute_builtin():
    reg = PluginRegistry(signing_secret=b"sec")
    man = {
        "name": "lab_recon",
        "version": "1.0.0",
        "capabilities": ["recon.summary"],
        "description": "lab",
    }
    sig = reg.sign_manifest(man)
    reg.register(man, sig, enable=True)
    result = reg.execute("lab_recon", "recon.summary", {"hostname": "box1"})
    assert result["ok"] is True
    assert result["result"]["hostname"] == "box1"


@pytest.mark.asyncio
async def test_ai_chain_api(client, admin_headers):
    books = await client.get("/api/v1/ai/playbooks", headers=admin_headers)
    assert books.status_code == 200
    assert any(p["id"] == "recon_then_classify" for p in books.json()["playbooks"])

    chained = await client.post(
        "/api/v1/ai/chain",
        headers=admin_headers,
        json={"playbook": "recon_then_classify", "user_data": "windows domain lab"},
    )
    assert chained.status_code == 200
    body = chained.json()
    assert body["mode"] == "chained"
    assert body["steps_run"] >= 1


@pytest.mark.asyncio
async def test_profile_create_api(client, admin_headers):
    r = await client.post(
        "/api/v1/profiles",
        headers=admin_headers,
        json={
            "name": "custom-blend",
            "channel": "http",
            "http": {
                "uris": ["/cdn/x/events"],
                "user_agent": "CustomAgent/1.0",
                "jitter_pct": 15,
            },
        },
    )
    assert r.status_code == 200
    assert r.json()["id"].startswith("prof_")
    assert "/cdn/x/events" in r.json()["http"]["uris"]


@pytest.mark.asyncio
async def test_implant_generate_api(client, admin_headers):
    r = await client.post(
        "/api/v1/implants/generate",
        headers=admin_headers,
        json={
            "family": "memory_beacon_python",
            "platform": "linux",
            "arch": "x64",
            "host": "1.2.3.4",
            "port": 8443,
            "evasion": True,
        },
    )
    assert r.status_code == 200
    assert "1.2.3.4" in r.json()["content"]


@pytest.mark.asyncio
async def test_plugin_persist_and_execute(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"plugins_enabled": True}},
    )
    # use server secret - we need to register with correct signature
    # Call through admin by constructing signature matching server default
    from squidc5.plugins.registry import PluginRegistry

    reg = PluginRegistry()  # same default secret as server
    man = {
        "name": "lab_recon",
        "version": "1.0.0",
        "capabilities": ["recon.summary"],
        "description": "lab",
    }
    sig = reg.sign_manifest(man)
    reg_r = await client.post(
        "/api/v1/plugins/register",
        headers=admin_headers,
        json={"manifest": man, "signature": sig, "enable": True},
    )
    assert reg_r.status_code == 200
    ex = await client.post(
        "/api/v1/plugins/execute",
        headers=admin_headers,
        json={"name": "lab_recon", "capability": "recon.summary", "args": {"hostname": "t"}},
    )
    assert ex.status_code == 200
    assert ex.json()["ok"] is True


@pytest.mark.asyncio
async def test_collab_chat_and_owner(client, admin_headers):
    b = await client.post("/api/v1/implant/beacon", json={"hostname": "chat-host"})
    sid = b.json()["session_id"]
    chat = await client.post(
        "/api/v1/collab/chat",
        headers=admin_headers,
        json={"message": "taking shell handoff"},
    )
    assert chat.status_code == 200
    listed = await client.get("/api/v1/collab/chat", headers=admin_headers)
    assert listed.status_code == 200
    assert any("handoff" in m["message"] for m in listed.json()["messages"])

    own = await client.post(
        f"/api/v1/sessions/{sid}/owner",
        headers=admin_headers,
        json={"owner": "op-alpha"},
    )
    assert own.status_code == 200
    assert own.json()["owner"] == "op-alpha"


@pytest.mark.asyncio
async def test_observability_report_and_anomalies(client, admin_headers):
    an = await client.get("/api/v1/observability/anomalies", headers=admin_headers)
    assert an.status_code == 200
    assert "findings" in an.json()
    rep = await client.get("/api/v1/observability/report", headers=admin_headers)
    assert rep.status_code == 200
    assert "markdown" in rep.json()
    assert "SquidC5" in rep.json()["markdown"]


@pytest.mark.asyncio
async def test_deploy_helpers_api(client, admin_headers):
    redir = await client.post(
        "/api/v1/deploy/redirector",
        headers=admin_headers,
        json={"server_name": "edge.lab", "beacon_uris": ["/v1/telemetry"]},
    )
    assert redir.status_code == 200
    assert "nginx" in redir.json()["format"]
    assert "location /v1/telemetry" in redir.json()["config"]

    cert = await client.post(
        "/api/v1/deploy/cert-plan",
        headers=admin_headers,
        json={"domains": ["a.lab", "b.lab"], "days": 45},
    )
    assert cert.status_code == 200
    assert cert.json()["interval_days"] == 45


@pytest.mark.asyncio
async def test_ai_new_capabilities_offline(client, admin_headers):
    for cap in ("evasion_suggest", "beacon_anomaly"):
        r = await client.post(
            "/api/v1/ai/run",
            headers=admin_headers,
            json={"capability": cap, "user_data": "lab metrics"},
        )
        assert r.status_code == 200
        assert r.json()["mode"] == "offline"
