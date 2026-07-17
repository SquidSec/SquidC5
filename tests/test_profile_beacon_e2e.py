"""Profile-aware HTTP beacon end-to-end: activate → generate → check-in."""

from __future__ import annotations

import json

import pytest


@pytest.mark.asyncio
async def test_unwrap_and_match_paths():
    from squidc5.profiles.engine import ProfileEngine
    from squidc5.profiles.models import C2Profile, HttpProfile

    eng = ProfileEngine.__new__(ProfileEngine)
    eng._cache = {}
    eng._active_id = None
    p = C2Profile(
        id="t",
        name="t",
        channel="http",
        http=HttpProfile(
            uris=["/v1/telemetry", "/api/client/events"],
            request_body_template='{"Records":[{beacon}]}',
        ),
        active=True,
    )
    eng._cache[p.id] = p
    eng._active_id = p.id

    kind, prof = eng.match_beacon_path("/v1/telemetry")
    assert kind == "beacon" and prof and prof.id == "t"
    kind, _ = eng.match_beacon_path("/v1/telemetry/result")
    assert kind == "result"
    kind, _ = eng.match_beacon_path("/api/v1/implant/beacon")
    assert kind == "beacon"
    kind, _ = eng.match_beacon_path("/nope")
    assert kind == ""

    wrapped = json.dumps({"Records": [{"session_id": "ses_x", "hostname": "h1"}]})
    data = eng.unwrap_request_body(p, wrapped)
    assert data["session_id"] == "ses_x"
    assert data["hostname"] == "h1"

    flat = eng.unwrap_request_body(p, json.dumps({"hostname": "solo"}))
    assert flat["hostname"] == "solo"

    out = eng.wrap_response(p, {"session_id": "ses_1", "task": None})
    assert "ses_1" in out


@pytest.mark.asyncio
async def test_activate_generate_checkin_amazon(client, admin_headers):
    # activate amazon-cdn blend
    act = await client.post(
        "/api/v1/profiles/prof_amazon_cdn/activate", headers=admin_headers
    )
    assert act.status_code == 200
    assert act.json()["id"] == "prof_amazon_cdn"

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
    content = gen.json()["content"]
    assert gen.json().get("profile_id") == "prof_amazon_cdn"
    # URI from amazon profile
    assert "/v1/telemetry" in content or "/api/client/events" in content or "/cdn/config/refresh" in content
    assert "aws-sdk-python" in content or "User-Agent" in content
    assert "JITTER" in content or "jitter" in content.lower() or "uniform" in content

    # live check-in on a profile URI with wrapped body
    uri = "/v1/telemetry"
    body = {"Records": [{"hostname": "lab-profile-host", "session_id": None}]}
    r = await client.post(uri, content=json.dumps(body), headers={"Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("session_id", "").startswith("ses_")
    assert "task" in data

    # result path
    # create a task first via API
    sid = data["session_id"]
    task = await client.post(
        "/api/v1/tasks",
        headers=admin_headers,
        json={"session_id": sid, "command": "echo profile-ok"},
    )
    assert task.status_code == 200
    tid = task.json()["id"]

    # poll via profile path to get task
    r2 = await client.post(
        uri,
        content=json.dumps({"Records": [{"session_id": sid, "hostname": "lab-profile-host"}]}),
        headers={"Content-Type": "application/json"},
    )
    assert r2.status_code == 200
    polled = r2.json()
    assert polled.get("task") and polled["task"]["id"] == tid

    res = await client.post(
        uri + "/result",
        content=json.dumps({"Records": [{"task_id": tid, "result": "profile-ok\n"}]}),
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 200
    assert res.json().get("status") == "ok"

    done = await client.get(f"/api/v1/tasks/{tid}", headers=admin_headers)
    assert done.json()["status"] == "completed"
    assert "profile-ok" in (done.json().get("result") or "")


@pytest.mark.asyncio
async def test_default_legacy_beacon_still_works(client, admin_headers):
    await client.post("/api/v1/profiles/prof_default_http/activate", headers=admin_headers)
    b = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "legacy-host"},
    )
    assert b.status_code == 200
    assert b.json()["session_id"].startswith("ses_")


@pytest.mark.asyncio
async def test_generate_uses_active_profile_when_unspecified(client, admin_headers):
    await client.post(
        "/api/v1/profiles/prof_ms_graph/activate", headers=admin_headers
    )
    gen = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={
            "template": "http_beacon_python",
            "host": "10.0.0.1",
            "port": 8443,
        },
    )
    assert gen.status_code == 200
    content = gen.json()["content"]
    assert "v1.0" in content or "graph" in content.lower() or "drive" in content or "communications" in content
