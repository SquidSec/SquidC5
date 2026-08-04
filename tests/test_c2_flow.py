import socket

import pytest


def _free_tcp_port(host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


@pytest.mark.asyncio
async def test_beacon_task_cycle(client, admin_headers):
    # Implant checks in
    b = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "victim-1", "username": "bob"},
    )
    assert b.status_code == 200
    sid = b.json()["session_id"]
    assert sid.startswith("ses_")

    sessions = await client.get("/api/v1/sessions", headers=admin_headers)
    assert any(s["id"] == sid for s in sessions.json())

    task = await client.post(
        "/api/v1/tasks",
        headers=admin_headers,
        json={"session_id": sid, "command": "whoami"},
    )
    assert task.status_code == 200
    tid = task.json()["id"]

    # Beacon polls and gets task
    b2 = await client.post(
        "/api/v1/implant/beacon",
        json={"session_id": sid, "hostname": "victim-1"},
    )
    assert b2.json()["task"]["id"] == tid
    assert b2.json()["task"]["command"] == "whoami"

    # Implant returns result
    res = await client.post(
        "/api/v1/implant/beacon/result",
        json={"task_id": tid, "result": "bob"},
    )
    assert res.status_code == 200

    done = await client.get(f"/api/v1/tasks/{tid}", headers=admin_headers)
    assert done.json()["status"] == "completed"
    assert done.json()["result"] == "bob"


@pytest.mark.asyncio
async def test_payload_generate(client, admin_headers):
    r = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={"template": "http_beacon_python", "host": "10.0.0.1", "port": 8443},
    )
    assert r.status_code == 200
    assert "10.0.0.1" in r.json()["content"]
    assert r.json()["content_b64"]


@pytest.mark.asyncio
async def test_listener_create(client, admin_headers):
    # Ephemeral port — fixed 9001 collides when 3.11/3.12 CI jobs share a runner host.
    port = _free_tcp_port()
    r = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "http-1", "kind": "http", "host": "127.0.0.1", "port": port},
    )
    assert r.status_code == 200, r.text
    lid = r.json()["id"]
    start = await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    assert start.status_code == 200, start.text
    assert start.json()["status"] == "running"
    stop = await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)
    assert stop.status_code == 200, stop.text
