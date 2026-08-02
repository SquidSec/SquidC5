import pytest


@pytest.mark.asyncio
async def test_sessions_clear_unverified(client, admin_headers):
    # Create shell sessions via reverse_shell listener + raw connect that goes quiet
    lr = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "shell-clear-test", "kind": "reverse_shell", "port": 19044},
    )
    assert lr.status_code == 200
    lid = lr.json()["id"]
    st = await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    assert st.status_code == 200

    import asyncio

    # silent connect - creates session until probe drops it
    reader, writer = await asyncio.open_connection("127.0.0.1", 19044)
    await asyncio.sleep(0.6)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    await asyncio.sleep(0.3)
    # clear unverified (and closed leftovers)
    clr = await client.post(
        "/api/v1/sessions/clear",
        headers=admin_headers,
        json={"unverified_only": False, "all_shells": True, "delete": True},
    )
    assert clr.status_code == 200
    assert "removed" in clr.json()

    rows = await client.get(
        "/api/v1/sessions?status=all&kind=reverse_shell,tcp",
        headers=admin_headers,
    )
    shells = [r for r in rows.json() if r.get("kind") in ("reverse_shell", "tcp")]
    # all shells from this test should be gone
    assert not any(r.get("listener_id") == lid for r in shells)

    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


@pytest.mark.asyncio
async def test_sessions_delete_endpoint(client, admin_headers):
    b = await client.post(
        "/api/v1/implant/beacon",
        json={"hostname": "clear-me", "username": "u"},
    )
    sid = b.json()["session_id"]
    d = await client.delete(f"/api/v1/sessions/{sid}", headers=admin_headers)
    assert d.status_code == 200
    g = await client.get(f"/api/v1/sessions/{sid}", headers=admin_headers)
    assert g.status_code == 404
