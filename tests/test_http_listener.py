import pytest

from squidc5.listeners.http_listener import _json_body


def test_json_body():
    assert _json_body(b'{"a":1}') == {"a": 1}
    assert _json_body(b"") == {}
    assert _json_body(b"not-json") == {}


@pytest.mark.asyncio
async def test_http_listener_binds(client, admin_headers):
    r = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "http-bind-test", "kind": "http", "port": 19001},
    )
    assert r.status_code == 200
    lid = r.json()["id"]
    start = await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    assert start.status_code == 200
    assert start.json()["status"] == "running"

    # Real TCP connect to bound port
    import asyncio

    reader, writer = await asyncio.open_connection("127.0.0.1", 19001)
    writer.write(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    data = await reader.read(4096)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    assert b"200" in data
    assert b"squidc5-http-listener" in data or b"ok" in data.lower()

    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)
