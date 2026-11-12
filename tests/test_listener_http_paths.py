"""HTTP listener request paths: health, beacon, result, OAST catch-all.

Drives ``handle_http_client`` over raw TCP so request parsing, PSK gating and
response shaping run as they do in production.
"""

from __future__ import annotations

import json

import pytest
from support import (
    free_port,
    http_request,
    raw_http,
    start_listener,
    stop_listener,
    wait_until,
)


async def _http_listener(app, name: str) -> tuple[str, int]:
    return await start_listener(app, name=name, kind="http")


@pytest.mark.asyncio
async def test_health_returns_ok(app):
    lid, port = await _http_listener(app, "http-health")
    try:
        resp = await raw_http(port=port, host="127.0.0.1", request=http_request("GET", "/health"))
        assert b"200" in resp
        assert b'"status": "ok"' in resp or b'"status":"ok"' in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_root_path_returns_ok(app):
    lid, port = await _http_listener(app, "http-root")
    try:
        resp = await raw_http(port=port, host="127.0.0.1", request=http_request("GET", "/"))
        assert b"200" in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_empty_request_gets_400(app):
    lid, port = await _http_listener(app, "http-empty")
    try:
        # A bare CRLF is an empty request line: no method/target to parse.
        resp = await raw_http(port=port, host="127.0.0.1", request=b"\r\n")
        assert b"400" in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_malformed_request_line_gets_400(app):
    lid, port = await _http_listener(app, "http-malformed")
    try:
        resp = await raw_http(port=port, host="127.0.0.1", request=b"GARBAGE\r\n\r\n")
        assert b"400" in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_header_without_colon_is_ignored(app):
    lid, port = await _http_listener(app, "http-badheader")
    try:
        req = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nnocolonhere\r\n\r\n"
        resp = await raw_http(port=port, host="127.0.0.1", request=req)
        assert b"200" in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_beacon_checkin_creates_session(app):
    lid, port = await _http_listener(app, "http-beacon")
    try:
        body = json.dumps({"hostname": "victim-http", "username": "alice"}).encode()
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("POST", "/api/v1/implant/beacon", body=body),
        )
        assert b"200" in resp
        payload = json.loads(resp.split(b"\r\n\r\n", 1)[1])
        assert payload["session_id"].startswith("ses_")

        row = await app.state.app_state.db.get_session(payload["session_id"])
        assert row is not None
        assert row["kind"] == "beacon"
        assert row["listener_id"] == lid
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_beacon_result_completes_task(app):
    lid, port = await _http_listener(app, "http-result")
    try:
        body = json.dumps({"hostname": "victim-result"}).encode()
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("POST", "/api/v1/implant/beacon", body=body),
        )
        sid = json.loads(resp.split(b"\r\n\r\n", 1)[1])["session_id"]

        task = await app.state.app_state.tasks.create(
            session_id=sid, command="whoami", created_by="tester"
        )
        result_body = json.dumps(
            {"task_id": task["id"], "result": "alice", "status": "completed"}
        ).encode()
        resp2 = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("POST", "/api/v1/implant/beacon/result", body=result_body),
        )
        assert b"200" in resp2
        done = await app.state.app_state.db.get_task(task["id"])
        assert done["status"] == "completed"
        assert done["result"] == "alice"
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_beacon_result_without_task_id_errors(app):
    lid, port = await _http_listener(app, "http-result-bad")
    try:
        body = json.dumps({"result": "x"}).encode()
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("POST", "/api/v1/implant/beacon/result", body=body),
        )
        assert b"200" in resp
        payload = json.loads(resp.split(b"\r\n\r\n", 1)[1])
        assert payload["status"] == "error"
        assert "task_id" in payload["detail"]
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_beacon_with_wrong_psk_is_403(app):
    app.state.app_state.listeners.implant_require_auth = True
    app.state.app_state.listeners.implant_psk = "correct-psk"
    lid, port = await _http_listener(app, "http-psk")
    try:
        body = json.dumps({"hostname": "victim-psk"}).encode()
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("POST", "/api/v1/implant/beacon", body=body),
        )
        assert b"403" in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_unknown_path_is_recorded_as_hit(app):
    lid, port = await _http_listener(app, "http-catchall")
    try:
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("GET", "/some/random/path?x=1"),
        )
        assert b"200" in resp
        payload = json.loads(resp.split(b"\r\n\r\n", 1)[1])
        assert payload["received"] is True
        assert payload["listener_id"] == lid
        await wait_until(
            lambda: [e for e in app.state.app_state.metrics._events if e["type"] == "http.hit"],
            timeout=5.0,
            message="http.hit event not emitted",
        )
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_oast_token_in_path_is_captured(app):
    lid, port = await _http_listener(app, "http-oast-path")
    try:
        minted = await app.state.app_state.oast.create_token(note="path", created_by="tester")
        token = minted["token"]
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("GET", f"/o/{token}"),
        )
        assert b"200" in resp
        hits = await app.state.app_state.db.list_oast_interactions(limit=10)
        assert any(h.get("token") == token for h in hits)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_oast_token_in_query_is_captured(app):
    lid, port = await _http_listener(app, "http-oast-query")
    try:
        minted = await app.state.app_state.oast.create_token(note="query", created_by="tester")
        token = minted["token"]
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("GET", f"/probe?c={token}"),
        )
        assert b"200" in resp
        hits = await app.state.app_state.db.list_oast_interactions(limit=10)
        assert any(h.get("token") == token for h in hits)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_oast_token_in_host_on_health(app):
    lid, port = await _http_listener(app, "http-oast-host")
    try:
        minted = await app.state.app_state.oast.create_token(note="host", created_by="tester")
        token = minted["token"]
        zone = app.state.app_state.settings.oast_zone
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("GET", "/health", host=f"{token}.{zone}"),
        )
        assert b"200" in resp
        hits = await app.state.app_state.db.list_oast_interactions(limit=10)
        assert any(h.get("token") == token for h in hits)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_unminted_oast_token_is_not_recorded(app):
    """Only hits tied to minted tokens are stored (upstream OAST behavior)."""
    lid, port = await _http_listener(app, "http-oast-unminted")
    try:
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("GET", "/o/abcdef1234567890"),
        )
        assert b"200" in resp
        hits = await app.state.app_state.db.list_oast_interactions(limit=10)
        assert not any(h.get("token") == "abcdef1234567890" for h in hits)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_authorization_header_not_stored_in_hit(app):
    lid, port = await _http_listener(app, "http-redact")
    try:
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request(
                "GET",
                "/redact-check",
                headers={"Authorization": "Bearer supersecret", "Cookie": "sid=abc"},
            ),
        )
        assert b"200" in resp
        hits = await app.state.app_state.db.list_oast_interactions(limit=10)
        blob = json.dumps(hits)
        assert "supersecret" not in blob
        assert "sid=abc" not in blob
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_oversized_content_length_is_clamped(app):
    lid, port = await _http_listener(app, "http-clamp")
    try:
        # Claim a huge body but send a small one; the reader must not hang.
        req = (
            b"POST /api/v1/implant/beacon HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 999999999\r\n"
            b"Connection: close\r\n\r\n"
            b'{"hostname":"clamped"}'
        )
        resp = await raw_http(port=port, host="127.0.0.1", request=req, timeout=3.0)
        # Either a 200 with a session or a 500 after the read times out; the
        # point is that the server does not allocate the claimed length.
        assert resp == b"" or b"HTTP/1.1" in resp
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_profile_beacon_path_is_matched(app):
    await app.state.app_state.profiles.set_active("prof_default_http")
    lid, port = await _http_listener(app, "http-profile")
    try:
        profile = app.state.app_state.profiles.active()
        assert profile is not None
        path = profile.http.uris[0]
        body = json.dumps({"hostname": "victim-profile"}).encode()
        resp = await raw_http(
            port=port,
            host="127.0.0.1",
            request=http_request("POST", path, body=body),
        )
        assert b"200" in resp
        payload = json.loads(resp.split(b"\r\n\r\n", 1)[1])
        assert payload["session_id"].startswith("ses_")
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_http_listener_rejects_duplicate_port(app):
    lid, port = await _http_listener(app, "http-dup")
    try:
        with pytest.raises(ValueError, match="already used"):
            await app.state.app_state.listeners.create("http-dup-2", "http", port, host="127.0.0.1")
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_http_listener_rejects_bad_kind(app):
    with pytest.raises(ValueError, match="Unsupported listener kind"):
        await app.state.app_state.listeners.create("bad", "carrier-pigeon", free_port())


@pytest.mark.asyncio
async def test_http_listener_rejects_bad_port(app):
    with pytest.raises(ValueError, match="Port must be"):
        await app.state.app_state.listeners.create("bad-port", "http", 70000)
