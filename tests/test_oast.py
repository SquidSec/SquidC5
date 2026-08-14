"""OAST Collaborator: tokens, HTTP/DNS/SMTP hits, correlation."""

from __future__ import annotations

import asyncio
import struct

import pytest

from squidc5.listeners.dns_listener import build_dns_answers, build_dns_response, parse_dns_query
from squidc5.listeners.smtp_listener import extract_smtp_token
from squidc5.oast.store import (
    extract_token_from_host,
    extract_token_from_path,
    extract_token_from_query,
    mint_token,
)


def test_mint_and_extract_token():
    t = mint_token()
    assert 8 <= len(t) <= 32
    assert extract_token_from_path(f"/o/{t}") == t
    assert extract_token_from_path(f"/{t}/x") == t
    assert extract_token_from_query({"c": t}) == t
    assert extract_token_from_host(f"{t}.oast.squidoffense.com", "oast.squidoffense.com") == t


def test_extract_smtp_token():
    assert extract_smtp_token("abcd1234ef@oast.squidoffense.com") == "abcd1234ef"
    assert extract_smtp_token("<deadbeefcafe@x.invalid>") == "deadbeefcafe"


@pytest.mark.asyncio
async def test_oast_token_api_shape(client, admin_headers):
    r = await client.post(
        "/api/v1/oast/tokens",
        headers=admin_headers,
        json={"note": "xss-lab"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token"]
    assert body["dns_name"].endswith(body["token"] + "." + body["dns_name"].split(".", 1)[-1]) or body[
        "dns_name"
    ].startswith(body["token"])
    assert body["token"] in body["dns_name"]
    assert body["token"] in body["http_url"]
    assert body["smtp_to"].startswith(body["token"] + "@")
    assert body.get("hit_count") == 0
    lst = await client.get("/api/v1/oast/tokens", headers=admin_headers)
    assert lst.status_code == 200
    row = next(x for x in lst.json() if x["id"] == body["id"])
    assert row["hit_count"] == 0


@pytest.mark.asyncio
async def test_oast_token_update_and_delete(client, admin_headers):
    r = await client.post("/api/v1/oast/tokens", headers=admin_headers, json={"note": "old"})
    assert r.status_code == 200
    tid = r.json()["id"]
    secret = r.json()["token"]
    patched = await client.patch(
        f"/api/v1/oast/tokens/{tid}",
        headers=admin_headers,
        json={"note": "renamed-canary"},
    )
    assert patched.status_code == 200
    assert patched.json()["note"] == "renamed-canary"
    assert patched.json()["token"] == secret
    got = await client.get(f"/api/v1/oast/tokens/{tid}", headers=admin_headers)
    assert got.json()["note"] == "renamed-canary"
    gone = await client.delete(f"/api/v1/oast/tokens/{tid}", headers=admin_headers)
    assert gone.status_code == 200
    assert (await client.get(f"/api/v1/oast/tokens/{tid}", headers=admin_headers)).status_code == 404


@pytest.mark.asyncio
async def test_oast_http_hit(client, admin_headers):
    r = await client.post(
        "/api/v1/oast/tokens",
        headers=admin_headers,
        json={"note": "http"},
    )
    token = r.json()["token"]

    lr = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "oast-http", "kind": "http", "port": 19050},
    )
    lid = lr.json()["id"]
    await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)

    reader, writer = await asyncio.open_connection("127.0.0.1", 19050)
    writer.write(f"GET /{token}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read(4096)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    assert b"200" in data

    poll = await client.get(f"/api/v1/oast/hits?token={token}", headers=admin_headers)
    assert poll.status_code == 200
    hits = poll.json()["hits"]
    assert any(h.get("protocol") == "http" and h.get("token") == token for h in hits)

    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


@pytest.mark.asyncio
async def test_oast_urls_include_running_http_port(client, admin_headers):
    lr = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "oast-http-port", "kind": "http", "port": 19051},
    )
    lid = lr.json()["id"]
    await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    r = await client.post("/api/v1/oast/tokens", headers=admin_headers, json={"note": "port"})
    body = r.json()
    assert ":19051" in body["http_url_path"]
    assert body["http_port"] == 19051
    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


@pytest.mark.asyncio
async def test_oast_root_host_header_records_hit(client, admin_headers):
    r = await client.post("/api/v1/oast/tokens", headers=admin_headers, json={"note": "root"})
    token = r.json()["token"]
    lr = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "oast-root", "kind": "http", "port": 19052},
    )
    lid = lr.json()["id"]
    await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    reader, writer = await asyncio.open_connection("127.0.0.1", 19052)
    writer.write(
        f"GET / HTTP/1.1\r\nHost: {token}.oast.lab.invalid\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    await reader.read(4096)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    poll = await client.get(f"/api/v1/oast/hits?token={token}", headers=admin_headers)
    hits = poll.json()["hits"]
    assert any(h.get("token") == token for h in hits)
    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


@pytest.mark.asyncio
async def test_dns_oast_subdomain(client, admin_headers):
    r = await client.post("/api/v1/oast/tokens", headers=admin_headers, json={"note": "dns"})
    token = r.json()["token"]

    lr = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={
            "name": "oast-dns",
            "kind": "dns",
            "port": 19553,
            "config": {"zone": "oast.lab.invalid", "mode": "oast", "public_ip": "159.203.99.184"},
        },
    )
    lid = lr.json()["id"]
    await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)

    labels = [token, "oast", "lab", "invalid"]
    q = bytearray(struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0))
    for lab in labels:
        b = lab.encode("ascii")
        q.append(len(b))
        q.extend(b)
    q.append(0)
    q += struct.pack("!HH", 1, 1)  # A IN

    loop = asyncio.get_running_loop()

    class _P(asyncio.DatagramProtocol):
        def __init__(self):
            self.got = asyncio.Event()
            self.data = b""

        def datagram_received(self, data, addr):
            self.data = data
            self.got.set()

    transport, proto = await loop.create_datagram_endpoint(_P, local_addr=("127.0.0.1", 0))
    transport.sendto(bytes(q), ("127.0.0.1", 19553))
    try:
        await asyncio.wait_for(proto.got.wait(), timeout=2.0)
        # A answer should include public IP bytes
        assert b"\x9f\xcb\x63\xb8" in proto.data  # 159.203.99.184
    finally:
        transport.close()

    poll = await client.get(
        f"/api/v1/oast/hits?token={token}&protocol=dns",
        headers=admin_headers,
    )
    assert poll.json()["count"] >= 1

    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


@pytest.mark.asyncio
async def test_smtp_oast(client, admin_headers):
    await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"smtp_oast": True}},
    )
    r = await client.post("/api/v1/oast/tokens", headers=admin_headers, json={"note": "smtp"})
    token = r.json()["token"]

    lr = await client.post(
        "/api/v1/listeners",
        headers=admin_headers,
        json={"name": "oast-smtp", "kind": "smtp", "port": 19025},
    )
    assert lr.status_code == 200, lr.text
    lid = lr.json()["id"]
    st = await client.post(f"/api/v1/listeners/{lid}/start", headers=admin_headers)
    assert st.status_code == 200

    reader, writer = await asyncio.open_connection("127.0.0.1", 19025)
    assert (await reader.readline()).startswith(b"220")
    writer.write(b"EHLO test\r\n")
    await writer.drain()
    while True:
        line = await reader.readline()
        if line.startswith(b"250 ") and not line.startswith(b"250-"):
            break
    writer.write(b"MAIL FROM:<a@b.invalid>\r\n")
    await writer.drain()
    await reader.readline()
    writer.write(f"RCPT TO:<{token}@oast.lab.invalid>\r\n".encode())
    await writer.drain()
    await reader.readline()
    writer.write(b"DATA\r\n")
    await writer.drain()
    await reader.readline()
    writer.write(b"Subject: x\r\n\r\nhello\r\n.\r\n")
    await writer.drain()
    assert b"250" in await reader.readline()
    writer.write(b"QUIT\r\n")
    await writer.drain()
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    poll = await client.get(
        f"/api/v1/oast/hits?token={token}&protocol=smtp",
        headers=admin_headers,
    )
    assert poll.json()["count"] >= 1
    await client.post(f"/api/v1/listeners/{lid}/stop", headers=admin_headers)


def test_parse_dns_roundtrip():
    assert parse_dns_query(b"") is None
    q = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    for lab in (b"a", b"b"):
        q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack("!HH", 1, 1)
    parsed = parse_dns_query(q)
    assert parsed is not None
    txid, labels, qtype = parsed
    assert labels == ["a", "b"]
    resp = build_dns_response(txid, q, "ok")
    assert len(resp) > 12
    resp2 = build_dns_answers(txid, q, [(1, bytes([1, 2, 3, 4]))])
    assert b"\x01\x02\x03\x04" in resp2
