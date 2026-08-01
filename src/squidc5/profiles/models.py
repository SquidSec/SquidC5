"""Malleable / adaptive C2 profile models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class HttpProfile:
    """HTTP/S beacon surface: URI, headers, body wrappers, user-agent."""

    uris: list[str] = field(default_factory=lambda: ["/api/v1/implant/beacon"])
    method: str = "POST"
    headers: dict[str, str] = field(
        default_factory=lambda: {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    # Body: {beacon} is replaced with JSON beacon payload
    request_body_template: str = "{beacon}"
    # Response: extract task JSON from wrapper if needed
    response_prefix: str = ""
    response_suffix: str = ""
    # Sleep between beacons (seconds) before jitter
    sleep_sec: float = 5.0
    jitter_pct: float = 20.0  # 0-100
    decoy_enabled: bool = False
    decoy_paths: list[str] = field(default_factory=lambda: ["/favicon.ico", "/robots.txt", "/health"])
    # Ordered encode pipeline (implant applies encode; server reverse-decodes)
    # e.g. [{"name":"base64"},{"name":"prepend","value":"data="}]
    transforms: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DnsProfile:
    """DNS C2 (data in subdomain labels). Lab/authorized only."""

    zone: str = "c2.example.invalid"
    max_label_len: int = 63
    sleep_sec: float = 10.0
    jitter_pct: float = 30.0
    record_type: str = "TXT"


@dataclass
class WsProfile:
    """WebSocket C2 path and framing."""

    path: str = "/ws/v1/beacon"
    subprotocol: str = ""
    sleep_sec: float = 3.0
    jitter_pct: float = 15.0
    ping_interval_sec: float = 30.0


@dataclass
class C2Profile:
    id: str
    name: str
    description: str = ""
    channel: str = "http"  # http | dns | ws
    http: HttpProfile = field(default_factory=HttpProfile)
    dns: DnsProfile = field(default_factory=DnsProfile)
    ws: WsProfile = field(default_factory=WsProfile)
    active: bool = False
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> C2Profile:
        http = HttpProfile(**(data.get("http") or {}))
        dns = DnsProfile(**(data.get("dns") or {}))
        ws = WsProfile(**(data.get("ws") or {}))
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description") or "",
            channel=data.get("channel") or "http",
            http=http,
            dns=dns,
            ws=ws,
            active=bool(data.get("active")),
            version=int(data.get("version") or 1),
        )


def _amazon_like() -> C2Profile:
    return C2Profile(
        id="prof_amazon_cdn",
        name="amazon-cdn-blend",
        description="HTTP traffic shaped like CDN/API client noise",
        channel="http",
        http=HttpProfile(
            uris=["/v1/telemetry", "/api/client/events", "/cdn/config/refresh"],
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Request-Id": "{uuid}",
                "X-Amz-Target": "Telemetry.PutEvents",
            },
            user_agent="aws-sdk-python/1.34.0 Python/3.11 Linux",
            request_body_template='{"Records":[{beacon}]}',
            sleep_sec=8.0,
            jitter_pct=35.0,
            decoy_enabled=True,
            decoy_paths=["/favicon.ico", "/robots.txt", "/.well-known/security.txt"],
        ),
    )


def _office_like() -> C2Profile:
    return C2Profile(
        id="prof_ms_graph",
        name="ms-graph-blend",
        description="HTTP shaped like Microsoft Graph-style calls",
        channel="http",
        http=HttpProfile(
            uris=["/v1.0/me/drive/root/delta", "/v1.0/communications/callRecords"],
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "ConsistencyLevel": "eventual",
            },
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            request_body_template='{"value":{beacon}}',
            sleep_sec=12.0,
            jitter_pct=40.0,
            decoy_enabled=True,
        ),
    )


def _default_http() -> C2Profile:
    return C2Profile(
        id="prof_default_http",
        name="default-http",
        description="Native SquidC5 HTTP beacon path (cleartext lab default)",
        channel="http",
        http=HttpProfile(),
        active=True,
    )


def _default_dns() -> C2Profile:
    return C2Profile(
        id="prof_default_dns",
        name="default-dns",
        description="DNS TXT channel skeleton (authorized lab only)",
        channel="dns",
        dns=DnsProfile(),
    )


def _default_ws() -> C2Profile:
    return C2Profile(
        id="prof_default_ws",
        name="default-ws",
        description="WebSocket channel skeleton",
        channel="ws",
        ws=WsProfile(),
    )


DEFAULT_PROFILES: list[C2Profile] = [
    _default_http(),
    _amazon_like(),
    _office_like(),
    _default_dns(),
    _default_ws(),
]
