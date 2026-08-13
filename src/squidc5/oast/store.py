"""OAST tokens (unique payload IDs) and multi-protocol hit store."""

from __future__ import annotations

import json
import re
import secrets
import time
from collections import defaultdict, deque
from typing import Any

from squidc5.db.store import Database
from squidc5.metrics.collector import MetricsCollector

_TOKEN_RE = re.compile(r"^[a-z0-9]{8,32}$")
_PATH_TOKEN_RE = re.compile(
    r"(?:^|/)(?:o|oast|c|p|id)/([a-z0-9]{8,32})(?:/|$)",
    re.IGNORECASE,
)


def mint_token(nbytes: int = 6) -> str:
    """8-12 hex chars, dns/url-safe."""
    return secrets.token_hex(nbytes)


def extract_token_from_path(path: str) -> str | None:
    if not path:
        return None
    m = _PATH_TOKEN_RE.search(path.split("?", 1)[0])
    if m:
        return m.group(1).lower()
    segs = [s for s in path.split("?", 1)[0].strip("/").split("/") if s]
    if segs and _TOKEN_RE.match(segs[0].lower()):
        return segs[0].lower()
    return None


def extract_token_from_host(host: str, zone: str = "") -> str | None:
    if not host:
        return None
    h = host.split(":")[0].lower().strip(".")
    if zone:
        z = zone.lower().strip(".")
        if h == z or h.endswith("." + z):
            left = h[: -(len(z) + 1)] if h != z else ""
            if left:
                first = left.split(".")[0]
                if _TOKEN_RE.match(first):
                    return first
    first = h.split(".")[0]
    if _TOKEN_RE.match(first):
        return first
    return None


def extract_token_from_query(query: dict[str, Any]) -> str | None:
    for key in ("c", "id", "oast", "token", "cid"):
        v = query.get(key)
        if isinstance(v, list):
            v = v[0] if v else None
        if isinstance(v, str) and _TOKEN_RE.match(v.lower()):
            return v.lower()
    return None


def strip_secrets(headers: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in headers.items():
        if k.lower() in ("authorization", "cookie", "set-cookie", "proxy-authorization"):
            continue
        out[k] = v
    return out


class RateLimiter:
    """Simple per-IP sliding window (in-memory)."""

    def __init__(self, limit: int = 120, window_sec: float = 60.0) -> None:
        self.limit = max(1, limit)
        self.window = window_sec
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


class OastService:
    def __init__(
        self,
        db: Database,
        metrics: MetricsCollector | None = None,
        *,
        zone: str = "oast.lab.invalid",
        public_host: str = "",
        public_ip: str = "",
        http_port: int = 80,
        scheme: str = "http",
        rate_limit: int = 120,
    ) -> None:
        self.db = db
        self.metrics = metrics
        self.zone = (zone or "oast.lab.invalid").lower().strip(".")
        self.public_host = public_host or self.zone
        self.public_ip = public_ip or "127.0.0.1"
        self.http_port = http_port
        self.scheme = scheme
        self.rate = RateLimiter(limit=rate_limit)

    def allow_remote(self, remote: str | None) -> bool:
        ip = (remote or "unknown").split(":")[0]
        return self.rate.allow(ip)

    async def create_token(
        self,
        *,
        note: str = "",
        created_by: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        token = mint_token()
        for _ in range(8):
            if not await self.db.get_oast_client_by_token(token):
                break
            token = mint_token()
        m = dict(meta or {})
        if note:
            m["note"] = note
        cid = await self.db.create_oast_client(
            token=token,
            label=note or token,
            created_by=created_by,
            meta=m,
        )
        await self.db.audit(
            actor=created_by or "operator",
            actor_type="operator",
            action="oast.token.created",
            resource=cid,
            details={"token": token, "note": note[:200]},
            risk_score=0,
        )
        if self.metrics:
            await self.metrics.emit("oast.token.created", {"id": cid, "token": token})
        return self.format_token_response(cid, token, note=note)

    # aliases used by older routes
    async def create_client(self, **kwargs: Any) -> dict[str, Any]:
        note = kwargs.get("label") or kwargs.get("note") or ""
        return await self.create_token(
            note=str(note),
            created_by=kwargs.get("created_by"),
            meta=kwargs.get("meta"),
        )

    def format_token_response(
        self,
        client_id: str,
        token: str,
        *,
        note: str = "",
        hit_count: int = 0,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        zone = self.zone
        host = self.public_host or zone
        port_s = f":{self.http_port}" if self.http_port not in (80, 443) else ""
        dns_name = f"{token}.{zone}"
        http_url = f"{self.scheme}://{token}.{zone}{port_s}/"
        http_path = f"{self.scheme}://{host}{port_s}/{token}/"
        smtp_to = f"{token}@{zone}"
        return {
            "id": client_id,
            "token": token,
            "note": note,
            "dns_name": dns_name,
            "http_url": http_url,
            "http_url_path": http_path,
            "smtp_to": smtp_to,
            "payloads": {
                "dns": dns_name,
                "http": http_url,
                "http_path": http_path,
                "smtp": smtp_to,
                "token": token,
            },
            "zone": zone,
            "public_ip": self.public_ip,
            "hit_count": int(hit_count),
            "created_by": created_by,
        }

    async def list_tokens(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self.db.list_oast_clients(limit=limit)
        counts = await self.db.count_oast_hits_by_client()
        out = []
        for r in rows:
            n = self._norm_client(r)
            note = str((n.get("meta") or {}).get("note") or n.get("label") or "")
            cid = str(n["id"])
            out.append(
                self.format_token_response(
                    cid,
                    n["token"],
                    note=note,
                    hit_count=counts.get(cid, 0),
                    created_by=n.get("created_by"),
                )
            )
        return out

    async def get_token(self, token_id: str) -> dict[str, Any] | None:
        row = await self.db.get_oast_client(token_id)
        if not row:
            return None
        n = self._norm_client(row)
        note = str((n.get("meta") or {}).get("note") or n.get("label") or "")
        counts = await self.db.count_oast_hits_by_client()
        cid = str(n["id"])
        return self.format_token_response(
            cid,
            n["token"],
            note=note,
            hit_count=counts.get(cid, 0),
            created_by=n.get("created_by"),
        )

    async def list_clients(self, limit: int = 100) -> list[dict[str, Any]]:
        return await self.list_tokens(limit=limit)

    async def get_client(self, client_id: str) -> dict[str, Any] | None:
        return await self.get_token(client_id)

    async def get_by_token(self, token: str) -> dict[str, Any] | None:
        row = await self.db.get_oast_client_by_token(token.lower())
        if not row:
            return None
        n = self._norm_client(row)
        note = str((n.get("meta") or {}).get("note") or n.get("label") or "")
        return self.format_token_response(n["id"], n["token"], note=note)

    async def resolve_token(self, token: str | None) -> str | None:
        if not token:
            return None
        row = await self.db.get_oast_client_by_token(token.lower())
        return str(row["id"]) if row else None

    async def record(
        self,
        *,
        protocol: str,
        listener_id: str | None = None,
        remote: str | None = None,
        token: str | None = None,
        client_id: str | None = None,
        raw: dict[str, Any] | None = None,
        correlation_key: str | None = None,
    ) -> dict[str, Any]:
        if not client_id and token:
            client_id = await self.resolve_token(token)
        summary = raw or {}
        if isinstance(summary.get("headers"), dict):
            summary = {**summary, "headers": strip_secrets(summary["headers"])}
        iid = await self.db.create_oast_interaction(
            client_id=client_id,
            protocol=protocol,
            listener_id=listener_id,
            remote=remote,
            raw=summary,
            correlation_key=correlation_key or token,
            token=token,
        )
        await self.db.audit(
            actor="oast",
            actor_type="listener",
            action="oast.hit",
            resource=iid,
            details={
                "protocol": protocol,
                "token": token,
                "remote": (remote or "")[:80],
                "client_id": client_id,
            },
            risk_score=1,
        )
        if self.metrics:
            await self.metrics.incr("oast.hits")
            await self.metrics.incr("oast.interactions")
            await self.metrics.emit(
                "oast.hit",
                {
                    "id": iid,
                    "protocol": protocol,
                    "client_id": client_id,
                    "token": token,
                    "remote": remote,
                    "listener_id": listener_id,
                },
            )
        row = await self.db.get_oast_interaction(iid)
        return self._norm_hit(row)  # type: ignore[arg-type]

    async def list_hits(
        self,
        *,
        client_id: str | None = None,
        token: str | None = None,
        protocol: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if token and not client_id:
            c = await self.db.get_oast_client_by_token(token.lower())
            if c:
                client_id = str(c["id"])
            # also match by token column even if unregistered
        rows = await self.db.list_oast_interactions(
            client_id=client_id,
            protocol=protocol,
            since=since,
            limit=limit,
            token=token if not client_id else None,
        )
        return [self._norm_hit(r) for r in rows]

    async def poll(self, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.list_hits(**kwargs)

    async def delete_client(self, client_id: str) -> bool:
        return await self.db.delete_oast_client(client_id)

    def payload_urls(self, token: str, **kwargs: Any) -> dict[str, str]:
        r = self.format_token_response("x", token)
        return r["payloads"]

    def _norm_client(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        meta = out.get("meta")
        if isinstance(meta, str):
            try:
                out["meta"] = json.loads(meta)
            except Exception:
                out["meta"] = {}
        return out

    def _norm_hit(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        raw = out.get("raw")
        if isinstance(raw, str):
            try:
                out["raw"] = json.loads(raw)
            except Exception:
                out["raw"] = {"raw": raw}
        # Collaborator-style aliases
        out["summary"] = out.get("raw")
        out["remote_ip"] = out.get("remote")
        return out

    def _norm_interaction(self, row: dict[str, Any]) -> dict[str, Any]:
        return self._norm_hit(row)
