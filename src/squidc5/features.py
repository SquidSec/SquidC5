"""Runtime feature flags — toggled by admin, enforced server-side."""

from __future__ import annotations

import json
from typing import Any

from squidc5.db.store import Database

# Keys are stable API names. Values are defaults when unset.
DEFAULT_FEATURES: dict[str, bool] = {
    "ai_enabled": True,
    "mcp_enabled": False,  # external AI off until explicitly enabled
    "shell_auto_stabilize": True,
    "shell_exec_probe": True,
    "shell_broadcast": True,
    "false_shell_filter": True,
    "implant_beacon": True,
    "http_listeners": True,
    "reverse_shell_listeners": True,
    "payloads_generate": True,
    "public_docs": False,  # never expose Swagger/OpenAPI
    "ops_dashboard": True,
    "malleable_profiles": True,
    "plugins_enabled": False,  # deny by default until allow-listed
    "collab_teams": True,
    "observability_timeline": True,
}

FEATURE_LABELS: dict[str, str] = {
    "ai_enabled": "Admin AI (LLM capabilities)",
    "mcp_enabled": "External MCP tools",
    "shell_auto_stabilize": "Reverse-shell auto stage-2",
    "shell_exec_probe": "Shell exec verification / zombie drop",
    "shell_broadcast": "Shell broadcast to all verified",
    "false_shell_filter": "TLS/HTTP false-shell filter",
    "implant_beacon": "HTTP implant beacon endpoints",
    "http_listeners": "HTTP listeners (beacon/OAST)",
    "reverse_shell_listeners": "Reverse-shell / TCP listeners",
    "payloads_generate": "Payload generation",
    "public_docs": "Public /docs and OpenAPI (keep OFF)",
    "ops_dashboard": "Ops dashboard (/ops)",
    "malleable_profiles": "Malleable / adaptive C2 profiles",
    "plugins_enabled": "Plugin registry (allow-list)",
    "collab_teams": "Multi-operator teams / handoff",
    "observability_timeline": "Timeline + ATT&CK mapping",
}


class FeatureFlags:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._cache: dict[str, bool] | None = None

    async def load(self) -> dict[str, bool]:
        row = await self.db.get_policy("features")
        if not row:
            await self.db.set_policy("features", dict(DEFAULT_FEATURES))
            self._cache = dict(DEFAULT_FEATURES)
            return self._cache
        rules = row["rules"]
        if isinstance(rules, str):
            rules = json.loads(rules)
        merged = dict(DEFAULT_FEATURES)
        for k, v in (rules or {}).items():
            if k in DEFAULT_FEATURES:
                merged[k] = bool(v)
        # Non-negotiable hardened defaults (cannot be re-enabled via UI)
        merged["public_docs"] = False
        self._cache = merged
        return merged

    async def get_all(self) -> dict[str, bool]:
        if self._cache is None:
            return await self.load()
        return dict(self._cache)

    async def enabled(self, key: str) -> bool:
        flags = await self.get_all()
        return bool(flags.get(key, DEFAULT_FEATURES.get(key, False)))

    async def set_many(self, updates: dict[str, Any], actor: str) -> dict[str, bool]:
        flags = await self.get_all()
        for k, v in updates.items():
            if k not in DEFAULT_FEATURES:
                continue
            if k == "public_docs":
                # Hard-locked off for military-grade deployments
                flags[k] = False
                continue
            flags[k] = bool(v)
        flags["public_docs"] = False
        await self.db.set_policy("features", flags)
        self._cache = flags
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="features.update",
            details={"keys": list(updates.keys())},
            risk_score=6,
        )
        return flags

    def catalog(self) -> list[dict[str, str]]:
        return [
            {"key": k, "label": FEATURE_LABELS.get(k, k), "default": str(DEFAULT_FEATURES[k])}
            for k in DEFAULT_FEATURES
        ]
