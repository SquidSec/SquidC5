"""Configurable policy engine governing humans, external AI, and admin AI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from squidc5.auth.tokens import AuthContext
from squidc5.db.store import Database

DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "deny_actions": [],
    "allow_actions": ["*"],
    "require_hitl": [
        "payloads.generate_custom",
        "shell.interactive",
        "files.upload",
        "ai.admin.unrestricted",
    ],
    "risk_thresholds": {
        "auto_allow_max": 3,
        "hitl_min": 7,
        "deny_min": 10,
    },
    "external_ai": {
        "max_chain_length": 1,
        "require_explicit_tools": True,
        "deny_autonomous_planning": True,
    },
    "admin_ai": {
        "sandbox": True,
        "no_raw_session_ingest": True,
        "allowed_capabilities": [
            "payload_template",
            "phishing_asset",
            "doc_generate",
            "shell_classify",
            "recon_assist",
        ],
        "max_untrusted_chars": 512,
    },
    "action_risk": {
        "sessions.list": 0,
        "sessions.get": 0,
        "tasks.list": 0,
        "tasks.create": 4,
        "listeners.create": 5,
        "listeners.start": 5,
        "listeners.stop": 2,
        "payloads.generate": 6,
        "shell.interact": 8,
        "files.download": 5,
        "files.upload": 7,
        "ai.admin": 3,
        "tokens.create": 6,
        "policy.update": 9,
    },
}


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    risk_score: int
    require_hitl: bool = False


class PolicyEngine:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._cache: dict[str, Any] | None = None

    async def load(self) -> dict[str, Any]:
        row = await self.db.get_policy("default")
        if not row:
            await self.db.set_policy("default", DEFAULT_POLICY)
            self._cache = dict(DEFAULT_POLICY)
            return self._cache
        rules = row["rules"]
        if isinstance(rules, str):
            rules = json.loads(rules)
        self._cache = rules
        return rules

    async def get_rules(self) -> dict[str, Any]:
        if self._cache is None:
            return await self.load()
        return self._cache

    async def update(self, rules: dict[str, Any], actor: str) -> None:
        merged = await self.get_rules()
        merged.update(rules)
        await self.db.set_policy("default", merged)
        self._cache = merged
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="policy.update",
            details={"keys": list(rules.keys())},
            risk_score=9,
        )

    def score(self, action: str, rules: dict[str, Any]) -> int:
        return int(rules.get("action_risk", {}).get(action, 5))

    async def evaluate(
        self,
        auth: AuthContext,
        action: str,
        resource: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        rules = await self.get_rules()
        risk = self.score(action, rules)
        deny = set(rules.get("deny_actions") or [])
        allow = set(rules.get("allow_actions") or [])
        hitl_actions = set(rules.get("require_hitl") or [])
        thresholds = rules.get("risk_thresholds") or {}

        if action in deny or (deny and "*" in deny):
            return PolicyDecision(False, f"Action {action} denied by policy", risk)

        if allow and "*" not in allow and action not in allow:
            return PolicyDecision(False, f"Action {action} not in allow list", risk)

        if auth.actor_type == "external_ai":
            eai = rules.get("external_ai") or {}
            if eai.get("deny_autonomous_planning") and (extra or {}).get("chain_length", 1) > eai.get(
                "max_chain_length", 1
            ):
                return PolicyDecision(
                    False,
                    "External AI autonomous chaining denied (determinism preference)",
                    risk + 2,
                )

        if risk >= int(thresholds.get("deny_min", 10)) and "admin" not in auth.scopes:
            return PolicyDecision(False, f"Risk score {risk} exceeds deny threshold", risk)

        require_hitl = action in hitl_actions or risk >= int(thresholds.get("hitl_min", 7))
        if require_hitl and "admin" not in auth.scopes and not (extra or {}).get("hitl_approved"):
            return PolicyDecision(
                False,
                f"Human-in-the-loop required for {action}",
                risk,
                require_hitl=True,
            )

        return PolicyDecision(True, "allowed", risk, require_hitl=require_hitl)

    async def check_and_audit(
        self,
        auth: AuthContext,
        action: str,
        resource: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        decision = await self.evaluate(auth, action, resource, extra)
        await self.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action=action,
            resource=resource,
            details={"reason": decision.reason, **(extra or {})},
            risk_score=decision.risk_score,
            allowed=decision.allowed,
        )
        await self.db.incr_metric("policy.checks")
        if not decision.allowed:
            await self.db.incr_metric("policy.denies")
        return decision
