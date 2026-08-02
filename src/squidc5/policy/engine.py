"""Configurable policy engine governing humans, external AI, and admin AI."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from squidc5.auth.tokens import AuthContext
from squidc5.db.store import Database


def hitl_binding_hash(
    action: str,
    resource: str | None,
    extra: dict[str, Any] | None,
) -> str:
    """Bind approval to action + resource + full command (or other intent fields)."""
    extra = extra or {}
    # Full command - do not truncate (truncation enables prefix-collision bypass)
    intent = {
        "action": action,
        "resource": resource or "",
        "command": str(extra.get("command") or ""),
        "capability": str(extra.get("capability") or ""),
    }
    raw = json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()

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
                "evasion_suggest",
                "beacon_anomaly",
                "opsec_review",
                "profile_mutate",
                "implant_build_plan",
                "session_triage",
                "task_suggest",
                "report_draft",
                "hitl_brief",
                "anomaly_explain",
            ],

        "max_untrusted_chars": 512,
    },
    "action_risk": {
        "sessions.list": 0,
        "sessions.get": 0,
        "sessions.clear": 2,
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
        "tokens.update": 6,
        "policy.update": 9,
    },
}


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    risk_score: int
    require_hitl: bool = False
    hitl_request_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


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

    async def _server_hitl_approved(
        self,
        auth: AuthContext,
        action: str,
        resource: str | None,
        extra: dict[str, Any] | None,
    ) -> bool:
        """True only when a server-side approved HITL request is presented."""
        rid = (extra or {}).get("hitl_request_id")
        if not rid or not isinstance(rid, str):
            return False
        row = await self.db.get_hitl_request(rid)
        if not row:
            return False
        if row.get("status") != "approved":
            return False
        exp = row.get("expires_at")
        if exp is not None and float(exp) < time.time():
            return False
        if row.get("action") != action:
            return False
        # Same operator (or admin using the grant)
        if row.get("actor") != auth.name and "admin" not in auth.scopes:
            return False
        res = row.get("resource")
        if res and resource and res != resource:
            return False
        # Must match command/intent binding from original request
        expected = hitl_binding_hash(action, resource, extra)
        stored = (row.get("binding_hash") or "").strip()
        if not stored or stored != expected:
            return False
        return True

    async def evaluate(
        self,
        auth: AuthContext,
        action: str,
        resource: str | None = None,
        extra: dict[str, Any] | None = None,
        *,
        create_hitl: bool = True,
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
        # Admins bypass HITL; client-asserted hitl_approved is IGNORED
        if require_hitl and "admin" not in auth.scopes:
            if await self._server_hitl_approved(auth, action, resource, extra):
                rid = str((extra or {}).get("hitl_request_id") or "")
                # H01: single-use grant
                if rid:
                    await self.db.consume_hitl_request(rid)
                return PolicyDecision(
                    True,
                    "allowed (HITL approved)",
                    risk,
                    require_hitl=True,
                    hitl_request_id=rid or None,
                )
            hid: str | None = None
            if create_hitl:
                safe_details = {
                    k: v
                    for k, v in (extra or {}).items()
                    if k not in ("hitl_approved", "api_key", "token", "hitl_request_id")
                }
                # Cap stored detail length only (binding uses full command separately)
                if isinstance(safe_details.get("command"), str) and len(safe_details["command"]) > 2000:
                    safe_details["command"] = safe_details["command"][:2000] + "...[truncated]"
                binding = hitl_binding_hash(action, resource, extra)
                hid = await self.db.create_hitl_request(
                    action=action,
                    actor=auth.name,
                    actor_type=auth.actor_type,
                    resource=resource,
                    details=safe_details,
                    binding_hash=binding,
                    risk_score=risk,
                )
            return PolicyDecision(
                False,
                f"Human-in-the-loop required for {action}",
                risk,
                require_hitl=True,
                hitl_request_id=hid,
                details={"hitl_request_id": hid} if hid else {},
            )

        return PolicyDecision(True, "allowed", risk, require_hitl=require_hitl)

    async def check_and_audit(
        self,
        auth: AuthContext,
        action: str,
        resource: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        # Strip spoofable client flag before evaluate
        clean_extra = dict(extra or {})
        clean_extra.pop("hitl_approved", None)
        decision = await self.evaluate(auth, action, resource, clean_extra)
        audit_details = {
            "reason": decision.reason,
            **{k: v for k, v in clean_extra.items() if k != "hitl_approved"},
        }
        if decision.hitl_request_id:
            audit_details["hitl_request_id"] = decision.hitl_request_id
        await self.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action=action,
            resource=resource,
            details=audit_details,
            risk_score=decision.risk_score,
            allowed=decision.allowed,
        )
        await self.db.incr_metric("policy.checks")
        if not decision.allowed:
            await self.db.incr_metric("policy.denies")
            if decision.require_hitl:
                await self.db.incr_metric("policy.hitl_required")
        return decision
