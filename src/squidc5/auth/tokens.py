"""Server-generated scoped tokens. Only server issues tokens; usage is audited."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

from squidc5.db.store import Database

# Canonical scopes
SCOPES = frozenset(
    {
        "admin",
        "sessions:read",
        "sessions:write",
        "tasks:read",
        "tasks:write",
        "listeners:read",
        "listeners:write",
        "payloads:generate",
        "metrics:read",
        "audit:read",
        "shell:interact",
        "ai:use",
        "mcp:connect",
        "tokens:manage",
        "llm:manage",
        "policy:manage",
        "files:read",
        "files:write",
        "phone:operator",
        "profiles:read",
        "profiles:write",
        "plugins:manage",
        "collab:use",
        "oast:read",
        "oast:write",
    }
)

# Short operator-facing descriptions (UI checkboxes / docs)
SCOPE_DESCRIPTIONS: dict[str, str] = {
    "admin": "Full control - all scopes, admin UI module, privileged grants",
    "sessions:read": "List and inspect beacons and shells",
    "sessions:write": "Close and reap sessions",
    "tasks:read": "List and inspect beacon tasks",
    "tasks:write": "Create, edit, and cancel tasks",
    "listeners:read": "List listeners and status",
    "listeners:write": "Create, start, stop, and delete listeners",
    "payloads:generate": "Generate payloads/implants and save artifacts",
    "metrics:read": "Metrics, health details, live event counters",
    "audit:read": "Read the audit log",
    "shell:interact": "Run shell commands, file ops, SOCKS, BOF",
    "ai:use": "INKO chat and Admin AI capabilities",
    "mcp:connect": "External MCP tool bridge (plus per-token tool list)",
    "tokens:manage": "Mint, update, list, and revoke non-privileged tokens",
    "llm:manage": "Configure BYO LLM connections",
    "policy:manage": "View and edit policy rules",
    "files:read": "Reserved for file-read least privilege",
    "files:write": "Reserved for file-write least privilege",
    "phone:operator": "Phone-oriented operator profile marker",
    "profiles:read": "List and view malleable C2 profiles",
    "profiles:write": "Create, edit, activate, and push profiles",
    "plugins:manage": "Install and enable server plugins",
    "collab:use": "Teams, claim/handoff, chat, presence",
    "oast:read": "List OAST tokens and poll hits",
    "oast:write": "Mint and delete OAST tokens",
}

# Privileged scopes - never included in "non-admin" presets
PRIVILEGED_SCOPES = frozenset(
    {"admin", "tokens:manage", "policy:manage", "llm:manage", "plugins:manage"}
)

# All operational scopes a non-admin full operator may hold
_FULL_OPERATOR_SCOPES = sorted(
    s
    for s in SCOPES
    if s not in PRIVILEGED_SCOPES and s != "mcp:connect"
)

# Named presets for mint/edit UI (scopes only; MCP tools optional)
SCOPE_PRESETS: list[dict[str, Any]] = [
    {
        "id": "full_operator",
        "label": "Full operator",
        "description": (
            "All day-to-day ops abilities (shells, listeners, payloads, profiles, "
            "OAST, collab, INKO) - no admin/token/policy/LLM manage."
        ),
        "scopes": list(_FULL_OPERATOR_SCOPES),
    },
    {
        "id": "operator",
        "label": "Operator",
        "description": "Day-to-day shells, tasks, listeners read, collab - no payload/profile edits.",
        "scopes": [
            "sessions:read",
            "sessions:write",
            "tasks:read",
            "tasks:write",
            "shell:interact",
            "listeners:read",
            "collab:use",
            "metrics:read",
            "audit:read",
        ],
    },
    {
        "id": "read_only_ai",
        "label": "Read-only + INKO",
        "description": "Observe everything and use INKO - cannot create listeners, tasks, or payloads.",
        "scopes": [
            "sessions:read",
            "tasks:read",
            "listeners:read",
            "metrics:read",
            "audit:read",
            "profiles:read",
            "oast:read",
            "collab:use",
            "ai:use",
        ],
    },
    {
        "id": "read_only",
        "label": "Read only",
        "description": "Watch sessions, listeners, metrics, audit - no writes and no AI.",
        "scopes": [
            "sessions:read",
            "tasks:read",
            "listeners:read",
            "metrics:read",
            "audit:read",
            "profiles:read",
            "oast:read",
        ],
    },
    {
        "id": "listener_ops",
        "label": "Listener ops",
        "description": "Create/start/stop listeners only.",
        "scopes": ["listeners:read", "listeners:write", "metrics:read", "sessions:read"],
    },
    {
        "id": "payload_dev",
        "label": "Payload / profiles",
        "description": "Generate implants, edit profiles, save artifacts.",
        "scopes": [
            "payloads:generate",
            "profiles:read",
            "profiles:write",
            "listeners:read",
            "sessions:read",
            "metrics:read",
        ],
    },
    {
        "id": "phone_shell",
        "label": "Phone shell",
        "description": "Minimal phone console: sessions, shell, metrics, collab.",
        "scopes": [
            "sessions:read",
            "shell:interact",
            "metrics:read",
            "collab:use",
            "phone:operator",
        ],
    },
    {
        "id": "ai_operator",
        "label": "INKO + operate",
        "description": "INKO plus shell/tasks/payloads for AI-assisted ops (still non-admin).",
        "scopes": [
            "ai:use",
            "sessions:read",
            "sessions:write",
            "tasks:read",
            "tasks:write",
            "shell:interact",
            "listeners:read",
            "listeners:write",
            "payloads:generate",
            "profiles:read",
            "metrics:read",
            "audit:read",
            "collab:use",
        ],
    },
    {
        "id": "mcp_external",
        "label": "MCP external AI",
        "description": "External model via MCP with default safe tools only (no shell).",
        "scopes": [
            "mcp:connect",
            "sessions:read",
            "tasks:read",
            "tasks:write",
            "metrics:read",
            "audit:read",
        ],
        "mcp_tools": [
            "list_sessions",
            "get_session",
            "list_tasks",
            "create_task",
            "list_listeners",
            "get_metrics",
            "list_audit",
        ],
    },
    {
        "id": "token_admin",
        "label": "Token admin",
        "description": "Mint/update non-privileged tokens only (not full admin).",
        "scopes": ["tokens:manage", "sessions:read", "metrics:read"],
        "admin_only": True,
    },
    {
        "id": "full_admin",
        "label": "Full admin",
        "description": "Break-glass admin - all capabilities.",
        "scopes": ["admin"],
        "admin_only": True,
    },
]

# Default MCP tools an external AI may call (strict allow-list)
DEFAULT_MCP_TOOLS = frozenset(
    {
        "list_sessions",
        "get_session",
        "list_tasks",
        "create_task",
        "list_listeners",
        "get_metrics",
        "list_audit",
    }
)

ALL_MCP_TOOLS = frozenset(
    {
        "list_sessions",
        "get_session",
        "close_session",
        "list_tasks",
        "get_task",
        "create_task",
        "list_listeners",
        "create_listener",
        "start_listener",
        "stop_listener",
        "delete_listener",
        "generate_payload",
        "list_payload_templates",
        "get_metrics",
        "list_audit",
        "interact_shell",
        "whoami",
        "get_platform_status",
        "oast_mint",
        "oast_list_tokens",
        "oast_get_token",
        "oast_revoke",
        "oast_hits",
    }
)


def scope_catalog() -> dict[str, Any]:
    """UI/API catalog: scopes with descriptions + named presets."""
    scopes = [
        {
            "id": s,
            "description": SCOPE_DESCRIPTIONS.get(s, s),
            "privileged": s in PRIVILEGED_SCOPES,
        }
        for s in sorted(SCOPES)
    ]
    presets = []
    for p in SCOPE_PRESETS:
        # Deduplicate while preserving order
        seen: set[str] = set()
        clean_scopes: list[str] = []
        for s in p["scopes"]:
            if s not in seen:
                seen.add(s)
                clean_scopes.append(s)
        presets.append(
            {
                "id": p["id"],
                "label": p["label"],
                "description": p["description"],
                "scopes": clean_scopes,
                "mcp_tools": list(p["mcp_tools"]) if p.get("mcp_tools") else None,
                "admin_only": bool(p.get("admin_only")),
            }
        )
    return {
        "scopes": scopes,
        "presets": presets,
        "privileged_scopes": sorted(PRIVILEGED_SCOPES),
        "non_admin_scopes": sorted(SCOPES - PRIVILEGED_SCOPES),
    }


def generate_token() -> str:
    return f"sc5_{secrets.token_urlsafe(32)}"


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class AuthContext:
    token_id: str
    name: str
    scopes: list[str]
    mcp_tools: list[str]
    actor_type: str = "operator"

    def has_scope(self, scope: str) -> bool:
        if "admin" in self.scopes:
            return True
        return scope in self.scopes

    def can_mcp_tool(self, tool: str) -> bool:
        if "admin" in self.scopes:
            return tool in ALL_MCP_TOOLS
        return tool in self.mcp_tools and tool in ALL_MCP_TOOLS


class TokenService:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def bootstrap_admin(self, raw_token: str | None = None) -> str:
        """Create admin token if none exists. Returns raw token once."""
        existing = await self.db.fetchone(
            "SELECT id FROM tokens WHERE scopes LIKE '%admin%' AND revoked = 0 LIMIT 1"
        )
        if existing:
            return ""
        raw = raw_token or generate_token()
        await self.db.create_token(
            name="squidc5-admin",
            token_hash=hash_token(raw),
            scopes=["admin"],
            mcp_tools=list(ALL_MCP_TOOLS),
            created_by="system",
        )
        await self.db.audit(
            actor="system",
            actor_type="system",
            action="token.bootstrap_admin",
            details={"name": "squidc5-admin"},
        )
        return raw

    async def rename(self, token_id: str, name: str) -> bool:
        clean = (name or "").strip()
        if not clean or len(clean) > 64:
            raise ValueError("name must be 1-64 characters")
        if any(c in clean for c in "\n\r\t"):
            raise ValueError("name must not contain control characters")
        return await self.db.rename_token(token_id, clean)

    def _validate_grant(
        self,
        scopes: list[str],
        mcp_tools: list[str] | None,
        *,
        grantor_scopes: list[str] | frozenset[str] | None,
        grantor_is_admin: bool,
    ) -> tuple[list[str], list[str]]:
        """Validate scopes/tools a grantor may assign. Returns (scopes, tools)."""
        invalid = set(scopes) - SCOPES
        if invalid:
            raise ValueError(f"Invalid scopes: {sorted(invalid)}")
        if not grantor_is_admin:
            priv = set(scopes) & PRIVILEGED_SCOPES
            if priv:
                raise ValueError(f"Only admin may grant privileged scopes: {sorted(priv)}")
            if grantor_scopes is not None:
                missing = set(scopes) - set(grantor_scopes)
                if missing:
                    raise ValueError(f"Cannot grant scopes you lack: {sorted(missing)}")
        tools = list(mcp_tools) if mcp_tools is not None else []
        if "admin" in scopes and not tools and mcp_tools is None:
            tools = list(ALL_MCP_TOOLS)
        elif not tools and "mcp:connect" in scopes and mcp_tools is None:
            tools = list(DEFAULT_MCP_TOOLS)
        bad_tools = set(tools) - ALL_MCP_TOOLS
        if bad_tools:
            raise ValueError(f"Invalid MCP tools: {sorted(bad_tools)}")
        if not grantor_is_admin and tools:
            danger = {"interact_shell", "create_listener", "start_listener", "stop_listener"}
            if set(tools) & danger:
                raise ValueError(f"Only admin may grant MCP tools: {sorted(set(tools) & danger)}")
        return list(scopes), tools

    async def create(
        self,
        name: str,
        scopes: list[str],
        mcp_tools: list[str] | None = None,
        created_by: str | None = None,
        expires_at: float | None = None,
        *,
        grantor_scopes: list[str] | frozenset[str] | None = None,
        grantor_is_admin: bool = False,
    ) -> tuple[str, str]:
        scopes, tools = self._validate_grant(
            scopes,
            mcp_tools,
            grantor_scopes=grantor_scopes,
            grantor_is_admin=grantor_is_admin,
        )
        raw = generate_token()
        tid = await self.db.create_token(
            name=name,
            token_hash=hash_token(raw),
            scopes=scopes,
            mcp_tools=tools,
            created_by=created_by,
            expires_at=expires_at,
        )
        await self.db.audit(
            actor=created_by or "unknown",
            actor_type="operator",
            action="token.create",
            resource=tid,
            details={"name": name, "scopes": scopes, "mcp_tools": tools},
            risk_score=5,
        )
        return tid, raw

    async def update(
        self,
        token_id: str,
        *,
        name: str | None = None,
        scopes: list[str] | None = None,
        mcp_tools: list[str] | None = None,
        actor: str = "unknown",
        grantor_scopes: list[str] | frozenset[str] | None = None,
        grantor_is_admin: bool = False,
    ) -> dict[str, Any]:
        """Update name/scopes/mcp_tools. Does not rotate the secret."""
        row = await self.db.get_token_by_id(token_id)
        if not row or row.get("revoked"):
            raise KeyError("token not found")
        before = self.parse_row(row)
        # tokens:manage must not touch tokens that already hold privileged scopes
        if not grantor_is_admin:
            held_priv = set(before.get("scopes") or []) & PRIVILEGED_SCOPES
            if held_priv:
                raise PermissionError(
                    f"Only admin may modify tokens with privileged scopes: {sorted(held_priv)}"
                )
        new_name = before["name"]
        if name is not None:
            clean = name.strip()
            if not clean or len(clean) > 64:
                raise ValueError("name must be 1-64 characters")
            if any(c in clean for c in "\n\r\t"):
                raise ValueError("name must not contain control characters")
            new_name = clean
        new_scopes = list(before["scopes"])
        new_tools = list(before.get("mcp_tools") or [])
        if scopes is not None:
            new_scopes, validated_tools = self._validate_grant(
                scopes,
                mcp_tools if mcp_tools is not None else new_tools,
                grantor_scopes=grantor_scopes,
                grantor_is_admin=grantor_is_admin,
            )
            if mcp_tools is not None:
                new_tools = validated_tools
            elif "mcp:connect" not in new_scopes:
                new_tools = []
            else:
                # keep existing tools if still valid; else default
                keep = [t for t in new_tools if t in ALL_MCP_TOOLS]
                new_tools = keep or (
                    list(DEFAULT_MCP_TOOLS) if "mcp:connect" in new_scopes else []
                )
        elif mcp_tools is not None:
            _, new_tools = self._validate_grant(
                new_scopes,
                mcp_tools,
                grantor_scopes=grantor_scopes,
                grantor_is_admin=grantor_is_admin,
            )
        if scopes is None and mcp_tools is None and name is None:
            raise ValueError("nothing to update")
        ok = await self.db.update_token(
            token_id,
            name=new_name if name is not None else None,
            scopes=new_scopes if scopes is not None else None,
            mcp_tools=new_tools if (scopes is not None or mcp_tools is not None) else None,
        )
        if not ok:
            raise KeyError("token not found")
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="token.update",
            resource=token_id,
            details={
                "from": {"name": before["name"], "scopes": before["scopes"], "mcp_tools": before.get("mcp_tools")},
                "to": {"name": new_name, "scopes": new_scopes, "mcp_tools": new_tools},
            },
            risk_score=5,
        )
        updated = await self.db.get_token_by_id(token_id)
        assert updated is not None
        return self.parse_row(updated)

    async def authenticate(self, raw: str) -> AuthContext | None:
        # sc5_ current; ss2_ accepted for legacy tokens from pre-rebrand installs
        if not raw or not (raw.startswith("sc5_") or raw.startswith("ss2_")):
            return None
        row = await self.db.get_token_by_hash(hash_token(raw))
        if not row:
            return None
        await self.db.touch_token(row["id"])
        scopes = json.loads(row["scopes"])
        mcp_tools = json.loads(row.get("mcp_tools") or "[]")
        actor_type = "admin" if "admin" in scopes else "operator"
        if "mcp:connect" in scopes and "admin" not in scopes:
            actor_type = "external_ai"
        return AuthContext(
            token_id=row["id"],
            name=row["name"],
            scopes=scopes,
            mcp_tools=mcp_tools,
            actor_type=actor_type,
        )

    async def revoke(self, token_id: str, actor: str) -> bool:
        ok = await self.db.revoke_token(token_id)
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="token.revoke",
            resource=token_id,
            risk_score=3,
        )
        return ok

    async def roll(
        self,
        token_id: str,
        *,
        actor: str = "unknown",
        grantor_is_admin: bool = False,
        skip_privilege_check: bool = False,
        audit_action: str = "token.roll",
    ) -> tuple[dict[str, Any], str]:
        """Rotate the secret for an active token. Old secret stops working immediately.

        Returns (token_row_without_secret, new_raw_token).
        """
        row = await self.db.get_token_by_id(token_id)
        if not row or row.get("revoked"):
            raise KeyError("token not found")
        before = self.parse_row(row)
        if not skip_privilege_check and not grantor_is_admin:
            held_priv = set(before.get("scopes") or []) & PRIVILEGED_SCOPES
            if held_priv:
                raise PermissionError(
                    f"Only admin may roll tokens with privileged scopes: {sorted(held_priv)}"
                )
        raw = generate_token()
        ok = await self.db.update_token(token_id, token_hash=hash_token(raw))
        if not ok:
            raise KeyError("token not found")
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action=audit_action,
            resource=token_id,
            details={"name": before.get("name"), "scopes": before.get("scopes")},
            risk_score=6,
        )
        updated = await self.db.get_token_by_id(token_id)
        assert updated is not None
        return self.parse_row(updated), raw

    async def create_connection_ticket(
        self,
        token_id: str,
        *,
        actor: str = "unknown",
        grantor_is_admin: bool = False,
        ttl_sec: int = 3600,
        note: str = "",
    ) -> dict[str, Any]:
        """Mint a one-time connection ticket for an existing token (no secret exposed).

        Recipient redeems the ticket; server rolls the token and returns the new secret once.
        """
        import time as _time

        row = await self.db.get_token_by_id(token_id)
        if not row or row.get("revoked"):
            raise KeyError("token not found")
        parsed = self.parse_row(row)
        if not grantor_is_admin:
            held_priv = set(parsed.get("scopes") or []) & PRIVILEGED_SCOPES
            if held_priv:
                raise PermissionError(
                    f"Only admin may issue connection links for privileged tokens: {sorted(held_priv)}"
                )
        ttl = max(60, min(int(ttl_sec or 3600), 86_400))  # 1 min .. 24 h
        # sc5t_ prefix so tickets are distinct from API secrets
        raw_ticket = f"sc5t_{secrets.token_urlsafe(32)}"
        expires_at = _time.time() + ttl
        tid = await self.db.create_connection_ticket(
            ticket_hash=hash_token(raw_ticket),
            token_id=token_id,
            created_by=actor,
            expires_at=expires_at,
            note=note,
        )
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="token.connection_ticket",
            resource=token_id,
            details={
                "ticket_id": tid,
                "expires_at": expires_at,
                "ttl_sec": ttl,
                "name": parsed.get("name"),
            },
            risk_score=4,
        )
        return {
            "ticket_id": tid,
            "ticket": raw_ticket,
            "token_id": token_id,
            "name": parsed.get("name"),
            "scopes": parsed.get("scopes") or [],
            "expires_at": expires_at,
            "ttl_sec": ttl,
        }

    async def redeem_connection_ticket(self, raw_ticket: str) -> dict[str, Any]:
        """Redeem a one-time ticket: roll target token and return new secret once."""
        import time as _time

        raw = (raw_ticket or "").strip()
        if not raw.startswith("sc5t_"):
            raise ValueError("invalid ticket")
        row = await self.db.get_connection_ticket_by_hash(hash_token(raw))
        if not row:
            raise KeyError("ticket not found")
        if row.get("used_at") is not None:
            raise ValueError("ticket already used")
        if float(row.get("expires_at") or 0) < _time.time():
            raise ValueError("ticket expired")
        token_id = row["token_id"]
        # Mark used first (single-use); if roll fails, ticket stays consumed
        marked = await self.db.mark_connection_ticket_used(row["id"])
        if not marked:
            raise ValueError("ticket already used")
        try:
            tok_row, new_raw = await self.roll(
                token_id,
                actor=row.get("created_by") or "ticket",
                skip_privilege_check=True,
                audit_action="token.roll_via_ticket",
            )
        except KeyError as e:
            raise ValueError("target token missing or revoked") from e
        await self.db.audit(
            actor="ticket",
            actor_type="system",
            action="token.connection_ticket_redeem",
            resource=token_id,
            details={"ticket_id": row["id"], "name": tok_row.get("name")},
            risk_score=5,
        )
        return {
            "token": new_raw,
            "id": tok_row["id"],
            "name": tok_row.get("name"),
            "scopes": tok_row.get("scopes") or [],
            "rolled": True,
        }

    def parse_row(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        out["scopes"] = json.loads(row["scopes"]) if isinstance(row["scopes"], str) else row["scopes"]
        out["mcp_tools"] = (
            json.loads(row["mcp_tools"]) if isinstance(row["mcp_tools"], str) else row["mcp_tools"]
        )
        return out
