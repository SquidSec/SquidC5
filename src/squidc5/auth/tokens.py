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
        "list_tasks",
        "create_task",
        "list_listeners",
        "create_listener",
        "start_listener",
        "stop_listener",
        "generate_payload",
        "get_metrics",
        "list_audit",
        "interact_shell",
    }
)


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
            name="bootstrap-admin",
            token_hash=hash_token(raw),
            scopes=["admin"],
            mcp_tools=list(ALL_MCP_TOOLS),
            created_by="system",
        )
        await self.db.audit(
            actor="system",
            actor_type="system",
            action="token.bootstrap_admin",
            details={"name": "bootstrap-admin"},
        )
        return raw

    # Scopes only a true admin may grant
    PRIVILEGED_SCOPES = frozenset(
        {"admin", "tokens:manage", "policy:manage", "llm:manage", "plugins:manage"}
    )

    async def rename(self, token_id: str, name: str) -> bool:
        clean = (name or "").strip()
        if not clean or len(clean) > 64:
            raise ValueError("name must be 1-64 characters")
        if any(c in clean for c in "\n\r\t"):
            raise ValueError("name must not contain control characters")
        return await self.db.rename_token(token_id, clean)

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
        invalid = set(scopes) - SCOPES
        if invalid:
            raise ValueError(f"Invalid scopes: {sorted(invalid)}")
        # C01: cannot mint privileges you lack
        if not grantor_is_admin:
            priv = set(scopes) & self.PRIVILEGED_SCOPES
            if priv:
                raise ValueError(f"Only admin may grant privileged scopes: {sorted(priv)}")
            if grantor_scopes is not None:
                missing = set(scopes) - set(grantor_scopes)
                if missing:
                    raise ValueError(f"Cannot grant scopes you lack: {sorted(missing)}")
        tools = list(mcp_tools) if mcp_tools is not None else []
        if "admin" in scopes and not tools:
            tools = list(ALL_MCP_TOOLS)
        elif not tools and "mcp:connect" in scopes:
            tools = list(DEFAULT_MCP_TOOLS)
        bad_tools = set(tools) - ALL_MCP_TOOLS
        if bad_tools:
            raise ValueError(f"Invalid MCP tools: {sorted(bad_tools)}")
        # Non-admin cannot grant dangerous MCP tools beyond their own list
        if not grantor_is_admin and mcp_tools:
            # strip interact_shell / listener mutators unless grantor is admin
            danger = {"interact_shell", "create_listener", "start_listener", "stop_listener"}
            if set(tools) & danger:
                raise ValueError(f"Only admin may grant MCP tools: {sorted(set(tools) & danger)}")
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

    def parse_row(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        out["scopes"] = json.loads(row["scopes"]) if isinstance(row["scopes"], str) else row["scopes"]
        out["mcp_tools"] = (
            json.loads(row["mcp_tools"]) if isinstance(row["mcp_tools"], str) else row["mcp_tools"]
        )
        return out
