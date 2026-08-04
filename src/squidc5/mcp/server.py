"""
MCP interface for external AI agents.

External AIs are heavily restricted:
- Only explicitly allow-listed tools per token
- Same REST scopes + claim locks + HITL policy actions as HTTP API
- Server-side chain budget (client chain_length ignored for autonomy)
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from squidc5.auth.tokens import AuthContext
from squidc5.core.state import AppState

# Server-side per-token call budget (X05)
_MCP_BUDGET: dict[str, list[float]] = {}
_MCP_MAX_PER_MIN = 30


class MCPToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    chain_length: int = 1  # ignored for enforcement; server budget applies


class MCPToolResult(BaseModel):
    ok: bool
    tool: str
    result: Any = None
    error: str | None = None


def _get_state(request: Request) -> AppState:
    return request.app.state.app_state


def _check_budget(token_id: str) -> bool:
    now = time.time()
    window = _MCP_BUDGET.setdefault(token_id, [])
    _MCP_BUDGET[token_id] = [t for t in window if now - t < 60.0]
    if len(_MCP_BUDGET[token_id]) >= _MCP_MAX_PER_MIN:
        return False
    _MCP_BUDGET[token_id].append(now)
    return True


async def _auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> AuthContext:
    state: AppState = request.app.state.app_state
    if hasattr(state, "features") and not await state.features.enabled("mcp_enabled"):
        raise HTTPException(
            403,
            "MCP disabled by feature flag (enable Admin → Features → mcp_enabled)",
        )
    if not state.settings.mcp_enabled:
        raise HTTPException(
            403,
            "MCP disabled in server settings (set SQUIDC5_MCP_ENABLED=true and restart)",
        )
    raw = None
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    elif x_api_token:
        raw = x_api_token.strip()
    if not raw:
        raise HTTPException(401, "Missing token")
    ctx = await state.tokens.authenticate(raw)
    if not ctx:
        raise HTTPException(401, "Invalid token")
    if not ctx.has_scope("mcp:connect") and not ctx.has_scope("admin"):
        raise HTTPException(403, "mcp:connect scope required")
    return ctx


# tool -> required scopes (any) + policy action name
_TOOL_GATES: dict[str, tuple[list[str], str]] = {
    "list_sessions": (["sessions:read", "admin"], "sessions.list"),
    "get_session": (["sessions:read", "admin"], "sessions.list"),
    "list_tasks": (["tasks:read", "admin"], "tasks.list"),
    "create_task": (["tasks:write", "admin"], "tasks.create"),
    "list_listeners": (["listeners:read", "admin"], "listeners.list"),
    "create_listener": (["listeners:write", "admin"], "listeners.create"),
    "start_listener": (["listeners:write", "admin"], "listeners.start"),
    "stop_listener": (["listeners:write", "admin"], "listeners.stop"),
    "generate_payload": (["payloads:generate", "admin"], "payloads.generate"),
    "get_metrics": (["metrics:read", "admin"], "metrics.read"),
    "list_audit": (["audit:read", "admin"], "audit.read"),
    "interact_shell": (["shell:interact", "admin"], "shell.interact"),
}


def build_mcp_router() -> APIRouter:
    router = APIRouter(prefix="/mcp", tags=["mcp"])

    @router.get("/tools")
    async def list_tools(
        request: Request,
        auth: AuthContext = Depends(_auth),
    ) -> dict[str, Any]:
        state = _get_state(request)
        allowed = set(auth.mcp_tools) if "admin" not in auth.scopes else None
        catalog = _tool_catalog()
        tools = []
        for t in catalog:
            if allowed is not None and t["name"] not in allowed:
                continue
            if not auth.can_mcp_tool(t["name"]):
                continue
            tools.append(t)
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="mcp.list_tools",
            details={"count": len(tools)},
        )
        return {
            "tools": tools,
            "policy": {
                "deterministic": True,
                "max_chain_length": 1,
                "server_budget_per_min": _MCP_MAX_PER_MIN,
                "note": "External AI must call tools explicitly; server enforces rate budget.",
            },
        }

    @router.post("/call", response_model=MCPToolResult)
    async def call_tool(
        body: MCPToolCall,
        request: Request,
        auth: AuthContext = Depends(_auth),
    ) -> MCPToolResult:
        state = _get_state(request)
        if hasattr(state, "features") and not await state.features.enabled("mcp_enabled"):
            return MCPToolResult(ok=False, tool=body.name, error="MCP disabled by feature flag")
        if not auth.can_mcp_tool(body.name):
            await state.db.audit(
                actor=auth.name,
                actor_type=auth.actor_type,
                action="mcp.call.denied",
                details={"tool": body.name},
                allowed=False,
                risk_score=6,
            )
            return MCPToolResult(ok=False, tool=body.name, error="Tool not allow-listed for this token")

        if not _check_budget(auth.token_id):
            return MCPToolResult(ok=False, tool=body.name, error="MCP rate budget exceeded")

        gate = _TOOL_GATES.get(body.name)
        if not gate:
            return MCPToolResult(ok=False, tool=body.name, error="Unknown tool")
        need_scopes, policy_action = gate
        if not any(auth.has_scope(s) for s in need_scopes) and not auth.has_scope("admin"):
            return MCPToolResult(
                ok=False, tool=body.name, error=f"Requires one of scopes: {need_scopes}"
            )

        extra: dict[str, Any] = {
            "args_keys": list(body.arguments.keys()),
            "command": body.arguments.get("command"),
            "hitl_request_id": body.arguments.get("hitl_request_id"),
        }
        # X05: ignore client chain_length for autonomy (always treat as 1)
        decision = await state.policy.check_and_audit(
            auth,
            action=policy_action,
            resource=body.arguments.get("session_id"),
            extra=extra,
        )
        if not decision.allowed:
            return MCPToolResult(ok=False, tool=body.name, error=decision.reason)

        handlers = _handlers(state, auth)
        handler = handlers.get(body.name)
        if not handler:
            return MCPToolResult(ok=False, tool=body.name, error="Unknown tool")

        try:
            result = await handler(body.arguments)
            await state.metrics.incr("mcp.calls")
            await state.metrics.emit("mcp.call", {"tool": body.name, "actor": auth.name})
            return MCPToolResult(ok=True, tool=body.name, result=result)
        except PermissionError as exc:
            return MCPToolResult(ok=False, tool=body.name, error=str(exc))
        except Exception as exc:
            await state.db.audit(
                actor=auth.name,
                actor_type=auth.actor_type,
                action="mcp.call.error",
                details={"tool": body.name, "error": type(exc).__name__},
                allowed=False,
                risk_score=4,
            )
            return MCPToolResult(ok=False, tool=body.name, error="tool error")

    @router.get("/health")
    async def mcp_health(request: Request) -> dict[str, str]:
        # L13: no unauth fingerprint when MCP off
        state = _get_state(request)
        if not state.settings.mcp_enabled:
            raise HTTPException(404, "not found")
        if hasattr(state, "features") and not await state.features.enabled("mcp_enabled"):
            raise HTTPException(404, "not found")
        raise HTTPException(401, "auth required")

    return router


def _tool_catalog() -> list[dict[str, Any]]:
    return [
        {"name": "list_sessions", "description": "List C2 sessions", "inputSchema": {"type": "object", "properties": {"status": {"type": "string"}}}},
        {"name": "get_session", "description": "Get session by id", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}}, "required": ["session_id"]}},
        {"name": "list_tasks", "description": "List tasks", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}}}},
        {"name": "create_task", "description": "Task a session", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}, "command": {"type": "string"}, "args": {"type": "object"}, "hitl_request_id": {"type": "string"}}, "required": ["session_id", "command"]}},
        {"name": "list_listeners", "description": "List listeners", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "create_listener", "description": "Create listener", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "kind": {"type": "string"}, "port": {"type": "integer"}, "host": {"type": "string"}}, "required": ["name", "kind", "port"]}},
        {"name": "start_listener", "description": "Start listener", "inputSchema": {"type": "object", "properties": {"listener_id": {"type": "string"}}, "required": ["listener_id"]}},
        {"name": "stop_listener", "description": "Stop listener", "inputSchema": {"type": "object", "properties": {"listener_id": {"type": "string"}}, "required": ["listener_id"]}},
        {"name": "generate_payload", "description": "Generate payload from template", "inputSchema": {"type": "object", "properties": {"template": {"type": "string"}, "host": {"type": "string"}, "port": {"type": "integer"}}, "required": ["template", "host", "port"]}},
        {"name": "get_metrics", "description": "Get metrics snapshot", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "list_audit", "description": "List audit entries", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
        {"name": "interact_shell", "description": "Send command to reverse shell session", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}, "command": {"type": "string"}, "hitl_request_id": {"type": "string"}}, "required": ["session_id", "command"]}},
    ]


def _handlers(state: AppState, auth: AuthContext) -> dict[str, Callable[[dict[str, Any]], Awaitable[Any]]]:
    async def list_sessions(args: dict[str, Any]) -> Any:
        return await state.sessions.list(status=args.get("status"))

    async def get_session(args: dict[str, Any]) -> Any:
        s = await state.sessions.get(args["session_id"])
        if not s:
            raise KeyError("session not found")
        return s

    async def list_tasks(args: dict[str, Any]) -> Any:
        return await state.tasks.list(session_id=args.get("session_id"))

    async def create_task(args: dict[str, Any]) -> Any:
        sid = args["session_id"]
        await state.teams.assert_write_access(sid, auth.name, is_admin=auth.has_scope("admin"))
        return await state.tasks.create(
            session_id=sid,
            command=args["command"],
            args=args.get("args"),
            created_by=auth.name,
        )

    async def list_listeners(args: dict[str, Any]) -> Any:
        return await state.listeners.list()

    async def create_listener(args: dict[str, Any]) -> Any:
        if not await state.features.enabled("http_listeners") and args.get("kind") == "http":
            raise PermissionError("HTTP listeners disabled")
        if args.get("kind") in ("tcp", "reverse_shell") and not await state.features.enabled(
            "reverse_shell_listeners"
        ):
            raise PermissionError("Reverse-shell listeners disabled")
        return await state.listeners.create(
            name=args["name"],
            kind=args["kind"],
            port=int(args["port"]),
            host=args.get("host", "0.0.0.0"),
        )

    async def start_listener(args: dict[str, Any]) -> Any:
        return await state.listeners.start(args["listener_id"])

    async def stop_listener(args: dict[str, Any]) -> Any:
        return await state.listeners.stop(args["listener_id"])

    async def generate_payload(args: dict[str, Any]) -> Any:
        if not await state.features.enabled("payloads_generate"):
            raise PermissionError("Payload generation disabled")
        return state.payloads.generate(
            template=args["template"],
            host=args["host"],
            port=int(args["port"]),
        )

    async def get_metrics(args: dict[str, Any]) -> Any:
        return await state.metrics.snapshot()

    async def list_audit(args: dict[str, Any]) -> Any:
        return await state.audit.list(limit=int(args.get("limit", 50)))

    async def interact_shell(args: dict[str, Any]) -> Any:
        sid = args["session_id"]
        await state.teams.assert_write_access(sid, auth.name, is_admin=auth.has_scope("admin"))
        ok = await state.listeners.send_shell(sid, args["command"])
        if not ok:
            raise RuntimeError("No live reverse shell for session")
        return {"sent": True, "session_id": sid}

    return {
        "list_sessions": list_sessions,
        "get_session": get_session,
        "list_tasks": list_tasks,
        "create_task": create_task,
        "list_listeners": list_listeners,
        "create_listener": create_listener,
        "start_listener": start_listener,
        "stop_listener": stop_listener,
        "generate_payload": generate_payload,
        "get_metrics": get_metrics,
        "list_audit": list_audit,
        "interact_shell": interact_shell,
    }
