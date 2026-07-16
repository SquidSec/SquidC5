"""
MCP interface for external AI agents.

External AIs are heavily restricted:
- Only explicitly allow-listed tools per token
- Deterministic single-tool calls preferred
- All invocations audited via policy engine
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from squidsec2.auth.tokens import AuthContext
from squidsec2.core.state import AppState


class MCPToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    chain_length: int = 1


class MCPToolResult(BaseModel):
    ok: bool
    tool: str
    result: Any = None
    error: str | None = None


def _get_state(request: Request) -> AppState:
    return request.app.state.app_state


async def _auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> AuthContext:
    state: AppState = request.app.state.app_state
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


def build_mcp_router() -> APIRouter:
    router = APIRouter(prefix="/mcp", tags=["mcp"])

    @router.get("/tools")
    async def list_tools(
        request: Request,
        auth: AuthContext = Depends(_auth),
    ) -> dict[str, Any]:
        """Return only tools allow-listed for this token (strict restriction)."""
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
                "note": "External AI must call tools explicitly; autonomous chaining is denied by default.",
            },
        }

    @router.post("/call", response_model=MCPToolResult)
    async def call_tool(
        body: MCPToolCall,
        request: Request,
        auth: AuthContext = Depends(_auth),
    ) -> MCPToolResult:
        state = _get_state(request)
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

        decision = await state.policy.check_and_audit(
            auth,
            action=f"mcp.{body.name}",
            extra={"chain_length": body.chain_length, "args_keys": list(body.arguments.keys())},
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
        except Exception as exc:
            await state.db.audit(
                actor=auth.name,
                actor_type=auth.actor_type,
                action="mcp.call.error",
                details={"tool": body.name, "error": str(exc)},
                allowed=False,
                risk_score=4,
            )
            return MCPToolResult(ok=False, tool=body.name, error=str(exc))

    @router.get("/health")
    async def mcp_health() -> dict[str, str]:
        return {"status": "ok", "protocol": "squidsec2-mcp-lite"}

    return router


def _tool_catalog() -> list[dict[str, Any]]:
    return [
        {"name": "list_sessions", "description": "List C2 sessions", "inputSchema": {"type": "object", "properties": {"status": {"type": "string"}}}},
        {"name": "get_session", "description": "Get session by id", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}}, "required": ["session_id"]}},
        {"name": "list_tasks", "description": "List tasks", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}}}},
        {"name": "create_task", "description": "Task a session", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}, "command": {"type": "string"}, "args": {"type": "object"}}, "required": ["session_id", "command"]}},
        {"name": "list_listeners", "description": "List listeners", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "create_listener", "description": "Create listener", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "kind": {"type": "string"}, "port": {"type": "integer"}, "host": {"type": "string"}}, "required": ["name", "kind", "port"]}},
        {"name": "start_listener", "description": "Start listener", "inputSchema": {"type": "object", "properties": {"listener_id": {"type": "string"}}, "required": ["listener_id"]}},
        {"name": "stop_listener", "description": "Stop listener", "inputSchema": {"type": "object", "properties": {"listener_id": {"type": "string"}}, "required": ["listener_id"]}},
        {"name": "generate_payload", "description": "Generate payload from template", "inputSchema": {"type": "object", "properties": {"template": {"type": "string"}, "host": {"type": "string"}, "port": {"type": "integer"}}, "required": ["template", "host", "port"]}},
        {"name": "get_metrics", "description": "Get metrics snapshot", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "list_audit", "description": "List audit entries", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
        {"name": "interact_shell", "description": "Send command to reverse shell session", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}, "command": {"type": "string"}}, "required": ["session_id", "command"]}},
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
        return await state.tasks.create(
            session_id=args["session_id"],
            command=args["command"],
            args=args.get("args"),
            created_by=auth.name,
        )

    async def list_listeners(args: dict[str, Any]) -> Any:
        return await state.listeners.list()

    async def create_listener(args: dict[str, Any]) -> Any:
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
        ok = await state.listeners.send_shell(args["session_id"], args["command"])
        if not ok:
            raise RuntimeError("No live reverse shell for session")
        return {"sent": True, "session_id": args["session_id"]}

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
