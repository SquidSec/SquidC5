"""REST API routes for operators, implants, and admin."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from squidsec2.api.deps import get_auth, get_state, require_scope
from squidsec2.auth.tokens import ALL_MCP_TOOLS, DEFAULT_MCP_TOOLS, SCOPES, AuthContext

# --- Request models ---


class TokenCreate(BaseModel):
    name: str
    scopes: list[str]
    mcp_tools: list[str] | None = None


class ListenerCreate(BaseModel):
    name: str
    kind: str = "http"
    host: str = "0.0.0.0"
    port: int
    config: dict[str, Any] = Field(default_factory=dict)


class TaskCreate(BaseModel):
    session_id: str
    command: str
    args: dict[str, Any] = Field(default_factory=dict)
    hitl_approved: bool = False


class PayloadRequest(BaseModel):
    template: str
    host: str
    port: int
    interval: int = 5


class LLMConfig(BaseModel):
    name: str
    provider: str = "openai"
    model: str
    base_url: str | None = None
    api_key: str | None = None
    capabilities: list[str] | None = None


class AIRunRequest(BaseModel):
    capability: str
    user_data: str = ""
    llm_id: str | None = None


class ShellCommand(BaseModel):
    session_id: str
    command: str
    hitl_approved: bool = False


class BeaconIn(BaseModel):
    session_id: str | None = None
    hostname: str | None = None
    username: str | None = None
    os_info: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskResultIn(BaseModel):
    task_id: str
    result: str
    status: str = "completed"


class PolicyUpdate(BaseModel):
    rules: dict[str, Any]


def build_api_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")

    # ----- Health / meta -----

    @api.get("/health")
    async def health(request: Request) -> dict[str, Any]:
        state = get_state(request)
        return {
            "status": "ok",
            "app": state.settings.app_name,
            "version": "0.1.0",
        }

    @api.get("/meta")
    async def meta(auth: AuthContext = Depends(get_auth)) -> dict[str, Any]:
        return {
            "scopes": sorted(SCOPES),
            "default_mcp_tools": sorted(DEFAULT_MCP_TOOLS),
            "all_mcp_tools": sorted(ALL_MCP_TOOLS),
            "actor": auth.name,
            "actor_type": auth.actor_type,
        }

    # ----- Tokens -----

    @api.post("/tokens")
    async def create_token(
        body: TokenCreate,
        request: Request,
        auth: AuthContext = Depends(require_scope("tokens:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(auth, "tokens.create", extra={"name": body.name})
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            tid, raw = await state.tokens.create(
                name=body.name,
                scopes=body.scopes,
                mcp_tools=body.mcp_tools,
                created_by=auth.name,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return {"id": tid, "token": raw, "name": body.name, "scopes": body.scopes}

    @api.get("/tokens")
    async def list_tokens(
        request: Request,
        auth: AuthContext = Depends(require_scope("tokens:manage", "admin")),
    ) -> list[dict[str, Any]]:
        state = get_state(request)
        rows = await state.db.list_tokens()
        return [state.tokens.parse_row(r) for r in rows]

    @api.delete("/tokens/{token_id}")
    async def revoke_token(
        token_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("tokens:manage", "admin")),
    ) -> dict[str, bool]:
        state = get_state(request)
        ok = await state.tokens.revoke(token_id, auth.name)
        return {"revoked": ok}

    # ----- Sessions -----

    @api.get("/sessions")
    async def list_sessions(
        request: Request,
        status: str | None = None,
        auth: AuthContext = Depends(require_scope("sessions:read", "admin")),
    ) -> list[dict[str, Any]]:
        state = get_state(request)
        await state.policy.check_and_audit(auth, "sessions.list")
        return await state.sessions.list(status=status)

    @api.get("/sessions/{session_id}")
    async def get_session(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        s = await state.sessions.get(session_id)
        if not s:
            raise HTTPException(404, "session not found")
        return s

    @api.post("/sessions/{session_id}/close")
    async def close_session(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:write", "admin")),
    ) -> dict[str, str]:
        state = get_state(request)
        await state.sessions.close(session_id)
        return {"status": "closed", "id": session_id}

    # ----- Tasks -----

    @api.get("/tasks")
    async def list_tasks(
        request: Request,
        session_id: str | None = None,
        auth: AuthContext = Depends(require_scope("tasks:read", "admin")),
    ) -> list[dict[str, Any]]:
        state = get_state(request)
        return await state.tasks.list(session_id=session_id)

    @api.post("/tasks")
    async def create_task(
        body: TaskCreate,
        request: Request,
        auth: AuthContext = Depends(require_scope("tasks:write", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(
            auth,
            "tasks.create",
            resource=body.session_id,
            extra={"hitl_approved": body.hitl_approved, "command": body.command[:100]},
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            return await state.tasks.create(
                session_id=body.session_id,
                command=body.command,
                args=body.args,
                created_by=auth.name,
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @api.get("/tasks/{task_id}")
    async def get_task(
        task_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("tasks:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        t = await state.tasks.get(task_id)
        if not t:
            raise HTTPException(404, "task not found")
        return t

    # ----- Listeners -----

    @api.get("/listeners")
    async def list_listeners(
        request: Request,
        auth: AuthContext = Depends(require_scope("listeners:read", "admin")),
    ) -> list[dict[str, Any]]:
        return await get_state(request).listeners.list()

    @api.post("/listeners")
    async def create_listener(
        body: ListenerCreate,
        request: Request,
        auth: AuthContext = Depends(require_scope("listeners:write", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(
            auth, "listeners.create", extra={"port": body.port, "kind": body.kind}
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            return await state.listeners.create(
                name=body.name, kind=body.kind, port=body.port, host=body.host, config=body.config
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @api.post("/listeners/{listener_id}/start")
    async def start_listener(
        listener_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("listeners:write", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(auth, "listeners.start", resource=listener_id)
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            return await state.listeners.start(listener_id)
        except KeyError:
            raise HTTPException(404, "listener not found") from None
        except OSError as e:
            raise HTTPException(400, f"bind failed: {e}") from e

    @api.post("/listeners/{listener_id}/stop")
    async def stop_listener(
        listener_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("listeners:write", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        try:
            return await state.listeners.stop(listener_id)
        except KeyError:
            raise HTTPException(404, "listener not found") from None

    @api.delete("/listeners/{listener_id}")
    async def delete_listener(
        listener_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("listeners:write", "admin")),
    ) -> dict[str, bool]:
        ok = await get_state(request).listeners.delete(listener_id)
        return {"deleted": ok}

    # ----- Payloads -----

    @api.get("/payloads/templates")
    async def payload_templates(
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, list[str]]:
        from squidsec2.payloads.generator import PayloadGenerator

        return {"templates": PayloadGenerator().list_templates()}

    @api.post("/payloads/generate")
    async def generate_payload(
        body: PayloadRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(
            auth, "payloads.generate", extra={"template": body.template}
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            result = state.payloads.generate(
                template=body.template, host=body.host, port=body.port, interval=body.interval
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.metrics.incr("payloads.generated")
        return result

    # ----- Shell interact -----

    @api.post("/shell/command")
    async def shell_command(
        body: ShellCommand,
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(
            auth,
            "shell.interact",
            resource=body.session_id,
            extra={"hitl_approved": body.hitl_approved},
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        ok = await state.listeners.send_shell(body.session_id, body.command)
        if not ok:
            raise HTTPException(404, "No live reverse shell for session")
        return {"sent": True}

    # ----- Metrics / audit / events -----

    @api.get("/metrics")
    async def metrics(
        request: Request,
        auth: AuthContext = Depends(require_scope("metrics:read", "admin")),
    ) -> dict[str, Any]:
        return await get_state(request).metrics.snapshot()

    @api.get("/audit")
    async def audit_list(
        request: Request,
        limit: int = 100,
        offset: int = 0,
        auth: AuthContext = Depends(require_scope("audit:read", "admin")),
    ) -> list[dict[str, Any]]:
        return await get_state(request).audit.list(limit=limit, offset=offset)

    @api.get("/events/stream")
    async def events_stream(
        request: Request,
        auth: AuthContext = Depends(require_scope("metrics:read", "admin")),
    ) -> StreamingResponse:
        state = get_state(request)
        queue = state.metrics.subscribe()

        async def gen():
            try:
                yield f"data: {json.dumps({'type': 'connected'})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except TimeoutError:
                        yield f"data: {json.dumps({'type': 'ping'})}\n\n"
            finally:
                state.metrics.unsubscribe(queue)

        return StreamingResponse(gen(), media_type="text/event-stream")

    # ----- Policy -----

    @api.get("/policy")
    async def get_policy(
        request: Request,
        auth: AuthContext = Depends(require_scope("policy:manage", "admin")),
    ) -> dict[str, Any]:
        return await get_state(request).policy.get_rules()

    @api.put("/policy")
    async def update_policy(
        body: PolicyUpdate,
        request: Request,
        auth: AuthContext = Depends(require_scope("policy:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        await state.policy.update(body.rules, auth.name)
        return await state.policy.get_rules()

    # ----- Admin AI / LLM -----

    @api.get("/llm")
    async def list_llm(
        request: Request,
        auth: AuthContext = Depends(require_scope("llm:manage", "admin")),
    ) -> list[dict[str, Any]]:
        return await get_state(request).admin_ai.list_llms()

    @api.post("/llm")
    async def configure_llm(
        body: LLMConfig,
        request: Request,
        auth: AuthContext = Depends(require_scope("llm:manage", "admin")),
    ) -> dict[str, str]:
        state = get_state(request)
        lid = await state.admin_ai.configure_llm(
            name=body.name,
            provider=body.provider,
            model=body.model,
            base_url=body.base_url,
            api_key=body.api_key,
            capabilities=body.capabilities,
        )
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="llm.configure",
            resource=lid,
            details={"name": body.name, "model": body.model},
            risk_score=4,
        )
        return {"id": lid}

    @api.post("/ai/run")
    async def ai_run(
        body: AIRunRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("ai:use", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        decision = await state.policy.check_and_audit(
            auth, "ai.admin", extra={"capability": body.capability}
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            return await state.admin_ai.run(
                capability=body.capability,
                user_data=body.user_data,
                actor=auth.name,
                llm_id=body.llm_id,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    # ----- Implant (no auth — session-bound beacon) -----

    implant = APIRouter(prefix="/implant", tags=["implant"])

    @implant.post("/beacon")
    async def beacon(body: BeaconIn, request: Request) -> dict[str, Any]:
        state = get_state(request)
        client = request.client.host if request.client else None
        if body.session_id:
            existing = await state.sessions.get(body.session_id)
            if existing and existing["status"] == "active":
                await state.sessions.heartbeat(
                    body.session_id,
                    hostname=body.hostname,
                    username=body.username,
                    os_info=body.os_info,
                )
                sid = body.session_id
            else:
                sid = await state.sessions.register(
                    kind="beacon",
                    remote_addr=client,
                    hostname=body.hostname,
                    username=body.username,
                    os_info=body.os_info,
                    metadata=body.metadata,
                )
        else:
            sid = await state.sessions.register(
                kind="beacon",
                remote_addr=client,
                hostname=body.hostname,
                username=body.username,
                os_info=body.os_info,
                metadata=body.metadata,
            )
        task = await state.tasks.poll(sid)
        return {"session_id": sid, "task": task}

    @implant.post("/beacon/result")
    async def beacon_result(body: TaskResultIn, request: Request) -> dict[str, str]:
        state = get_state(request)
        await state.tasks.complete(body.task_id, body.result, body.status)
        return {"status": "ok"}

    api.include_router(implant)
    return api
