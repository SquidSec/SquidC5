"""SquidC5 application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from squidc5 import __version__
from squidc5.ai.admin_ai import AdminAI
from squidc5.api.routes import build_api_router
from squidc5.audit.trail import AuditTrail
from squidc5.auth.tokens import TokenService
from squidc5.collab.teams import TeamService
from squidc5.config import Settings, get_settings
from squidc5.core.state import AppState
from squidc5.db.store import Database
from squidc5.features import FeatureFlags
from squidc5.implants.registry import ImplantRegistry
from squidc5.listeners.manager import ListenerManager
from squidc5.logging_setup import configure_logging
from squidc5.mcp.server import build_mcp_router
from squidc5.metrics.collector import MetricsCollector
from squidc5.oast.store import OastService
from squidc5.observability.timeline import TimelineService
from squidc5.paths import web_dir
from squidc5.payloads.generator import PayloadGenerator
from squidc5.plugins.registry import PluginRegistry
from squidc5.policy.engine import PolicyEngine
from squidc5.profiles.engine import ProfileEngine
from squidc5.sessions.manager import SessionManager
from squidc5.tasking.manager import TaskManager

configure_logging(json_logs=False, debug=False)
log = logging.getLogger("squidc5")


async def build_state(settings: Settings) -> AppState:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.resolve_db_path())
    await db.connect()

    tokens = TokenService(db)
    policy = PolicyEngine(db)
    await policy.load()
    audit = AuditTrail(db)
    metrics = MetricsCollector(db, buffer_size=settings.event_buffer_size)
    sessions = SessionManager(db, metrics)
    tasks = TaskManager(db, metrics)
    payloads = PayloadGenerator()
    from squidc5.crypto.secrets import SecretBox, resolve_secrets_key

    secret_box = SecretBox(
        resolve_secrets_key(explicit=settings.secrets_key, data_dir=settings.data_dir)
    )
    admin_ai = AdminAI(db, metrics, policy, secrets=secret_box)
    features = FeatureFlags(db)
    await features.load()
    profiles = ProfileEngine(db)
    await profiles.load()
    implants = ImplantRegistry()
    teams = TeamService(db)
    from squidc5.plugins.registry import resolve_plugin_signing_secret

    plugin_secret = resolve_plugin_signing_secret(
        explicit=settings.plugin_signing_secret,
        data_dir=settings.data_dir,
        debug=settings.debug,
    )
    plugins = PluginRegistry(signing_secret=plugin_secret, db=db)
    await plugins.load_from_db()
    timeline = TimelineService(db)
    oast = OastService(
        db,
        metrics,
        zone=settings.oast_zone,
        public_host=settings.public_host or settings.oast_zone,
        public_ip=settings.public_ip or settings.public_host or "127.0.0.1",
        http_port=settings.oast_http_port,
        rate_limit=settings.oast_rate_limit_per_minute,
    )
    from squidc5.ai.chain import AIChainRunner

    ai_chain = AIChainRunner(admin_ai, max_steps=3)

    listeners = ListenerManager(
        db,
        metrics,
        session_factory=sessions.register,
        reject_factory=sessions.reject,
        auto_stabilize=settings.shell_auto_stabilize,
        public_host=settings.public_host,
        stabilize_delay_sec=settings.shell_stabilize_delay_sec,
        probe_wait_sec=settings.shell_probe_wait_sec,
    )
    listeners.task_poll = tasks.poll
    listeners.task_complete = tasks.complete
    listeners.oast = oast if settings.oast_enabled else None
    listeners.oast_zone = settings.oast_zone
    listeners.public_ip = settings.public_ip or settings.public_host
    sessions.interactive_check = listeners.is_live
    sessions.verified_check = listeners.is_verified
    sessions.exec_probe = listeners.probe_exec
    sessions.drop_channel = listeners.drop_channel
    listeners.feature_check = features.enabled
    listeners.profile_engine = profiles
    # After restart, reverse_shell rows can still say active with no socket
    orphaned = await sessions.close_orphaned_shells(probe=False)
    if orphaned:
        log.warning("Closed %s orphaned reverse-shell session(s) with no live TCP channel", orphaned)

    admin_once = await tokens.bootstrap_admin(settings.admin_token_bootstrap)
    if admin_once:
        token_file = settings.data_dir / "admin_token.txt"
        token_file.write_text(admin_once + "\n", encoding="utf-8")
        try:
            token_file.chmod(0o600)
        except OSError:
            log.warning("Could not chmod 0600 on %s", token_file)
        log.warning("Bootstrap admin token written to %s — store securely and rotate", token_file)

    from squidc5.implants.crypto import resolve_implant_psk

    implant_psk = resolve_implant_psk(
        explicit=settings.implant_psk,
        data_dir=settings.data_dir,
    )

    return AppState(
        settings=settings,
        db=db,
        tokens=tokens,
        policy=policy,
        audit=audit,
        metrics=metrics,
        sessions=sessions,
        listeners=listeners,
        tasks=tasks,
        payloads=payloads,
        admin_ai=admin_ai,
        features=features,
        profiles=profiles,
        implants=implants,
        teams=teams,
        plugins=plugins,
        timeline=timeline,
        oast=oast,
        ai_chain=ai_chain,
        admin_token_once=admin_once,
        implant_psk=implant_psk,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(json_logs=settings.log_json, debug=settings.debug)
    for w in settings.validate_runtime():
        log.warning("config: %s", w)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state = await build_state(settings)
        app.state.app_state = state
        try:
            restore = await state.listeners.restore_running()
        except Exception:
            log.exception("Listener restore failed")
            restore = {"restored": [], "errors": [{"error": "restore crashed"}]}
        await state.db.audit(
            actor="system",
            actor_type="system",
            action="server.start",
            details={
                "version": __version__,
                "port": settings.port,
                "listeners_restored": restore.get("restored") or [],
                "listeners_restore_errors": restore.get("errors") or [],
            },
        )
        log.info("SquidC5 v%s listening on %s:%s", __version__, settings.host, settings.port)
        yield
        await state.listeners.stop_all()
        await state.db.audit(actor="system", actor_type="system", action="server.stop")
        await state.db.close()
        log.info("SquidC5 shutdown complete")

    # Hardened surface: no public Swagger/ReDoc/OpenAPI by default.
    # (Military / red-team deployment — do not advertise the API map.)
    app = FastAPI(
        title="SquidC5",
        description="Authorized operations only",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    from squidc5.api.rate_limit import (
        ApiRateLimitState,
        client_key_from_request,
        path_is_rate_limit_exempt,
    )

    rate_limit_state = ApiRateLimitState(
        limit_per_minute=settings.rate_limit_per_minute,
        auth_fail_limit_per_minute=settings.auth_fail_limit_per_minute,
    )
    app.state.rate_limit = rate_limit_state

    from squidc5.api.max_body import MaxBodySizeMiddleware

    app.add_middleware(MaxBodySizeMiddleware, max_body_bytes=settings.max_body_bytes)

    # Secure CORS: no wildcard. Allow:
    #  - explicit SQUIDC5_CORS_ORIGINS
    #  - same-host origins (so /ops on this server can use Authorization)
    from urllib.parse import urlparse

    from starlette.responses import JSONResponse
    from starlette.responses import Response as StarletteResponse

    def _cors_origin_allowed(origin: str | None, host_header: str | None) -> str | None:
        if not origin:
            return None
        # Browsers send Origin: null for file:// pages
        if origin == "null":
            # Allow local HTML testing only when public_host is set (ops still preferred)
            if (settings.public_host or "").strip():
                return "null"
            return None
        allowed = list(settings.cors_origins or [])
        if origin in allowed:
            return origin
        # Same-host / public host: allow ops dashboard preflights (Authorization header)
        try:
            o = urlparse(origin)
            if o.scheme not in ("http", "https") or not o.hostname:
                return None
            host = (host_header or "").split(",")[0].strip()
            host_name = host.split(":")[0].lower() if host else ""
            origin_host = (o.hostname or "").lower()
            if host and o.netloc == host:
                return origin
            if host_name and origin_host == host_name:
                return origin
            pub = (settings.public_host or "").strip().lower()
            if pub and origin_host == pub:
                return origin
            # Loopback variants (local ops testing)
            if origin_host in ("127.0.0.1", "localhost") and host_name in ("127.0.0.1", "localhost"):
                return origin
        except Exception:
            return None
        return None

    @app.middleware("http")
    async def security_and_cors_middleware(request, call_next):
        origin = request.headers.get("origin")
        host_hdr = request.headers.get("host")
        allow_origin = _cors_origin_allowed(origin, host_hdr)

        if request.method == "OPTIONS":
            # Answer preflight without requiring route OPTIONS handlers
            resp = StarletteResponse(status_code=204)
            if allow_origin:
                resp.headers["Access-Control-Allow-Origin"] = allow_origin
                resp.headers["Vary"] = "Origin"
                resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                resp.headers["Access-Control-Allow-Headers"] = (
                    "Authorization, Content-Type, X-API-Token, Accept"
                )
                resp.headers["Access-Control-Max-Age"] = "600"
            if settings.security_headers:
                resp.headers["X-Content-Type-Options"] = "nosniff"
                resp.headers["X-Frame-Options"] = "DENY"
            return resp

        path = request.url.path
        ckey = client_key_from_request(request)
        rl: ApiRateLimitState = request.app.state.rate_limit
        if not path_is_rate_limit_exempt(path):
            ok, retry_after = rl.check_request(ckey)
            if not ok:
                resp = JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(retry_after or 60)},
                )
                if allow_origin:
                    resp.headers["Access-Control-Allow-Origin"] = allow_origin
                    resp.headers["Vary"] = "Origin"
                if settings.security_headers:
                    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
                    resp.headers.setdefault("X-Frame-Options", "DENY")
                    resp.headers.setdefault("Cache-Control", "no-store")
                return resp

        response = await call_next(request)
        if response.status_code == 401 and not path_is_rate_limit_exempt(path):
            rl.record_auth_failure(ckey)
        if allow_origin:
            response.headers["Access-Control-Allow-Origin"] = allow_origin
            response.headers["Vary"] = "Origin"
        if settings.security_headers:
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault(
                "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
            )
            response.headers.setdefault("Cache-Control", "no-store")
            # connect-src must allow the C2 itself (same host) for /ops API calls
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: https://i.imgur.com; "
                "style-src 'self' 'unsafe-inline' https://squidoffense.com; "
                "script-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            )
        return response

    app.include_router(build_api_router())
    # MCP routes always mounted; runtime feature flag / settings gate access
    app.include_router(build_mcp_router())
    from squidc5.listeners.ws_beacon import build_ws_router

    app.include_router(build_ws_router())

    # Operator phone/desktop console (static) — works from source, Docker, frozen binary
    wdir = web_dir()
    dash_file = wdir / "phone-dashboard.html"
    assets = wdir / "assets"
    if wdir.is_dir():
        if assets.is_dir():
            app.mount("/ops/assets", StaticFiles(directory=str(assets)), name="ops-assets")

        @app.get("/ops")
        @app.get("/ops/")
        async def ops_console():
            if dash_file.is_file():
                return FileResponse(
                    dash_file,
                    media_type="text/html",
                    headers={"Cache-Control": "no-store"},
                )
            return RedirectResponse("/")

        @app.get("/ops/dashboard")
        async def ops_dashboard_alias():
            return RedirectResponse("/ops", status_code=307)

    @app.get("/")
    async def root() -> dict[str, str]:
        # Minimal banner — no docs/OpenAPI pointers
        return {
            "service": "sc5",
            "status": "ok",
        }

    # Profile-aware HTTP beacon catch-all (custom URIs from active/known profiles)
    from squidc5.profiles.http_beacon import process_beacon_checkin, process_beacon_result

    @app.api_route("/{full_path:path}", methods=["POST"], include_in_schema=False)
    async def profile_beacon_catch(request: Request, full_path: str) -> Response:
        state = request.app.state.app_state
        path = "/" + full_path if not full_path.startswith("/") else full_path
        # never steal reserved API/ops/mcp surfaces
        if (
            path.startswith("/api/")
            or path.startswith("/ops")
            or path.startswith("/mcp")
            or path in ("/", "/docs", "/redoc", "/openapi.json")
        ):
            raise HTTPException(404, "Not found")
        pe = state.profiles
        kind, prof = pe.match_beacon_path(path)
        if kind not in ("beacon", "result"):
            raise HTTPException(404, "Not found")
        if not await state.features.enabled("implant_beacon"):
            raise HTTPException(403, "Implant beacon is disabled by feature flag")
        raw = await request.body()
        payload = pe.unwrap_request_body(prof, raw)
        client = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        try:
            if kind == "beacon":
                result = await process_beacon_checkin(
                    state, remote_addr=client, payload=payload, user_agent=ua
                )
            else:
                result = await process_beacon_result(state, payload)
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return Response(content=pe.wrap_response(prof, result), media_type="application/json")

    # Explicit 404 for common doc probes (even if something re-enables openapi later)
    @app.get("/docs")
    @app.get("/docs/")
    @app.get("/redoc")
    @app.get("/redoc/")
    @app.get("/openapi.json")
    async def docs_disabled() -> dict[str, str]:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not found")

    return app


def cli() -> None:
    settings = get_settings()
    configure_logging(json_logs=settings.log_json, debug=settings.debug)
    try:
        for w in settings.validate_runtime():
            log.warning("config: %s", w)
    except ValueError as e:
        raise SystemExit(f"Invalid configuration: {e}") from e
    ssl_kwargs: dict = {}
    if settings.tls_enabled:
        from squidc5.tls.certs import ensure_instance_tls

        if settings.tls_cert_file and settings.tls_key_file:
            cert_path = Path(settings.tls_cert_file)
            key_path = Path(settings.tls_key_file)
            if not cert_path.is_file() or not key_path.is_file():
                raise SystemExit(
                    f"SQUIDC5_TLS_CERT_FILE / SQUIDC5_TLS_KEY_FILE not found: {cert_path} {key_path}"
                )
            created = False
        else:
            cert_path, key_path, created = ensure_instance_tls(
                settings.data_dir,
                public_host=settings.public_host or "",
                force_new=settings.tls_force_new,
            )
        ssl_kwargs["ssl_certfile"] = str(cert_path)
        ssl_kwargs["ssl_keyfile"] = str(key_path)
        scheme = "https"
        if created:
            log.warning(
                "TLS is ON with a new self-signed cert. Use https://%s:%s/ops "
                "(accept browser warning) — tokens on the wire are encrypted.",
                settings.host if settings.host not in ("0.0.0.0", "::") else "HOST",
                settings.port,
            )
        else:
            log.info("TLS enabled (%s)", cert_path)
    else:
        scheme = "http"
        log.warning(
            "TLS disabled (SQUIDC5_TLS_ENABLED=false) — ops/API/MCP traffic is plaintext"
        )

    log.info(
        "Starting SquidC5 %s on %s://%s:%s",
        __version__,
        scheme,
        settings.host,
        settings.port,
    )
    uvicorn.run(
        "squidc5.main:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level="debug" if settings.debug else "info",
        workers=1,
        **ssl_kwargs,
    )


if __name__ == "__main__":
    cli()
