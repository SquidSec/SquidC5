"""SquidSeC2 application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from squidsec2 import __version__
from squidsec2.ai.admin_ai import AdminAI
from squidsec2.api.routes import build_api_router
from squidsec2.audit.trail import AuditTrail
from squidsec2.auth.tokens import TokenService
from squidsec2.config import Settings, get_settings
from squidsec2.core.state import AppState
from squidsec2.db.store import Database
from squidsec2.listeners.manager import ListenerManager
from squidsec2.mcp.server import build_mcp_router
from squidsec2.metrics.collector import MetricsCollector
from squidsec2.payloads.generator import PayloadGenerator
from squidsec2.policy.engine import PolicyEngine
from squidsec2.sessions.manager import SessionManager
from squidsec2.tasking.manager import TaskManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("squidsec2")


async def build_state(settings: Settings) -> AppState:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.database_path)
    await db.connect()

    tokens = TokenService(db)
    policy = PolicyEngine(db)
    await policy.load()
    audit = AuditTrail(db)
    metrics = MetricsCollector(db, buffer_size=settings.event_buffer_size)
    sessions = SessionManager(db, metrics)
    tasks = TaskManager(db, metrics)
    payloads = PayloadGenerator()
    admin_ai = AdminAI(db, metrics, policy)

    listeners = ListenerManager(db, metrics, session_factory=sessions.register)

    admin_once = await tokens.bootstrap_admin(settings.admin_token_bootstrap)
    if admin_once:
        token_file = settings.data_dir / "admin_token.txt"
        token_file.write_text(admin_once + "\n", encoding="utf-8")
        log.warning("Bootstrap admin token written to %s — store securely and rotate", token_file)

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
        admin_token_once=admin_once,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state = await build_state(settings)
        app.state.app_state = state
        await state.db.audit(
            actor="system",
            actor_type="system",
            action="server.start",
            details={"version": __version__, "port": settings.port},
        )
        log.info("SquidSeC2 v%s listening on %s:%s", __version__, settings.host, settings.port)
        yield
        await state.listeners.stop_all()
        await state.db.audit(actor="system", actor_type="system", action="server.stop")
        await state.db.close()
        log.info("SquidSeC2 shutdown complete")

    app = FastAPI(
        title="SquidSeC2",
        description="Lightweight, security-first, AI-native C2 for authorized red team operations",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(build_api_router())
    if settings.mcp_enabled:
        app.include_router(build_mcp_router())

    @app.get("/")
    async def root() -> dict[str, str]:
        return {
            "name": "SquidSeC2",
            "version": __version__,
            "docs": "/docs",
            "health": "/api/v1/health",
            "mcp": "/mcp/health",
        }

    return app


def cli() -> None:
    settings = get_settings()
    uvicorn.run(
        "squidsec2.main:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level="debug" if settings.debug else "info",
        workers=1,
    )


if __name__ == "__main__":
    cli()
