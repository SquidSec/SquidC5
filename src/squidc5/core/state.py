"""Shared application state — thread/async safe via component locks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from squidc5.ai.admin_ai import AdminAI
    from squidc5.audit.trail import AuditTrail
    from squidc5.auth.tokens import TokenService
    from squidc5.collab.teams import TeamService
    from squidc5.config import Settings
    from squidc5.db.store import Database
    from squidc5.features import FeatureFlags
    from squidc5.implants.registry import ImplantRegistry
    from squidc5.listeners.manager import ListenerManager
    from squidc5.metrics.collector import MetricsCollector
    from squidc5.oast.store import OastService
    from squidc5.observability.timeline import TimelineService
    from squidc5.payloads.generator import PayloadGenerator
    from squidc5.plugins.registry import PluginRegistry
    from squidc5.policy.engine import PolicyEngine
    from squidc5.profiles.engine import ProfileEngine
    from squidc5.sessions.manager import SessionManager
    from squidc5.tasking.manager import TaskManager


@dataclass
class AppState:
    settings: Settings
    db: Database
    tokens: TokenService
    policy: PolicyEngine
    audit: AuditTrail
    metrics: MetricsCollector
    sessions: SessionManager
    listeners: ListenerManager
    tasks: TaskManager
    payloads: PayloadGenerator
    admin_ai: AdminAI
    features: FeatureFlags
    profiles: ProfileEngine
    implants: ImplantRegistry
    teams: TeamService
    plugins: PluginRegistry
    timeline: TimelineService
    oast: OastService | None = None
    ai_chain: Any = None
    admin_token_once: str = ""
    shell_buffers: dict[str, list[str]] = field(default_factory=dict)
