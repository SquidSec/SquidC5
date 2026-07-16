"""Shared application state — thread/async safe via component locks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from squidsec2.ai.admin_ai import AdminAI
    from squidsec2.audit.trail import AuditTrail
    from squidsec2.auth.tokens import TokenService
    from squidsec2.config import Settings
    from squidsec2.db.store import Database
    from squidsec2.listeners.manager import ListenerManager
    from squidsec2.metrics.collector import MetricsCollector
    from squidsec2.payloads.generator import PayloadGenerator
    from squidsec2.policy.engine import PolicyEngine
    from squidsec2.sessions.manager import SessionManager
    from squidsec2.tasking.manager import TaskManager


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
    admin_token_once: str = ""
    shell_buffers: dict[str, list[str]] = field(default_factory=dict)
