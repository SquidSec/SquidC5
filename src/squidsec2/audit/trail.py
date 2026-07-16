"""Immutable audit trail facade."""

from __future__ import annotations

from typing import Any

from squidsec2.db.store import Database


class AuditTrail:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def record(
        self,
        actor: str,
        actor_type: str,
        action: str,
        resource: str | None = None,
        details: dict[str, Any] | None = None,
        risk_score: int = 0,
        allowed: bool = True,
    ) -> None:
        await self.db.audit(
            actor=actor,
            actor_type=actor_type,
            action=action,
            resource=resource,
            details=details,
            risk_score=risk_score,
            allowed=allowed,
        )

    async def list(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return await self.db.list_audit(limit=limit, offset=offset)
