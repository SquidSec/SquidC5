"""Immutable audit trail facade."""

from __future__ import annotations

import time
from typing import Any

from squidc5.db.store import Database


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

    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
        *,
        actor: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        return await self.db.list_audit(limit=limit, offset=offset, actor=actor, action=action)

    async def purge_older_than_days(self, days: int) -> int:
        """Enforce retention: delete rows older than N days."""
        days = max(1, int(days))
        cutoff = time.time() - (days * 86400.0)
        return await self.db.purge_audit_before(cutoff)
