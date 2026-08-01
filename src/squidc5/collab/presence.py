"""In-memory operator presence (M4) — who is online on this teamserver."""

from __future__ import annotations

import time
from typing import Any


class PresenceService:
    """Heartbeat map: actor -> last seen + optional status/viewing."""

    def __init__(self, ttl_sec: float = 90.0) -> None:
        self._ttl = ttl_sec
        self._actors: dict[str, dict[str, Any]] = {}

    def heartbeat(
        self,
        actor: str,
        *,
        status: str = "online",
        viewing_session: str | None = None,
        token_id: str | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        entry = {
            "actor": actor,
            "status": (status or "online")[:32],
            "ts": now,
            "viewing_session": viewing_session,
            "token_id": (token_id or "")[:16] or None,
        }
        self._actors[actor] = entry
        self._prune(now)
        return entry

    def list_online(self) -> list[dict[str, Any]]:
        now = time.time()
        self._prune(now)
        return sorted(self._actors.values(), key=lambda x: x.get("actor") or "")

    def offline(self, actor: str) -> bool:
        return self._actors.pop(actor, None) is not None

    def _prune(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        dead = [a for a, e in self._actors.items() if now - float(e.get("ts") or 0) > self._ttl]
        for a in dead:
            del self._actors[a]
