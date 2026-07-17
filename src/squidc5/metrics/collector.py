"""Lightweight metrics and real-time event buffer."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from squidc5.db.store import Database


class MetricsCollector:
    def __init__(self, db: Database, buffer_size: int = 500) -> None:
        self.db = db
        self._events: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._lock = asyncio.Lock()
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self.started_at = time.time()

    async def incr(self, key: str, amount: float = 1.0) -> None:
        await self.db.incr_metric(key, amount)

    async def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        event = {
            "ts": time.time(),
            "type": event_type,
            "payload": payload or {},
        }
        async with self._lock:
            self._events.append(event)
            dead: list[asyncio.Queue[dict[str, Any]]] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)
        await self.incr(f"events.{event_type}")

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def snapshot(self) -> dict[str, Any]:
        metrics = await self.db.get_metrics()
        return {
            "uptime_seconds": time.time() - self.started_at,
            "metrics": metrics,
            "recent_events": list(self._events)[-50:],
            "subscribers": len(self._subscribers),
        }
