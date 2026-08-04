"""Lightweight metrics and real-time event buffer.

Counters are accumulated in memory and flushed to SQLite on a short interval
so beacon storms and multi-op traffic do not serialize on every incr().
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any

from squidc5.db.store import Database

log = logging.getLogger("squidc5.metrics")


class MetricsCollector:
    def __init__(
        self,
        db: Database,
        buffer_size: int = 500,
        *,
        flush_interval_sec: float = 1.0,
    ) -> None:
        self.db = db
        self._events: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._lock = asyncio.Lock()
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self.started_at = time.time()
        self._pending: dict[str, float] = {}
        self._flush_interval = max(0.2, float(flush_interval_sec))
        self._flush_task: asyncio.Task[None] | None = None
        self._closed = False

    def start(self) -> None:
        """Begin background flush loop (call after event loop is running)."""
        if self._flush_task is None or self._flush_task.done():
            self._closed = False
            self._flush_task = asyncio.create_task(self._flush_loop(), name="metrics-flush")

    async def stop(self) -> None:
        self._closed = True
        t = self._flush_task
        self._flush_task = None
        if t is not None:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        await self.flush()

    async def _flush_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(self._flush_interval)
                try:
                    await self.flush()
                except Exception:
                    log.exception("metrics flush failed")
        except asyncio.CancelledError:
            return

    async def incr(self, key: str, amount: float = 1.0) -> None:
        async with self._lock:
            self._pending[key] = self._pending.get(key, 0.0) + float(amount)

    async def flush(self) -> None:
        async with self._lock:
            batch = self._pending
            self._pending = {}
        if batch:
            await self.db.incr_metrics_batch(batch)

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
            self._pending[f"events.{event_type}"] = self._pending.get(f"events.{event_type}", 0.0) + 1.0

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def snapshot(self) -> dict[str, Any]:
        await self.flush()
        metrics = await self.db.get_metrics()
        return {
            "uptime_seconds": time.time() - self.started_at,
            "metrics": metrics,
            "recent_events": list(self._events)[-50:],
            "subscribers": len(self._subscribers),
            "pending_counters": len(self._pending),
        }
