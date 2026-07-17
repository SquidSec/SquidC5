"""Structured session tasking."""

from __future__ import annotations

import json
from typing import Any

from squidc5.db.store import Database
from squidc5.metrics.collector import MetricsCollector


class TaskManager:
    def __init__(self, db: Database, metrics: MetricsCollector) -> None:
        self.db = db
        self.metrics = metrics

    async def create(
        self,
        session_id: str,
        command: str,
        args: dict[str, Any] | None = None,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        session = await self.db.get_session(session_id)
        if not session:
            raise KeyError("session not found")
        if session["status"] != "active":
            raise ValueError("session not active")
        tid = await self.db.create_task(session_id, command, args, created_by)
        await self.metrics.incr("tasks.created")
        await self.metrics.emit(
            "task.created",
            {"id": tid, "session_id": session_id, "command": command},
        )
        row = await self.db.get_task(tid)
        return self._norm(row)  # type: ignore[arg-type]

    async def get(self, task_id: str) -> dict[str, Any] | None:
        row = await self.db.get_task(task_id)
        return self._norm(row) if row else None

    async def list(self, session_id: str | None = None) -> list[dict[str, Any]]:
        return [self._norm(r) for r in await self.db.list_tasks(session_id)]

    async def poll(self, session_id: str) -> dict[str, Any] | None:
        row = await self.db.next_pending_task(session_id)
        return self._norm(row) if row else None

    async def complete(self, task_id: str, result: str, status: str = "completed") -> dict[str, Any]:
        await self.db.complete_task(task_id, result, status)
        await self.metrics.incr("tasks.completed")
        await self.metrics.emit("task.completed", {"id": task_id, "status": status})
        row = await self.db.get_task(task_id)
        return self._norm(row)  # type: ignore[arg-type]

    def _norm(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        args = out.get("args")
        if isinstance(args, str):
            try:
                out["args"] = json.loads(args)
            except json.JSONDecodeError:
                out["args"] = {}
        return out
