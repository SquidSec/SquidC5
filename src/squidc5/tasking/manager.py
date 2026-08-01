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

    # Structured file-op commands (C05) — implants execute when recognized
    FILE_OPS = frozenset({"file:list", "file:read", "file:write", "file:delete"})

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
        args = dict(args or {})
        cmd = (command or "").strip()
        # Engagement ROE: banned commands
        eng = getattr(self, "engagement", None)
        if eng is not None:
            if eng.expired():
                raise ValueError("engagement window ended")
            if eng.command_banned(cmd):
                raise ValueError("command banned by engagement policy")
        # Normalize file ops into args schema
        if cmd.startswith("file:"):
            if cmd not in self.FILE_OPS:
                raise ValueError(f"unknown file op: {cmd}")
            args.setdefault("op", cmd.split(":", 1)[1])
            if cmd in ("file:read", "file:write", "file:delete") and not args.get("path"):
                raise ValueError("path required for file op")
            if cmd == "file:write" and "content" not in args and "content_b64" not in args:
                raise ValueError("content or content_b64 required for file:write")
            # Chunked transfer metadata (implant honors offset/length when present)
            if "offset" in args:
                args["offset"] = int(args["offset"])
            if "length" in args:
                args["length"] = int(args["length"])
        if cmd == "profile:switch":
            if not args.get("profile_id"):
                raise ValueError("profile_id required for profile:switch")
            # Engagement ROE: file writes may require HITL approval id on task args
            if (
                cmd == "file:write"
                and eng is not None
                and getattr(eng, "require_hitl_file_write", False)
                and not args.get("hitl_request_id")
                and created_by != "admin"
            ):
                # Callers with admin scope pass via API after HITL; non-approved blocked here
                if not args.get("hitl_approved_server"):
                    raise ValueError("file:write requires HITL approval under engagement policy")
        tid = await self.db.create_task(session_id, cmd, args, created_by)
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
