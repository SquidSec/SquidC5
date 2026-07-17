"""SQLite persistence with async access and thread-safe connection handling."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    mcp_tools TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    created_by TEXT,
    expires_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_used_at REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    remote_addr TEXT,
    user_agent TEXT,
    hostname TEXT,
    username TEXT,
    os_info TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    listener_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    last_seen_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS listeners (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '0.0.0.0',
    port INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'stopped',
    config TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    command TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    created_by TEXT,
    created_at REAL NOT NULL,
    completed_at REAL,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    risk_score INTEGER NOT NULL DEFAULT 0,
    allowed INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS llm_connections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    base_url TEXT,
    model TEXT NOT NULL,
    api_key_enc TEXT,
    capabilities TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    rules TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
    key TEXT PRIMARY KEY,
    value REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
"""


def _now() -> float:
    return time.time()


def _uid(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(8)}" if prefix else secrets.token_hex(12)


class Database:
    """Async SQLite store. One connection guarded by an asyncio lock."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.path))
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not connected")
        return self._db

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> aiosqlite.Cursor:
        async with self._lock:
            cur = await self.conn.execute(sql, params)
            await self.conn.commit()
            return cur

    async def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        async with self._lock:
            cur = await self.conn.execute(sql, params)
            row = await cur.fetchone()
            return dict(row) if row else None

    async def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        async with self._lock:
            cur = await self.conn.execute(sql, params)
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # --- Tokens ---

    async def create_token(
        self,
        name: str,
        token_hash: str,
        scopes: list[str],
        mcp_tools: list[str] | None = None,
        created_by: str | None = None,
        expires_at: float | None = None,
    ) -> str:
        tid = _uid("tok_")
        await self.execute(
            """INSERT INTO tokens
               (id, name, token_hash, scopes, mcp_tools, created_at, created_by, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tid,
                name,
                token_hash,
                json.dumps(scopes),
                json.dumps(mcp_tools or []),
                _now(),
                created_by,
                expires_at,
            ),
        )
        return tid

    async def get_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        row = await self.fetchone(
            "SELECT * FROM tokens WHERE token_hash = ? AND revoked = 0",
            (token_hash,),
        )
        if row and row.get("expires_at") and row["expires_at"] < _now():
            return None
        return row

    async def list_tokens(self) -> list[dict[str, Any]]:
        return await self.fetchall(
            "SELECT id, name, scopes, mcp_tools, created_at, created_by, expires_at, "
            "revoked, last_used_at FROM tokens ORDER BY created_at DESC"
        )

    async def revoke_token(self, token_id: str) -> bool:
        cur = await self.execute("UPDATE tokens SET revoked = 1 WHERE id = ?", (token_id,))
        return cur.rowcount > 0

    async def touch_token(self, token_id: str) -> None:
        await self.execute("UPDATE tokens SET last_used_at = ? WHERE id = ?", (_now(), token_id))

    # --- Sessions ---

    async def create_session(
        self,
        kind: str,
        remote_addr: str | None = None,
        user_agent: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        os_info: str | None = None,
        listener_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        sid = _uid("ses_")
        now = _now()
        await self.execute(
            """INSERT INTO sessions
               (id, kind, remote_addr, user_agent, hostname, username, os_info,
                status, listener_id, metadata, created_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)""",
            (
                sid,
                kind,
                remote_addr,
                user_agent,
                hostname,
                username,
                os_info,
                listener_id,
                json.dumps(metadata or {}),
                now,
                now,
            ),
        )
        return sid

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM sessions WHERE id = ?", (session_id,))

    async def list_sessions(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            return await self.fetchall(
                "SELECT * FROM sessions WHERE status = ? ORDER BY last_seen_at DESC",
                (status,),
            )
        return await self.fetchall("SELECT * FROM sessions ORDER BY last_seen_at DESC")

    async def update_session(self, session_id: str, **fields: Any) -> None:
        if not fields:
            return
        allowed = {
            "status",
            "hostname",
            "username",
            "os_info",
            "metadata",
            "last_seen_at",
            "remote_addr",
        }
        sets: list[str] = []
        vals: list[Any] = []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if v is None and k != "metadata":
                continue
            if k == "metadata" and isinstance(v, dict):
                v = json.dumps(v)
            sets.append(f"{k} = ?")
            vals.append(v)
        if not sets:
            return
        vals.append(session_id)
        await self.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id = ?", tuple(vals))

    async def delete_session(self, session_id: str) -> bool:
        cur = await self.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        return cur.rowcount > 0

    # --- Listeners ---

    async def create_listener(
        self,
        name: str,
        kind: str,
        port: int,
        host: str = "0.0.0.0",
        config: dict[str, Any] | None = None,
    ) -> str:
        lid = _uid("lis_")
        await self.execute(
            """INSERT INTO listeners (id, name, kind, host, port, status, config, created_at)
               VALUES (?, ?, ?, ?, ?, 'stopped', ?, ?)""",
            (lid, name, kind, host, port, json.dumps(config or {}), _now()),
        )
        return lid

    async def get_listener(self, listener_id: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM listeners WHERE id = ?", (listener_id,))

    async def list_listeners(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM listeners ORDER BY created_at DESC")

    async def set_listener_status(self, listener_id: str, status: str) -> None:
        await self.execute("UPDATE listeners SET status = ? WHERE id = ?", (status, listener_id))

    async def delete_listener(self, listener_id: str) -> bool:
        cur = await self.execute("DELETE FROM listeners WHERE id = ?", (listener_id,))
        return cur.rowcount > 0

    # --- Tasks ---

    async def create_task(
        self,
        session_id: str,
        command: str,
        args: dict[str, Any] | None = None,
        created_by: str | None = None,
    ) -> str:
        tid = _uid("tsk_")
        await self.execute(
            """INSERT INTO tasks (id, session_id, command, args, status, created_by, created_at)
               VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
            (tid, session_id, command, json.dumps(args or {}), created_by, _now()),
        )
        return tid

    async def get_task(self, task_id: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM tasks WHERE id = ?", (task_id,))

    async def list_tasks(self, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id:
            return await self.fetchall(
                "SELECT * FROM tasks WHERE session_id = ? ORDER BY created_at DESC",
                (session_id,),
            )
        return await self.fetchall("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 200")

    async def complete_task(self, task_id: str, result: str, status: str = "completed") -> None:
        await self.execute(
            "UPDATE tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?",
            (status, result, _now(), task_id),
        )

    async def next_pending_task(self, session_id: str) -> dict[str, Any] | None:
        row = await self.fetchone(
            """SELECT * FROM tasks WHERE session_id = ? AND status = 'pending'
               ORDER BY created_at ASC LIMIT 1""",
            (session_id,),
        )
        if row:
            await self.execute("UPDATE tasks SET status = 'running' WHERE id = ?", (row["id"],))
            row["status"] = "running"
        return row

    # --- Audit ---

    async def audit(
        self,
        actor: str,
        actor_type: str,
        action: str,
        resource: str | None = None,
        details: dict[str, Any] | None = None,
        risk_score: int = 0,
        allowed: bool = True,
    ) -> None:
        await self.execute(
            """INSERT INTO audit_log
               (ts, actor, actor_type, action, resource, details, risk_score, allowed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _now(),
                actor,
                actor_type,
                action,
                resource,
                json.dumps(details or {}),
                risk_score,
                1 if allowed else 0,
            ),
        )

    async def list_audit(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return await self.fetchall(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    # --- LLM ---

    async def upsert_llm(
        self,
        name: str,
        provider: str,
        model: str,
        base_url: str | None = None,
        api_key_enc: str | None = None,
        capabilities: list[str] | None = None,
        llm_id: str | None = None,
    ) -> str:
        lid = llm_id or _uid("llm_")
        existing = await self.fetchone("SELECT id FROM llm_connections WHERE id = ?", (lid,))
        if existing:
            await self.execute(
                """UPDATE llm_connections SET name=?, provider=?, base_url=?, model=?,
                   api_key_enc=?, capabilities=? WHERE id=?""",
                (
                    name,
                    provider,
                    base_url,
                    model,
                    api_key_enc,
                    json.dumps(capabilities or []),
                    lid,
                ),
            )
        else:
            await self.execute(
                """INSERT INTO llm_connections
                   (id, name, provider, base_url, model, api_key_enc, capabilities, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    lid,
                    name,
                    provider,
                    base_url,
                    model,
                    api_key_enc,
                    json.dumps(capabilities or []),
                    _now(),
                ),
            )
        return lid

    async def list_llms(self) -> list[dict[str, Any]]:
        rows = await self.fetchall(
            "SELECT id, name, provider, base_url, model, capabilities, enabled, created_at "
            "FROM llm_connections ORDER BY created_at DESC"
        )
        return rows

    async def get_llm(self, llm_id: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM llm_connections WHERE id = ?", (llm_id,))

    # --- Policies ---

    async def set_policy(self, name: str, rules: dict[str, Any], policy_id: str | None = None) -> str:
        pid = policy_id or _uid("pol_")
        existing = await self.fetchone("SELECT id FROM policies WHERE name = ?", (name,))
        if existing:
            await self.execute(
                "UPDATE policies SET rules = ? WHERE name = ?",
                (json.dumps(rules), name),
            )
            return existing["id"]
        await self.execute(
            "INSERT INTO policies (id, name, rules, created_at) VALUES (?, ?, ?, ?)",
            (pid, name, json.dumps(rules), _now()),
        )
        return pid

    async def get_policy(self, name: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM policies WHERE name = ? AND enabled = 1", (name,))

    async def list_policies(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM policies ORDER BY name")

    # --- Metrics ---

    async def incr_metric(self, key: str, amount: float = 1.0) -> None:
        row = await self.fetchone("SELECT value FROM metrics WHERE key = ?", (key,))
        if row:
            await self.execute(
                "UPDATE metrics SET value = ?, updated_at = ? WHERE key = ?",
                (row["value"] + amount, _now(), key),
            )
        else:
            await self.execute(
                "INSERT INTO metrics (key, value, updated_at) VALUES (?, ?, ?)",
                (key, amount, _now()),
            )

    async def get_metrics(self) -> dict[str, float]:
        rows = await self.fetchall("SELECT key, value FROM metrics")
        return {r["key"]: r["value"] for r in rows}
