"""SQLite persistence with async access and thread-safe connection handling."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Any

import aiosqlite

from squidc5.db.migrate import BASELINE_SQL, apply_migrations

# Back-compat alias for anything importing SCHEMA
SCHEMA = BASELINE_SQL

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
        await apply_migrations(self._db)
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

    # --- HITL approval queue ---

    async def create_hitl_request(
        self,
        *,
        action: str,
        actor: str,
        actor_type: str = "operator",
        resource: str | None = None,
        details: dict[str, Any] | None = None,
        binding_hash: str = "",
        risk_score: int = 0,
        ttl_sec: float = 900.0,
    ) -> str:
        hid = _uid("hitl_")
        now = _now()
        await self.execute(
            """INSERT INTO hitl_requests
               (id, action, resource, actor, actor_type, details, binding_hash, risk_score, status, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (
                hid,
                action,
                resource,
                actor,
                actor_type,
                json.dumps(details or {}),
                binding_hash or "",
                risk_score,
                now,
                now + float(ttl_sec),
            ),
        )
        return hid

    async def get_hitl_request(self, request_id: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM hitl_requests WHERE id = ?", (request_id,))

    async def list_hitl_requests(
        self, *, status: str | None = "pending", limit: int = 100
    ) -> list[dict[str, Any]]:
        lim = min(max(int(limit), 1), 500)
        if status:
            return await self.fetchall(
                "SELECT * FROM hitl_requests WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, lim),
            )
        return await self.fetchall(
            "SELECT * FROM hitl_requests ORDER BY created_at DESC LIMIT ?",
            (lim,),
        )

    async def resolve_hitl_request(
        self, request_id: str, *, status: str, resolved_by: str
    ) -> bool:
        if status not in ("approved", "denied"):
            raise ValueError("status must be approved or denied")
        cur = await self.execute(
            """UPDATE hitl_requests SET status = ?, resolved_at = ?, resolved_by = ?
               WHERE id = ? AND status = 'pending'""",
            (status, _now(), resolved_by, request_id),
        )
        return cur.rowcount > 0

    async def consume_hitl_request(self, request_id: str) -> bool:
        """H01: single-use — approved → consumed after one successful authorization."""
        cur = await self.execute(
            """UPDATE hitl_requests SET status = 'consumed', resolved_at = COALESCE(resolved_at, ?)
               WHERE id = ? AND status = 'approved'""",
            (_now(), request_id),
        )
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

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task only (not running/completed)."""
        cur = await self.execute(
            """UPDATE tasks SET status = 'cancelled', completed_at = ?, result = COALESCE(result, '')
               WHERE id = ? AND status = 'pending'""",
            (_now(), task_id),
        )
        return cur.rowcount > 0

    async def update_pending_task(
        self,
        task_id: str,
        *,
        command: str | None = None,
        args: dict[str, Any] | None = None,
    ) -> bool:
        """Modify command/args on a pending task only."""
        row = await self.get_task(task_id)
        if not row or row.get("status") != "pending":
            return False
        new_cmd = command if command is not None else row.get("command")
        if args is not None:
            new_args = json.dumps(args)
        else:
            existing = row.get("args")
            new_args = existing if isinstance(existing, str) else json.dumps(existing or {})
        cur = await self.execute(
            """UPDATE tasks SET command = ?, args = ? WHERE id = ? AND status = 'pending'""",
            (new_cmd, new_args, task_id),
        )
        return cur.rowcount > 0

    async def list_tasks(
        self, session_id: str | None = None, *, status: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(200)
        return await self.fetchall(
            f"SELECT * FROM tasks {where} ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        )

    async def complete_task(
        self,
        task_id: str,
        result: str,
        status: str = "completed",
        *,
        session_id: str | None = None,
    ) -> bool:
        """C07: optionally bind completion to session; only pending/running tasks."""
        if session_id:
            cur = await self.execute(
                """UPDATE tasks SET status = ?, result = ?, completed_at = ?
                   WHERE id = ? AND session_id = ? AND status IN ('pending', 'running')""",
                (status, result, _now(), task_id, session_id),
            )
        else:
            cur = await self.execute(
                """UPDATE tasks SET status = ?, result = ?, completed_at = ?
                   WHERE id = ? AND status IN ('pending', 'running')""",
                (status, result, _now(), task_id),
            )
        return cur.rowcount > 0

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
        import hashlib

        ts = _now()
        det = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        prev_row = await self.fetchone(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        )
        prev = ""
        if prev_row:
            prev = (prev_row.get("chain_hash") if isinstance(prev_row, dict) else prev_row[0]) or ""
        ts_s = format(float(ts), ".12f")
        material = (
            f"{prev}|{ts_s}|{actor}|{actor_type}|{action}|{resource or ''}|"
            f"{det}|{risk_score}|{1 if allowed else 0}"
        )
        chain = hashlib.sha256(material.encode("utf-8")).hexdigest()
        # Prefer new columns when migration applied; fall back for mid-upgrade
        try:
            await self.execute(
                """INSERT INTO audit_log
                   (ts, actor, actor_type, action, resource, details, risk_score, allowed, chain_hash, prev_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ts,
                    actor,
                    actor_type,
                    action,
                    resource,
                    det,
                    risk_score,
                    1 if allowed else 0,
                    chain,
                    prev,
                ),
            )
        except Exception:
            await self.execute(
                """INSERT INTO audit_log
                   (ts, actor, actor_type, action, resource, details, risk_score, allowed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ts,
                    actor,
                    actor_type,
                    action,
                    resource,
                    det,
                    risk_score,
                    1 if allowed else 0,
                ),
            )

    async def list_audit(
        self,
        limit: int = 100,
        offset: int = 0,
        *,
        actor: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if action:
            clauses.append("action LIKE ?")
            params.append(f"{action}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        return await self.fetchall(
            f"SELECT * FROM audit_log {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    async def purge_audit_before(self, cutoff_ts: float) -> int:
        """Delete audit rows older than cutoff. Returns rows deleted."""
        cur = await self.execute("DELETE FROM audit_log WHERE ts < ?", (float(cutoff_ts),))
        return int(cur.rowcount or 0)

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

    # --- C2 profiles ---

    async def list_profiles(self) -> list[dict[str, Any]]:
        rows = await self.fetchall(
            "SELECT id, name, config, active, created_at, updated_at FROM c2_profiles ORDER BY name"
        )
        for r in rows:
            if isinstance(r.get("config"), str):
                r["config"] = json.loads(r["config"])
        return rows

    async def upsert_profile(
        self, profile_id: str, name: str, config: dict[str, Any], active: bool = False
    ) -> None:
        existing = await self.fetchone("SELECT id FROM c2_profiles WHERE id = ?", (profile_id,))
        now = _now()
        if existing:
            await self.execute(
                "UPDATE c2_profiles SET name = ?, config = ?, active = ?, updated_at = ? WHERE id = ?",
                (name, json.dumps(config), 1 if active else 0, now, profile_id),
            )
        else:
            await self.execute(
                "INSERT INTO c2_profiles (id, name, config, active, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (profile_id, name, json.dumps(config), 1 if active else 0, now, now),
            )

    async def set_active_profile(self, profile_id: str) -> None:
        await self.execute("UPDATE c2_profiles SET active = 0")
        await self.execute(
            "UPDATE c2_profiles SET active = 1, updated_at = ? WHERE id = ?",
            (_now(), profile_id),
        )

    # --- Teams / collab ---

    async def list_teams(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM teams ORDER BY name")

    async def create_team(self, name: str, created_by: str) -> str:
        tid = _uid("team_")
        await self.execute(
            "INSERT INTO teams (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
            (tid, name, created_by, _now()),
        )
        return tid

    async def add_session_handoff(self, session_id: str, entry: dict[str, Any]) -> None:
        await self.execute(
            "INSERT INTO session_handoffs (session_id, payload, ts) VALUES (?, ?, ?)",
            (session_id, json.dumps(entry), entry.get("ts") or _now()),
        )

    async def get_session_handoffs(self, session_id: str) -> list[dict[str, Any]]:
        rows = await self.fetchall(
            "SELECT payload, ts FROM session_handoffs WHERE session_id = ? ORDER BY ts ASC",
            (session_id,),
        )
        out = []
        for r in rows:
            p = r["payload"]
            if isinstance(p, str):
                p = json.loads(p)
            out.append(p)
        return out

    async def set_session_owner(self, session_id: str, owner: str) -> None:
        row = await self.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        meta = row.get("metadata") or {}
        if isinstance(meta, str):
            meta = json.loads(meta)
        meta["owner"] = owner
        await self.update_session(session_id, metadata=json.dumps(meta))

    # --- Operator chat ---

    async def add_chat(self, actor: str, message: str, team_id: str | None = None) -> dict[str, Any]:
        ts = _now()
        await self.execute(
            "INSERT INTO operator_chat (team_id, actor, message, ts) VALUES (?, ?, ?, ?)",
            (team_id, actor, message[:4000], ts),
        )
        return {"actor": actor, "message": message[:4000], "team_id": team_id, "ts": ts}

    async def list_chat(self, limit: int = 50, team_id: str | None = None) -> list[dict[str, Any]]:
        if team_id:
            return await self.fetchall(
                "SELECT id, team_id, actor, message, ts FROM operator_chat "
                "WHERE team_id = ? ORDER BY ts DESC LIMIT ?",
                (team_id, limit),
            )
        # M06: global channel only (exclude team-scoped rows)
        return await self.fetchall(
            "SELECT id, team_id, actor, message, ts FROM operator_chat "
            "WHERE team_id IS NULL OR team_id = '' ORDER BY ts DESC LIMIT ?",
            (limit,),
        )

    # --- Plugins persistence ---

    async def upsert_plugin(
        self, name: str, version: str, manifest: dict[str, Any], signature: str, enabled: bool
    ) -> None:
        existing = await self.fetchone("SELECT name FROM plugins WHERE name = ?", (name,))
        if existing:
            await self.execute(
                "UPDATE plugins SET version=?, manifest=?, signature=?, enabled=? WHERE name=?",
                (version, json.dumps(manifest), signature, 1 if enabled else 0, name),
            )
        else:
            await self.execute(
                "INSERT INTO plugins (name, version, manifest, signature, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, version, json.dumps(manifest), signature, 1 if enabled else 0, _now()),
            )

    async def list_plugins_db(self) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM plugins ORDER BY name")
        for r in rows:
            if isinstance(r.get("manifest"), str):
                r["manifest"] = json.loads(r["manifest"])
        return rows

    async def set_plugin_enabled(self, name: str, enabled: bool) -> bool:
        cur = await self.execute(
            "UPDATE plugins SET enabled = ? WHERE name = ?",
            (1 if enabled else 0, name),
        )
        return cur.rowcount > 0

    # --- Team membership ---

    async def add_team_member(self, team_id: str, actor: str, role: str = "operator") -> None:
        await self.execute(
            "INSERT OR REPLACE INTO team_members (team_id, actor, role, added_at) VALUES (?, ?, ?, ?)",
            (team_id, actor, role, _now()),
        )

    async def list_team_members(self, team_id: str) -> list[dict[str, Any]]:
        return await self.fetchall(
            "SELECT team_id, actor, role, added_at FROM team_members WHERE team_id = ? ORDER BY actor",
            (team_id,),
        )

    async def remove_team_member(self, team_id: str, actor: str) -> bool:
        cur = await self.execute(
            "DELETE FROM team_members WHERE team_id = ? AND actor = ?",
            (team_id, actor),
        )
        return cur.rowcount > 0

    # --- OAST (Collaborator-style) ---

    async def create_oast_client(
        self,
        token: str,
        label: str = "",
        created_by: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> str:
        cid = _uid("oast_")
        await self.execute(
            "INSERT INTO oast_clients (id, token, label, created_by, meta, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (cid, token, label or token, created_by, json.dumps(meta or {}), _now()),
        )
        return cid

    async def get_oast_client(self, client_id: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM oast_clients WHERE id = ?", (client_id,))

    async def get_oast_client_by_token(self, token: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM oast_clients WHERE token = ?", (token,))

    async def list_oast_clients(self, limit: int = 100) -> list[dict[str, Any]]:
        return await self.fetchall(
            "SELECT * FROM oast_clients ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )

    async def delete_oast_client(self, client_id: str) -> bool:
        await self.execute("DELETE FROM oast_interactions WHERE client_id = ?", (client_id,))
        cur = await self.execute("DELETE FROM oast_clients WHERE id = ?", (client_id,))
        return cur.rowcount > 0

    async def create_oast_interaction(
        self,
        *,
        client_id: str | None,
        protocol: str,
        listener_id: str | None,
        remote: str | None,
        raw: dict[str, Any],
        correlation_key: str | None = None,
        token: str | None = None,
    ) -> str:
        iid = _uid("hit_")
        await self.execute(
            "INSERT INTO oast_interactions "
            "(id, client_id, token, protocol, listener_id, remote, raw, correlation_key, ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                iid,
                client_id,
                token,
                protocol,
                listener_id,
                remote,
                json.dumps(raw)[:200_000],
                correlation_key,
                _now(),
            ),
        )
        return iid

    async def get_oast_interaction(self, interaction_id: str) -> dict[str, Any] | None:
        return await self.fetchone(
            "SELECT * FROM oast_interactions WHERE id = ?",
            (interaction_id,),
        )

    async def list_oast_interactions(
        self,
        *,
        client_id: str | None = None,
        protocol: str | None = None,
        since: float | None = None,
        limit: int = 100,
        token: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if client_id:
            clauses.append("client_id = ?")
            args.append(client_id)
        if token:
            clauses.append("token = ?")
            args.append(token.lower())
        if protocol:
            clauses.append("protocol = ?")
            args.append(protocol)
        if since is not None:
            clauses.append("ts > ?")
            args.append(since)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        args.append(min(max(limit, 1), 1000))
        return await self.fetchall(
            f"SELECT * FROM oast_interactions{where} ORDER BY ts DESC LIMIT ?",
            tuple(args),
        )
