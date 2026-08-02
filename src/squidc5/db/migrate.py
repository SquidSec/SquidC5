"""Versioned SQLite schema migrations."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

log = logging.getLogger("squidc5.db.migrate")

# Baseline matches historical CREATE TABLE IF NOT EXISTS bootstrap.
BASELINE_SQL = """
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

CREATE TABLE IF NOT EXISTS c2_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    config TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_by TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS session_handoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handoffs_session ON session_handoffs(session_id);

CREATE TABLE IF NOT EXISTS operator_chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id TEXT,
    actor TEXT NOT NULL,
    message TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_ts ON operator_chat(ts);

CREATE TABLE IF NOT EXISTS plugins (
    name TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    manifest TEXT NOT NULL,
    signature TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS team_members (
    team_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    added_at REAL NOT NULL,
    PRIMARY KEY (team_id, actor)
);

CREATE TABLE IF NOT EXISTS oast_clients (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    created_by TEXT,
    meta TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS oast_interactions (
    id TEXT PRIMARY KEY,
    client_id TEXT,
    token TEXT,
    protocol TEXT NOT NULL,
    listener_id TEXT,
    remote TEXT,
    raw TEXT NOT NULL DEFAULT '{}',
    correlation_key TEXT,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oast_clients_token ON oast_clients(token);
CREATE INDEX IF NOT EXISTS idx_oast_interactions_ts ON oast_interactions(ts);
CREATE INDEX IF NOT EXISTS idx_oast_interactions_client ON oast_interactions(client_id);
CREATE INDEX IF NOT EXISTS idx_oast_interactions_token ON oast_interactions(token);
"""

HITL_REQUESTS_SQL = """
CREATE TABLE IF NOT EXISTS hitl_requests (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    resource TEXT,
    actor TEXT NOT NULL,
    actor_type TEXT NOT NULL DEFAULT 'operator',
    details TEXT NOT NULL DEFAULT '{}',
    binding_hash TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    resolved_at REAL,
    resolved_by TEXT,
    expires_at REAL
);
CREATE INDEX IF NOT EXISTS idx_hitl_status ON hitl_requests(status);
CREATE INDEX IF NOT EXISTS idx_hitl_actor ON hitl_requests(actor);
"""

# (version, description, sql) — versions must be contiguous starting at 1
AUDIT_INTEGRITY_SQL = """
ALTER TABLE audit_log ADD COLUMN chain_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
"""

OPERATOR_ASSETS_SQL = """
CREATE TABLE IF NOT EXISTS operator_assets (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '{}',
    created_by TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operator_assets_kind ON operator_assets(kind);
CREATE INDEX IF NOT EXISTS idx_operator_assets_created ON operator_assets(created_at);
"""

MIGRATIONS: Sequence[tuple[int, str, str]] = (
    (1, "baseline schema", BASELINE_SQL),
    (2, "HITL approval queue", HITL_REQUESTS_SQL),
    (3, "audit integrity chain columns", AUDIT_INTEGRITY_SQL),
    (4, "operator assets library", OPERATOR_ASSETS_SQL),
)

SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL PRIMARY KEY,
    applied_at REAL NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
"""


async def get_schema_version(db: Any) -> int:
    await db.execute(SCHEMA_VERSION_TABLE)
    await db.commit()
    cur = await db.execute("SELECT MAX(version) AS v FROM schema_version")
    row = await cur.fetchone()
    if row is None:
        return 0
    # aiosqlite.Row or tuple
    try:
        v = row["v"]
    except (KeyError, TypeError, IndexError):
        v = row[0] if row else None
    return int(v or 0)


async def _legacy_db_without_version(db: Any) -> bool:
    """True if pre-migration DB (has tokens, no schema_version rows)."""
    cur = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tokens'"
    )
    row = await cur.fetchone()
    return row is not None


async def apply_migrations(db: Any) -> int:
    """Apply pending migrations. Returns resulting schema version."""
    current = await get_schema_version(db)
    target = MIGRATIONS[-1][0] if MIGRATIONS else 0

    if current == 0 and await _legacy_db_without_version(db):
        # Existing install: stamp baseline without re-running (IF NOT EXISTS is safe either way)
        import time

        await db.executescript(BASELINE_SQL)
        await db.execute(
            "INSERT OR REPLACE INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
            (1, time.time(), "baseline schema (legacy stamp)"),
        )
        await db.commit()
        current = 1
        log.info("Stamped legacy database at schema version 1")

    import time

    for version, description, sql in MIGRATIONS:
        if version <= current:
            continue
        if version != current + 1:
            raise RuntimeError(
                f"Migration gap: at {current}, next is {version} (expected {current + 1})"
            )
        log.info("Applying schema migration v%s: %s", version, description)
        await db.executescript(sql)
        await db.execute(
            "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
            (version, time.time(), description),
        )
        await db.commit()
        current = version

    if current != target:
        raise RuntimeError(f"Schema version {current} != target {target}")
    return current
