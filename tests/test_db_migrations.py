"""Schema migration framework (B01)."""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest

from squidc5.db.migrate import BASELINE_SQL, MIGRATIONS, apply_migrations, get_schema_version
from squidc5.db.store import Database


@pytest.mark.asyncio
async def test_fresh_db_applies_all_migrations(tmp_path: Path):
    db_path = tmp_path / "fresh.db"
    db = Database(db_path)
    await db.connect()
    assert db._db is not None
    ver = await get_schema_version(db._db)
    assert ver == MIGRATIONS[-1][0]
    # core tables exist
    cur = await db._db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tokens'"
    )
    assert await cur.fetchone() is not None
    cur = await db._db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    assert await cur.fetchone() is not None
    await db.close()


@pytest.mark.asyncio
async def test_legacy_db_stamped_without_data_loss(tmp_path: Path):
    """Pre-migration DB with data is stamped to v1 and keeps rows."""
    path = tmp_path / "legacy.db"
    async with aiosqlite.connect(str(path)) as raw:
        await raw.executescript(BASELINE_SQL)
        await raw.execute(
            "INSERT INTO tokens (id, name, token_hash, scopes, created_at) "
            "VALUES ('t1', 'keep-me', 'hash1', '[\"admin\"]', 1.0)"
        )
        await raw.commit()

    db = Database(path)
    await db.connect()
    ver = await get_schema_version(db._db)
    assert ver >= 1
    cur = await db._db.execute("SELECT name FROM tokens WHERE id='t1'")
    row = await cur.fetchone()
    assert row is not None
    assert row["name"] == "keep-me"
    await db.close()


@pytest.mark.asyncio
async def test_reconnect_is_idempotent(tmp_path: Path):
    path = tmp_path / "idem.db"
    db = Database(path)
    await db.connect()
    v1 = await get_schema_version(db._db)
    await db.close()

    db2 = Database(path)
    await db2.connect()
    v2 = await get_schema_version(db2._db)
    assert v2 == v1
    await db2.close()


@pytest.mark.asyncio
async def test_apply_migrations_direct(tmp_path: Path):
    path = tmp_path / "direct.db"
    async with aiosqlite.connect(str(path)) as raw:
        raw.row_factory = aiosqlite.Row
        ver = await apply_migrations(raw)
        assert ver == MIGRATIONS[-1][0]
        ver2 = await apply_migrations(raw)
        assert ver2 == ver
