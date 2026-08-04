"""B1: SQLite WAL read/write separation + metrics batching."""

from __future__ import annotations

import asyncio

import pytest

from squidc5.db.store import Database
from squidc5.metrics.collector import MetricsCollector


@pytest.mark.asyncio
async def test_concurrent_reads_during_writes(tmp_path):
    db = Database(tmp_path / "c.db")
    await db.connect()
    try:
        await db.create_session(kind="beacon", hostname="h0")
        sids = []
        for i in range(20):
            sids.append(await db.create_session(kind="beacon", hostname=f"h{i}"))

        async def reader() -> int:
            n = 0
            for _ in range(30):
                rows = await db.fetchall("SELECT id FROM sessions WHERE status = ?", ("active",))
                n += len(rows)
            return n

        async def writer() -> None:
            for i in range(15):
                await db.create_session(kind="beacon", hostname=f"w{i}")

        results = await asyncio.gather(reader(), reader(), writer(), reader())
        assert results[0] > 0
        rows = await db.list_sessions(status="active")
        assert len(rows) >= 35
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_metrics_batch_upsert(tmp_path):
    db = Database(tmp_path / "m.db")
    await db.connect()
    try:
        await db.incr_metrics_batch({"a": 1.0, "b": 2.0})
        await db.incr_metrics_batch({"a": 3.0, "c": 1.0})
        m = await db.get_metrics()
        assert m["a"] == 4.0
        assert m["b"] == 2.0
        assert m["c"] == 1.0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_metrics_collector_flush(tmp_path):
    db = Database(tmp_path / "mc.db")
    await db.connect()
    try:
        mc = MetricsCollector(db, flush_interval_sec=10.0)
        await mc.incr("x", 5)
        await mc.emit("test.event", {"k": 1})
        # not flushed yet
        snap_pending = await db.get_metrics()
        assert snap_pending.get("x", 0) == 0
        await mc.flush()
        m = await db.get_metrics()
        assert m["x"] == 5.0
        assert m.get("events.test.event") == 1.0
        snap = await mc.snapshot()
        assert snap["metrics"]["x"] == 5.0
        assert any(e["type"] == "test.event" for e in snap["recent_events"])
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_read_conn_query_only(tmp_path):
    db = Database(tmp_path / "ro.db")
    await db.connect()
    try:
        assert db._ro is not None
        # Writes still work on primary
        sid = await db.create_session(kind="beacon", hostname="ro-test")
        row = await db.fetchone("SELECT id FROM sessions WHERE id = ?", (sid,))
        assert row and row["id"] == sid
    finally:
        await db.close()
