"""SessionManager lifecycle: close, delete, reject, clear, orphan reaping, enrich."""

from __future__ import annotations

import json

import pytest

from squidc5.sessions.manager import SessionManager


async def _register(app, kind: str = "reverse_shell", **kwargs) -> str:
    return await app.state.app_state.sessions.register(kind=kind, **kwargs)


@pytest.mark.asyncio
async def test_heartbeat_updates_last_seen(app):
    sid = await _register(app)
    before = (await app.state.app_state.db.get_session(sid))["last_seen_at"]
    await app.state.app_state.sessions.heartbeat(sid, hostname="hb-host")
    row = await app.state.app_state.db.get_session(sid)
    assert row["last_seen_at"] >= before
    assert row["hostname"] == "hb-host"


@pytest.mark.asyncio
async def test_close_without_drop_keeps_channel(app):
    sid = await _register(app)
    await app.state.app_state.sessions.close(sid, drop=False)
    row = await app.state.app_state.db.get_session(sid)
    assert row["status"] == "closed"


@pytest.mark.asyncio
async def test_close_swallows_drop_errors(app):
    sid = await _register(app)

    async def _boom(_sid: str) -> None:
        raise RuntimeError("drop failed")

    app.state.app_state.sessions.drop_channel = _boom
    app.state.app_state.sessions.kill_channel = None
    await app.state.app_state.sessions.close(sid)
    row = await app.state.app_state.db.get_session(sid)
    assert row["status"] == "closed"


@pytest.mark.asyncio
async def test_delete_swallows_drop_errors(app):
    sid = await _register(app)

    async def _boom(_sid: str) -> None:
        raise RuntimeError("drop failed")

    app.state.app_state.sessions.drop_channel = _boom
    assert await app.state.app_state.sessions.delete(sid) is True
    assert await app.state.app_state.db.get_session(sid) is None


@pytest.mark.asyncio
async def test_delete_missing_session_returns_false(app):
    assert await app.state.app_state.sessions.delete("ses_missing") is False


@pytest.mark.asyncio
async def test_reject_removes_session_and_emits(app):
    sid = await _register(app)
    await app.state.app_state.sessions.reject(sid, "tls_handshake")
    assert await app.state.app_state.db.get_session(sid) is None
    events = [e for e in app.state.app_state.metrics._events if e["type"] == "session.rejected"]
    assert events
    assert events[-1]["payload"]["reason"] == "tls_handshake"


@pytest.mark.asyncio
async def test_reject_swallows_drop_errors(app):
    sid = await _register(app)

    async def _boom(_sid: str) -> None:
        raise RuntimeError("nope")

    app.state.app_state.sessions.drop_channel = _boom
    await app.state.app_state.sessions.reject(sid, "noise")
    assert await app.state.app_state.db.get_session(sid) is None


@pytest.mark.asyncio
async def test_clear_shells_deletes_unverified(app):
    sid = await _register(app)
    out = await app.state.app_state.sessions.clear_shells(unverified_only=True, delete=True)
    assert out["removed"] >= 1
    assert await app.state.app_state.db.get_session(sid) is None


@pytest.mark.asyncio
async def test_clear_shells_skips_verified(app):
    sid = await _register(app)
    app.state.app_state.sessions.verified_check = lambda _sid: True
    out = await app.state.app_state.sessions.clear_shells(unverified_only=True, delete=True)
    assert out["removed"] == 0
    assert await app.state.app_state.db.get_session(sid) is not None


@pytest.mark.asyncio
async def test_clear_shells_honors_metadata_verified(app):
    sid = await _register(app, metadata={"verified": True})
    app.state.app_state.sessions.verified_check = None
    out = await app.state.app_state.sessions.clear_shells(unverified_only=True, delete=True)
    assert out["removed"] == 0
    assert await app.state.app_state.db.get_session(sid) is not None


@pytest.mark.asyncio
async def test_clear_shells_closed_only(app):
    active = await _register(app)
    closed = await _register(app)
    await app.state.app_state.db.update_session(closed, status="closed")
    out = await app.state.app_state.sessions.clear_shells(closed_only=True, delete=True)
    assert out["removed"] >= 1
    assert await app.state.app_state.db.get_session(closed) is None
    assert await app.state.app_state.db.get_session(active) is not None


@pytest.mark.asyncio
async def test_clear_shells_active_only(app):
    active = await _register(app)
    closed = await _register(app)
    await app.state.app_state.db.update_session(closed, status="closed")
    out = await app.state.app_state.sessions.clear_shells(active_only=True, delete=True)
    assert out["removed"] >= 1
    assert await app.state.app_state.db.get_session(active) is None
    assert await app.state.app_state.db.get_session(closed) is not None


@pytest.mark.asyncio
async def test_clear_shells_close_instead_of_delete(app):
    sid = await _register(app)
    out = await app.state.app_state.sessions.clear_shells(delete=False)
    assert out["closed"] >= 1
    row = await app.state.app_state.db.get_session(sid)
    assert row is not None
    assert row["status"] == "closed"


@pytest.mark.asyncio
async def test_clear_shells_ignores_beacons(app):
    sid = await _register(app, kind="beacon")
    out = await app.state.app_state.sessions.clear_shells(delete=True)
    assert out["removed"] == 0
    assert await app.state.app_state.db.get_session(sid) is not None


@pytest.mark.asyncio
async def test_close_orphaned_shells_closes_dead(app):
    sid = await _register(app)
    app.state.app_state.sessions.interactive_check = lambda _sid: False
    closed = await app.state.app_state.sessions.close_orphaned_shells(probe=False)
    assert closed >= 1
    row = await app.state.app_state.db.get_session(sid)
    assert row["status"] == "closed"


@pytest.mark.asyncio
async def test_close_orphaned_shells_probe_drops_failing(app):
    sid = await _register(app)
    app.state.app_state.sessions.interactive_check = lambda _sid: True

    async def _fail(_sid: str) -> bool:
        return False

    app.state.app_state.sessions.exec_probe = _fail
    closed = await app.state.app_state.sessions.close_orphaned_shells(probe=True)
    assert closed >= 1
    row = await app.state.app_state.db.get_session(sid)
    assert row["status"] == "closed"


@pytest.mark.asyncio
async def test_close_orphaned_shells_probe_keeps_passing(app):
    sid = await _register(app)
    app.state.app_state.sessions.interactive_check = lambda _sid: True

    async def _ok(_sid: str) -> bool:
        return True

    app.state.app_state.sessions.exec_probe = _ok
    closed = await app.state.app_state.sessions.close_orphaned_shells(probe=True)
    assert closed == 0
    row = await app.state.app_state.db.get_session(sid)
    assert row["status"] == "active"


@pytest.mark.asyncio
async def test_close_orphaned_shells_probe_exception_counts_as_failure(app):
    sid = await _register(app)
    app.state.app_state.sessions.interactive_check = lambda _sid: True

    async def _boom(_sid: str) -> bool:
        raise RuntimeError("probe crashed")

    app.state.app_state.sessions.exec_probe = _boom
    closed = await app.state.app_state.sessions.close_orphaned_shells(probe=True)
    assert closed >= 1
    row = await app.state.app_state.db.get_session(sid)
    assert row["status"] == "closed"


@pytest.mark.asyncio
async def test_enrich_marks_dead_shell(app):
    sid = await _register(app)
    app.state.app_state.sessions.interactive_check = lambda _sid: False
    row = await app.state.app_state.sessions.get(sid)
    assert row["interactive"] is False
    assert row["dead"] is True
    assert "stale" in row["note"]


@pytest.mark.asyncio
async def test_enrich_marks_unverified_shell(app):
    sid = await _register(app)
    app.state.app_state.sessions.interactive_check = lambda _sid: True
    app.state.app_state.sessions.verified_check = lambda _sid: False
    row = await app.state.app_state.sessions.get(sid)
    assert row["interactive"] is True
    assert row["verified"] is False
    assert "not yet verified" in row["note"]


@pytest.mark.asyncio
async def test_enrich_marks_beacon_taskable(app):
    sid = await _register(app, kind="beacon")
    row = await app.state.app_state.sessions.get(sid)
    assert row["taskable"] is True
    assert row["interactive"] is False


@pytest.mark.asyncio
async def test_enrich_uses_metadata_verified(app):
    sid = await _register(app, metadata={"exec_ok": True})
    app.state.app_state.sessions.interactive_check = lambda _sid: True
    app.state.app_state.sessions.verified_check = None
    row = await app.state.app_state.sessions.get(sid)
    assert row["verified"] is True


@pytest.mark.asyncio
async def test_normalize_handles_bad_json_metadata(app):
    sid = await _register(app)
    await app.state.app_state.db.execute(
        "UPDATE sessions SET metadata = ? WHERE id = ?", ("{not json", sid)
    )
    row = await app.state.app_state.sessions.get(sid)
    assert row["metadata"] == {}


@pytest.mark.asyncio
async def test_list_filters_by_status(app):
    active = await _register(app)
    closed = await _register(app)
    await app.state.app_state.db.update_session(closed, status="closed")
    rows = await app.state.app_state.sessions.list(status="active")
    ids = {r["id"] for r in rows}
    assert active in ids
    assert closed not in ids


@pytest.mark.asyncio
async def test_get_missing_returns_none(app):
    assert await app.state.app_state.sessions.get("ses_missing") is None


@pytest.mark.asyncio
async def test_register_emits_created_event(app):
    sid = await _register(app, remote_addr="10.1.1.1:5555")
    events = [e for e in app.state.app_state.metrics._events if e["type"] == "session.created"]
    assert any(e["payload"]["id"] == sid for e in events)


@pytest.mark.asyncio
async def test_manager_works_without_optional_callbacks(tmp_path):
    """SessionManager must not require listener wiring to function."""
    from squidc5.db.store import Database
    from squidc5.metrics.collector import MetricsCollector

    db = Database(tmp_path / "solo.db")
    await db.connect()
    try:
        metrics = MetricsCollector(db)
        manager = SessionManager(db, metrics)
        sid = await manager.register(kind="reverse_shell")
        assert await manager.delete(sid) is True
        assert await manager.clear_shells() == {"removed": 0, "closed": 0}
        assert await manager.close_orphaned_shells() == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_metadata_roundtrip_is_json(app):
    sid = await _register(app, metadata={"team_id": "t1", "note": "x"})
    row = await app.state.app_state.db.get_session(sid)
    assert json.loads(row["metadata"])["team_id"] == "t1"
