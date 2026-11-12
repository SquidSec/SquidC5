"""Reverse-shell TCP lifecycle: accept, classify, probe, verify, drop.

These tests drive ``ListenerManager._handle_tcp`` over real sockets with a
scripted peer, so the classification, exec-probe, stabilize and cleanup paths
run as they do in production.
"""

from __future__ import annotations

import asyncio

import pytest
from support import (
    BINARY_NOISE,
    FakeShell,
    collect_events,
    start_listener,
    stop_listener,
    wait_for_closed,
    wait_for_gone,
    wait_for_session,
    wait_for_verified,
    wait_until,
)


@pytest.mark.asyncio
async def test_real_shell_is_verified_and_runs_commands(app):
    lid, port = await start_listener(app, name="tcp-real")
    try:
        async with FakeShell("127.0.0.1", port, mode="real") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            assert await wait_for_verified(app, sid)

            result = await app.state.app_state.listeners.run_shell(sid, "id", wait_sec=2.0)
            assert result["sent"] is True
            assert result["verified"] is True
            assert "uid=0" in result["output"]
            assert "id" in shell.received
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_echo_only_peer_is_dropped_as_zombie(app):
    lid, port = await start_listener(app, name="tcp-echo")
    try:
        async with FakeShell("127.0.0.1", port, mode="echo_only") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            # run_shell before the background probe drops the channel
            result = await app.state.app_state.listeners.run_shell(sid, "whoami", wait_sec=1.5)
            assert result["error"] == "echo_only_zombie"
            assert result["dropped"] is True
            assert result["verified"] is False
            assert "whoami" in shell.received
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_silent_peer_is_dropped_unverified(app):
    lid, port = await start_listener(app, name="tcp-silent")
    try:
        async with FakeShell("127.0.0.1", port, mode="silent"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            closed = await wait_for_closed(app, sid, timeout=12.0)
            assert closed["status"] == "closed"
            assert not app.state.app_state.listeners.is_verified(sid)
            assert collect_events(app, "shell.unverified_drop")
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_tls_clienthello_rejected_before_session(app):
    lid, port = await start_listener(app, name="tcp-tls")
    try:
        async with FakeShell("127.0.0.1", port, mode="tls"):
            await wait_until(
                lambda: collect_events(app, "shell.false_positive"),
                timeout=5.0,
                message="TLS probe was not classified as a false positive",
            )
        rows = await app.state.app_state.db.list_sessions(status=None)
        assert not [r for r in rows if r.get("listener_id") == lid]
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_http_probe_rejected_before_session(app):
    lid, port = await start_listener(app, name="tcp-http-probe")
    try:
        async with FakeShell("127.0.0.1", port, mode="http"):
            await wait_until(
                lambda: collect_events(app, "shell.false_positive"),
                timeout=5.0,
                message="HTTP probe was not classified as a false positive",
            )
        rows = await app.state.app_state.db.list_sessions(status=None)
        assert not [r for r in rows if r.get("listener_id") == lid]
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_binary_noise_midstream_rejects_session(app):
    lid, port = await start_listener(app, name="tcp-binary")
    try:
        async with FakeShell("127.0.0.1", port, mode="real") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            await shell.send(BINARY_NOISE)
            await wait_for_gone(app, sid, timeout=8.0)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_stable_banner_marks_session_stage2(app):
    lid, port = await start_listener(app, name="tcp-stable")
    try:
        async with FakeShell("127.0.0.1", port, mode="real", banner="SC5_STABLE_LINUX\n"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]

            async def _stabilized() -> bool:
                current = await app.state.app_state.db.get_session(sid)
                meta = (current or {}).get("metadata") or {}
                if isinstance(meta, str):
                    import json

                    meta = json.loads(meta or "{}")
                return bool(meta.get("stabilized"))

            await wait_until(_stabilized, timeout=6.0, message="stable banner not recorded")
            current = await app.state.app_state.db.get_session(sid)
            assert current["os_info"] == "linux"
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_client_disconnect_closes_session(app):
    lid, port = await start_listener(app, name="tcp-disconnect")
    try:
        shell = FakeShell("127.0.0.1", port, mode="real")
        await shell.connect()
        row = await wait_for_session(app, listener_id=lid)
        sid = row["id"]
        await shell.close()
        closed = await wait_for_closed(app, sid, timeout=8.0)
        assert closed["status"] == "closed"
        assert collect_events(app, "shell.disconnected")
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_false_shell_filter_off_accepts_tls_probe(app):
    await app.state.app_state.features.set_many({"false_shell_filter": False}, actor="test")
    lid, port = await start_listener(app, name="tcp-filter-off")
    try:
        async with FakeShell("127.0.0.1", port, mode="tls"):
            row = await wait_for_session(app, listener_id=lid)
            assert row["kind"] == "reverse_shell"
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_exec_probe_off_skips_verification(app):
    await app.state.app_state.features.set_many({"shell_exec_probe": False}, actor="test")
    lid, port = await start_listener(app, name="tcp-probe-off")
    try:
        async with FakeShell("127.0.0.1", port, mode="silent"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            await asyncio.sleep(1.0)
            assert not app.state.app_state.listeners.is_verified(sid)
            current = await app.state.app_state.db.get_session(sid)
            assert current["status"] == "active"
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_auto_stabilize_injects_stage2(app):
    await app.state.app_state.features.set_many({"shell_auto_stabilize": True}, actor="test")
    lid, port = await start_listener(app, name="tcp-autostab")
    try:
        async with FakeShell("127.0.0.1", port, mode="real") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]

            async def _stabilized() -> bool:
                current = await app.state.app_state.db.get_session(sid)
                meta = (current or {}).get("metadata") or {}
                if isinstance(meta, str):
                    import json

                    meta = json.loads(meta or "{}")
                return bool(meta.get("stage2"))

            await wait_until(_stabilized, timeout=15.0, message="auto-stabilize never ran")
            assert any("SC5_STAGE2" in line or "base64" in line for line in shell.received)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_kill_channel_sends_die_and_drops(app):
    lid, port = await start_listener(app, name="tcp-kill")
    try:
        async with FakeShell("127.0.0.1", port, mode="real") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            assert await wait_for_verified(app, sid)
            await app.state.app_state.listeners.kill_channel(sid)
            await wait_for_closed(app, sid, timeout=8.0)
            assert any("SC5_DIE" in line for line in shell.received)
            assert not app.state.app_state.listeners.is_live(sid)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_resolve_callback_uses_socket_when_no_public_host(app):
    lid, port = await start_listener(app, name="tcp-callback")
    try:
        async with FakeShell("127.0.0.1", port, mode="real"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            host, cb_port = await app.state.app_state.listeners.resolve_callback(sid)
            assert host == "127.0.0.1"
            assert cb_port == port
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_resolve_callback_prefers_public_host(app):
    app.state.app_state.listeners.public_host = "c2.example.test"
    lid, port = await start_listener(app, name="tcp-callback-ph")
    try:
        async with FakeShell("127.0.0.1", port, mode="real"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            host, cb_port = await app.state.app_state.listeners.resolve_callback(sid)
            assert host == "c2.example.test"
            assert cb_port == port
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_resolve_callback_without_channel_raises(app):
    sid = await app.state.app_state.sessions.register(kind="reverse_shell", remote_addr="10.0.0.9:1")
    with pytest.raises(RuntimeError):
        await app.state.app_state.listeners.resolve_callback(sid)


@pytest.mark.asyncio
async def test_stabilize_requires_live_channel(app):
    sid = await app.state.app_state.sessions.register(kind="reverse_shell", remote_addr="10.0.0.9:2")
    with pytest.raises(RuntimeError, match="live reverse shell"):
        await app.state.app_state.listeners.stabilize_session(sid)


@pytest.mark.asyncio
async def test_stabilize_with_linux_hint(app):
    lid, port = await start_listener(app, name="tcp-stab-linux")
    try:
        async with FakeShell("127.0.0.1", port, mode="real") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            out = await app.state.app_state.listeners.stabilize_session(
                sid, os_hint="linux", actor="tester"
            )
            assert out["status"] == "stabilized"
            assert out["os"] == "linux"
            assert out["method"] == "python_stage2_line_exec"
            assert any("base64 -d" in line for line in shell.received)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_stabilize_with_windows_hint(app):
    lid, port = await start_listener(app, name="tcp-stab-win")
    try:
        async with FakeShell("127.0.0.1", port, mode="real") as shell:
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            out = await app.state.app_state.listeners.stabilize_session(
                sid, os_hint="windows", actor="tester"
            )
            assert out["status"] == "stabilized"
            assert out["os"] == "windows"
            assert any("powershell" in line.lower() for line in shell.received)
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_stabilize_skips_when_already_stable(app):
    lid, port = await start_listener(app, name="tcp-stab-skip")
    try:
        async with FakeShell("127.0.0.1", port, mode="real", banner="SC5_STABLE_LINUX\n"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            out = await app.state.app_state.listeners.stabilize_session(sid)
            assert out["status"] == "already_stable"
            assert out["callback"] == f"127.0.0.1:{port}"
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_stabilize_reports_session_gone(app):
    lid, port = await start_listener(app, name="tcp-stab-gone")
    try:
        async with FakeShell("127.0.0.1", port, mode="real"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            await app.state.app_state.db.delete_session(sid)
            out = await app.state.app_state.listeners.stabilize_session(sid, os_hint="linux")
            assert out["status"] == "error"
            assert out["reason"] == "session_gone"
    finally:
        await stop_listener(app, lid)


@pytest.mark.asyncio
async def test_send_shell_rejects_unknown_session(app):
    assert await app.state.app_state.listeners.send_shell("ses_missing", "id") is False


@pytest.mark.asyncio
async def test_run_shell_without_live_channel(app):
    out = await app.state.app_state.listeners.run_shell("ses_missing", "id")
    assert out["sent"] is False
    assert out["error"] == "no_live_channel"


@pytest.mark.asyncio
async def test_probe_exec_without_live_channel(app):
    assert await app.state.app_state.listeners.probe_exec("ses_missing") is False


@pytest.mark.asyncio
async def test_get_buffer_and_output_text(app):
    lid, port = await start_listener(app, name="tcp-buffer")
    try:
        async with FakeShell("127.0.0.1", port, mode="real"):
            row = await wait_for_session(app, listener_id=lid)
            sid = row["id"]
            await wait_until(
                lambda: app.state.app_state.listeners.get_output_text(sid),
                timeout=5.0,
                message="no output buffered",
            )
            assert app.state.app_state.listeners.get_buffer(sid)
            assert "bash" in app.state.app_state.listeners.get_output_text(sid)
    finally:
        await stop_listener(app, lid)
