"""Multi-type listeners. Port-flexible - no default 80/443 requirement."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from collections.abc import Awaitable, Callable
from typing import Any

from squidc5.db.store import Database
from squidc5.metrics.collector import MetricsCollector
from squidc5.shells.classify import classify_inbound
from squidc5.shells.stabilize import ShellStabilizer, detect_os

log = logging.getLogger("squidc5.listeners")

SessionFactory = Callable[..., Awaitable[str]]
RejectFactory = Callable[[str, str], Awaitable[None]]


class ListenerManager:
    def __init__(
        self,
        db: Database,
        metrics: MetricsCollector,
        session_factory: SessionFactory | None = None,
        reject_factory: RejectFactory | None = None,
        *,
        auto_stabilize: bool = True,
        public_host: str = "",
        stabilize_delay_sec: float = 0.8,
        probe_wait_sec: float = 1.5,
    ) -> None:
        self.db = db
        self.metrics = metrics
        self.session_factory = session_factory
        self.reject_factory = reject_factory
        self.auto_stabilize = auto_stabilize
        self.public_host = public_host
        self.stabilize_delay_sec = stabilize_delay_sec
        self.probe_wait_sec = probe_wait_sec
        # Optional task poll/complete for HTTP beacon listeners
        self.task_poll: Callable[[str], Awaitable[dict[str, Any] | None]] | None = None
        self.task_complete: Callable[[str, str, str], Awaitable[Any]] | None = None
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._udp: dict[str, asyncio.DatagramTransport] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._shell_queues: dict[str, asyncio.Queue[str | None]] = {}
        self._shell_buffers: dict[str, list[str]] = {}
        self._shell_seq: dict[str, int] = {}  # increments on each output chunk
        self._shell_events: dict[str, asyncio.Event] = {}
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._rejected: set[str] = set()
        self._verified: set[str] = set()
        self._restart_counts: dict[str, int] = {}
        self._max_restarts: int = 5
        self._supervise: bool = True
        # Optional: async (key) -> bool feature flag checker
        self.feature_check = None
        # OAST Collaborator store (set from main)
        self.oast = None
        self.profile_engine = None

    async def create(
        self,
        name: str,
        kind: str,
        port: int,
        host: str = "0.0.0.0",
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if kind not in ("http", "https", "tcp", "reverse_shell", "dns", "smtp"):
            raise ValueError(f"Unsupported listener kind: {kind}")
        if port < 1 or port > 65535:
            raise ValueError("Port must be 1-65535")
        # Reject port already used by another listener (any status)
        existing = await self.db.fetchall(
            "SELECT id, name, status, kind FROM listeners WHERE port = ? AND host = ?",
            (int(port), host or "0.0.0.0"),
        )
        if existing:
            e0 = existing[0]
            raise ValueError(
                f"Port {port} already used by listener {e0.get('name') or e0.get('id')} "
                f"({e0.get('kind')}, {e0.get('status')})"
            )
        lid = await self.db.create_listener(name, kind, port, host, config)
        await self.metrics.emit("listener.created", {"id": lid, "kind": kind, "port": port})
        row = await self.db.get_listener(lid)
        return self._norm(row)  # type: ignore[arg-type]

    async def list(self) -> list[dict[str, Any]]:
        return [self._norm(r) for r in await self.db.list_listeners()]

    async def get(self, listener_id: str) -> dict[str, Any] | None:
        row = await self.db.get_listener(listener_id)
        return self._norm(row) if row else None

    async def start(self, listener_id: str) -> dict[str, Any]:
        row = await self.db.get_listener(listener_id)
        if not row:
            raise KeyError("listener not found")
        async with self._lock:
            if listener_id in self._servers or listener_id in self._udp:
                return self._norm(row)
            kind = row["kind"]
            host = row["host"]
            port = int(row["port"])
            if kind in ("http", "https"):
                from squidc5.listeners.http_listener import handle_http_client

                ssl_ctx = None
                if kind == "https":
                    import ssl

                    from squidc5.tls.library import resolve_listener_ssl_paths

                    data_dir = getattr(self, "data_dir", None)
                    if data_dir is None:
                        raise ValueError("HTTPS listener requires data_dir on ListenerManager")
                    paths = resolve_listener_ssl_paths(data_dir)
                    if not paths:
                        raise ValueError(
                            "No TLS certificate available for HTTPS - upload one under Admin -> TLS"
                        )
                    cert_p, key_p = paths
                    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ssl_ctx.load_cert_chain(str(cert_p), str(key_p))
                server = await asyncio.start_server(
                    lambda r, w: handle_http_client(self, listener_id, r, w),
                    host=host,
                    port=port,
                    ssl=ssl_ctx,
                )
                self._servers[listener_id] = server
                task = asyncio.create_task(
                    server.serve_forever(), name=f"listener-{kind}-{listener_id}"
                )
                self._tasks[listener_id] = task
                self._attach_supervisor(listener_id, task)
                await self.db.set_listener_status(listener_id, "running")
                log.info("Started %s listener %s on %s:%s", kind, listener_id, host, port)
            elif kind == "dns":
                from squidc5.listeners.dns_listener import start_dns_server

                cfg = row.get("config") or {}
                if isinstance(cfg, str):
                    cfg = json.loads(cfg)
                cfg = cfg or {}
                zone = str(cfg.get("zone") or getattr(self, "oast_zone", None) or "c2.lab.invalid")
                mode = str(cfg.get("mode") or "both")  # beacon | oast | both
                public_ip = str(
                    cfg.get("public_ip")
                    or getattr(self, "public_ip", None)
                    or self.public_host
                    or "127.0.0.1"
                )
                ns_name = str(cfg.get("ns_name") or f"ns1.{zone}")
                transport, _proto = await start_dns_server(
                    self,
                    listener_id,
                    host,
                    port,
                    zone,
                    mode=mode,
                    public_ip=public_ip,
                    ns_name=ns_name,
                )
                self._udp[listener_id] = transport
                await self.db.set_listener_status(listener_id, "running")
                log.info(
                    "Started dns listener %s on %s:%s zone=%s mode=%s",
                    listener_id,
                    host,
                    port,
                    zone,
                    mode,
                )
            elif kind == "smtp":
                from squidc5.listeners.smtp_listener import handle_smtp_client

                server = await asyncio.start_server(
                    lambda r, w: handle_smtp_client(self, listener_id, r, w),
                    host=host,
                    port=port,
                )
                self._servers[listener_id] = server
                task = asyncio.create_task(server.serve_forever(), name=f"listener-smtp-{listener_id}")
                self._tasks[listener_id] = task
                self._attach_supervisor(listener_id, task)
                await self.db.set_listener_status(listener_id, "running")
                log.info("Started smtp listener %s on %s:%s", listener_id, host, port)
            elif kind in ("tcp", "reverse_shell"):
                server = await asyncio.start_server(
                    lambda r, w: self._handle_tcp(listener_id, kind, r, w),
                    host=host,
                    port=port,
                )
                self._servers[listener_id] = server
                task = asyncio.create_task(server.serve_forever(), name=f"listener-{listener_id}")
                self._tasks[listener_id] = task
                self._attach_supervisor(listener_id, task)
                await self.db.set_listener_status(listener_id, "running")
                log.info("Started %s listener %s on %s:%s", kind, listener_id, host, port)
            else:
                raise ValueError(f"Cannot start kind {kind}")
        await self.metrics.incr("listeners.started")
        await self.metrics.emit("listener.started", {"id": listener_id})
        updated = await self.db.get_listener(listener_id)
        return self._norm(updated)  # type: ignore[arg-type]

    async def stop(self, listener_id: str, *, persist_status: bool = True) -> dict[str, Any]:
        async with self._lock:
            task = self._tasks.pop(listener_id, None)
            server = self._servers.pop(listener_id, None)
            udp = self._udp.pop(listener_id, None)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            if server:
                server.close()
                await server.wait_closed()
            if udp:
                udp.close()
            if persist_status:
                await self.db.set_listener_status(listener_id, "stopped")
        await self.metrics.emit("listener.stopped", {"id": listener_id})
        row = await self.db.get_listener(listener_id)
        return self._norm(row)  # type: ignore[arg-type]

    async def delete(self, listener_id: str) -> bool:
        if listener_id in self._servers or listener_id in self._udp:
            await self.stop(listener_id)
        return await self.db.delete_listener(listener_id)

    async def stop_all(self, *, persist_status: bool = False) -> None:
        """Stop in-process sockets. Default leaves DB status for restart restore."""
        ids = list(set(self._servers.keys()) | set(self._udp.keys()))
        for lid in ids:
            try:
                await self.stop(lid, persist_status=persist_status)
            except Exception:
                log.exception("Error stopping listener %s", lid)

    async def restore_running(self) -> dict[str, Any]:
        """Start listeners marked running in DB (process restart recovery)."""
        restored: list[str] = []
        errors: list[dict[str, str]] = []
        rows = await self.db.list_listeners()
        for row in rows:
            if (row.get("status") or "") != "running":
                continue
            lid = row["id"]
            try:
                await self.start(lid)
                restored.append(lid)
            except Exception as e:
                log.exception("Failed to restore listener %s", lid)
                try:
                    await self.db.set_listener_status(lid, "error")
                except Exception:
                    pass
                errors.append({"id": lid, "error": str(e)[:200]})
                await self.metrics.emit(
                    "listener.restore_failed",
                    {"id": lid, "error": str(e)[:200]},
                )
        if restored:
            log.info("Restored %s listener(s) from DB: %s", len(restored), restored)
        return {"restored": restored, "errors": errors}

    def _attach_supervisor(self, listener_id: str, task: asyncio.Task[None]) -> None:
        if not self._supervise:
            return

        def _done(t: asyncio.Task[None]) -> None:
            if t.cancelled():
                return
            exc = t.exception()
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._on_listener_crash(listener_id, exc))
            except RuntimeError:
                pass

        task.add_done_callback(_done)

    async def _on_listener_crash(self, listener_id: str, exc: BaseException | None) -> None:
        """Restart crashed listener tasks with backoff (max_restarts)."""
        row = await self.db.get_listener(listener_id)
        if not row or (row.get("status") or "") != "running":
            return
        # Clean dead refs
        async with self._lock:
            self._tasks.pop(listener_id, None)
            srv = self._servers.pop(listener_id, None)
            if srv:
                try:
                    srv.close()
                except Exception:
                    pass
        n = self._restart_counts.get(listener_id, 0) + 1
        self._restart_counts[listener_id] = n
        if n > self._max_restarts:
            log.error("Listener %s exceeded max restarts (%s); marking error", listener_id, self._max_restarts)
            await self.db.set_listener_status(listener_id, "error")
            await self.metrics.emit(
                "listener.supervise_give_up",
                {"id": listener_id, "error": str(exc)[:200] if exc else "exit"},
            )
            return
        delay = min(30.0, 0.5 * (2 ** (n - 1)))
        log.warning(
            "Listener %s task ended (%s); restart %s/%s in %.1fs",
            listener_id,
            exc or "clean exit",
            n,
            self._max_restarts,
            delay,
        )
        await asyncio.sleep(delay)
        try:
            await self.start(listener_id)
            await self.metrics.emit("listener.supervised_restart", {"id": listener_id, "n": n})
        except Exception as e:
            log.exception("Supervised restart failed for %s", listener_id)
            await self.db.set_listener_status(listener_id, "error")
            await self.metrics.emit(
                "listener.supervise_failed",
                {"id": listener_id, "error": str(e)[:200]},
            )

    def _enable_keepalive(self, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock is None:
            return
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
        except OSError:
            pass

    def _callback_host_port(
        self, writer: asyncio.StreamWriter, listener_port: int
    ) -> tuple[str, int]:
        if self.public_host:
            return self.public_host, listener_port
        sockname = writer.get_extra_info("sockname")
        if sockname and sockname[0] not in ("0.0.0.0", "::", ""):
            return str(sockname[0]), int(sockname[1] or listener_port)
        return "127.0.0.1", listener_port

    async def _reject_session(self, sid: str, reason: str, remote: str) -> None:
        self._rejected.add(sid)
        self._shell_queues.pop(sid, None)
        self._shell_buffers.pop(sid, None)
        self._writers.pop(sid, None)
        log.info("Rejecting false shell %s from %s (%s)", sid, remote, reason)
        if self.reject_factory:
            await self.reject_factory(sid, reason)
        else:
            await self.db.delete_session(sid)
            await self.metrics.emit("session.rejected", {"id": sid, "reason": reason})
        await self.metrics.incr("shell.false_positive")

    async def _handle_tcp(
        self,
        listener_id: str,
        kind: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        sid = None
        rejected = False
        self._enable_keepalive(writer)
        try:
            # Peek first bytes before registering session when data arrives fast
            # (TLS scanners on 443). Real shells often send nothing initially.
            first: bytes | None = None
            try:
                first = await asyncio.wait_for(reader.read(512), timeout=0.4)
            except TimeoutError:
                first = None

            if first:
                do_filter = True
                if self.feature_check is not None:
                    try:
                        do_filter = await self.feature_check("false_shell_filter")
                    except Exception:
                        pass
                if do_filter:
                    verdict = classify_inbound(first)
                    if not verdict.is_shell:
                        log.info(
                            "Dropping inbound from %s before session create: %s",
                            remote,
                            verdict.reason,
                        )
                        await self.metrics.emit(
                            "shell.false_positive",
                            {"remote": remote, "reason": verdict.reason, "pre_session": True},
                        )
                        await self.metrics.incr("shell.false_positive")
                        return

            if self.session_factory:
                sid = await self.session_factory(
                    kind="reverse_shell" if kind == "reverse_shell" else "tcp",
                    remote_addr=remote,
                    listener_id=listener_id,
                )
            else:
                sid = await self.db.create_session(
                    kind="reverse_shell" if kind == "reverse_shell" else "tcp",
                    remote_addr=remote,
                    listener_id=listener_id,
                )
            q: asyncio.Queue[str | None] = asyncio.Queue()
            self._shell_queues[sid] = q
            self._shell_buffers[sid] = []
            self._shell_seq[sid] = 0
            self._shell_events[sid] = asyncio.Event()
            self._writers[sid] = writer

            if first:
                text0 = first.decode("utf-8", errors="replace")
                self._shell_buffers[sid].append(text0)
                await self.metrics.emit(
                    "shell.output",
                    {"session_id": sid, "data": text0[:2000]},
                )

            await self.metrics.emit(
                "shell.connected",
                {"session_id": sid, "remote": remote, "listener_id": listener_id},
            )

            row = await self.db.get_listener(listener_id)
            listener_port = int(row["port"]) if row else 0
            cb_host, cb_port = self._callback_host_port(writer, listener_port)

            async def pump_out() -> None:
                while True:
                    cmd = await q.get()
                    if cmd is None:
                        break
                    payload = cmd if cmd.endswith("\n") else cmd + "\n"
                    writer.write(payload.encode("utf-8", errors="replace"))
                    await writer.drain()

            out_task = asyncio.create_task(pump_out())
            stabilize_task: asyncio.Task[None] | None = None
            # Auto-stabilize: feature flag is the runtime switch (seeded from settings default OFF)
            do_stabilize = bool(self.auto_stabilize)
            do_probe = True
            do_filter = True
            if self.feature_check is not None:
                try:
                    do_stabilize = bool(await self.feature_check("shell_auto_stabilize"))
                    do_probe = await self.feature_check("shell_exec_probe")
                    do_filter = await self.feature_check("false_shell_filter")
                except Exception:
                    pass
            if kind == "reverse_shell" and do_stabilize:
                stabilize_task = asyncio.create_task(
                    self._stabilize_session(sid, cb_host, cb_port, delay=True),
                    name=f"stabilize-{sid}",
                )
            # Verify channel can execute - drop echo-only zombies
            if do_probe:
                asyncio.create_task(
                    self._verify_or_drop(sid, remote),
                    name=f"verify-{sid}",
                )

            try:
                while True:
                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=120.0)
                    except TimeoutError:
                        if sid in self._rejected:
                            break
                        # Do NOT touch last_seen_at on idle - that fakes a live shell.
                        # Probe whether the socket is still writable.
                        try:
                            if writer.is_closing():
                                break
                        except Exception:
                            break
                        continue
                    if not data:
                        break

                    # Continuous false-shell filtering on every chunk
                    verdict = classify_inbound(data)
                    if not verdict.is_shell and verdict.confidence >= 0.8:
                        rejected = True
                        if stabilize_task and not stabilize_task.done():
                            stabilize_task.cancel()
                        await self._reject_session(sid, verdict.reason, remote)
                        break

                    text = data.decode("utf-8", errors="replace")
                    buf = self._shell_buffers.get(sid)
                    if buf is not None:
                        buf.append(text)
                        if len(buf) > 200:
                            del buf[:-100]
                    self._shell_seq[sid] = self._shell_seq.get(sid, 0) + 1
                    ev = self._shell_events.get(sid)
                    if ev is not None:
                        ev.set()

                    if "SC5_STABLE" in text:
                        await self.db.update_session(
                            sid,
                            metadata={
                                "stabilized": True,
                                "stage2": True,
                                "stable_banner": True,
                            },
                            os_info=(
                                "windows"
                                if "WIN" in text.upper()
                                else "linux"
                                if "LINUX" in text.upper()
                                else None
                            ),
                        )

                    await self.db.execute(
                        "UPDATE sessions SET last_seen_at = ? WHERE id = ?",
                        (time.time(), sid),
                    )
                    await self.metrics.emit(
                        "shell.output",
                        {"session_id": sid, "data": text[:2000]},
                    )
            finally:
                if stabilize_task and not stabilize_task.done():
                    stabilize_task.cancel()
                    try:
                        await stabilize_task
                    except asyncio.CancelledError:
                        pass
                out_task.cancel()
                try:
                    await out_task
                except asyncio.CancelledError:
                    pass
        except Exception:
            log.exception("TCP handler error for %s", remote)
        finally:
            if sid and sid not in self._rejected and not rejected:
                self._shell_queues.pop(sid, None)
                self._shell_buffers.pop(sid, None)
                self._shell_seq.pop(sid, None)
                self._shell_events.pop(sid, None)
                self._writers.pop(sid, None)
                await self.db.update_session(sid, status="closed")
                await self.metrics.emit("shell.disconnected", {"session_id": sid})
            elif sid:
                self._shell_queues.pop(sid, None)
                self._shell_buffers.pop(sid, None)
                self._shell_seq.pop(sid, None)
                self._shell_events.pop(sid, None)
                self._writers.pop(sid, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def resolve_callback(self, session_id: str) -> tuple[str, int]:
        """Public host + listener port for stage-2 reconnect."""
        writer = self._writers.get(session_id)
        if writer is None:
            raise RuntimeError("session has no live TCP channel")
        srow = await self.db.get_session(session_id)
        listener_port = 0
        if srow and srow.get("listener_id"):
            lrow = await self.db.get_listener(str(srow["listener_id"]))
            if lrow:
                listener_port = int(lrow["port"] or 0)
        return self._callback_host_port(writer, listener_port)

    async def stabilize_session(
        self,
        session_id: str,
        *,
        os_hint: str | None = None,
        actor: str = "operator",
        delay: bool = False,
    ) -> dict[str, Any]:
        """Operator one-shot: probe OS (or use hint) and inject Win/Linux stage-2."""
        if not self.is_live(session_id):
            raise RuntimeError("session is not a live reverse shell")
        host, port = await self.resolve_callback(session_id)
        return await self._stabilize_session(
            session_id,
            host,
            port,
            os_hint=os_hint,
            actor=actor,
            delay=delay,
            reject_on_noise=False,
        )

    async def _stabilize_session(
        self,
        session_id: str,
        host: str,
        port: int,
        *,
        os_hint: str | None = None,
        actor: str = "system",
        delay: bool = True,
        reject_on_noise: bool = True,
    ) -> dict[str, Any]:
        """Probe OS then inject platform stage-2 reconnect agent (Linux/Windows)."""
        try:
            if delay:
                await asyncio.sleep(self.stabilize_delay_sec)
            if session_id in self._rejected:
                return {"status": "rejected", "session_id": session_id}

            early = "".join(self._shell_buffers.get(session_id, [])[-10:])
            if early:
                v = classify_inbound(early)
                if not v.is_shell and v.confidence >= 0.8:
                    if reject_on_noise:
                        await self._reject_session(session_id, v.reason, "stabilize-early")
                        return {"status": "rejected", "reason": v.reason, "session_id": session_id}
                    return {"status": "error", "reason": v.reason, "session_id": session_id}

            if "SC5_STABLE" in early:
                log.info("Session %s already stable (banner) - skip re-stage", session_id)
                row = await self.db.get_session(session_id)
                existing: dict[str, Any] = {}
                if row and row.get("metadata"):
                    try:
                        existing = (
                            json.loads(row["metadata"])
                            if isinstance(row["metadata"], str)
                            else dict(row["metadata"])
                        )
                    except (json.JSONDecodeError, TypeError):
                        existing = {}
                existing.update({"stabilized": True, "stage2": True, "stable_banner": True})
                await self.db.update_session(session_id, metadata=existing)
                await self.metrics.emit(
                    "shell.stabilize.skip",
                    {"session_id": session_id, "reason": "already_stable"},
                )
                return {
                    "status": "already_stable",
                    "session_id": session_id,
                    "callback": f"{host}:{port}",
                }

            stabilizer = ShellStabilizer(host, port)
            if delay:
                await asyncio.sleep(0.3)
            if session_id in self._rejected:
                return {"status": "rejected", "session_id": session_id}

            hint = (os_hint or "").strip().lower()
            family = "unknown"
            if hint in ("linux", "unix", "posix"):
                family = "linux"
            elif hint in ("windows", "win", "win32"):
                family = "windows"
            else:
                probe = stabilizer.probe_command()
                await self.send_shell(session_id, probe)
                await asyncio.sleep(self.probe_wait_sec)
                if session_id in self._rejected:
                    return {"status": "rejected", "session_id": session_id}

                blob = "".join(self._shell_buffers.get(session_id, [])[-20:])
                if blob:
                    v = classify_inbound(blob)
                    if not v.is_shell and v.confidence >= 0.8:
                        if reject_on_noise:
                            await self._reject_session(session_id, v.reason, "stabilize-probe")
                            return {"status": "rejected", "reason": v.reason, "session_id": session_id}
                        return {"status": "error", "reason": v.reason, "session_id": session_id}

                if "SC5_STABLE" in blob:
                    log.info("Session %s became stable during probe - skip", session_id)
                    return {
                        "status": "already_stable",
                        "session_id": session_id,
                        "callback": f"{host}:{port}",
                    }

                family = detect_os(blob)
                # Prefer session os_info when probe is ambiguous
                if family == "unknown":
                    srow = await self.db.get_session(session_id)
                    oi = ((srow or {}).get("os_info") or "").lower()
                    if "win" in oi:
                        family = "windows"
                    elif "linux" in oi or "unix" in oi or "darwin" in oi:
                        family = "linux"

            plan = stabilizer.plan(family)

            log.info(
                "Stabilizing session %s as %s via %s (callback %s:%s) actor=%s",
                session_id,
                plan.os_family,
                plan.method,
                host,
                port,
                actor,
            )
            await self.metrics.emit(
                "shell.stabilize.start",
                {
                    "session_id": session_id,
                    "os": plan.os_family,
                    "method": plan.method,
                    "callback": f"{host}:{port}",
                    "actor": actor,
                },
            )

            for cmd in plan.commands:
                if session_id in self._rejected:
                    return {"status": "rejected", "session_id": session_id}
                ok = await self.send_shell(session_id, cmd)
                if not ok:
                    break
                await asyncio.sleep(1.2)

            meta = {
                "stabilized": True,
                "stage2": True,
                "stabilize_os": plan.os_family,
                "stabilize_method": plan.method,
                "stabilize_callback": f"{host}:{port}",
                "stabilize_notes": plan.notes,
                "stabilize_actor": actor,
            }
            row = await self.db.get_session(session_id)
            if not row:
                return {"status": "error", "reason": "session_gone", "session_id": session_id}
            existing = {}
            if row.get("metadata"):
                try:
                    existing = (
                        json.loads(row["metadata"])
                        if isinstance(row["metadata"], str)
                        else dict(row["metadata"])
                    )
                except (json.JSONDecodeError, TypeError):
                    existing = {}
            existing.update(meta)
            fields: dict[str, Any] = {"metadata": existing}
            if plan.os_family != "unknown":
                fields["os_info"] = plan.os_family
            await self.db.update_session(session_id, **fields)
            await self.metrics.incr("shell.stabilized")
            await self.metrics.emit(
                "shell.stabilize.done",
                {"session_id": session_id, "os": plan.os_family, "method": plan.method},
            )
            await self.db.audit(
                actor=actor,
                actor_type="operator" if actor != "system" else "system",
                action="shell.stabilize",
                resource=session_id,
                details=meta,
                risk_score=4,
            )
            return {
                "status": "stabilized",
                "session_id": session_id,
                "os": plan.os_family,
                "method": plan.method,
                "callback": f"{host}:{port}",
                "notes": plan.notes,
            }
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("Stabilize failed for %s", session_id)
            await self.metrics.emit("shell.stabilize.error", {"session_id": session_id})
            raise RuntimeError(str(e) or "stabilize failed") from e

    def is_live(self, session_id: str) -> bool:
        """True only while a TCP reverse-shell channel is attached in this process."""
        if session_id in self._rejected:
            return False
        if session_id not in self._shell_queues:
            return False
        writer = self._writers.get(session_id)
        if writer is None:
            return False
        try:
            return not writer.is_closing()
        except Exception:
            return False

    def is_verified(self, session_id: str) -> bool:
        """Live channel that passed exec probe (preferred for operator use)."""
        return self.is_live(session_id) and session_id in self._verified

    # session ids that passed probe_exec
    # note: initialized in __init__ via attribute set below if missing

    async def drop_channel(self, session_id: str) -> None:
        """Force-close a live TCP channel (used after failed exec probe)."""
        self._rejected.add(session_id)
        self._verified.discard(session_id)
        self._shell_queues.pop(session_id, None)
        self._shell_buffers.pop(session_id, None)
        self._shell_seq.pop(session_id, None)
        self._shell_events.pop(session_id, None)
        writer = self._writers.pop(session_id, None)
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass

    async def mark_verified(self, session_id: str) -> None:
        self._verified.add(session_id)
        row = await self.db.get_session(session_id)
        meta: dict[str, Any] = {}
        if row:
            raw = row.get("metadata") or {}
            if isinstance(raw, str):
                try:
                    meta = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    meta = {}
            elif isinstance(raw, dict):
                meta = dict(raw)
        meta["exec_ok"] = True
        meta["verified"] = True
        await self.db.update_session(session_id, metadata=meta)
        # Ensure host reappears on Assets if previously bulk-dismissed
        try:
            from squidc5.hosts.graph import host_key_for_session

            if row:
                key = host_key_for_session({**dict(row), "verified": True, "metadata": meta})
                await self.db.unhide_host_graph(key)
        except Exception:
            log.debug("host unhide after verify failed", exc_info=True)

    async def _verify_or_drop(self, session_id: str, remote: str) -> None:
        """After connect (+ optional stabilize), require real command execution."""
        try:
            # Wait for stage-2 / banner; retry probe a few times
            ok = False
            for attempt in range(4):
                await asyncio.sleep(1.5 if attempt == 0 else 1.0)
                if session_id in self._rejected or not self.is_live(session_id):
                    return
                # If stage-2 banner already seen, still need exec proof
                ok = await self.probe_exec(session_id, timeout=1.5)
                if ok:
                    break
            if ok:
                await self.mark_verified(session_id)
                await self.metrics.emit(
                    "shell.verified",
                    {"session_id": session_id, "remote": remote},
                )
                log.info("Verified shell %s from %s", session_id, remote)
                return
            log.info("Dropping non-executing shell %s from %s", session_id, remote)
            self._verified.discard(session_id)
            await self.drop_channel(session_id)
            await self.db.update_session(session_id, status="closed")
            await self.metrics.emit(
                "shell.unverified_drop",
                {"session_id": session_id, "remote": remote},
            )
            await self.metrics.incr("shell.unverified_drop")
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("verify_or_drop failed for %s", session_id)

    async def probe_exec(self, session_id: str, timeout: float = 1.2) -> bool:
        """
        Prove the remote actually *executes* commands (not echo-only / half-dead).

        Sends:  SC5_PING <token>   (stage-2) then fallback echo SC5_PONG <token>
        Expects a result line exactly: SC5_PONG <token>
        """
        if not self.is_live(session_id):
            return False
        import secrets

        token = secrets.token_hex(4)
        expect = f"SC5_PONG {token}"

        async def _wait_marker(before: int, limit: float) -> bool:
            end = time.time() + limit
            while time.time() < end:
                text = "".join(self._shell_buffers.get(session_id, []))[before:]
                for line in text.splitlines():
                    if line.strip() == expect:
                        return True
                await asyncio.sleep(0.08)
            return False

        before = len("".join(self._shell_buffers.get(session_id, [])))
        if not await self.send_shell(session_id, f"SC5_PING {token}"):
            return False
        if await _wait_marker(before, timeout * 0.55):
            return True
        before2 = len("".join(self._shell_buffers.get(session_id, [])))
        if not await self.send_shell(session_id, f"echo {expect}"):
            return False
        return await _wait_marker(before2, timeout * 0.55)

    async def send_shell(self, session_id: str, command: str) -> bool:
        if session_id in self._rejected:
            return False
        q = self._shell_queues.get(session_id)
        if not q:
            return False
        writer = self._writers.get(session_id)
        if writer is not None:
            try:
                if writer.is_closing():
                    return False
            except Exception:
                return False
        await q.put(command)
        return True

    def get_buffer(self, session_id: str, limit: int = 50) -> list[str]:
        buf = self._shell_buffers.get(session_id, [])
        return buf[-limit:]

    def get_output_text(self, session_id: str, limit_chars: int = 8000) -> str:
        text = "".join(self._shell_buffers.get(session_id, []))
        if len(text) > limit_chars:
            return text[-limit_chars:]
        return text

    async def run_shell(
        self,
        session_id: str,
        command: str,
        wait_sec: float = 2.5,
        idle_sec: float = 0.45,
    ) -> dict[str, Any]:
        """
        Send a command and collect output that arrives afterward.

        Returns sent/output/timeout metadata for the operator CLI.
        """
        if not self.is_live(session_id):
            return {
                "sent": False,
                "session_id": session_id,
                "interactive": False,
                "output": "",
                "error": "no_live_channel",
            }

        before_seq = self._shell_seq.get(session_id, 0)
        before_len = len("".join(self._shell_buffers.get(session_id, [])))
        ev = self._shell_events.get(session_id)
        if ev is not None:
            ev.clear()

        ok = await self.send_shell(session_id, command)
        if not ok:
            return {
                "sent": False,
                "session_id": session_id,
                "interactive": False,
                "output": "",
                "error": "send_failed",
            }

        deadline = time.time() + max(0.2, wait_sec)
        got_any = False
        last_progress = time.time()
        last_seq = before_seq

        while time.time() < deadline:
            if not self.is_live(session_id):
                break
            seq = self._shell_seq.get(session_id, 0)
            if seq > last_seq:
                got_any = True
                last_seq = seq
                last_progress = time.time()
            # After first output, stop when shell goes quiet
            if got_any and (time.time() - last_progress) >= idle_sec:
                break
            if ev is not None:
                try:
                    await asyncio.wait_for(ev.wait(), timeout=0.2)
                    ev.clear()
                except TimeoutError:
                    pass
            else:
                await asyncio.sleep(0.15)

        full = "".join(self._shell_buffers.get(session_id, []))
        output = full[before_len:] if len(full) >= before_len else full
        # Cap response size for API
        if len(output) > 16000:
            output = output[-16000:]

        # Auto-verify real execution; flag pure echo (zombie)
        stripped_out = output.strip()
        cmd_stripped = command.strip()
        is_echo_only = bool(stripped_out) and (
            stripped_out == cmd_stripped
            or stripped_out.replace("\r", "") == cmd_stripped
        )
        is_real = bool(stripped_out) and not is_echo_only and (
            stripped_out.startswith("SC5_PONG")
            or "SC5_PONG " in stripped_out
            or not stripped_out.startswith(cmd_stripped)
        )
        if is_real and session_id not in self._verified:
            await self.mark_verified(session_id)
        if is_echo_only:
            # Echo-only TCP zombies look live but never execute
            log.info("Echo-only response on %s - dropping channel", session_id)
            await self.drop_channel(session_id)
            try:
                await self.db.update_session(session_id, status="closed")
            except Exception:
                pass
            await self.metrics.incr("shell.echo_zombie_drop")
            return {
                "sent": True,
                "session_id": session_id,
                "interactive": False,
                "verified": False,
                "command": command,
                "output": "",
                "error": "echo_only_zombie",
                "dropped": True,
                "waited_sec": round(max(0.0, wait_sec - max(0.0, deadline - time.time())), 2),
                "timed_out": False,
                "bytes": 0,
            }

        return {
            "sent": True,
            "session_id": session_id,
            "interactive": True,
            "verified": session_id in self._verified,
            "command": command,
            "output": output,
            "waited_sec": round(max(0.0, wait_sec - max(0.0, deadline - time.time())), 2),
            "timed_out": not got_any,
            "bytes": len(output.encode("utf-8", errors="replace")),
        }

    async def handle_beacon(
        self,
        listener_id: str,
        remote_addr: str | None,
        payload: dict[str, Any],
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """HTTP beacon check-in (same semantics as main API implant route)."""
        session_id = payload.get("session_id")
        hostname = payload.get("hostname")
        username = payload.get("username")
        os_info = payload.get("os_info")
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        metadata = {**metadata, "http_listener_id": listener_id}

        sid: str
        if session_id:
            existing = await self.db.get_session(session_id)
            if existing and existing.get("status") == "active":
                await self.db.update_session(
                    session_id,
                    hostname=hostname,
                    username=username,
                    os_info=os_info,
                    last_seen_at=time.time(),
                    metadata={
                        **(
                            json.loads(existing["metadata"])
                            if isinstance(existing.get("metadata"), str)
                            else (existing.get("metadata") or {})
                        ),
                        **metadata,
                    },
                )
                sid = session_id
            else:
                sid = await self._register_beacon(
                    remote_addr, user_agent, hostname, username, os_info, listener_id, metadata
                )
        else:
            sid = await self._register_beacon(
                remote_addr, user_agent, hostname, username, os_info, listener_id, metadata
            )

        task = None
        if self.task_poll:
            task = await self.task_poll(sid)
        await self.metrics.emit(
            "http.beacon",
            {"session_id": sid, "listener_id": listener_id, "remote": remote_addr},
        )
        return {"session_id": sid, "task": task}

    async def _register_beacon(
        self,
        remote_addr: str | None,
        user_agent: str | None,
        hostname: str | None,
        username: str | None,
        os_info: str | None,
        listener_id: str,
        metadata: dict[str, Any],
    ) -> str:
        if self.session_factory:
            return await self.session_factory(
                kind="beacon",
                remote_addr=remote_addr,
                user_agent=user_agent,
                hostname=hostname,
                username=username,
                os_info=os_info,
                listener_id=listener_id,
                metadata=metadata,
            )
        return await self.db.create_session(
            kind="beacon",
            remote_addr=remote_addr,
            user_agent=user_agent,
            hostname=hostname,
            username=username,
            os_info=os_info,
            listener_id=listener_id,
            metadata=metadata,
        )

    async def handle_beacon_result(self, payload: dict[str, Any]) -> dict[str, str]:
        task_id = str(payload.get("task_id") or "")
        result = str(payload.get("result") or "")
        status = str(payload.get("status") or "completed")
        session_id = payload.get("session_id")
        if not task_id:
            return {"status": "error", "detail": "task_id required"}
        # C07: bind to session when known
        if session_id:
            ok = await self.db.complete_task(
                task_id, result, status, session_id=str(session_id)
            )
            if not ok:
                return {"status": "error", "detail": "task/session mismatch or finalized"}
        elif self.task_complete:
            # Prefer task manager complete which validates state
            try:
                await self.task_complete(task_id, result, status)
            except TypeError:
                await self.task_complete(task_id, result, status)
            except KeyError:
                return {"status": "error", "detail": "task not found or finalized"}
        else:
            ok = await self.db.complete_task(task_id, result, status)
            if not ok:
                return {"status": "error", "detail": "task not found or finalized"}
        return {"status": "ok"}

    async def record_http_hit(self, listener_id: str, hit: dict[str, Any]) -> None:
        """OAST-style catch-all for non-beacon HTTP requests."""
        from squidc5.oast.store import (
            extract_token_from_host,
            extract_token_from_path,
            extract_token_from_query,
        )

        path = str(hit.get("path") or "")
        query = hit.get("query") if isinstance(hit.get("query"), dict) else {}
        headers = hit.get("headers") if isinstance(hit.get("headers"), dict) else {}
        zone = getattr(self, "oast_zone", "") or ""
        token = (
            extract_token_from_path(path)
            or extract_token_from_query(query)
            or extract_token_from_host(str(headers.get("host") or ""), zone=zone)
        )
        hit = {**hit, "token": token}
        if self.oast is not None:
            await self.oast.record(
                protocol="http",
                listener_id=listener_id,
                remote=str(hit.get("remote") or ""),
                token=token,
                raw=hit,
                correlation_key=token,
            )
        await self.metrics.incr("http.hits")
        await self.metrics.emit("http.hit", hit)
        await self.db.audit(
            actor="implant",
            actor_type="http_listener",
            action="http.hit",
            resource=listener_id,
            details={
                "remote": hit.get("remote"),
                "method": hit.get("method"),
                "path": path[:200],
                "token": token,
            },
            risk_score=1,
        )

    def _norm(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        cfg = out.get("config")
        if isinstance(cfg, str):
            try:
                out["config"] = json.loads(cfg)
            except json.JSONDecodeError:
                out["config"] = {}
        return out
