"""Minimal SMTP OAST listener - log MAIL/RCPT/DATA only; never relay."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from squidc5.listeners.manager import ListenerManager

log = logging.getLogger("squidc5.listeners.smtp")

_TOKEN_RE = re.compile(r"([a-z0-9]{8,32})@", re.I)
_LOCAL_RE = re.compile(r"^([a-z0-9]{8,32})$", re.I)


def extract_smtp_token(rcpt: str, mail_from: str = "", data: str = "") -> str | None:
    for src in (rcpt, mail_from):
        m = _TOKEN_RE.search(src or "")
        if m:
            return m.group(1).lower()
        local = (src or "").split("@", 1)[0].strip("<> ").lower()
        if _LOCAL_RE.match(local):
            return local
    m = re.search(r"(?:id|oast|c)=([a-z0-9]{8,32})", data or "", re.I)
    if m:
        return m.group(1).lower()
    return None


async def handle_smtp_client(
    manager: ListenerManager,
    listener_id: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
    oast = getattr(manager, "oast", None)
    if oast is not None and not oast.allow_remote(remote):
        try:
            await _send(writer, "421 rate limited")
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return

    mail_from = ""
    rcpts: list[str] = []
    try:
        await _send(writer, "220 squidc5-oast ESMTP ready")
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=60.0)
            except TimeoutError:
                break
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            upper = text.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                await _send(writer, "250-squidc5-oast")
                await _send(writer, "250 OK")
            elif upper.startswith("MAIL FROM:"):
                mail_from = text[10:].strip()
                await _send(writer, "250 OK")
            elif upper.startswith("RCPT TO:"):
                rcpts.append(text[8:].strip())
                await _send(writer, "250 OK")
            elif upper == "DATA":
                await _send(writer, "354 End data with <CR><LF>.<CR><LF>")
                chunks: list[str] = []
                while True:
                    dline = await asyncio.wait_for(reader.readline(), timeout=120.0)
                    if not dline:
                        break
                    s = dline.decode("utf-8", errors="replace")
                    if s.rstrip("\r\n") == ".":
                        break
                    chunks.append(s)
                data_buf = "".join(chunks)[:8192]
                await _record(manager, listener_id, remote, mail_from, rcpts, data_buf)
                await _send(writer, "250 OK queued")  # accepted + discarded (no relay)
                mail_from, rcpts = "", []
            elif upper in ("QUIT", "RSET"):
                if upper == "RSET":
                    mail_from, rcpts = "", []
                    await _send(writer, "250 OK")
                else:
                    await _send(writer, "221 bye")
                    break
            elif upper.startswith("NOOP") or upper.startswith("VRFY") or upper.startswith("HELP"):
                await _send(writer, "250 OK")
            else:
                await _send(writer, "250 OK")
    except Exception:
        log.exception("SMTP handler error from %s", remote)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _record(
    manager: ListenerManager,
    listener_id: str,
    remote: str,
    mail_from: str,
    rcpts: list[str],
    data: str,
) -> None:
    token = None
    for r in rcpts:
        token = extract_smtp_token(r, mail_from, data)
        if token:
            break
    if not token:
        token = extract_smtp_token("", mail_from, data)
    hit: dict[str, Any] = {
        "listener_id": listener_id,
        "remote": remote,
        "mail_from": mail_from[:500],
        "rcpt_to": [r[:500] for r in rcpts[:20]],
        "data_preview": data[:2000],
        "token": token,
        "ts": time.time(),
        "relay": False,
    }
    oast = getattr(manager, "oast", None)
    if oast is not None:
        await oast.record(
            protocol="smtp",
            listener_id=listener_id,
            remote=remote,
            token=token,
            raw=hit,
            correlation_key=token,
        )
    await manager.metrics.incr("smtp.hits")
    await manager.metrics.emit("smtp.hit", hit)
    await manager.db.audit(
        actor="implant",
        actor_type="smtp_listener",
        action="smtp.hit",
        resource=listener_id,
        details={"remote": remote, "token": token, "rcpt": (rcpts[0] if rcpts else "")[:200]},
        risk_score=1,
    )


async def _send(writer: asyncio.StreamWriter, line: str) -> None:
    writer.write((line + "\r\n").encode("utf-8"))
    await writer.drain()
