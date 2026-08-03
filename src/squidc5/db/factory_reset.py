"""Factory reset: wipe operator data back to first-boot shape."""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("squidc5.db.factory_reset")

CONFIRM_PHRASE = "FACTORY RESET"

# Files always removed (secrets + bootstrap token)
_ALWAYS_WIPE_FILES = (
    "admin_token.txt",
    "secrets.key",
    "implant_psk.txt",
    "plugin_signing.secret",
)


def _unlink(path: Path) -> bool:
    try:
        if path.is_file() or path.is_symlink():
            path.unlink()
            return True
        if path.is_dir():
            shutil.rmtree(path)
            return True
    except OSError as e:
        log.warning("factory reset could not remove %s: %s", path, e)
    return False


def wipe_data_dir(
    data_dir: Path,
    *,
    keep_tls: bool = True,
    keep_implant_psk: bool = False,
    regenerate_instance_tls: bool = False,
) -> dict[str, Any]:
    """Delete DB + secrets on disk. Does not touch process env."""
    data_dir = Path(data_dir)
    removed: list[str] = []
    data_dir.mkdir(parents=True, exist_ok=True)

    db = data_dir / "squidc5.db"
    for p in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
        if _unlink(p):
            removed.append(p.name)

    for name in _ALWAYS_WIPE_FILES:
        if name == "implant_psk.txt" and keep_implant_psk:
            continue
        p = data_dir / name
        if _unlink(p):
            removed.append(name)

    tls = data_dir / "tls"
    if regenerate_instance_tls and tls.is_dir():
        for name in ("server.crt", "server.key", "instance_id"):
            p = tls / name
            if _unlink(p):
                removed.append(f"tls/{name}")
    if not keep_tls and tls.exists():
        if _unlink(tls):
            removed.append("tls/")

    return {
        "data_dir": str(data_dir),
        "removed": removed,
        "keep_tls": keep_tls,
        "keep_implant_psk": keep_implant_psk,
        "regenerate_instance_tls": regenerate_instance_tls,
        "ts": time.time(),
    }


async def factory_reset_running(
    app: Any,
    *,
    keep_tls: bool = True,
    keep_implant_psk: bool = False,
    regenerate_instance_tls: bool = False,
    actor: str = "admin",
) -> dict[str, Any]:
    """Stop listeners, wipe data_dir state, rebuild AppState in-process.

    Returns dict including one-time ``admin_token`` for the new bootstrap admin.
    """
    from squidc5.main import build_state

    old = app.state.app_state
    settings = old.settings
    data_dir = Path(settings.data_dir)

    # Best-effort audit before wipe (chain will be destroyed)
    try:
        await old.db.audit(
            actor=actor,
            actor_type="admin",
            action="system.factory_reset",
            details={
                "keep_tls": keep_tls,
                "keep_implant_psk": keep_implant_psk,
                "regenerate_instance_tls": regenerate_instance_tls,
            },
            risk_score=10,
        )
    except Exception:
        log.exception("pre-reset audit failed")

    try:
        await old.listeners.stop_all(persist_status=False)
    except Exception:
        log.exception("stop_all during factory reset")

    try:
        if old.socks is not None and hasattr(old.socks, "close_all"):
            await old.socks.close_all()
    except Exception:
        pass

    await old.db.close()

    wipe_info = wipe_data_dir(
        data_dir,
        keep_tls=keep_tls,
        keep_implant_psk=keep_implant_psk,
        regenerate_instance_tls=regenerate_instance_tls,
    )

    # Force fresh secrets even if env pinned empty; build_state resolves files again
    new_state = await build_state(settings)
    app.state.app_state = new_state

    admin_token = ""
    token_file = data_dir / "admin_token.txt"
    if token_file.is_file():
        admin_token = token_file.read_text(encoding="utf-8").strip()
    elif new_state.admin_token_once:
        admin_token = new_state.admin_token_once

    # Ensure bootstrap wrote a token (build_state already does; double-check empty)
    if not admin_token:
        raw = await new_state.tokens.bootstrap_admin(settings.admin_token_bootstrap)
        if raw:
            token_file.write_text(raw + "\n", encoding="utf-8")
            try:
                token_file.chmod(0o600)
            except OSError:
                pass
            admin_token = raw

    log.warning(
        "Factory reset complete by %s keep_tls=%s removed=%s",
        actor,
        keep_tls,
        wipe_info.get("removed"),
    )

    return {
        "status": "reset",
        "admin_token": admin_token,
        "admin_name": "squidc5-admin",
        "note": "All sessions, tokens, LLMs, and audit history wiped. "
        "Save the admin_token now — it is only returned once. "
        "Reconnect Ops with the new token.",
        **wipe_info,
        "pid": os.getpid(),
    }
