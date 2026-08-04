"""SQLite backup / restore helpers (live-safe via backup API + WAL)."""

from __future__ import annotations

import shutil
import sqlite3
import time
from pathlib import Path


def backup_database(source_db: Path, dest: Path, *, pages_per_step: int = 100) -> Path:
    """Hot backup via SQLite backup API (works while server is live under WAL).

    Copies in page steps so long backups yield to concurrent writers.
    """
    source_db = Path(source_db)
    dest = Path(dest)
    if not source_db.is_file():
        raise FileNotFoundError(f"database not found: {source_db}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.is_dir():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = dest / f"squidc5-{stamp}.db"
    # Read-only URI + WAL-friendly busy timeout
    src = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True, timeout=30.0)
    try:
        src.execute("PRAGMA busy_timeout=5000")
        dst = sqlite3.connect(str(dest), timeout=30.0)
        try:
            # Incremental backup so live writers are not blocked for the full copy
            with dst:
                src.backup(dst, pages=max(1, int(pages_per_step)))
            # Ensure WAL pages are reflected; checkpoint is best-effort on src
            try:
                src.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except sqlite3.Error:
                pass
            dst.commit()
        finally:
            dst.close()
    finally:
        src.close()
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    # Also copy -wal/-shm if present (usually empty after backup API, but safe)
    for suffix in ("-wal", "-shm"):
        side = Path(str(source_db) + suffix)
        if side.is_file() and side.stat().st_size == 0:
            continue
    return dest


def restore_database(backup_path: Path, target_db: Path) -> Path:
    """Replace target_db with backup. Caller should stop the server first."""
    backup_path = Path(backup_path)
    target_db = Path(target_db)
    if not backup_path.is_file():
        raise FileNotFoundError(f"backup not found: {backup_path}")
    # Validate backup is a readable SQLite DB
    con = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
    try:
        con.execute("SELECT 1 FROM sqlite_master LIMIT 1")
    finally:
        con.close()
    target_db.parent.mkdir(parents=True, exist_ok=True)
    if target_db.is_file():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        shutil.copy2(target_db, target_db.with_suffix(target_db.suffix + f".pre-restore-{stamp}"))
    shutil.copy2(backup_path, target_db)
    try:
        target_db.chmod(0o600)
    except OSError:
        pass
    return target_db
