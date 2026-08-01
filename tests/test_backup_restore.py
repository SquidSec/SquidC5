"""SQLite backup/restore (B04)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from squidc5.cli import main
from squidc5.db.backup import backup_database, restore_database
from squidc5.db.store import Database


@pytest.mark.asyncio
async def test_backup_and_restore_roundtrip(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    db_path = data / "squidc5.db"
    db = Database(db_path)
    await db.connect()
    await db.execute(
        "INSERT INTO tokens (id, name, token_hash, scopes, created_at) "
        "VALUES ('t1', 'keep', 'h1', '[\"admin\"]', 1.0)"
    )
    await db.close()

    bak = backup_database(db_path, tmp_path / "out" / "snap.db")
    assert bak.is_file()

    # mutate original
    con = sqlite3.connect(str(db_path))
    con.execute("DELETE FROM tokens")
    con.commit()
    con.close()

    restore_database(bak, db_path)
    con = sqlite3.connect(str(db_path))
    row = con.execute("SELECT name FROM tokens WHERE id='t1'").fetchone()
    con.close()
    assert row is not None
    assert row[0] == "keep"


def test_cli_backup_restore(tmp_path: Path, capsys):
    data = tmp_path / "d"
    data.mkdir()
    db_path = data / "squidc5.db"
    con = sqlite3.connect(str(db_path))
    con.executescript("CREATE TABLE t (id INT); INSERT INTO t VALUES (1);")
    con.close()

    out = tmp_path / "b.db"
    main(["backup", str(out), "--data-dir", str(data)])
    printed = json.loads(capsys.readouterr().out)
    assert printed["ok"] is True
    assert Path(printed["backup"]).is_file()

    # wipe and restore
    db_path.unlink()
    main(["restore", str(out), "--data-dir", str(data)])
    printed2 = json.loads(capsys.readouterr().out)
    assert printed2["ok"] is True
    con = sqlite3.connect(str(db_path))
    assert con.execute("SELECT id FROM t").fetchone()[0] == 1
    con.close()
