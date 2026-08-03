"""Admin factory reset API + wipe helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squidc5.cli import main
from squidc5.db.factory_reset import CONFIRM_PHRASE, wipe_data_dir


@pytest.mark.asyncio
async def test_factory_reset_requires_confirm(client, admin_headers):
    r = await client.post(
        "/api/v1/admin/factory-reset",
        headers=admin_headers,
        json={"confirm": "nope"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_factory_reset_admin_only(client, admin_headers):
    from tests.conftest import bearer, mint_token

    op = await mint_token(client, admin_headers, "op", ["sessions:read"])
    r = await client.post(
        "/api/v1/admin/factory-reset",
        headers=bearer(op["token"]),
        json={"confirm": CONFIRM_PHRASE},
    )
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_factory_reset_wipes_and_returns_token(client, admin_headers, app):
    # create extra token so we can prove wipe
    mint = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={"name": "doomed", "scopes": ["sessions:read"]},
    )
    assert mint.status_code == 200
    before = await client.get("/api/v1/tokens", headers=admin_headers)
    assert before.status_code == 200
    before_rows = before.json()
    assert isinstance(before_rows, list)
    assert len(before_rows) >= 2

    r = await client.post(
        "/api/v1/admin/factory-reset",
        headers=admin_headers,
        json={
            "confirm": CONFIRM_PHRASE,
            "keep_tls": True,
            "keep_implant_psk": False,
            "regenerate_instance_tls": False,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("status") == "reset"
    new_tok = body.get("admin_token") or ""
    assert new_tok.startswith("sc5_")
    assert body.get("admin_name") == "squidc5-admin"

    # tests pin admin_token_bootstrap so secret may match bootstrap value
    new_h = {"Authorization": f"Bearer {new_tok}"}
    who = await client.get("/api/v1/meta", headers=new_h)
    assert who.status_code == 200
    tokens = await client.get("/api/v1/tokens", headers=new_h)
    assert tokens.status_code == 200
    names = [t.get("name") for t in (tokens.json() or [])]
    assert "doomed" not in names
    assert any(n == "squidc5-admin" for n in names)


def test_wipe_data_dir_files(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "squidc5.db").write_bytes(b"x")
    (data / "admin_token.txt").write_text("old\n")
    (data / "secrets.key").write_text("k")
    (data / "implant_psk.txt").write_text("p")
    tls = data / "tls"
    tls.mkdir()
    (tls / "server.crt").write_text("c")
    info = wipe_data_dir(data, keep_tls=True, keep_implant_psk=True)
    assert not (data / "squidc5.db").exists()
    assert not (data / "admin_token.txt").exists()
    assert (data / "implant_psk.txt").exists()
    assert (tls / "server.crt").exists()
    assert "squidc5.db" in info["removed"]


def test_cli_factory_reset(tmp_path: Path, capsys):
    data = tmp_path / "d"
    data.mkdir()
    (data / "squidc5.db").write_bytes(b"garbage")
    (data / "admin_token.txt").write_text("old\n")
    main(["factory-reset", "--yes", "--data-dir", str(data)])
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["admin_token"].startswith("sc5_")
    assert (data / "admin_token.txt").is_file()
    assert (data / "squidc5.db").is_file()
