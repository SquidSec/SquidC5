"""Asymmetric key vault: create, derive public key, decrypt. Private keys never leave the server."""

from __future__ import annotations

import base64

import pytest
from conftest import bearer, mint_token

from squidc5.crypto.asymmetric import generate_keypair, open_message, public_encodings, rsa_oaep_encrypt, seal
from squidc5.db.migrate import MIGRATIONS


def test_derive_public_and_roundtrip():
    private_pem, public_pem = generate_keypair(2048)
    enc = public_encodings(private_pem, comment="key_test")
    assert enc["public_pem"] == public_pem
    assert enc["public_pkcs1_pem"].startswith("-----BEGIN RSA PUBLIC KEY-----")
    assert str(enc["public_openssh"]).startswith("ssh-rsa ")
    assert "PRIVATE" not in public_pem
    raw = rsa_oaep_encrypt(public_pem, b"ping")
    assert open_message(private_pem, base64.b64encode(raw).decode()) == b"ping"
    sealed = seal(public_pem, b"hello vault")
    assert sealed.startswith("sc5e1:")
    assert open_message(private_pem, sealed) == b"hello vault"


def test_rejects_bad_key_size():
    with pytest.raises(ValueError):
        generate_keypair(1024)


@pytest.mark.asyncio
async def test_migration_creates_asym_keys(tmp_path):
    from squidc5.db.store import Database

    db = Database(tmp_path / "k.db")
    await db.connect()
    assert MIGRATIONS[-1][0] >= 7
    row = await db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='asym_keys'"
    )
    assert row is not None
    await db.close()


async def _enable(client, admin_headers):
    r = await client.put(
        "/api/v1/features",
        headers=admin_headers,
        json={"features": {"asym_keys": True}},
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_disabled_by_default(client, admin_headers):
    r = await client.post("/api/v1/keys", headers=admin_headers, json={"name": "nope"})
    assert r.status_code == 403
    flags = await client.get("/api/v1/features", headers=admin_headers)
    assert flags.json()["features"]["asym_keys"] is False


@pytest.mark.asyncio
async def test_create_public_decrypt_and_no_private_leak(client, admin_headers, app):
    await _enable(client, admin_headers)
    created = await client.post(
        "/api/v1/keys",
        headers=admin_headers,
        json={"name": "lab-vault", "key_size": 2048},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    kid = body["id"]
    assert body["public_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "private" not in body
    assert "PRIVATE KEY" not in created.text

    listed = await client.get("/api/v1/keys", headers=admin_headers)
    assert listed.status_code == 200
    assert any(row["id"] == kid for row in listed.json())
    assert "PRIVATE KEY" not in listed.text
    assert "private_pem" not in listed.text

    derived = await client.get(f"/api/v1/keys/{kid}/public", headers=admin_headers)
    assert derived.status_code == 200, derived.text
    pub = derived.json()
    assert pub["derived"] is True
    assert pub["public_pem"] == body["public_pem"]
    assert pub["public_pkcs1_pem"].startswith("-----BEGIN RSA PUBLIC KEY-----")
    assert pub["public_openssh"].startswith("ssh-rsa ")
    assert pub["fingerprint_sha256"] == body["fingerprint_sha256"]
    assert "PRIVATE" not in derived.text

    sealed = await client.post(
        f"/api/v1/keys/{kid}/encrypt",
        headers=admin_headers,
        json={"plaintext": "authorized-note"},
    )
    assert sealed.status_code == 200
    token = sealed.json()["ciphertext"]
    assert token.startswith("sc5e1:")

    opened = await client.post(
        f"/api/v1/keys/{kid}/decrypt",
        headers=admin_headers,
        json={"ciphertext": token},
    )
    assert opened.status_code == 200, opened.text
    assert opened.json()["plaintext"] == "authorized-note"
    assert "PRIVATE KEY" not in opened.text

    raw = rsa_oaep_encrypt(body["public_pem"], b"oaep-ok")
    raw_open = await client.post(
        f"/api/v1/keys/{kid}/decrypt",
        headers=admin_headers,
        json={"ciphertext": base64.b64encode(raw).decode()},
    )
    assert raw_open.status_code == 200
    assert raw_open.json()["plaintext"] == "oaep-ok"

    stored = await app.state.app_state.db.fetchone(
        "SELECT private_pem_enc FROM asym_keys WHERE id = ?",
        (kid,),
    )
    assert stored["private_pem_enc"].startswith("enc:v1:")
    assert "PRIVATE KEY" not in stored["private_pem_enc"]

    audit = await client.get("/api/v1/audit?limit=30", headers=admin_headers)
    blob = audit.text
    assert "PRIVATE KEY" not in blob
    assert "authorized-note" not in blob
    assert token not in blob


@pytest.mark.asyncio
async def test_scope_and_auth_gates(client, admin_headers):
    await _enable(client, admin_headers)
    assert (await client.post("/api/v1/keys", json={"name": "x"})).status_code == 401
    reader = await mint_token(client, admin_headers, "key-reader", ["keys:read"])
    rh = bearer(reader["token"])
    denied = await client.post("/api/v1/keys", headers=rh, json={"name": "no-write"})
    assert denied.status_code == 403
    created = await client.post("/api/v1/keys", headers=admin_headers, json={"name": "scoped"})
    kid = created.json()["id"]
    assert (await client.get(f"/api/v1/keys/{kid}/public", headers=rh)).status_code == 200
    sealed = (
        await client.post(
            f"/api/v1/keys/{kid}/encrypt",
            headers=rh,
            json={"plaintext": "secret-body"},
        )
    ).json()["ciphertext"]
    assert (
        await client.post(
            f"/api/v1/keys/{kid}/decrypt",
            headers=rh,
            json={"ciphertext": sealed},
        )
    ).status_code == 403
    stranger = await mint_token(client, admin_headers, "no-keys", ["sessions:read"])
    assert (
        await client.get("/api/v1/keys", headers=bearer(stranger["token"]))
    ).status_code == 403


@pytest.mark.asyncio
async def test_tokens_manage_cannot_grant_key_write(client, admin_headers):
    mgr = await mint_token(client, admin_headers, "mgr", ["tokens:manage", "sessions:read"])
    r = await client.post(
        "/api/v1/tokens",
        headers=bearer(mgr["token"]),
        json={"name": "vault", "scopes": ["keys:write", "keys:decrypt"]},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_bad_ciphertext_and_delete(client, admin_headers):
    await _enable(client, admin_headers)
    created = await client.post("/api/v1/keys", headers=admin_headers, json={"name": "drop-me"})
    kid = created.json()["id"]
    bad = await client.post(
        f"/api/v1/keys/{kid}/decrypt",
        headers=admin_headers,
        json={"ciphertext": base64.b64encode(b"\x00" * 256).decode()},
    )
    assert bad.status_code == 400
    assert "PRIVATE" not in bad.text
    other = await client.post("/api/v1/keys", headers=admin_headers, json={"name": "other", "key_size": 2048})
    foreign = seal(other.json()["public_pem"], b"not-for-you")
    mismatch = await client.post(
        f"/api/v1/keys/{kid}/decrypt",
        headers=admin_headers,
        json={"ciphertext": foreign},
    )
    assert mismatch.status_code == 400
    gone = await client.delete(f"/api/v1/keys/{kid}", headers=admin_headers)
    assert gone.status_code == 200
    assert (await client.get(f"/api/v1/keys/{kid}", headers=admin_headers)).status_code == 404


@pytest.mark.asyncio
async def test_rejects_weak_size(client, admin_headers):
    await _enable(client, admin_headers)
    r = await client.post(
        "/api/v1/keys",
        headers=admin_headers,
        json={"name": "weak", "key_size": 1024},
    )
    assert r.status_code == 400
