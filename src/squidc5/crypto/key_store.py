"""Server-side asymmetric key vault. Private keys are encrypted at rest and never returned."""

from __future__ import annotations

import secrets
import time
from typing import Any

from squidc5.crypto.asymmetric import (
    ALG,
    MAX_KEYS,
    AsymKeyError,
    generate_keypair,
    open_message,
    public_encodings,
    seal,
    validate_key_size,
    validate_name,
)
from squidc5.crypto.secrets import SecretBox
from squidc5.db.store import Database


class AsymKeyService:
    def __init__(self, db: Database, secrets: SecretBox) -> None:
        self.db = db
        self.secrets = secrets

    async def create(self, name: str, key_size: int, created_by: str | None) -> dict[str, Any]:
        cleaned = validate_name(name)
        size = validate_key_size(key_size)
        count = await self.db.fetchone("SELECT COUNT(*) AS n FROM asym_keys")
        if count and int(count["n"]) >= MAX_KEYS:
            raise AsymKeyError("limit", "key limit reached")
        private_pem, public_pem = generate_keypair(size)
        key_id = f"key_{secrets.token_hex(8)}"
        enc = public_encodings(private_pem, comment=key_id)
        if enc["public_pem"] != public_pem:
            raise AsymKeyError("invalid", "public key derivation failed")
        stored = self.secrets.encrypt(private_pem)
        if not stored or "PRIVATE KEY" in stored:
            raise AsymKeyError("invalid", "private key storage failed")
        now = time.time()
        await self.db.execute(
            "INSERT INTO asym_keys "
            "(id, name, algorithm, key_size, public_pem, fingerprint_sha256, private_pem_enc, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                key_id,
                cleaned,
                ALG,
                size,
                public_pem,
                str(enc["fingerprint_sha256"]),
                stored,
                created_by,
                now,
            ),
        )
        return self._public_view(
            {
                "id": key_id,
                "name": cleaned,
                "algorithm": ALG,
                "key_size": size,
                "public_pem": public_pem,
                "fingerprint_sha256": enc["fingerprint_sha256"],
                "created_by": created_by,
                "created_at": now,
            }
        )

    async def list_keys(self, limit: int = 100) -> list[dict[str, Any]]:
        cap = max(1, min(int(limit), MAX_KEYS))
        rows = await self.db.fetchall(
            "SELECT id, name, algorithm, key_size, public_pem, fingerprint_sha256, created_by, created_at "
            "FROM asym_keys ORDER BY created_at DESC LIMIT ?",
            (cap,),
        )
        return [self._public_view(r) for r in rows]

    async def get(self, key_id: str) -> dict[str, Any]:
        row = await self._row(key_id)
        return self._public_view(row)

    async def public_key(self, key_id: str) -> dict[str, Any]:
        """Re-derive public encodings from the stored private key."""
        row = await self._row(key_id)
        private_pem = self._unlock(row)
        enc = public_encodings(private_pem, comment=key_id)
        if enc["public_pem"] != row["public_pem"] or enc["fingerprint_sha256"] != row["fingerprint_sha256"]:
            raise AsymKeyError("invalid", "stored public key does not match private key")
        return {
            "id": row["id"],
            "name": row["name"],
            "algorithm": enc["algorithm"],
            "key_size": enc["key_size"],
            "public_pem": enc["public_pem"],
            "public_pkcs1_pem": enc["public_pkcs1_pem"],
            "public_openssh": enc["public_openssh"],
            "fingerprint_sha256": enc["fingerprint_sha256"],
            "derived": True,
        }

    async def encrypt(self, key_id: str, plaintext: bytes) -> dict[str, str]:
        row = await self._row(key_id)
        token = seal(row["public_pem"], plaintext)
        return {"id": key_id, "ciphertext": token, "format": "sc5e1"}

    async def decrypt(self, key_id: str, ciphertext: str) -> dict[str, Any]:
        row = await self._row(key_id)
        private_pem = self._unlock(row)
        pt = open_message(private_pem, ciphertext)
        out: dict[str, Any] = {
            "id": key_id,
            "plaintext_b64": _b64(pt),
            "encoding": "binary",
        }
        try:
            text = pt.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is not None:
            out["plaintext"] = text
            out["encoding"] = "utf-8"
        return out

    async def delete(self, key_id: str) -> bool:
        self._check_id(key_id)
        cur = await self.db.execute("DELETE FROM asym_keys WHERE id = ?", (key_id,))
        return cur.rowcount > 0

    async def _row(self, key_id: str) -> dict[str, Any]:
        self._check_id(key_id)
        row = await self.db.fetchone("SELECT * FROM asym_keys WHERE id = ?", (key_id,))
        if not row:
            raise AsymKeyError("not_found", "key not found")
        return row

    def _unlock(self, row: dict[str, Any]) -> str:
        try:
            private_pem = self.secrets.decrypt(row["private_pem_enc"])
        except ValueError as e:
            raise AsymKeyError("unavailable", "key material unavailable") from e
        if not private_pem or "PRIVATE KEY" not in private_pem:
            raise AsymKeyError("unavailable", "key material unavailable")
        return private_pem

    @staticmethod
    def _check_id(key_id: str) -> None:
        if not key_id or not key_id.startswith("key_") or len(key_id) > 64:
            raise AsymKeyError("not_found", "key not found")

    @staticmethod
    def _public_view(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "algorithm": row["algorithm"],
            "key_size": row["key_size"],
            "public_pem": row["public_pem"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "created_by": row.get("created_by"),
            "created_at": row["created_at"],
        }


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")
