"""At-rest encryption for server secrets (LLM API keys, etc.)."""

from __future__ import annotations

import base64
import logging
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

log = logging.getLogger("squidc5.crypto")

ENC_PREFIX = "enc:v1:"
SECRETS_KEY_FILENAME = "secrets.key"
_SALT = b"squidc5-secrets-v1"


def _derive_fernet_key(material: bytes) -> bytes:
    """Derive a url-safe 32-byte Fernet key from arbitrary material."""
    if material.startswith(b"fernet:"):
        return material[len(b"fernet:") :].strip()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=480_000,
    )
    raw = kdf.derive(material)
    return base64.urlsafe_b64encode(raw)


def resolve_secrets_key(*, explicit: str | None, data_dir: Path) -> bytes:
    """Load or generate master key material for at-rest encryption."""
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip().encode("utf-8")
    path = Path(data_dir) / SECRETS_KEY_FILENAME
    if path.is_file():
        data = path.read_bytes().strip()
        if data:
            return data
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    material = secrets.token_urlsafe(48).encode("utf-8")
    path.write_bytes(material + b"\n")
    try:
        path.chmod(0o600)
    except OSError:
        log.warning("Could not chmod 0600 on %s", path)
    log.info("Generated secrets master key at %s", path)
    return material


class SecretBox:
    """Encrypt/decrypt small secrets; plaintext legacy values pass through on decrypt."""

    def __init__(self, key_material: bytes) -> None:
        self._fernet = Fernet(_derive_fernet_key(key_material))

    def encrypt(self, plaintext: str | None) -> str | None:
        if plaintext is None or plaintext == "":
            return plaintext
        if plaintext.startswith(ENC_PREFIX):
            return plaintext
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return ENC_PREFIX + token

    def decrypt(self, stored: str | None) -> str | None:
        if stored is None or stored == "":
            return stored
        if not stored.startswith(ENC_PREFIX):
            # Legacy plaintext row
            return stored
        token = stored[len(ENC_PREFIX) :].encode("ascii")
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Failed to decrypt secret (wrong SQUIDC5_SECRETS_KEY?)") from e

    def is_encrypted(self, stored: str | None) -> bool:
        return bool(stored and stored.startswith(ENC_PREFIX))
