"""Implant channel AEAD (ChaCha20-Poly1305) for beacon check-ins."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ALG = "chacha20-poly1305"
PSK_FILENAME = "implant_psk.txt"
ENVELOPE_KEYS = frozenset({"v", "n", "c", "alg"})


def derive_key(psk: str | bytes) -> bytes:
    """SHA256(psk) — must match agents/sc5beacon crypto.go."""
    raw = psk.encode("utf-8") if isinstance(psk, str) else psk
    return hashlib.sha256(raw).digest()


def resolve_implant_psk(*, explicit: str | None, data_dir: Path) -> str:
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip()
    path = Path(data_dir) / PSK_FILENAME
    if path.is_file():
        val = path.read_text(encoding="utf-8").strip()
        if val:
            return val
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    val = secrets.token_urlsafe(32)
    path.write_text(val + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return val


def _aad(extra: bytes | None = None) -> bytes:
    # H09: bind protocol version as AAD (session/path can be layered later)
    base = b"sc5-aead-v1"
    return base + (b"|" + extra if extra else b"")


def seal(psk: str | bytes, obj: dict[str, Any], *, aad: bytes | None = None) -> dict[str, Any]:
    key = derive_key(psk)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ct = aead.encrypt(nonce, pt, _aad(aad))
    return {
        "v": 1,
        "alg": ALG,
        "n": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        "c": base64.urlsafe_b64encode(ct).decode("ascii").rstrip("="),
    }


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def is_envelope(obj: Any) -> bool:
    return isinstance(obj, dict) and ENVELOPE_KEYS.issubset(obj.keys()) and obj.get("v") == 1


def open_envelope(
    psk: str | bytes, envelope: dict[str, Any], *, aad: bytes | None = None
) -> dict[str, Any]:
    if not is_envelope(envelope):
        raise ValueError("not an implant envelope")
    if envelope.get("alg") != ALG:
        raise ValueError("unsupported implant cipher")
    key = derive_key(psk)
    aead = ChaCha20Poly1305(key)
    nonce = _b64d(str(envelope["n"]))
    if len(nonce) != 12:
        raise ValueError("invalid nonce")
    ct = _b64d(str(envelope["c"]))
    # Try new AAD first; fall back to legacy empty AAD for rolling upgrade
    last_err: Exception | None = None
    for associated in (_aad(aad), b"", None):
        try:
            pt = aead.decrypt(nonce, ct, associated)
            data = json.loads(pt.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("implant payload must be object")
            return data
        except Exception as e:
            last_err = e
            continue
    raise ValueError("invalid implant authentication") from last_err
