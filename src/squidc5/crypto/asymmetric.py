"""RSA-OAEP keypairs and hybrid envelopes. Private keys never leave this module's callers."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALG = "RSA-OAEP-SHA256"
ALLOWED_KEY_SIZES = frozenset({2048, 4096})
ENVELOPE_PREFIX = "sc5e1:"
AAD = b"squidc5-asym-v1"
MAX_PLAINTEXT = 32 * 1024
MAX_CIPHERTEXT_CHARS = 96 * 1024
MAX_KEYS = 128
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AsymKeyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def validate_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not _NAME_RE.fullmatch(cleaned):
        raise AsymKeyError("invalid", "name must be 1-64 chars [A-Za-z0-9._-]")
    return cleaned


def validate_key_size(key_size: int) -> int:
    try:
        size = int(key_size)
    except (TypeError, ValueError) as e:
        raise AsymKeyError("invalid", "key_size must be 2048 or 4096") from e
    if size not in ALLOWED_KEY_SIZES:
        raise AsymKeyError("invalid", "key_size must be 2048 or 4096")
    return size


def _oaep(algorithm: hashes.HashAlgorithm | None = None) -> padding.OAEP:
    digest = algorithm or hashes.SHA256()
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=digest),
        algorithm=digest,
        label=None,
    )


def _load_private(private_pem: str) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise AsymKeyError("invalid", "unsupported private key")
    return key


def generate_keypair(key_size: int = 2048) -> tuple[str, str]:
    size = validate_key_size(key_size)
    key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def public_encodings(private_pem: str, *, comment: str = "") -> dict[str, str | int]:
    """Derive public key encodings from a private key. Does not return the private key."""
    key = _load_private(private_pem)
    pub = key.public_key()
    spki = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    pkcs1 = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    ).decode("ascii")
    openssh = pub.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    if comment:
        safe = re.sub(r"[^A-Za-z0-9._-]", "", comment)[:64]
        if safe:
            openssh = f"{openssh} {safe}"
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    return {
        "algorithm": ALG,
        "key_size": key.key_size,
        "public_pem": spki,
        "public_pkcs1_pem": pkcs1,
        "public_openssh": openssh,
        "fingerprint_sha256": fingerprint,
    }


def rsa_oaep_decrypt(private_pem: str, ciphertext: bytes) -> bytes:
    """Decrypt raw RSA-OAEP. SHA-256 first, then SHA-1 (OpenSSL pkeyutl default)."""
    key = _load_private(private_pem)
    if len(ciphertext) != key.key_size // 8:
        raise AsymKeyError("decrypt_failed", "decryption failed")
    last: Exception | None = None
    for digest in (hashes.SHA256(), hashes.SHA1()):
        try:
            return key.decrypt(ciphertext, _oaep(digest))
        except Exception as e:
            last = e
    raise AsymKeyError("decrypt_failed", "decryption failed") from last


def rsa_oaep_encrypt(public_pem: str, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode("ascii"))
    try:
        return pub.encrypt(plaintext, _oaep())
    except Exception as e:
        raise AsymKeyError("invalid", "plaintext too large for raw RSA-OAEP") from e


def seal(public_pem: str, plaintext: bytes) -> str:
    if not isinstance(plaintext, bytes):
        raise AsymKeyError("invalid", "plaintext must be bytes")
    if len(plaintext) > MAX_PLAINTEXT:
        raise AsymKeyError("invalid", "plaintext too large")
    dek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext, AAD)
    ek = rsa_oaep_encrypt(public_pem, dek)
    blob = {
        "v": 1,
        "alg": "RSA-OAEP-256+A256GCM",
        "ek": base64.b64encode(ek).decode("ascii"),
        "n": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    raw = base64.b64encode(json.dumps(blob, separators=(",", ":")).encode("ascii")).decode("ascii")
    return ENVELOPE_PREFIX + raw


def _b64decode(text: str) -> bytes:
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        try:
            return base64.urlsafe_b64decode(padded)
        except Exception as e:
            raise AsymKeyError("decrypt_failed", "decryption failed") from e


def open_sealed(private_pem: str, token: str) -> bytes:
    if not token.startswith(ENVELOPE_PREFIX):
        raise AsymKeyError("decrypt_failed", "decryption failed")
    try:
        blob = json.loads(_b64decode(token[len(ENVELOPE_PREFIX) :]))
        ek = base64.b64decode(blob["ek"], validate=True)
        nonce = base64.b64decode(blob["n"], validate=True)
        ct = base64.b64decode(blob["ct"], validate=True)
    except AsymKeyError:
        raise
    except Exception as e:
        raise AsymKeyError("decrypt_failed", "decryption failed") from e
    if blob.get("v") != 1 or len(nonce) != 12 or len(ct) > MAX_PLAINTEXT + 32:
        raise AsymKeyError("decrypt_failed", "decryption failed")
    dek = rsa_oaep_decrypt(private_pem, ek)
    if len(dek) != 32:
        raise AsymKeyError("decrypt_failed", "decryption failed")
    try:
        pt = AESGCM(dek).decrypt(nonce, ct, AAD)
    except Exception as e:
        raise AsymKeyError("decrypt_failed", "decryption failed") from e
    if len(pt) > MAX_PLAINTEXT:
        raise AsymKeyError("invalid", "plaintext too large")
    return pt


def open_message(private_pem: str, ciphertext: str) -> bytes:
    text = (ciphertext or "").strip()
    if not text or len(text) > MAX_CIPHERTEXT_CHARS:
        raise AsymKeyError("invalid", "ciphertext missing or too large")
    if text.startswith(ENVELOPE_PREFIX):
        return open_sealed(private_pem, text)
    raw = _b64decode(text)
    if len(raw) > 512:
        raise AsymKeyError("decrypt_failed", "decryption failed")
    return rsa_oaep_decrypt(private_pem, raw)
