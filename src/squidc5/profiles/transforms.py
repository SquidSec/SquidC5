"""Malleable transform pipeline (encode/decode) for C2 body wrapping."""

from __future__ import annotations

import base64
import binascii
from typing import Any


def _b64e(data: bytes) -> bytes:
    return base64.b64encode(data)


def _b64d(data: bytes) -> bytes:
    return base64.b64decode(data, validate=False)


def _netbios_encode(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        out.append(0x41 + ((b >> 4) & 0x0F))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


def _netbios_decode(data: bytes) -> bytes:
    if len(data) % 2:
        raise ValueError("netbios length")
    out = bytearray()
    for i in range(0, len(data), 2):
        hi = data[i] - 0x41
        lo = data[i + 1] - 0x41
        if hi < 0 or hi > 15 or lo < 0 or lo > 15:
            raise ValueError("netbios alphabet")
        out.append((hi << 4) | lo)
    return bytes(out)


def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def apply_encode(pipeline: list[dict[str, Any]] | None, raw: bytes) -> bytes:
    """Apply transform steps for implant->server encode (operator profile)."""
    data = raw
    for step in pipeline or []:
        name = str(step.get("name") or step.get("t") or "").lower()
        if name in ("base64", "b64"):
            data = _b64e(data)
        elif name == "prepend":
            data = str(step.get("value") or "").encode() + data
        elif name == "append":
            data = data + str(step.get("value") or "").encode()
        elif name in ("xor", "xor_hex"):
            key_s = str(step.get("key") or step.get("value") or "")
            try:
                key = binascii.unhexlify(key_s) if name == "xor_hex" or all(
                    c in "0123456789abcdefABCDEF" for c in key_s
                ) else key_s.encode()
            except binascii.Error:
                key = key_s.encode()
            data = _xor(data, key)
        elif name == "netbios":
            data = _netbios_encode(data)
        else:
            raise ValueError(f"unknown transform: {name}")
    return data


def apply_decode(pipeline: list[dict[str, Any]] | None, raw: bytes) -> bytes:
    """Reverse transform pipeline (server-side unwrap)."""
    data = raw
    for step in reversed(pipeline or []):
        name = str(step.get("name") or step.get("t") or "").lower()
        if name in ("base64", "b64"):
            data = _b64d(data)
        elif name == "prepend":
            pref = str(step.get("value") or "").encode()
            if not data.startswith(pref):
                raise ValueError("prepend mismatch")
            data = data[len(pref) :]
        elif name == "append":
            suf = str(step.get("value") or "").encode()
            if not data.endswith(suf):
                raise ValueError("append mismatch")
            data = data[: -len(suf)] if suf else data
        elif name in ("xor", "xor_hex"):
            key_s = str(step.get("key") or step.get("value") or "")
            try:
                key = binascii.unhexlify(key_s) if name == "xor_hex" or all(
                    c in "0123456789abcdefABCDEF" for c in key_s
                ) else key_s.encode()
            except binascii.Error:
                key = key_s.encode()
            data = _xor(data, key)
        elif name == "netbios":
            data = _netbios_decode(data)
        else:
            raise ValueError(f"unknown transform: {name}")
    return data
