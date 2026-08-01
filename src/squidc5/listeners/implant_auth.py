"""Shared implant AEAD gate for HTTP/DNS listeners (C04/C05)."""

from __future__ import annotations

from typing import Any

from squidc5.implants.crypto import is_envelope, open_envelope, seal


def unwrap_implant_payload(
    payload: dict[str, Any],
    *,
    psk: str,
    require_auth: bool = True,
) -> dict[str, Any]:
    if is_envelope(payload):
        if not psk:
            raise PermissionError("Implant PSK not configured")
        try:
            return open_envelope(psk, payload)
        except Exception as e:
            raise PermissionError("Invalid implant authentication") from e
    if require_auth:
        raise PermissionError("Authenticated implant envelope required")
    return payload


def wrap_implant_response(
    result: dict[str, Any],
    *,
    psk: str,
    require_auth: bool = True,
) -> dict[str, Any]:
    if require_auth and psk:
        return seal(psk, result)
    return result
