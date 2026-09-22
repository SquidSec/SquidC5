"""Operator asymmetric key vault. Private keys are never returned."""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from squidc5.api.deps import get_state, require_scope
from squidc5.auth.tokens import AuthContext
from squidc5.crypto.asymmetric import MAX_PLAINTEXT, AsymKeyError

router = APIRouter(prefix="/keys", tags=["keys"])

_STATUS = {
    "not_found": 404,
    "decrypt_failed": 400,
    "invalid": 400,
    "limit": 409,
    "unavailable": 500,
}


class KeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    key_size: int = 2048


class KeyDecrypt(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=96_000)


class KeyEncrypt(BaseModel):
    plaintext: str | None = Field(default=None, max_length=MAX_PLAINTEXT)
    plaintext_b64: str | None = Field(default=None, max_length=96_000)


def _http(err: AsymKeyError) -> HTTPException:
    return HTTPException(_STATUS.get(err.code, 400), str(err))


def _policy_denied(decision) -> HTTPException:
    detail: dict[str, Any] = {"detail": decision.reason, "require_hitl": decision.require_hitl}
    if decision.hitl_request_id:
        detail["hitl_request_id"] = decision.hitl_request_id
    return HTTPException(status_code=403, detail=detail)


async def _ready(request: Request):
    state = get_state(request)
    if not await state.features.enabled("asym_keys"):
        raise HTTPException(403, "asymmetric keys disabled")
    if state.keys is None:
        raise HTTPException(500, "key service not initialized")
    return state


@router.post("")
async def create_key(
    body: KeyCreate,
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:write", "admin")),
) -> dict[str, Any]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(
        auth, "keys.create", extra={"name": body.name, "key_size": body.key_size}
    )
    if not decision.allowed:
        raise _policy_denied(decision)
    try:
        created = await state.keys.create(body.name, body.key_size, auth.name)
    except AsymKeyError as e:
        raise _http(e) from e
    await state.db.audit(
        actor=auth.name,
        actor_type=auth.actor_type,
        action="keys.create",
        resource=created["id"],
        details={"name": created["name"], "key_size": created["key_size"]},
        risk_score=6,
    )
    return created


@router.get("")
async def list_keys(
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:read", "admin")),
    limit: int = 100,
) -> list[dict[str, Any]]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(auth, "keys.list")
    if not decision.allowed:
        raise _policy_denied(decision)
    return await state.keys.list_keys(limit=limit)


@router.get("/{key_id}")
async def get_key(
    key_id: str,
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:read", "admin")),
) -> dict[str, Any]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(auth, "keys.get", resource=key_id)
    if not decision.allowed:
        raise _policy_denied(decision)
    try:
        return await state.keys.get(key_id)
    except AsymKeyError as e:
        raise _http(e) from e


@router.get("/{key_id}/public")
async def derive_public(
    key_id: str,
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:read", "admin")),
) -> dict[str, Any]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(auth, "keys.public", resource=key_id)
    if not decision.allowed:
        raise _policy_denied(decision)
    try:
        return await state.keys.public_key(key_id)
    except AsymKeyError as e:
        raise _http(e) from e


@router.post("/{key_id}/encrypt")
async def encrypt_for_key(
    key_id: str,
    body: KeyEncrypt,
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:read", "admin")),
) -> dict[str, str]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(
        auth, "keys.encrypt", resource=key_id, extra={"bytes": _plain_len(body)}
    )
    if not decision.allowed:
        raise _policy_denied(decision)
    try:
        return await state.keys.encrypt(key_id, _plaintext(body))
    except AsymKeyError as e:
        raise _http(e) from e


@router.post("/{key_id}/decrypt")
async def decrypt_for_key(
    key_id: str,
    body: KeyDecrypt,
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:decrypt", "admin")),
) -> dict[str, Any]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(
        auth,
        "keys.decrypt",
        resource=key_id,
        extra={"ciphertext_len": len(body.ciphertext)},
    )
    if not decision.allowed:
        raise _policy_denied(decision)
    try:
        opened = await state.keys.decrypt(key_id, body.ciphertext)
    except AsymKeyError as e:
        raise _http(e) from e
    await state.db.audit(
        actor=auth.name,
        actor_type=auth.actor_type,
        action="keys.decrypt",
        resource=key_id,
        details={"ciphertext_len": len(body.ciphertext), "encoding": opened.get("encoding")},
        risk_score=6,
    )
    return opened


@router.delete("/{key_id}")
async def delete_key(
    key_id: str,
    request: Request,
    auth: AuthContext = Depends(require_scope("keys:write", "admin")),
) -> dict[str, str]:
    state = await _ready(request)
    decision = await state.policy.check_and_audit(auth, "keys.delete", resource=key_id)
    if not decision.allowed:
        raise _policy_denied(decision)
    try:
        ok = await state.keys.delete(key_id)
    except AsymKeyError as e:
        raise _http(e) from e
    if not ok:
        raise HTTPException(404, "key not found")
    await state.db.audit(
        actor=auth.name,
        actor_type=auth.actor_type,
        action="keys.delete",
        resource=key_id,
        risk_score=5,
    )
    return {"status": "deleted", "id": key_id}


def _plaintext(body: KeyEncrypt) -> bytes:
    if body.plaintext_b64:
        try:
            raw = base64.b64decode(body.plaintext_b64, validate=True)
        except Exception as e:
            raise AsymKeyError("invalid", "plaintext_b64 invalid") from e
        if len(raw) > MAX_PLAINTEXT:
            raise AsymKeyError("invalid", "plaintext too large")
        return raw
    if body.plaintext is None:
        raise AsymKeyError("invalid", "plaintext required")
    raw = body.plaintext.encode("utf-8")
    if len(raw) > MAX_PLAINTEXT:
        raise AsymKeyError("invalid", "plaintext too large")
    return raw


def _plain_len(body: KeyEncrypt) -> int:
    if body.plaintext_b64:
        return len(body.plaintext_b64)
    return len(body.plaintext or "")
