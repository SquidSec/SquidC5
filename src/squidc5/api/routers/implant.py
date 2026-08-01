"""Implant beacon routes (unauthenticated; AEAD when required)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response as FastResponse

from squidc5.api.deps import get_state
from squidc5.profiles.http_beacon import process_beacon_checkin, process_beacon_result

router = APIRouter(prefix="/implant", tags=["implant"])


@router.post("/beacon")
async def beacon(request: Request):
    state = get_state(request)
    pe = state.profiles
    prof = pe.active()
    raw = await request.body()
    payload = pe.unwrap_request_body(prof, raw)
    client = request.client.host if request.client else None
    try:
        result = await process_beacon_checkin(
            state,
            remote_addr=client,
            payload=payload if isinstance(payload, dict) else {},
            user_agent=request.headers.get("user-agent"),
        )
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    return FastResponse(content=pe.wrap_response(prof, result), media_type="application/json")


@router.post("/beacon/result")
async def beacon_result(request: Request):
    state = get_state(request)
    pe = state.profiles
    prof = pe.active()
    raw = await request.body()
    payload = pe.unwrap_request_body(prof, raw)
    try:
        result = await process_beacon_result(state, payload if isinstance(payload, dict) else {})
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    return FastResponse(content=pe.wrap_response(prof, result), media_type="application/json")
