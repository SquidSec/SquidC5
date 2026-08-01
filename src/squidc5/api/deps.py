"""FastAPI auth dependencies."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Header, HTTPException, Request

from squidc5.auth.tokens import AuthContext
from squidc5.core.state import AppState


def get_state(request: Request) -> AppState:
    return request.app.state.app_state


async def get_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> AuthContext:
    state = get_state(request)
    raw = None
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    elif x_api_token:
        raw = x_api_token.strip()
    if not raw:
        raise HTTPException(status_code=401, detail="Missing API token")
    ctx = await state.tokens.authenticate(raw)
    if not ctx:
        raise HTTPException(status_code=401, detail="Invalid or revoked token")
    return ctx


def require_scope(*scopes: str) -> Callable:
    async def dependency(
        request: Request,
        authorization: str | None = Header(default=None),
        x_api_token: str | None = Header(default=None, alias="X-API-Token"),
    ) -> AuthContext:
        auth = await get_auth(request, authorization, x_api_token)
        if not any(auth.has_scope(s) for s in scopes) and not auth.has_scope("admin"):
            raise HTTPException(status_code=403, detail=f"Requires one of scopes: {scopes}")
        return auth

    return dependency
