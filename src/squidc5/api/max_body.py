"""Request body size limits."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class MaxBodySizeMiddleware:
    """Reject requests whose body exceeds max_body_bytes (413)."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max(0, int(max_body_bytes))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.max_body_bytes <= 0:
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers") or []
        }
        cl = headers.get("content-length")
        if cl is not None:
            try:
                length = int(cl)
            except ValueError:
                length = -1
            if length > self.max_body_bytes:
                resp = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )
                await resp(scope, receive, send)
                return

        max_bytes = self.max_body_bytes
        received = 0
        overflow = False
        chunks: list[bytes] = []
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                async def passthrough() -> Message:
                    return message

                await self.app(scope, passthrough, send)
                return
            body = message.get("body", b"") or b""
            chunks.append(body)
            received += len(body)
            if received > max_bytes:
                overflow = True
                break
            more = bool(message.get("more_body"))

        if overflow:
            resp = JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
            await resp(scope, receive, send)
            return

        full = b"".join(chunks)
        sent = False

        async def replay_receive() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": full, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
