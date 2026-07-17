"""Shared HTTP beacon check-in / result handling (profile-aware)."""

from __future__ import annotations

from typing import Any

from squidc5.core.state import AppState


async def process_beacon_checkin(
    state: AppState,
    *,
    remote_addr: str | None,
    payload: dict[str, Any],
    user_agent: str | None = None,
    listener_id: str | None = None,
) -> dict[str, Any]:
    """Register/heartbeat beacon session and return next task."""
    if not await state.features.enabled("implant_beacon"):
        raise PermissionError("Implant beacon is disabled by feature flag")

    session_id = payload.get("session_id")
    hostname = payload.get("hostname")
    username = payload.get("username")
    os_info = payload.get("os_info")
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    if user_agent and "user_agent" not in metadata:
        metadata = {**metadata, "user_agent": user_agent}
    if listener_id:
        metadata = {**metadata, "listener_id": listener_id}

    if session_id:
        existing = await state.sessions.get(session_id)
        if existing and existing["status"] == "active":
            await state.sessions.heartbeat(
                session_id,
                hostname=hostname,
                username=username,
                os_info=os_info,
            )
            sid = session_id
        else:
            sid = await state.sessions.register(
                kind="beacon",
                remote_addr=remote_addr,
                hostname=hostname,
                username=username,
                os_info=os_info,
                metadata=metadata,
                listener_id=listener_id,
            )
    else:
        sid = await state.sessions.register(
            kind="beacon",
            remote_addr=remote_addr,
            hostname=hostname,
            username=username,
            os_info=os_info,
            metadata=metadata,
            listener_id=listener_id,
        )
    task = await state.tasks.poll(sid)
    await state.metrics.incr("implant.beacon")
    return {"session_id": sid, "task": task}


async def process_beacon_result(state: AppState, payload: dict[str, Any]) -> dict[str, str]:
    task_id = payload.get("task_id")
    if not task_id:
        raise ValueError("task_id required")
    result = payload.get("result")
    if result is None:
        result = ""
    status = payload.get("status") or "completed"
    await state.tasks.complete(str(task_id), str(result), str(status))
    return {"status": "ok"}
