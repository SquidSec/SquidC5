"""Multi-operator collaboration: teams, claim/lock, handoff packs, spectator."""

from __future__ import annotations

import json
import time
from typing import Any

from squidc5.db.store import Database


def _meta(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {}
    meta = row.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    return dict(meta) if isinstance(meta, dict) else {}


def claim_info(meta: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    """Normalized claim fields for API/UI (handles expiry)."""
    ts = now if now is not None else time.time()
    claimed_by = meta.get("claimed_by")
    claimed_at = meta.get("claimed_at")
    expires_at = meta.get("claim_expires_at")
    expired = False
    if claimed_by and expires_at is not None:
        try:
            if float(expires_at) <= ts:
                expired = True
                claimed_by = None
        except (TypeError, ValueError):
            pass
    remaining = None
    if claimed_by and expires_at is not None:
        try:
            remaining = max(0.0, float(expires_at) - ts)
        except (TypeError, ValueError):
            remaining = None
    return {
        "claimed_by": claimed_by,
        "claimed_at": claimed_at,
        "claim_expires_at": expires_at if claimed_by else None,
        "claim_remaining_sec": remaining,
        "claim_expired": expired,
        "locked": bool(claimed_by),
    }


class TeamService:
    def __init__(
        self,
        db: Database,
        *,
        claim_ttl_sec: int = 3600,
        renew_on_activity: bool = True,
    ) -> None:
        self.db = db
        self.claim_ttl_sec = max(0, int(claim_ttl_sec or 0))
        self.renew_on_activity = bool(renew_on_activity)

    async def list_teams(self) -> list[dict[str, Any]]:
        return await self.db.list_teams()

    async def create_team(self, name: str, created_by: str) -> dict[str, Any]:
        tid = await self.db.create_team(name, created_by)
        return {"id": tid, "name": name, "created_by": created_by}

    def _expiry(self, claimed_at: float, ttl_sec: int | None) -> float | None:
        ttl = self.claim_ttl_sec if ttl_sec is None else max(0, int(ttl_sec))
        if ttl <= 0:
            return None
        return claimed_at + ttl

    async def _clear_expired_claim(self, session_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        """If claim expired, clear lock fields and return updated meta."""
        info = claim_info(meta)
        if not info["claim_expired"]:
            return meta
        was = meta.get("claimed_by")
        meta.pop("claimed_by", None)
        meta.pop("claim_expires_at", None)
        meta["claim_expired_at"] = time.time()
        meta["claim_expired_was"] = was
        await self.db.update_session(session_id, metadata=meta)
        await self.db.audit(
            actor="system",
            actor_type="system",
            action="session.claim_expire",
            resource=session_id,
            details={"was": was},
            risk_score=1,
        )
        return meta

    async def claim(
        self,
        session_id: str,
        actor: str,
        *,
        force: bool = False,
        is_admin: bool = False,
        ttl_sec: int | None = None,
    ) -> dict[str, Any]:
        """Claim session lock. Only admin may force-steal. Optional per-claim TTL override."""
        row = await self.db.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        meta = await self._clear_expired_claim(session_id, _meta(row))
        current = meta.get("claimed_by") or meta.get("owner")
        # owner alone does not block after release cleared claimed_by
        current_lock = meta.get("claimed_by")
        if current_lock and current_lock != actor and not (force and is_admin):
            raise PermissionError(f"Session claimed by {current_lock}")
        now = time.time()
        expires = self._expiry(now, ttl_sec)
        meta["claimed_by"] = actor
        meta["owner"] = actor
        meta["claimed_at"] = now
        if expires is not None:
            meta["claim_expires_at"] = expires
        else:
            meta.pop("claim_expires_at", None)
        if current_lock and current_lock != actor:
            meta["previous_claim"] = current_lock
        await self.db.update_session(session_id, metadata=meta)
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="session.claim",
            resource=session_id,
            details={
                "force": bool(force and is_admin),
                "previous": current_lock,
                "expires_at": expires,
            },
            risk_score=3 if force else 2,
        )
        return {
            "session_id": session_id,
            "claimed_by": actor,
            "claimed_at": now,
            "claim_expires_at": expires,
            "previous": current_lock or current,
        }

    async def release(
        self,
        session_id: str,
        actor: str,
        *,
        is_admin: bool = False,
    ) -> dict[str, Any]:
        row = await self.db.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        meta = await self._clear_expired_claim(session_id, _meta(row))
        current = meta.get("claimed_by")
        if current and current != actor and not is_admin:
            raise PermissionError(f"Session claimed by {current}")
        meta.pop("claimed_by", None)
        meta.pop("claim_expires_at", None)
        meta["released_by"] = actor
        meta["released_at"] = time.time()
        await self.db.update_session(session_id, metadata=meta)
        await self.db.audit(
            actor=actor,
            actor_type="operator",
            action="session.release",
            resource=session_id,
            details={"was": current},
            risk_score=1,
        )
        return {"session_id": session_id, "released": True, "was": current}

    async def assert_write_access(
        self,
        session_id: str,
        actor: str,
        *,
        is_admin: bool = False,
        renew: bool = True,
    ) -> None:
        """Raise PermissionError if claim lock blocks actor. Renews TTL for holder."""
        if is_admin:
            return
        row = await self.db.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        meta = await self._clear_expired_claim(session_id, _meta(row))
        claimed = meta.get("claimed_by")
        if claimed and claimed != actor:
            raise PermissionError(f"Session claimed by {claimed}; claim or release first")
        if claimed and claimed == actor and renew and self.renew_on_activity:
            expires = meta.get("claim_expires_at")
            if expires is not None and self.claim_ttl_sec > 0:
                now = time.time()
                meta["claim_expires_at"] = now + self.claim_ttl_sec
                meta["claim_renewed_at"] = now
                await self.db.update_session(session_id, metadata=meta)
        team_id = meta.get("team_id")
        if team_id:
            members = await self.db.list_team_members(str(team_id))
            names = {m.get("actor") for m in members}
            if actor not in names:
                raise PermissionError("Not a member of session team")

    async def handoff(
        self,
        session_id: str,
        from_actor: str,
        to_actor: str,
        note: str = "",
        *,
        transfer_claim: bool = True,
        include_pack: bool = True,
        state: Any = None,
    ) -> dict[str, Any]:
        """Handoff note + optional pack + claim transfer."""
        row = await self.db.get_session(session_id)
        if not row:
            raise KeyError(session_id)

        pack: dict[str, Any] = {}
        if include_pack:
            pack = await self._build_handoff_pack(session_id, state=state)

        entry = {
            "ts": time.time(),
            "from": from_actor,
            "to": to_actor,
            "note": (note or "")[:2000],
            "session_id": session_id,
            "pack": pack,
        }
        await self.db.add_session_handoff(session_id, entry)

        if transfer_claim and to_actor:
            meta = _meta(row)
            now = time.time()
            meta["claimed_by"] = to_actor
            meta["owner"] = to_actor
            meta["claimed_at"] = now
            meta["handed_off_from"] = from_actor
            expires = self._expiry(now, None)
            if expires is not None:
                meta["claim_expires_at"] = expires
            else:
                meta.pop("claim_expires_at", None)
            await self.db.update_session(session_id, metadata=meta)

        await self.db.audit(
            actor=from_actor,
            actor_type="operator",
            action="session.handoff",
            resource=session_id,
            details={"to": to_actor, "note_len": len(note or ""), "pack_keys": list(pack.keys())},
            risk_score=2,
        )
        return entry

    async def _build_handoff_pack(self, session_id: str, *, state: Any = None) -> dict[str, Any]:
        tasks: list[dict[str, Any]] = []
        try:
            rows = await self.db.list_tasks(session_id=session_id)
            for t in (rows or [])[:10]:
                tasks.append(
                    {
                        "id": t.get("id"),
                        "command": t.get("command"),
                        "status": t.get("status"),
                        "result": (str(t.get("result") or ""))[:500],
                    }
                )
        except Exception:
            tasks = []

        output_tail = ""
        if state is not None and getattr(state, "listeners", None):
            try:
                fn = getattr(state.listeners, "get_output_text", None)
                if callable(fn):
                    output_tail = str(fn(session_id, limit_chars=2000) or "")
            except Exception:
                pass

        roe: dict[str, Any] = {}
        if state is not None and getattr(state, "engagement", None):
            try:
                roe = state.engagement.to_dict()
            except Exception:
                roe = {}

        sess = await self.db.get_session(session_id)
        meta = _meta(sess)
        return {
            "session": {
                "id": session_id,
                "kind": (sess or {}).get("kind"),
                "hostname": (sess or {}).get("hostname"),
                "status": (sess or {}).get("status"),
                "claimed_by": meta.get("claimed_by"),
            },
            "recent_tasks": tasks,
            "output_tail": output_tail,
            "engagement": roe,
        }

    async def session_notes(self, session_id: str) -> list[dict[str, Any]]:
        return await self.db.get_session_handoffs(session_id)

    async def set_owner(self, session_id: str, owner: str) -> None:
        await self.db.set_session_owner(session_id, owner)

    async def spectator_view(self, session_id: str, *, state: Any = None) -> dict[str, Any]:
        """Read-only snapshot (no shell interact)."""
        row = await self.db.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        meta = await self._clear_expired_claim(session_id, _meta(row))
        info = claim_info(meta)
        tasks: list[dict[str, Any]] = []
        try:
            rows = await self.db.list_tasks(session_id=session_id)
            for t in (rows or [])[:20]:
                tasks.append(
                    {
                        "id": t.get("id"),
                        "command": t.get("command"),
                        "status": t.get("status"),
                        "result": (str(t.get("result") or ""))[:800],
                    }
                )
        except Exception:
            pass
        output_tail = ""
        if state is not None and getattr(state, "listeners", None):
            try:
                fn = getattr(state.listeners, "get_output_text", None)
                if callable(fn):
                    output_tail = str(fn(session_id, limit_chars=3000) or "")
            except Exception:
                pass
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "remote_addr": row.get("remote_addr"),
            "hostname": row.get("hostname"),
            "username": row.get("username"),
            "os_info": row.get("os_info"),
            "owner": meta.get("owner"),
            "claimed_by": info.get("claimed_by"),
            "claimed_at": info.get("claimed_at"),
            "claim_expires_at": info.get("claim_expires_at"),
            "claim_remaining_sec": info.get("claim_remaining_sec"),
            "team_id": meta.get("team_id"),
            "handoffs": await self.session_notes(session_id),
            "recent_tasks": tasks,
            "output_tail": output_tail,
            "mode": "spectator",
            "watching": True,
            "can_interact": False,
        }
