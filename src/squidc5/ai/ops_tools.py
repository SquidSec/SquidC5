"""Allow-listed C5 ops tools for Admin AI chat (railed — not open agent).

Each tool runs through the same scopes + policy engine as REST/MCP.
Tool results are size-capped and sanitized before returning to the LLM.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

from squidc5.ai.admin_ai import sanitize_untrusted
from squidc5.auth.tokens import AuthContext
from squidc5.core.state import AppState

# tool -> (required scopes any-of, policy action)
TOOL_GATES: dict[str, tuple[list[str], str]] = {
    "list_sessions": (["sessions:read", "admin"], "sessions.list"),
    "get_session": (["sessions:read", "admin"], "sessions.list"),
    "list_listeners": (["listeners:read", "admin"], "listeners.list"),
    "create_listener": (["listeners:write", "admin"], "listeners.create"),
    "start_listener": (["listeners:write", "admin"], "listeners.start"),
    "stop_listener": (["listeners:write", "admin"], "listeners.stop"),
    "delete_listener": (["listeners:write", "admin"], "listeners.stop"),
    "list_tasks": (["tasks:read", "admin"], "tasks.list"),
    "create_task": (["tasks:write", "admin"], "tasks.create"),
    "generate_payload": (["payloads:generate", "admin"], "payloads.generate"),
    "list_payload_templates": (["payloads:generate", "admin"], "payloads.generate"),
    "save_asset": (["payloads:generate", "profiles:write", "admin"], "payloads.generate"),
    "list_assets": (["payloads:generate", "profiles:read", "admin"], "payloads.generate"),
    "register_payload_template": (["payloads:generate", "admin"], "payloads.generate"),
    "list_profiles": (["profiles:read", "admin"], "profiles.list"),
    "activate_profile": (["profiles:write", "admin"], "profiles.activate"),
    "upsert_profile": (["profiles:write", "admin"], "profiles.write"),
    "get_metrics": (["metrics:read", "admin"], "metrics.read"),
    "list_recent_events": (["metrics:read", "sessions:read", "admin"], "metrics.read"),
    "list_audit": (["audit:read", "admin"], "audit.read"),
    "get_platform_status": (["metrics:read", "ai:use", "admin"], "metrics.read"),
    "interact_shell": (["shell:interact", "admin"], "shell.interact"),
}

# OpenAI-compatible tool schemas for chat/completions
OPENAI_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": "List C2 sessions (beacons and reverse shells). Filter by status if needed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "description": "Optional: active, closed, or omit for default",
                    },
                    "kind": {
                        "type": "string",
                        "description": "Optional: beacon, reverse_shell",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_session",
            "description": "Get one session by id with metadata.",
            "parameters": {
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_listeners",
            "description": "List all listeners (http, reverse_shell, dns, smtp, tcp) and their status/ports.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_listener",
            "description": (
                "Create a new listener. For reverse shells use kind=reverse_shell. "
                "Does not start it — call start_listener after create unless auto_start is true."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Short name e.g. rev-444"},
                    "kind": {
                        "type": "string",
                        "enum": ["http", "https", "tcp", "reverse_shell", "dns", "smtp"],
                    },
                    "port": {"type": "integer", "description": "TCP/UDP port 1-65535"},
                    "host": {
                        "type": "string",
                        "description": "Bind address, default 0.0.0.0",
                    },
                    "auto_start": {
                        "type": "boolean",
                        "description": "If true, start the listener immediately after create",
                    },
                    "zone": {
                        "type": "string",
                        "description": "DNS zone when kind=dns",
                    },
                },
                "required": ["name", "kind", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_listener",
            "description": "Start an existing listener by id.",
            "parameters": {
                "type": "object",
                "properties": {"listener_id": {"type": "string"}},
                "required": ["listener_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stop_listener",
            "description": "Stop a running listener by id.",
            "parameters": {
                "type": "object",
                "properties": {"listener_id": {"type": "string"}},
                "required": ["listener_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_listener",
            "description": "Stop (if needed) and delete a listener by id.",
            "parameters": {
                "type": "object",
                "properties": {"listener_id": {"type": "string"}},
                "required": ["listener_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_tasks",
            "description": "List tasks, optionally for one session.",
            "parameters": {
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_task",
            "description": "Queue a command/task on a beacon or session.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "command": {"type": "string"},
                    "args": {"type": "object"},
                },
                "required": ["session_id", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_payload_templates",
            "description": "List available payload template names.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_payload",
            "description": (
                "Generate a deterministic payload from a template "
                "(e.g. reverse_shell_bash, http_beacon_python). "
                "After generate, call save_asset so the operator can reuse it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "template": {"type": "string"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "interval": {"type": "integer"},
                    "save": {
                        "type": "boolean",
                        "description": "If true, also save to operator asset library",
                    },
                    "save_name": {"type": "string", "description": "Name when save=true"},
                },
                "required": ["template", "host", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_asset",
            "description": (
                "Save generated content (payload, profile JSON, implant plan) to the "
                "server asset library for later use by the operator."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["payload", "profile", "implant", "other"],
                    },
                    "name": {"type": "string"},
                    "content": {"type": "string"},
                    "meta": {"type": "object"},
                },
                "required": ["kind", "name", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_assets",
            "description": "List saved operator assets (payloads/profiles/implants).",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "register_payload_template",
            "description": "Register a custom payload template (placeholders {host} {port} {path} {interval}). Becomes usable in payloads generate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "content": {"type": "string"},
                    "note": {"type": "string"}
                },
                "required": ["name", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_profiles",
            "description": "List malleable C2 profiles and the active profile id.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "activate_profile",
            "description": "Activate a C2 profile by id.",
            "parameters": {
                "type": "object",
                "properties": {"profile_id": {"type": "string"}},
                "required": ["profile_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "upsert_profile",
            "description": "Create or update a simple HTTP C2 profile (name, uris, user_agent, sleep_sec, jitter_pct).",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "profile_id": {"type": "string"},
                    "uris": {"type": "array", "items": {"type": "string"}},
                    "user_agent": {"type": "string"},
                    "sleep_sec": {"type": "number"},
                    "jitter_pct": {"type": "number"},
                    "activate": {"type": "boolean"}
                },
                "required": ["name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_metrics",
            "description": "Get teamserver metrics counters snapshot.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_recent_events",
            "description": "Get recent live events from the event buffer (shell connect, tasks, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max events (default 30, max 80)",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_audit",
            "description": "List recent audit log entries.",
            "parameters": {
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_platform_status",
            "description": "High-level platform status: AI, features summary, version-ish health.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "interact_shell",
            "description": (
                "Send a command to a live reverse_shell session. High risk — "
                "requires shell:interact and may need HITL for non-admins."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "command": {"type": "string"},
                    "hitl_request_id": {"type": "string"},
                },
                "required": ["session_id", "command"],
            },
        },
    },
]

CHAT_SYSTEM_PROMPT = """You are INKO (Intelligent Neural Kinetic Operator) — SquidC5's neural operator assistant for this C5 (Command, Control, Cognitive, Collaborative, Coordination) teamserver.
When referring to yourself, use the name INKO.

You can:
1) Answer general security/ops questions clearly and helpfully.
2) Inspect THIS environment via tools (sessions, listeners, tasks, payloads, metrics, events, audit).
3) Perform allow-listed actions via tools (create/start/stop listeners, generate payloads, queue tasks, etc.).

Rules:
- Prefer tools over guessing about live environment state.
- When the user asks to set up a listener, create it AND start it (auto_start true or start_listener).
- For reverse shells use kind=reverse_shell. For HTTP beacons use kind=http. For TLS implant HTTP use kind=https.
- When you generate a payload/profile/implant the operator may reuse, call save_asset (or generate_payload with save=true).
- Never invent session IDs, listener IDs, or secrets. Use tools.
- Never dump API keys, tokens, or raw PII. Summarize tool results for the operator.
- Do not claim you ran a tool unless you did.
- Keep answers concise and operational. Use short bullet lists when listing resources.
- If a tool fails due to permissions/HITL, explain what the operator must approve or which scope is missing.
- You are authorized-use only; refuse illegal/unauthorized hacking requests outside this engagement platform.
"""


def _cap_json(obj: Any, max_chars: int = 6000) -> str:
    try:
        raw = json.dumps(obj, default=str)
    except Exception:
        raw = str(obj)
    if len(raw) > max_chars:
        return raw[: max_chars - 20] + "...[truncated]"
    return raw


def sanitize_tool_payload(obj: Any, max_chars: int = 6000) -> str:
    """Serialize tool output for the model — truncated + injection-scrubbed."""
    text = _cap_json(obj, max_chars=max_chars)
    return sanitize_untrusted(text, max_chars=max_chars)


def _handlers(
    state: AppState, auth: AuthContext
) -> dict[str, Callable[[dict[str, Any]], Awaitable[Any]]]:
    async def list_sessions(args: dict[str, Any]) -> Any:
        rows = await state.sessions.list(status=args.get("status"))
        kind = (args.get("kind") or "").strip()
        if kind:
            rows = [r for r in rows if r.get("kind") == kind]
        # slim for context
        out = []
        for r in rows[:80]:
            out.append(
                {
                    "id": r.get("id"),
                    "kind": r.get("kind"),
                    "status": r.get("status"),
                    "remote_addr": r.get("remote_addr"),
                    "hostname": r.get("hostname"),
                    "username": r.get("username"),
                    "verified": r.get("verified"),
                    "last_seen_at": r.get("last_seen_at"),
                }
            )
        return {"count": len(out), "sessions": out}

    async def get_session(args: dict[str, Any]) -> Any:
        s = await state.sessions.get(args["session_id"])
        if not s:
            raise KeyError("session not found")
        return s

    async def list_listeners(args: dict[str, Any]) -> Any:
        rows = await state.listeners.list()
        return {
            "count": len(rows),
            "listeners": [
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "kind": r.get("kind"),
                    "host": r.get("host"),
                    "port": r.get("port"),
                    "status": r.get("status"),
                }
                for r in rows
            ],
        }

    async def create_listener(args: dict[str, Any]) -> Any:
        kind = str(args.get("kind") or "")
        if not await state.features.enabled("http_listeners") and kind in ("http", "https"):
            raise PermissionError("HTTP/HTTPS listeners disabled")
        if kind in ("tcp", "reverse_shell") and not await state.features.enabled(
            "reverse_shell_listeners"
        ):
            raise PermissionError("Reverse-shell listeners disabled")
        if kind == "smtp" and not await state.features.enabled("smtp_oast"):
            raise PermissionError("SMTP listeners disabled")
        cfg: dict[str, Any] = {}
        if args.get("zone"):
            cfg["zone"] = str(args["zone"])
        row = await state.listeners.create(
            name=str(args["name"]),
            kind=kind,
            port=int(args["port"]),
            host=str(args.get("host") or "0.0.0.0"),
            config=cfg or None,
        )
        started = None
        if args.get("auto_start"):
            started = await state.listeners.start(row["id"])
        return {"created": row, "started": started}

    async def start_listener(args: dict[str, Any]) -> Any:
        return await state.listeners.start(args["listener_id"])

    async def stop_listener(args: dict[str, Any]) -> Any:
        return await state.listeners.stop(args["listener_id"])

    async def delete_listener(args: dict[str, Any]) -> Any:
        lid = args["listener_id"]
        try:
            await state.listeners.stop(lid)
        except Exception:
            pass
        await state.listeners.delete(lid)
        return {"deleted": lid}

    async def list_tasks(args: dict[str, Any]) -> Any:
        rows = await state.tasks.list(session_id=args.get("session_id"))
        return {"count": len(rows), "tasks": rows[:60]}

    async def create_task(args: dict[str, Any]) -> Any:
        sid = args["session_id"]
        await state.teams.assert_write_access(sid, auth.name, is_admin=auth.has_scope("admin"))
        return await state.tasks.create(
            session_id=sid,
            command=str(args["command"]),
            args=args.get("args"),
            created_by=auth.name,
        )

    async def list_payload_templates(args: dict[str, Any]) -> Any:
        customs: list[str] = []
        try:
            rows = await state.db.list_operator_assets(kind="template", limit=200)
            customs = [str(r.get("name") or "") for r in rows if r.get("name")]
        except Exception:
            customs = []
        names = state.payloads.list_templates(customs)
        return {"templates": names, "custom": customs}

    async def generate_payload(args: dict[str, Any]) -> Any:
        if not await state.features.enabled("payloads_generate"):
            raise PermissionError("Payload generation disabled")
        customs: dict[str, str] = {}
        try:
            rows = await state.db.list_operator_assets(kind="template", limit=200)
            for r in rows:
                full = await state.db.get_operator_asset(r["id"])
                if full and full.get("name") and full.get("content"):
                    customs[str(full["name"])] = str(full["content"])
        except Exception:
            customs = {}
        result = state.payloads.generate(
            template=str(args["template"]),
            host=str(args["host"]),
            port=int(args["port"]),
            interval=int(args.get("interval") or 5),
            custom_templates=customs,
        )
        full_payload = ""
        if isinstance(result, dict):
            full_payload = str(
                result.get("content") or result.get("payload") or result.get("body") or ""
            )
        saved = None
        if args.get("save") and full_payload:
            sname = str(args.get("save_name") or f"{args.get('template')}-{args.get('port')}")
            aid = await state.db.create_operator_asset(
                kind="payload",
                name=sname[:120],
                content=full_payload,
                meta={
                    "template": args.get("template"),
                    "host": args.get("host"),
                    "port": args.get("port"),
                },
                created_by=auth.name,
            )
            saved = {"id": aid, "name": sname, "kind": "payload"}
        # payloads may be large — cap script body for model context
        if isinstance(result, dict):
            for key in ("content", "payload"):
                if key in result and len(str(result.get(key) or "")) > 4000:
                    result = dict(result)
                    result[key] = str(result[key])[:4000] + "\n...[truncated]"
                    result["truncated"] = True
        if saved:
            if isinstance(result, dict):
                result = dict(result)
                result["saved_asset"] = saved
            else:
                result = {"result": result, "saved_asset": saved}
        return result

    async def save_asset(args: dict[str, Any]) -> Any:
        kind = str(args.get("kind") or "other").strip().lower()
        if kind not in ("payload", "profile", "implant", "other"):
            raise ValueError("kind must be payload|profile|implant|other")
        name = str(args.get("name") or "").strip()
        content = str(args.get("content") or "")
        if not name or not content.strip():
            raise ValueError("name and content required")
        meta = args.get("meta") if isinstance(args.get("meta"), dict) else {}
        aid = await state.db.create_operator_asset(
            kind=kind,
            name=name[:120],
            content=content,
            meta=meta,
            created_by=auth.name,
        )
        return {"id": aid, "kind": kind, "name": name}

    async def list_assets(args: dict[str, Any]) -> Any:
        kind = args.get("kind")
        rows = await state.db.list_operator_assets(
            kind=str(kind) if kind else None,
            limit=int(args.get("limit") or 50),
        )
        return {"count": len(rows), "assets": rows}

    async def get_metrics(args: dict[str, Any]) -> Any:
        snap = await state.metrics.snapshot()
        # drop bulky recent_events here — use list_recent_events
        if isinstance(snap, dict):
            snap = {k: v for k, v in snap.items() if k != "recent_events"}
        return snap

    async def list_recent_events(args: dict[str, Any]) -> Any:
        snap = await state.metrics.snapshot()
        ev = list(snap.get("recent_events") or [])
        limit = max(1, min(int(args.get("limit") or 30), 80))
        return {"count": len(ev[-limit:]), "events": ev[-limit:]}

    async def list_audit(args: dict[str, Any]) -> Any:
        limit = max(1, min(int(args.get("limit") or 40), 100))
        rows = await state.audit.list(limit=limit)
        return {"count": len(rows), "entries": rows}

    async def get_platform_status(args: dict[str, Any]) -> Any:
        ai = await state.admin_ai.status(debug=False)
        feats = await state.features.get_all()
        return {
            "ai": ai,
            "features": feats,
            "public_host": getattr(state.settings, "public_host", None),
        }

    async def interact_shell(args: dict[str, Any]) -> Any:
        sid = args["session_id"]
        await state.teams.assert_write_access(sid, auth.name, is_admin=auth.has_scope("admin"))
        ok = await state.listeners.send_shell(sid, str(args["command"]))
        if not ok:
            raise RuntimeError("No live reverse shell for session")
        return {"sent": True, "session_id": sid}

    async def register_payload_template(args: dict[str, Any]) -> Any:
        name = str(args.get("name") or "").strip().replace(" ", "_")
        content = str(args.get("content") or "")
        if not name or not content.strip():
            raise ValueError("name and content required")
        if name in getattr(state.payloads, "TEMPLATES", ()):
            raise ValueError(f"conflicts with builtin template: {name}")
        aid = await state.db.create_operator_asset(
            kind="template",
            name=name[:80],
            content=content,
            meta={"note": str(args.get("note") or ""), "via": "inko"},
            created_by=auth.name,
        )
        return {"id": aid, "name": name, "kind": "template"}

    async def list_profiles(args: dict[str, Any]) -> Any:
        if not await state.features.enabled("malleable_profiles"):
            raise PermissionError("Malleable profiles disabled")
        active = state.profiles.active()
        return {
            "profiles": state.profiles.list_profiles(),
            "active_id": active.id if active else None,
        }

    async def activate_profile(args: dict[str, Any]) -> Any:
        if not await state.features.enabled("malleable_profiles"):
            raise PermissionError("Malleable profiles disabled")
        pid = str(args.get("profile_id") or "")
        prof = await state.profiles.set_active(pid)
        return {"active_id": prof.id, "name": prof.name}

    async def upsert_profile(args: dict[str, Any]) -> Any:
        if not await state.features.enabled("malleable_profiles"):
            raise PermissionError("Malleable profiles disabled")
        import re
        import secrets

        from squidc5.profiles.models import C2Profile, HttpProfile

        name = str(args.get("name") or "inko-profile")
        uris = args.get("uris") or ["/api/v1/implant/beacon"]
        if not isinstance(uris, list):
            uris = [str(uris)]
        http = HttpProfile(
            uris=[str(u) for u in uris][:20],
            user_agent=str(args.get("user_agent") or "Mozilla/5.0"),
            sleep_sec=float(args.get("sleep_sec") or 5),
            jitter_pct=float(args.get("jitter_pct") or 20),
        )
        pid = str(args.get("profile_id") or "").strip()
        if not pid:
            slug = re.sub(r"[^a-z0-9_]+", "_", name.lower())[:24] or "prof"
            pid = f"prof_{slug}_{secrets.token_hex(3)}"
        prof = C2Profile(
            id=pid,
            name=name,
            channel="http",
            http=http,
            active=bool(args.get("activate")),
        )
        saved = await state.profiles.upsert(prof)
        if args.get("activate"):
            await state.profiles.set_active(saved.id)
        # also save as asset for artifacts page
        await state.db.create_operator_asset(
            kind="profile",
            name=name[:120],
            content=str(saved.to_dict()),
            meta={"profile_id": saved.id, "via": "inko"},
            created_by=auth.name,
        )
        return {"profile": saved.to_dict()}


    return {
        "list_sessions": list_sessions,
        "get_session": get_session,
        "list_listeners": list_listeners,
        "create_listener": create_listener,
        "start_listener": start_listener,
        "stop_listener": stop_listener,
        "delete_listener": delete_listener,
        "list_tasks": list_tasks,
        "create_task": create_task,
        "list_payload_templates": list_payload_templates,
        "generate_payload": generate_payload,
        "save_asset": save_asset,
        "list_assets": list_assets,
        "register_payload_template": register_payload_template,
        "list_profiles": list_profiles,
        "activate_profile": activate_profile,
        "upsert_profile": upsert_profile,
        "get_metrics": get_metrics,
        "list_recent_events": list_recent_events,
        "list_audit": list_audit,
        "get_platform_status": get_platform_status,
        "interact_shell": interact_shell,
    }


async def execute_ops_tool(
    state: AppState,
    auth: AuthContext,
    name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one allow-listed tool with scope + policy gates."""
    args = dict(arguments or {})
    name = (name or "").strip()
    gate = TOOL_GATES.get(name)
    if not gate:
        return {"ok": False, "tool": name, "error": "Unknown tool"}
    need_scopes, policy_action = gate
    if not any(auth.has_scope(s) for s in need_scopes) and not auth.has_scope("admin"):
        return {
            "ok": False,
            "tool": name,
            "error": f"Missing scope (need one of {need_scopes})",
        }

    extra: dict[str, Any] = {
        "args_keys": list(args.keys()),
        "command": args.get("command"),
        "hitl_request_id": args.get("hitl_request_id"),
        "via": "admin_ai.chat",
    }
    resource = args.get("session_id") or args.get("listener_id")
    decision = await state.policy.check_and_audit(
        auth,
        action=policy_action,
        resource=resource if isinstance(resource, str) else None,
        extra=extra,
    )
    if not decision.allowed:
        out: dict[str, Any] = {
            "ok": False,
            "tool": name,
            "error": decision.reason or "policy denied",
        }
        if getattr(decision, "require_hitl", False) or "hitl" in (decision.reason or "").lower():
            out["require_hitl"] = True
            hid = getattr(decision, "hitl_request_id", None)
            if hid:
                out["hitl_request_id"] = hid
        return out

    handlers = _handlers(state, auth)
    handler = handlers.get(name)
    if not handler:
        return {"ok": False, "tool": name, "error": "Unknown tool"}
    try:
        result = await handler(args)
        await state.metrics.incr("ai.chat.tool_ok")
        await state.metrics.emit(
            "ai.chat.tool",
            {"tool": name, "actor": auth.name, "ok": True},
        )
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action=f"ai.chat.tool.{name}",
            resource=str(resource) if resource else None,
            details={"tool": name, "ok": True},
            risk_score=4 if name in ("create_listener", "create_task", "interact_shell", "generate_payload") else 2,
        )
        return {"ok": True, "tool": name, "result": result}
    except PermissionError as exc:
        return {"ok": False, "tool": name, "error": str(exc)}
    except KeyError as exc:
        return {"ok": False, "tool": name, "error": str(exc) or "not found"}
    except Exception as exc:
        await state.metrics.incr("ai.chat.tool_err")
        await state.db.audit(
            actor=auth.name,
            actor_type=auth.actor_type,
            action="ai.chat.tool.error",
            details={"tool": name, "error": type(exc).__name__},
            allowed=False,
            risk_score=4,
        )
        return {"ok": False, "tool": name, "error": f"{type(exc).__name__}: {exc}"[:300]}


# --- Offline deterministic intents (no LLM) ---

_RE_CREATE_LISTENER = re.compile(
    r"(?i)\b(?:create|setup|set\s*up|add|start)\b.*\b(?:listener|reverse\s*shell|rev\s*shell)\b.*\b(?:port\s*)?(\d{2,5})\b"
)
_RE_LIST_SESSIONS = re.compile(r"(?i)\b(list|show|what)\b.*\b(sessions?|shells?|beacons?)\b")
_RE_LIST_LISTENERS = re.compile(r"(?i)\b(list|show|what)\b.*\blisteners?\b")
_RE_METRICS = re.compile(r"(?i)\b(metrics|status|health)\b")
_RE_EVENTS = re.compile(r"(?i)\b(events?|event\s*stream)\b")


async def offline_chat_intent(
    state: AppState, auth: AuthContext, message: str
) -> dict[str, Any] | None:
    """Best-effort offline handling for common ops phrases when no LLM is configured."""
    msg = (message or "").strip()
    if not msg:
        return None
    m = _RE_CREATE_LISTENER.search(msg)
    if m:
        port = int(m.group(1))
        kind = "reverse_shell"
        if re.search(r"(?i)\bhttp\b", msg):
            kind = "http"
        elif re.search(r"(?i)\bdns\b", msg):
            kind = "dns"
        name = f"ai-{kind}-{port}"
        r = await execute_ops_tool(
            state,
            auth,
            "create_listener",
            {"name": name, "kind": kind, "port": port, "auto_start": True},
        )
        return {
            "mode": "offline",
            "reply": _offline_reply_for_tool(r, f"Create {kind} listener on {port}"),
            "tool_trace": [r],
        }
    if _RE_LIST_SESSIONS.search(msg):
        r = await execute_ops_tool(state, auth, "list_sessions", {})
        return {
            "mode": "offline",
            "reply": _offline_reply_for_tool(r, "Sessions"),
            "tool_trace": [r],
        }
    if _RE_LIST_LISTENERS.search(msg):
        r = await execute_ops_tool(state, auth, "list_listeners", {})
        return {
            "mode": "offline",
            "reply": _offline_reply_for_tool(r, "Listeners"),
            "tool_trace": [r],
        }
    if _RE_EVENTS.search(msg):
        r = await execute_ops_tool(state, auth, "list_recent_events", {"limit": 20})
        return {
            "mode": "offline",
            "reply": _offline_reply_for_tool(r, "Recent events"),
            "tool_trace": [r],
        }
    if _RE_METRICS.search(msg):
        r = await execute_ops_tool(state, auth, "get_metrics", {})
        return {
            "mode": "offline",
            "reply": _offline_reply_for_tool(r, "Metrics"),
            "tool_trace": [r],
        }
    return None


def _offline_reply_for_tool(r: dict[str, Any], title: str) -> str:
    if not r.get("ok"):
        return f"{title}: failed — {r.get('error') or 'unknown error'}"
    return f"{title}:\n{_cap_json(r.get('result'), 3500)}"
