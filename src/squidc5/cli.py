"""SquidC5 operator CLI harness — local client for remote C2."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

DEFAULT_BASE = "http://127.0.0.1:8443"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "squidc5"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config() -> dict[str, Any]:
    for path in (CONFIG_FILE, Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "squidsec2" / "config.json"):
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return {}
    return {}


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass


def resolve_base(args: argparse.Namespace) -> str:
    if getattr(args, "url", None):
        return args.url.rstrip("/")
    env = os.environ.get("SQUIDC5_URL") or os.environ.get("SC5_URL")
    if env:
        return env.rstrip("/")
    cfg = load_config()
    return (cfg.get("url") or DEFAULT_BASE).rstrip("/")


def resolve_token(args: argparse.Namespace) -> str | None:
    if getattr(args, "token", None):
        return args.token
    env = os.environ.get("SQUIDC5_TOKEN") or os.environ.get("SC5_TOKEN")
    if env:
        return env
    return load_config().get("token")


def pp(data: Any) -> None:
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


def resolve_verify(args: argparse.Namespace) -> bool:
    """TLS verify; False for self-signed teamservers (--insecure / verify_ssl:false)."""
    if getattr(args, "insecure", False):
        return False
    env = os.environ.get("SQUIDC5_VERIFY_SSL") or os.environ.get("SC5_VERIFY_SSL")
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off")
    cfg = load_config()
    if "verify_ssl" in cfg:
        return bool(cfg["verify_ssl"])
    return True


class Client:
    def __init__(
        self,
        base: str,
        token: str | None,
        timeout: float = 30.0,
        *,
        verify: bool = True,
    ) -> None:
        self.base = base.rstrip("/")
        self.token = token
        headers: dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # Default 30s; long reaps/broadcasts can override per-call
        self._client = httpx.Client(
            base_url=self.base,
            headers=headers,
            timeout=timeout,
            verify=verify,
        )

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        r = self._client.request(method, path, **kwargs)
        if r.status_code >= 400:
            try:
                detail = r.json()
            except Exception:
                detail = r.text
            raise SystemExit(f"HTTP {r.status_code}: {detail}")
        if r.status_code == 204 or not r.content:
            return None
        ct = r.headers.get("content-type", "")
        if "application/json" in ct:
            return r.json()
        return r.text

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs)


def cmd_backup(args: argparse.Namespace) -> None:
    """Local SQLite backup (no API). Stop writes for best consistency in prod."""
    from squidc5.config import Settings
    from squidc5.db.backup import backup_database

    settings = Settings(
        data_dir=Path(args.data_dir) if args.data_dir else Path("data"),
        db_path=Path(args.db) if args.db else None,
    )
    src = settings.resolve_db_path()
    dest = Path(args.output)
    out = backup_database(src, dest)
    print(json.dumps({"ok": True, "source": str(src), "backup": str(out)}, indent=2))


def cmd_restore(args: argparse.Namespace) -> None:
    """Restore SQLite from backup file. Stop squidc5 before restore."""
    from squidc5.config import Settings
    from squidc5.db.backup import restore_database

    settings = Settings(
        data_dir=Path(args.data_dir) if args.data_dir else Path("data"),
        db_path=Path(args.db) if args.db else None,
    )
    target = settings.resolve_db_path()
    out = restore_database(Path(args.backup), target)
    print(
        json.dumps(
            {
                "ok": True,
                "restored_to": str(out),
                "note": "Restart squidc5 after restore",
            },
            indent=2,
        )
    )


def cmd_login(args: argparse.Namespace) -> None:
    cfg = load_config()
    if args.url:
        cfg["url"] = args.url.rstrip("/")
    if args.token:
        cfg["token"] = args.token
    if getattr(args, "insecure", False):
        cfg["verify_ssl"] = False
    if not cfg.get("url"):
        cfg["url"] = DEFAULT_BASE
    if not cfg.get("token"):
        raise SystemExit("Token required: sc5 login --token <token> [--url https://host:8443] [--insecure]")
    save_config(cfg)
    verify = resolve_verify(args)
    client = Client(cfg["url"], cfg["token"], verify=verify)
    try:
        health = client.get("/api/v1/health")
        meta = client.get("/api/v1/meta")
        pp(
            {
                "saved": str(CONFIG_FILE),
                "url": cfg["url"],
                "verify_ssl": verify,
                "health": health,
                "actor": meta.get("actor"),
            }
        )
    finally:
        client.close()


def cmd_whoami(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/meta"))


def cmd_health(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/health"))


def cmd_sessions_list(args: argparse.Namespace, client: Client) -> None:
    """
    Defaults: active + live only.
    Flags: --all (every status), --include-dead, --shells (reverse shells only).
    """
    # Fast reap: drop sessions with no TCP (probe is explicit via `sessions reap`)
    try:
        client.post("/api/v1/sessions/reap", json={"probe": False})
    except SystemExit:
        pass

    params: dict[str, Any] = {}
    if getattr(args, "all", False):
        pass  # no status filter
    else:
        status = getattr(args, "status", None)
        if status in (None, "active"):
            params["status"] = "active"
        elif status and status != "all":
            params["status"] = status

    if getattr(args, "shells", False):
        params["kind"] = "reverse_shell,tcp"

    # Default live-only unless user asks for dead/history
    live_only = not (getattr(args, "include_dead", False) or getattr(args, "all", False))
    if live_only:
        params["live_only"] = "true"

    rows = client.get("/api/v1/sessions", params=params) or []
    if getattr(args, "ids", False):
        for r in rows:
            print(r.get("id", ""))
        return
    pp(rows)


def cmd_sessions_get(args: argparse.Namespace, client: Client) -> None:
    pp(client.get(f"/api/v1/sessions/{args.id}"))


def cmd_sessions_close(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/sessions/{args.id}/close"))


def cmd_sessions_delete(args: argparse.Namespace, client: Client) -> None:
    pp(client.delete(f"/api/v1/sessions/{args.id}"))


def cmd_sessions_clear(args: argparse.Namespace, client: Client) -> None:
    """Bulk remove reverse-shell noise (default: unverified only)."""
    body: dict[str, Any] = {
        "delete": not getattr(args, "close_only", False),
        "unverified_only": not getattr(args, "all_shells", False),
        "closed_only": bool(getattr(args, "closed", False)),
        "active_only": bool(getattr(args, "active", False)),
        "all_shells": bool(getattr(args, "all_shells", False)),
    }
    if body["closed_only"] or body["active_only"]:
        body["unverified_only"] = bool(getattr(args, "unverified", False))
    pp(client.post("/api/v1/sessions/clear", json=body))


def cmd_sessions_reap(args: argparse.Namespace, client: Client) -> None:
    # Exec probe can take a bit with many sessions — raise timeout
    old = client._client.timeout
    client._client.timeout = httpx.Timeout(120.0)
    try:
        pp(
            client.post(
                "/api/v1/sessions/reap",
                json={"probe": not getattr(args, "no_probe", False)},
            )
        )
    finally:
        client._client.timeout = old


def cmd_tasks_list(args: argparse.Namespace, client: Client) -> None:
    params = {}
    if args.session:
        params["session_id"] = args.session
    pp(client.get("/api/v1/tasks", params=params))


def cmd_tasks_get(args: argparse.Namespace, client: Client) -> None:
    pp(client.get(f"/api/v1/tasks/{args.id}"))


def cmd_tasks_create(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {
        "session_id": args.session,
        "command": args.command,
        "hitl_approved": args.hitl,
    }
    if args.args_json:
        body["args"] = json.loads(args.args_json)
    pp(client.post("/api/v1/tasks", json=body))


def cmd_listeners_list(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/listeners"))


def cmd_listeners_create(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {
        "name": args.name,
        "kind": args.kind,
        "host": args.host,
        "port": args.port,
    }
    if args.kind == "dns":
        body["config"] = {
            "zone": getattr(args, "zone", None) or "c2.lab.invalid",
            "mode": getattr(args, "dns_mode", None) or "both",
        }
    pp(client.post("/api/v1/listeners", json=body))


def cmd_listeners_start(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/listeners/{args.id}/start"))


def cmd_listeners_stop(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/listeners/{args.id}/stop"))


def cmd_listeners_delete(args: argparse.Namespace, client: Client) -> None:
    pp(client.delete(f"/api/v1/listeners/{args.id}"))


def cmd_payloads_templates(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/payloads/templates"))


def cmd_payloads_generate(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {
        "template": args.template,
        "host": args.host,
        "port": args.port,
        "interval": args.interval,
    }
    if getattr(args, "profile", None):
        body["profile_id"] = args.profile
    if getattr(args, "scheme", None):
        body["scheme"] = args.scheme
    if getattr(args, "zone", None):
        body["zone"] = args.zone
    data = client.post("/api/v1/payloads/generate", json=body)
    if args.raw:
        print(data.get("content", ""))
    else:
        pp(data)


def cmd_profiles_list(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/profiles"))


def cmd_profiles_active(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/profiles/active"))


def cmd_profiles_activate(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/profiles/{args.id}/activate"))


def cmd_implants_families(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/implants/families"))


def cmd_implants_generate(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {
        "family": args.family,
        "platform": args.platform,
        "arch": args.arch,
        "host": args.host,
        "port": args.port,
        "evasion": not args.no_evasion,
    }
    if args.profile:
        body["profile_id"] = args.profile
    if args.path:
        body["path"] = args.path
    data = client.post("/api/v1/implants/generate", json=body)
    if args.raw:
        print(data.get("content", ""))
    else:
        pp(data)


def cmd_implants_build(args: argparse.Namespace, client: Client) -> None:
    body = {
        "os": args.os,
        "arch": args.arch,
        "host": args.host,
        "port": args.port,
        "scheme": args.scheme,
        "sleep": args.sleep,
        "jitter": args.jitter,
    }
    if args.kill_date:
        body["kill_date"] = args.kill_date
    if args.max_miss:
        body["max_miss"] = args.max_miss
    pp(client.post("/api/v1/implants/build", json=body))


def cmd_ai_playbooks(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/ai/playbooks"))


def cmd_ai_chain(args: argparse.Namespace, client: Client) -> None:
    pp(
        client.post(
            "/api/v1/ai/chain",
            json={"playbook": args.playbook, "user_data": args.data or ""},
        )
    )


def cmd_report(args: argparse.Namespace, client: Client) -> None:
    data = client.get("/api/v1/observability/report")
    if args.raw:
        print(data.get("markdown", ""))
    else:
        pp(data)


def cmd_redirector(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {
        "server_name": args.server_name,
        "upstream_host": args.upstream_host,
        "upstream_port": args.upstream_port,
        "listen_port": args.listen_port,
    }
    if args.uris:
        body["beacon_uris"] = [u.strip() for u in args.uris.split(",") if u.strip()]
    data = client.post("/api/v1/deploy/redirector", json=body)
    if args.raw:
        print(data.get("config", ""))
    else:
        pp(data)


def cmd_teams_list(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/teams"))


def cmd_teams_create(args: argparse.Namespace, client: Client) -> None:
    pp(client.post("/api/v1/teams", json={"name": args.name}))


def cmd_teams_members(args: argparse.Namespace, client: Client) -> None:
    pp(client.get(f"/api/v1/teams/{args.id}/members"))


def cmd_teams_add_member(args: argparse.Namespace, client: Client) -> None:
    pp(
        client.post(
            f"/api/v1/teams/{args.id}/members",
            json={"actor": args.actor, "role": args.role},
        )
    )


def _print_shell_result(data: dict[str, Any], *, json_mode: bool, verbose: bool, prefix: str = "") -> None:
    if json_mode:
        pp(data)
        return
    out = (data or {}).get("output") or ""
    if prefix:
        print(prefix, file=sys.stderr)
    if out:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    else:
        note = "no output (timeout)" if (data or {}).get("timed_out") else "no output"
        print(
            f"[sc5] sent={data.get('sent')} interactive={data.get('interactive')} — {note}",
            file=sys.stderr,
        )
    if verbose:
        meta = {k: v for k, v in (data or {}).items() if k != "output"}
        print(json.dumps(meta, indent=2), file=sys.stderr)


def cmd_shell(args: argparse.Namespace, client: Client) -> None:
    """
    sc5 shell <session_id> <command...>
    sc5 shell all <command...>
    sc5 shell --all <command...>
    """
    parts: list[str] = list(getattr(args, "parts", None) or [])
    broadcast = bool(getattr(args, "all", False))
    session: str | None = None
    command: str

    if broadcast:
        command = " ".join(parts).strip()
    elif parts and parts[0].lower() in ("all", "*", "broadcast"):
        broadcast = True
        command = " ".join(parts[1:]).strip()
    else:
        if len(parts) < 2:
            raise SystemExit("usage: sc5 shell <session_id> <command>  |  sc5 shell --all <command>")
        session = parts[0]
        command = " ".join(parts[1:]).strip()

    if not command:
        raise SystemExit("command required")

    if broadcast:
        data = client.post(
            "/api/v1/shell/broadcast",
            json={
                "command": command,
                "hitl_approved": args.hitl,
                "wait_sec": args.wait,
                "idle_sec": args.idle,
            },
        )
        if args.json:
            pp(data)
            return
        results = (data or {}).get("results") or []
        print(
            f"[sc5] broadcast to {data.get('targets', len(results))} verified shell(s)",
            file=sys.stderr,
        )
        if not results:
            print("[sc5] no verified reverse shells (run: sc5 sessions reap)", file=sys.stderr)
            return
        for res in results:
            sid = res.get("session_id", "?")
            remote = res.get("remote_addr") or ""
            if res.get("dropped") or res.get("error") == "echo_only_zombie":
                print(f"── {sid} {remote} ── DROPPED (echo-only zombie)", file=sys.stderr)
                continue
            _print_shell_result(
                res,
                json_mode=False,
                verbose=args.verbose,
                prefix=f"── {sid} {remote} ──",
            )
        return

    data = client.post(
        "/api/v1/shell/command",
        json={
            "session_id": session,
            "command": command,
            "hitl_approved": args.hitl,
            "wait_sec": args.wait,
            "idle_sec": args.idle,
        },
    )
    _print_shell_result(data, json_mode=args.json, verbose=args.verbose)


def cmd_metrics(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/metrics"))


def cmd_audit(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/audit", params={"limit": args.limit, "offset": args.offset}))


def cmd_events(args: argparse.Namespace, client: Client) -> None:
    headers = {"Accept": "text/event-stream"}
    if client.token:
        headers["Authorization"] = f"Bearer {client.token}"
    with httpx.stream(
        "GET",
        f"{client.base}/api/v1/events/stream",
        headers=headers,
        timeout=None,
    ) as resp:
        if resp.status_code >= 400:
            raise SystemExit(f"HTTP {resp.status_code}: {resp.read().decode()}")
        for line in resp.iter_lines():
            if not line:
                continue
            if line.startswith("data: "):
                payload = line[6:]
                try:
                    pp(json.loads(payload))
                except json.JSONDecodeError:
                    print(payload)
            else:
                print(line)


def cmd_oast_token_create(args: argparse.Namespace, client: Client) -> None:
    note = getattr(args, "note", None) or getattr(args, "label", None) or ""
    pp(client.post("/api/v1/oast/tokens", json={"note": note}))


def cmd_oast_tokens_list(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/oast/tokens"))


def cmd_oast_hits(args: argparse.Namespace, client: Client) -> None:
    q: dict[str, Any] = {"limit": getattr(args, "limit", 100)}
    if getattr(args, "token", None):
        q["token"] = args.token
    if getattr(args, "protocol", None):
        q["protocol"] = args.protocol
    if getattr(args, "client_id", None):
        q["client_id"] = args.client_id
    if getattr(args, "since", None) is not None:
        q["since"] = args.since
    pp(client.get("/api/v1/oast/hits", params=q))


# aliases
cmd_oast_mint = cmd_oast_token_create
cmd_oast_list = cmd_oast_tokens_list
cmd_oast_poll = cmd_oast_hits


def cmd_tokens_list(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/tokens"))


def cmd_tokens_create(args: argparse.Namespace, client: Client) -> None:
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    body: dict[str, Any] = {"name": args.name, "scopes": scopes}
    if args.mcp_tools:
        body["mcp_tools"] = [t.strip() for t in args.mcp_tools.split(",") if t.strip()]
    pp(client.post("/api/v1/tokens", json=body))


def cmd_tokens_revoke(args: argparse.Namespace, client: Client) -> None:
    pp(client.delete(f"/api/v1/tokens/{args.id}"))


def cmd_ai_run(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {"capability": args.capability, "user_data": args.data or ""}
    if args.llm:
        body["llm_id"] = args.llm
    pp(client.post("/api/v1/ai/run", json=body))


def cmd_llm_list(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/llm"))


def cmd_llm_add(args: argparse.Namespace, client: Client) -> None:
    body: dict[str, Any] = {
        "name": args.name,
        "provider": args.provider,
        "model": args.model,
    }
    if args.base_url:
        body["base_url"] = args.base_url
    if args.api_key:
        body["api_key"] = args.api_key
    if args.capabilities:
        body["capabilities"] = [c.strip() for c in args.capabilities.split(",") if c.strip()]
    pp(client.post("/api/v1/llm", json=body))


def cmd_mcp_tools(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/mcp/tools"))


def cmd_mcp_call(args: argparse.Namespace, client: Client) -> None:
    arguments = json.loads(args.args_json) if args.args_json else {}
    pp(client.post("/mcp/call", json={"name": args.name, "arguments": arguments}))


def cmd_policy_get(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/policy"))


def cmd_policy_hitl_list(args: argparse.Namespace, client: Client) -> None:
    params: dict[str, Any] = {}
    if args.status:
        params["status"] = args.status
    if args.limit:
        params["limit"] = args.limit
    pp(client.get("/api/v1/policy/hitl", params=params))


def cmd_policy_hitl_approve(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/policy/hitl/{args.request_id}/approve"))


def cmd_policy_hitl_deny(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/policy/hitl/{args.request_id}/deny"))


def cmd_policy_set(args: argparse.Namespace, client: Client) -> None:
    rules = json.loads(Path(args.file).read_text(encoding="utf-8") if args.file else args.json)
    pp(client.put("/api/v1/policy", json={"rules": rules}))


def cmd_config_show(args: argparse.Namespace) -> None:
    cfg = load_config()
    safe = dict(cfg)
    if "token" in safe and safe["token"] and not args.show_token:
        t = safe["token"]
        safe["token"] = t[:8] + "…" + t[-4:] if len(t) > 16 else "***"
    pp({"config_file": str(CONFIG_FILE), **safe})


def cmd_repl(args: argparse.Namespace, client: Client) -> None:
    print(f"SquidC5 REPL → {client.base}")
    print("Commands: sessions | tasks | listeners | metrics | audit | health | help | quit")
    print("Shortcuts: s <id> | t <session> <cmd> | g <template> <host> <port>")
    while True:
        try:
            line = input("sc5> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in ("q", "quit", "exit"):
            break
        if line in ("h", "help", "?"):
            print(
                "  sessions              list sessions\n"
                "  session <id>          get session\n"
                "  tasks [session_id]    list tasks\n"
                "  task <session> <cmd>  create task\n"
                "  listeners             list listeners\n"
                "  listen <name> <kind> <port>\n"
                "  start <listener_id>\n"
                "  stop <listener_id>\n"
                "  payload <tpl> <host> <port>\n"
                "  metrics | audit | health | whoami\n"
                "  ai <capability> [data]\n"
                "  quit"
            )
            continue
        parts = line.split()
        cmd = parts[0].lower()
        try:
            if cmd in ("sessions", "ses"):
                pp(client.get("/api/v1/sessions"))
            elif cmd in ("session", "s") and len(parts) >= 2:
                pp(client.get(f"/api/v1/sessions/{parts[1]}"))
            elif cmd in ("tasks",):
                params = {}
                if len(parts) >= 2:
                    params["session_id"] = parts[1]
                pp(client.get("/api/v1/tasks", params=params))
            elif cmd in ("task", "t") and len(parts) >= 3:
                command = " ".join(parts[2:])
                pp(
                    client.post(
                        "/api/v1/tasks",
                        json={"session_id": parts[1], "command": command},
                    )
                )
            elif cmd in ("listeners", "lis"):
                pp(client.get("/api/v1/listeners"))
            elif cmd == "listen" and len(parts) >= 4:
                pp(
                    client.post(
                        "/api/v1/listeners",
                        json={
                            "name": parts[1],
                            "kind": parts[2],
                            "port": int(parts[3]),
                            "host": parts[4] if len(parts) > 4 else "0.0.0.0",
                        },
                    )
                )
            elif cmd == "start" and len(parts) >= 2:
                pp(client.post(f"/api/v1/listeners/{parts[1]}/start"))
            elif cmd == "stop" and len(parts) >= 2:
                pp(client.post(f"/api/v1/listeners/{parts[1]}/stop"))
            elif cmd in ("payload", "g") and len(parts) >= 4:
                data = client.post(
                    "/api/v1/payloads/generate",
                    json={
                        "template": parts[1],
                        "host": parts[2],
                        "port": int(parts[3]),
                    },
                )
                print(data.get("content", data))
            elif cmd == "metrics":
                pp(client.get("/api/v1/metrics"))
            elif cmd == "audit":
                pp(client.get("/api/v1/audit", params={"limit": 20}))
            elif cmd == "health":
                pp(client.get("/api/v1/health"))
            elif cmd == "whoami":
                pp(client.get("/api/v1/meta"))
            elif cmd == "ai" and len(parts) >= 2:
                data = " ".join(parts[2:]) if len(parts) > 2 else ""
                pp(
                    client.post(
                        "/api/v1/ai/run",
                        json={"capability": parts[1], "user_data": data},
                    )
                )
            else:
                print("Unknown command. Type help.")
        except SystemExit as e:
            print(e)
        except Exception as e:
            print(f"error: {e}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sc5",
        description="SquidC5 operator CLI — control a remote C2 from your terminal",
    )
    p.add_argument("--url", help="C2 base URL (or SQUIDC5_URL / config)")
    p.add_argument("--token", help="API token (or SQUIDC5_TOKEN / config)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Skip TLS certificate verify (self-signed teamservers)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    # login / config
    login = sub.add_parser("login", help="Save URL + token to ~/.config/squidc5/config.json")
    login.add_argument("--url", default=None)
    login.add_argument("--token", required=True)
    login.set_defaults(func=cmd_login, needs_client=False)

    cfg = sub.add_parser("config", help="Show saved config")
    cfg.add_argument("--show-token", action="store_true")
    cfg.set_defaults(func=cmd_config_show, needs_client=False)

    bak = sub.add_parser("backup", help="Backup local SQLite DB (no API)")
    bak.add_argument(
        "output",
        nargs="?",
        default=".",
        help="Output file or directory (default: .)",
    )
    bak.add_argument("--data-dir", default=None, help="Data dir (default: ./data)")
    bak.add_argument("--db", default=None, help="Explicit DB path override")
    bak.set_defaults(func=cmd_backup, needs_client=False)

    rst = sub.add_parser("restore", help="Restore local SQLite DB from backup (stop server first)")
    rst.add_argument("backup", help="Backup .db file")
    rst.add_argument("--data-dir", default=None, help="Data dir (default: ./data)")
    rst.add_argument("--db", default=None, help="Explicit DB path override")
    rst.set_defaults(func=cmd_restore, needs_client=False)

    # simple
    for name, fn, help_ in (
        ("health", cmd_health, "Server health"),
        ("whoami", cmd_whoami, "Token identity / scopes"),
        ("metrics", cmd_metrics, "Metrics snapshot"),
        ("repl", cmd_repl, "Interactive REPL"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn, needs_client=True)

    # sessions
    ses = sub.add_parser("sessions", help="Session operations")
    ses_sub = ses.add_subparsers(dest="sessions_cmd", required=True)
    s_list = ses_sub.add_parser(
        "list",
        help="List sessions (default: active + live only)",
    )
    s_list.add_argument(
        "--status",
        default="active",
        help="active | closed | all (default: active)",
    )
    s_list.add_argument(
        "--all",
        action="store_true",
        help="Show all statuses (including closed); implies --include-dead",
    )
    s_list.add_argument(
        "--shells",
        "--reverse",
        dest="shells",
        action="store_true",
        help="Only reverse_shell/tcp sessions",
    )
    s_list.add_argument(
        "--include-dead",
        action="store_true",
        help="Include non-interactive/stale reverse shells",
    )
    s_list.add_argument(
        "--ids",
        action="store_true",
        help="Print session ids only (one per line)",
    )
    s_list.set_defaults(func=cmd_sessions_list, needs_client=True)
    s_get = ses_sub.add_parser("get", help="Get session")
    s_get.add_argument("id")
    s_get.set_defaults(func=cmd_sessions_get, needs_client=True)
    s_close = ses_sub.add_parser("close", help="Close session (keep row)")
    s_close.add_argument("id")
    s_close.set_defaults(func=cmd_sessions_close, needs_client=True)
    s_del = ses_sub.add_parser("delete", help="Hard-delete one session")
    s_del.add_argument("id")
    s_del.set_defaults(func=cmd_sessions_delete, needs_client=True)
    s_clear = ses_sub.add_parser(
        "clear",
        help="Bulk remove reverse-shell noise (default: unverified scanners)",
    )
    s_clear.add_argument(
        "--all-shells",
        action="store_true",
        help="Remove ALL reverse_shell/tcp sessions (verified too)",
    )
    s_clear.add_argument(
        "--closed",
        action="store_true",
        help="Only purge already-closed shell rows",
    )
    s_clear.add_argument(
        "--active",
        action="store_true",
        help="Only active shells",
    )
    s_clear.add_argument(
        "--unverified",
        action="store_true",
        help="With --closed/--active: only unverified",
    )
    s_clear.add_argument(
        "--close-only",
        action="store_true",
        help="Mark closed instead of hard-delete",
    )
    s_clear.set_defaults(func=cmd_sessions_clear, needs_client=True)
    s_reap = ses_sub.add_parser(
        "reap",
        help="Close dead reverse shells (no TCP, or fail exec probe)",
    )
    s_reap.add_argument(
        "--no-probe",
        action="store_true",
        help="Only drop sessions with no TCP channel (skip exec probe)",
    )
    s_reap.set_defaults(func=cmd_sessions_reap, needs_client=True)

    # tasks
    tsk = sub.add_parser("tasks", help="Task operations")
    tsk_sub = tsk.add_subparsers(dest="tasks_cmd", required=True)
    t_list = tsk_sub.add_parser("list", help="List tasks")
    t_list.add_argument("--session")
    t_list.set_defaults(func=cmd_tasks_list, needs_client=True)
    t_get = tsk_sub.add_parser("get", help="Get task")
    t_get.add_argument("id")
    t_get.set_defaults(func=cmd_tasks_get, needs_client=True)
    t_create = tsk_sub.add_parser("create", help="Create task")
    t_create.add_argument("session", help="Session id")
    t_create.add_argument("command", help="Command to run")
    t_create.add_argument("--args-json", dest="args_json")
    t_create.add_argument("--hitl", action="store_true")
    t_create.set_defaults(func=cmd_tasks_create, needs_client=True)

    # listeners
    lis = sub.add_parser("listeners", help="Listener operations")
    lis_sub = lis.add_subparsers(dest="listeners_cmd", required=True)
    l_list = lis_sub.add_parser("list")
    l_list.set_defaults(func=cmd_listeners_list, needs_client=True)
    l_create = lis_sub.add_parser("create")
    l_create.add_argument("name")
    l_create.add_argument("port", type=int)
    l_create.add_argument(
        "--kind",
        default="http",
        choices=["http", "tcp", "reverse_shell", "dns", "smtp"],
    )
    l_create.add_argument("--zone", default=None, help="DNS zone when kind=dns")
    l_create.add_argument(
        "--dns-mode",
        dest="dns_mode",
        default="both",
        choices=["beacon", "oast", "both"],
        help="DNS listener mode (default both)",
    )
    l_create.add_argument("--host", default="0.0.0.0")
    l_create.set_defaults(func=cmd_listeners_create, needs_client=True)
    l_start = lis_sub.add_parser("start")
    l_start.add_argument("id")
    l_start.set_defaults(func=cmd_listeners_start, needs_client=True)
    l_stop = lis_sub.add_parser("stop")
    l_stop.add_argument("id")
    l_stop.set_defaults(func=cmd_listeners_stop, needs_client=True)
    l_del = lis_sub.add_parser("delete")
    l_del.add_argument("id")
    l_del.set_defaults(func=cmd_listeners_delete, needs_client=True)

    # payloads
    pay = sub.add_parser("payloads", help="Payload generation")
    pay_sub = pay.add_subparsers(dest="payloads_cmd", required=True)
    p_tpl = pay_sub.add_parser("templates")
    p_tpl.set_defaults(func=cmd_payloads_templates, needs_client=True)
    p_gen = pay_sub.add_parser("generate")
    p_gen.add_argument("template")
    p_gen.add_argument("host")
    p_gen.add_argument("port", type=int)
    p_gen.add_argument("--interval", type=int, default=5)
    p_gen.add_argument("--profile", default=None, help="C2 profile id (default: active)")
    p_gen.add_argument("--scheme", default=None, help="http|https for HTTP beacons; ws|wss for WS")
    p_gen.add_argument("--zone", default=None, help="DNS zone override")
    p_gen.add_argument("--raw", action="store_true", help="Print payload content only")
    p_gen.set_defaults(func=cmd_payloads_generate, needs_client=True)

    # implants
    imp = sub.add_parser("implants", help="Advanced implant generation")
    imp_sub = imp.add_subparsers(dest="implants_cmd", required=True)
    im_f = imp_sub.add_parser("families")
    im_f.set_defaults(func=cmd_implants_families, needs_client=True)
    im_g = imp_sub.add_parser("generate")
    im_g.add_argument("family")
    im_g.add_argument("host")
    im_g.add_argument("port", type=int)
    im_g.add_argument("--platform", default="linux")
    im_g.add_argument("--arch", default="x64")
    im_g.add_argument("--profile", default=None)
    im_g.add_argument("--path", default=None)
    im_g.add_argument("--no-evasion", action="store_true")
    im_g.add_argument("--raw", action="store_true")
    im_g.set_defaults(func=cmd_implants_generate, needs_client=True)
    im_b = imp_sub.add_parser("build", help="Native sc5beacon build plan")
    im_b.add_argument("--os", default="linux")
    im_b.add_argument("--arch", default="amd64")
    im_b.add_argument("host")
    im_b.add_argument("port", type=int)
    im_b.add_argument("--scheme", default="https")
    im_b.add_argument("--sleep", type=float, default=5.0)
    im_b.add_argument("--jitter", type=float, default=20.0)
    im_b.add_argument("--kill-date", type=int, default=None)
    im_b.add_argument("--max-miss", type=int, default=0)
    im_b.set_defaults(func=cmd_implants_build, needs_client=True)

    # teams
    teams = sub.add_parser("teams", help="Multi-operator teams")
    teams_sub = teams.add_subparsers(dest="teams_cmd", required=True)
    tm_l = teams_sub.add_parser("list")
    tm_l.set_defaults(func=cmd_teams_list, needs_client=True)
    tm_c = teams_sub.add_parser("create")
    tm_c.add_argument("name")
    tm_c.set_defaults(func=cmd_teams_create, needs_client=True)
    tm_m = teams_sub.add_parser("members")
    tm_m.add_argument("id")
    tm_m.set_defaults(func=cmd_teams_members, needs_client=True)
    tm_a = teams_sub.add_parser("add-member")
    tm_a.add_argument("id")
    tm_a.add_argument("actor")
    tm_a.add_argument("--role", default="operator")
    tm_a.set_defaults(func=cmd_teams_add_member, needs_client=True)

    # report / redirector
    rep = sub.add_parser("report", help="Export operator markdown report")
    rep.add_argument("--raw", action="store_true")
    rep.set_defaults(func=cmd_report, needs_client=True)
    red = sub.add_parser("redirector", help="Generate nginx redirector snippet")
    red.add_argument("--server-name", default="cdn.example.invalid")
    red.add_argument("--upstream-host", default="127.0.0.1")
    red.add_argument("--upstream-port", type=int, default=8443)
    red.add_argument("--listen-port", type=int, default=443)
    red.add_argument("--uris", default=None, help="Comma-separated beacon URIs")
    red.add_argument("--raw", action="store_true")
    red.set_defaults(func=cmd_redirector, needs_client=True)

    # profiles
    prof = sub.add_parser("profiles", help="Malleable C2 profiles")
    prof_sub = prof.add_subparsers(dest="profiles_cmd", required=True)
    pr_list = prof_sub.add_parser("list")
    pr_list.set_defaults(func=cmd_profiles_list, needs_client=True)
    pr_act = prof_sub.add_parser("active")
    pr_act.set_defaults(func=cmd_profiles_active, needs_client=True)
    pr_set = prof_sub.add_parser("activate")
    pr_set.add_argument("id", help="Profile id")
    pr_set.set_defaults(func=cmd_profiles_activate, needs_client=True)

    # shell
    sh = sub.add_parser(
        "shell",
        help="Send command to reverse shell and print output (use --all for every live shell)",
    )
    sh.add_argument(
        "--all",
        action="store_true",
        help="Broadcast command to all live reverse shells",
    )
    sh.add_argument(
        "parts",
        nargs="+",
        help="SESSION_ID COMMAND...   or   all COMMAND...   or   (with --all) COMMAND...",
    )
    sh.add_argument("--hitl", action="store_true")
    sh.add_argument("--wait", type=float, default=3.0, help="Seconds to wait for output (default 3)")
    sh.add_argument("--idle", type=float, default=0.45, help="Quiet period after output to stop waiting")
    sh.add_argument("--json", action="store_true", help="Print full JSON response")
    sh.add_argument("-v", "--verbose", action="store_true", help="Print metadata to stderr")
    sh.set_defaults(func=cmd_shell, needs_client=True)

    out = sub.add_parser("output", help="Dump recent reverse-shell buffer")
    out.add_argument("session")
    out.add_argument("--limit", type=int, default=8000)

    def cmd_output(args: argparse.Namespace, client: Client) -> None:
        data = client.get(f"/api/v1/sessions/{args.session}/output", params={"limit": args.limit})
        text = (data or {}).get("output") or ""
        if text:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
        else:
            print("[sc5] (empty buffer)", file=sys.stderr)

    out.set_defaults(func=cmd_output, needs_client=True)

    # audit / events
    aud = sub.add_parser("audit", help="Audit log")
    aud.add_argument("--limit", type=int, default=50)
    aud.add_argument("--offset", type=int, default=0)
    aud.set_defaults(func=cmd_audit, needs_client=True)

    ev = sub.add_parser("events", help="Stream SSE events")
    ev.set_defaults(func=cmd_events, needs_client=True)

    # tokens
    tok = sub.add_parser("tokens", help="Token management")
    tok_sub = tok.add_subparsers(dest="tokens_cmd", required=True)
    tk_list = tok_sub.add_parser("list")
    tk_list.set_defaults(func=cmd_tokens_list, needs_client=True)
    tk_create = tok_sub.add_parser("create")
    tk_create.add_argument("name")
    tk_create.add_argument(
        "--scopes",
        required=True,
        help="Comma-separated scopes",
    )
    tk_create.add_argument("--mcp-tools", dest="mcp_tools", help="Comma-separated MCP tools")
    tk_create.set_defaults(func=cmd_tokens_create, needs_client=True)
    tk_rev = tok_sub.add_parser("revoke")
    tk_rev.add_argument("id")
    tk_rev.set_defaults(func=cmd_tokens_revoke, needs_client=True)

    # ai / llm
    ai = sub.add_parser("ai", help="Run Admin AI capability")
    ai.add_argument("capability")
    ai.add_argument("--data", default="")
    ai.add_argument("--llm", default=None)
    ai.set_defaults(func=cmd_ai_run, needs_client=True)

    pb = sub.add_parser("playbooks", help="List AI chain playbooks")
    pb.set_defaults(func=cmd_ai_playbooks, needs_client=True)
    ch = sub.add_parser("chain", help="Run railed AI playbook chain")
    ch.add_argument("playbook")
    ch.add_argument("--data", default="")
    ch.set_defaults(func=cmd_ai_chain, needs_client=True)

    llm = sub.add_parser("llm", help="LLM connection management")
    llm_sub = llm.add_subparsers(dest="llm_cmd", required=True)
    llm_list = llm_sub.add_parser("list")
    llm_list.set_defaults(func=cmd_llm_list, needs_client=True)
    llm_add = llm_sub.add_parser("add")
    llm_add.add_argument("name")
    llm_add.add_argument("model")
    llm_add.add_argument("--provider", default="openai")
    llm_add.add_argument("--base-url", dest="base_url")
    llm_add.add_argument("--api-key", dest="api_key")
    llm_add.add_argument("--capabilities")
    llm_add.set_defaults(func=cmd_llm_add, needs_client=True)

    # mcp
    mcp = sub.add_parser("mcp", help="MCP tools")
    mcp_sub = mcp.add_subparsers(dest="mcp_cmd", required=True)
    m_tools = mcp_sub.add_parser("tools")
    m_tools.set_defaults(func=cmd_mcp_tools, needs_client=True)
    m_call = mcp_sub.add_parser("call")
    m_call.add_argument("name")
    m_call.add_argument("--args-json", dest="args_json", default="{}")
    m_call.set_defaults(func=cmd_mcp_call, needs_client=True)

    # policy
    pol = sub.add_parser("policy", help="Policy engine")
    pol_sub = pol.add_subparsers(dest="policy_cmd", required=True)
    pol_get = pol_sub.add_parser("get")
    pol_get.set_defaults(func=cmd_policy_get, needs_client=True)
    pol_set = pol_sub.add_parser("set")
    pol_set.add_argument("--json", dest="json")
    pol_set.add_argument("--file")
    pol_set.set_defaults(func=cmd_policy_set, needs_client=True)
    pol_hitl = pol_sub.add_parser("hitl", help="HITL approval queue")
    pol_hitl_sub = pol_hitl.add_subparsers(dest="policy_hitl_cmd", required=True)
    ph_list = pol_hitl_sub.add_parser("list")
    ph_list.add_argument("--status", default="pending")
    ph_list.add_argument("--limit", type=int, default=50)
    ph_list.set_defaults(func=cmd_policy_hitl_list, needs_client=True)
    ph_ok = pol_hitl_sub.add_parser("approve")
    ph_ok.add_argument("request_id")
    ph_ok.set_defaults(func=cmd_policy_hitl_approve, needs_client=True)
    ph_no = pol_hitl_sub.add_parser("deny")
    ph_no.add_argument("request_id")
    ph_no.set_defaults(func=cmd_policy_hitl_deny, needs_client=True)

    # oast collaborator
    oast = sub.add_parser("oast", help="OAST Collaborator (tokens + hits)")
    oast_sub = oast.add_subparsers(dest="oast_cmd", required=True)
    o_tok = oast_sub.add_parser("token", help="Token operations")
    o_tok_sub = o_tok.add_subparsers(dest="oast_token_cmd", required=True)
    o_tok_c = o_tok_sub.add_parser("create", help="Mint unique OAST payloads")
    o_tok_c.add_argument("--note", default="", help="Operator note")
    o_tok_c.set_defaults(func=cmd_oast_token_create, needs_client=True)
    o_tokens = oast_sub.add_parser("tokens", help="List OAST tokens")
    o_tokens_sub = o_tokens.add_subparsers(dest="oast_tokens_cmd", required=False)
    o_tokens_list = o_tokens_sub.add_parser("list", help="List tokens")
    o_tokens_list.set_defaults(func=cmd_oast_tokens_list, needs_client=True)
    o_tokens.set_defaults(func=cmd_oast_tokens_list, needs_client=True)
    o_hits = oast_sub.add_parser("hits", help="Poll OAST hits (Collaborator-style)")
    o_hits.add_argument("--token")
    o_hits.add_argument("--protocol", choices=["http", "dns", "smtp"])
    o_hits.add_argument("--client-id", dest="client_id")
    o_hits.add_argument("--since", type=float, default=None)
    o_hits.add_argument("--limit", type=int, default=100)
    o_hits.set_defaults(func=cmd_oast_hits, needs_client=True)
    # aliases
    o_mint = oast_sub.add_parser("mint", help="Alias: token create")
    o_mint.add_argument("--note", default="")
    o_mint.add_argument("--label", default="")
    o_mint.set_defaults(func=cmd_oast_token_create, needs_client=True)
    o_poll = oast_sub.add_parser("poll", help="Alias: hits")
    o_poll.add_argument("--token")
    o_poll.add_argument("--protocol", choices=["http", "dns", "smtp"])
    o_poll.add_argument("--client-id", dest="client_id")
    o_poll.add_argument("--since", type=float, default=None)
    o_poll.add_argument("--limit", type=int, default=100)
    o_poll.set_defaults(func=cmd_oast_hits, needs_client=True)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    needs = getattr(args, "needs_client", True)
    if not needs:
        args.func(args)
        return

    base = resolve_base(args)
    token = resolve_token(args)
    if not token and args.command not in ("health",):
        # health is public; everything else needs token
        if args.command != "health":
            print(
                "No token configured. Run:\n"
                "  sc5 login --url http://HOST:8443 --token sc5_...\n"
                "or set SQUIDC5_TOKEN / --token",
                file=sys.stderr,
            )
            # still allow health without token
            if args.command != "health":
                raise SystemExit(1)

    verify = resolve_verify(args)
    client = Client(base, token, timeout=args.timeout, verify=verify)
    try:
        args.func(args, client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
