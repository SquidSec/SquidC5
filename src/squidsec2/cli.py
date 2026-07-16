"""SquidSeC2 operator CLI harness — local client for remote C2."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

DEFAULT_BASE = "http://127.0.0.1:8443"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "squidsec2"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config() -> dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
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
    env = os.environ.get("SQUIDSEC2_URL") or os.environ.get("SS2_URL")
    if env:
        return env.rstrip("/")
    cfg = load_config()
    return (cfg.get("url") or DEFAULT_BASE).rstrip("/")


def resolve_token(args: argparse.Namespace) -> str | None:
    if getattr(args, "token", None):
        return args.token
    env = os.environ.get("SQUIDSEC2_TOKEN") or os.environ.get("SS2_TOKEN")
    if env:
        return env
    return load_config().get("token")


def pp(data: Any) -> None:
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


class Client:
    def __init__(self, base: str, token: str | None, timeout: float = 30.0) -> None:
        self.base = base.rstrip("/")
        self.token = token
        headers: dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=self.base, headers=headers, timeout=timeout)

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


def cmd_login(args: argparse.Namespace) -> None:
    cfg = load_config()
    if args.url:
        cfg["url"] = args.url.rstrip("/")
    if args.token:
        cfg["token"] = args.token
    if not cfg.get("url"):
        cfg["url"] = DEFAULT_BASE
    if not cfg.get("token"):
        raise SystemExit("Token required: ss2 login --token <token> [--url http://host:8443]")
    save_config(cfg)
    client = Client(cfg["url"], cfg["token"])
    try:
        health = client.get("/api/v1/health")
        meta = client.get("/api/v1/meta")
        pp({"saved": str(CONFIG_FILE), "url": cfg["url"], "health": health, "actor": meta.get("actor")})
    finally:
        client.close()


def cmd_whoami(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/meta"))


def cmd_health(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/health"))


def cmd_sessions_list(args: argparse.Namespace, client: Client) -> None:
    params = {}
    if args.status:
        params["status"] = args.status
    pp(client.get("/api/v1/sessions", params=params))


def cmd_sessions_get(args: argparse.Namespace, client: Client) -> None:
    pp(client.get(f"/api/v1/sessions/{args.id}"))


def cmd_sessions_close(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/sessions/{args.id}/close"))


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
    pp(
        client.post(
            "/api/v1/listeners",
            json={
                "name": args.name,
                "kind": args.kind,
                "host": args.host,
                "port": args.port,
            },
        )
    )


def cmd_listeners_start(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/listeners/{args.id}/start"))


def cmd_listeners_stop(args: argparse.Namespace, client: Client) -> None:
    pp(client.post(f"/api/v1/listeners/{args.id}/stop"))


def cmd_listeners_delete(args: argparse.Namespace, client: Client) -> None:
    pp(client.delete(f"/api/v1/listeners/{args.id}"))


def cmd_payloads_templates(args: argparse.Namespace, client: Client) -> None:
    pp(client.get("/api/v1/payloads/templates"))


def cmd_payloads_generate(args: argparse.Namespace, client: Client) -> None:
    data = client.post(
        "/api/v1/payloads/generate",
        json={
            "template": args.template,
            "host": args.host,
            "port": args.port,
            "interval": args.interval,
        },
    )
    if args.raw:
        print(data.get("content", ""))
    else:
        pp(data)


def cmd_shell(args: argparse.Namespace, client: Client) -> None:
    pp(
        client.post(
            "/api/v1/shell/command",
            json={
                "session_id": args.session,
                "command": args.command,
                "hitl_approved": args.hitl,
            },
        )
    )


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
    print(f"SquidSeC2 REPL → {client.base}")
    print("Commands: sessions | tasks | listeners | metrics | audit | health | help | quit")
    print("Shortcuts: s <id> | t <session> <cmd> | g <template> <host> <port>")
    while True:
        try:
            line = input("ss2> ").strip()
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
        prog="ss2",
        description="SquidSeC2 operator CLI — control a remote C2 from your terminal",
    )
    p.add_argument("--url", help="C2 base URL (or SQUIDSEC2_URL / config)")
    p.add_argument("--token", help="API token (or SQUIDSEC2_TOKEN / config)")
    p.add_argument("--timeout", type=float, default=30.0)

    sub = p.add_subparsers(dest="command", required=True)

    # login / config
    login = sub.add_parser("login", help="Save URL + token to ~/.config/squidsec2/config.json")
    login.add_argument("--url", default=None)
    login.add_argument("--token", required=True)
    login.set_defaults(func=cmd_login, needs_client=False)

    cfg = sub.add_parser("config", help="Show saved config")
    cfg.add_argument("--show-token", action="store_true")
    cfg.set_defaults(func=cmd_config_show, needs_client=False)

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
    s_list = ses_sub.add_parser("list", help="List sessions")
    s_list.add_argument("--status")
    s_list.set_defaults(func=cmd_sessions_list, needs_client=True)
    s_get = ses_sub.add_parser("get", help="Get session")
    s_get.add_argument("id")
    s_get.set_defaults(func=cmd_sessions_get, needs_client=True)
    s_close = ses_sub.add_parser("close", help="Close session")
    s_close.add_argument("id")
    s_close.set_defaults(func=cmd_sessions_close, needs_client=True)

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
    l_create.add_argument("--kind", default="http", choices=["http", "tcp", "reverse_shell"])
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
    p_gen.add_argument("--raw", action="store_true", help="Print payload content only")
    p_gen.set_defaults(func=cmd_payloads_generate, needs_client=True)

    # shell
    sh = sub.add_parser("shell", help="Send command to reverse shell session")
    sh.add_argument("session")
    sh.add_argument("command")
    sh.add_argument("--hitl", action="store_true")
    sh.set_defaults(func=cmd_shell, needs_client=True)

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
                "  ss2 login --url http://HOST:8443 --token ss2_...\n"
                "or set SQUIDSEC2_TOKEN / --token",
                file=sys.stderr,
            )
            # still allow health without token
            if args.command != "health":
                raise SystemExit(1)

    client = Client(base, token, timeout=args.timeout)
    try:
        args.func(args, client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
