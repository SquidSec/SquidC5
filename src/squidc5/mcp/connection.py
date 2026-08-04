"""Build paste-ready MCP connection payloads for external LLM tools.

Formats: OpenCode remote MCP, Cursor mcpServers, generic JSON, sc5 CLI.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse


def normalize_api_base(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if not u:
        return ""
    # Drop trailing /api/v1 if present so we can rebuild paths cleanly
    if u.endswith("/api/v1"):
        u = u[: -len("/api/v1")]
    return u.rstrip("/")


def mcp_endpoint(api_base: str) -> str:
    base = normalize_api_base(api_base)
    return f"{base}/mcp" if base else "/mcp"


def build_mcp_connection(
    *,
    api_base: str,
    token: str,
    name: str = "squidc5",
    scopes: list[str] | None = None,
    mcp_tools: list[str] | None = None,
    token_id: str | None = None,
) -> dict[str, Any]:
    """Return multi-format connection blob for OpenCode / Grok / Cursor / CLI."""
    base = normalize_api_base(api_base)
    mcp_url = mcp_endpoint(base)
    server_key = _server_key(name)
    scopes = list(scopes or [])
    tools = list(mcp_tools or [])

    opencode = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            server_key: {
                "type": "remote",
                "url": mcp_url,
                "enabled": True,
                "oauth": False,
                "headers": {
                    "Authorization": f"Bearer {token}",
                },
            }
        },
    }

    # Cursor / VS Code style (also used by several clients)
    cursor = {
        "mcpServers": {
            server_key: {
                "url": mcp_url,
                "headers": {
                    "Authorization": f"Bearer {token}",
                },
            }
        }
    }

    # Generic single-server descriptor (Grok Build / custom)
    generic = {
        "name": server_key,
        "type": "remote",
        "url": mcp_url,
        "api_base": base,
        "token": token,
        "headers": {
            "Authorization": f"Bearer {token}",
            "X-API-Token": token,
        },
        "transport": "http-jsonrpc",
        "endpoints": {
            "jsonrpc": mcp_url,
            "tools_rest": f"{base}/mcp/tools",
            "call_rest": f"{base}/mcp/call",
        },
        "scopes": scopes,
        "mcp_tools": tools,
        "token_id": token_id,
        "notes": [
            "Authorized SquidC5 MCP only — least-privilege token",
            "Requires SQUIDC5_MCP_ENABLED=true and feature mcp_enabled",
            "Paste opencode block into opencode.json / opencode.jsonc under mcp",
            "Self-signed TLS: trust the teamserver CA or use a public cert",
        ],
    }

    # Prefer OpenCode snippet as primary copy text (most common paste target)
    copy_text = json.dumps(opencode, indent=2)

    # Also a one-line sc5 login for operators
    cli = f'sc5 login --url {base} --token {token}'
    if base.startswith("https://") and _looks_local_or_ip(base):
        cli += " --insecure"

    return {
        "mcp_url": mcp_url,
        "api_base": base,
        "server_name": server_key,
        "opencode": opencode,
        "cursor": cursor,
        "generic": generic,
        "cli": cli,
        "copy_text": copy_text,
        "formats": {
            "opencode_json": copy_text,
            "cursor_json": json.dumps(cursor, indent=2),
            "generic_json": json.dumps(generic, indent=2),
            "cli": cli,
        },
    }


def _server_key(name: str) -> str:
    raw = (name or "squidc5").strip().lower()
    out = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_"):
            out.append(ch)
        elif ch in (" ", ".", "/"):
            out.append("-")
    key = "".join(out).strip("-_") or "squidc5"
    if not key.startswith("squid") and "mcp" not in key:
        key = f"squidc5-{key}"
    return key[:48]


def _looks_local_or_ip(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return False
