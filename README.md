# SquidC5

**Lightweight, security-first, AI-native Command & Control for authorized red team operations.**

[![CI](https://github.com/DotNetRussell/SquidC5/actions/workflows/ci.yml/badge.svg)](https://github.com/DotNetRussell/SquidC5/actions/workflows/ci.yml)

> ⚠️ **Authorized use only.** SquidC5 is intended for legitimate penetration testing and red team engagements with explicit permission. Unauthorized access to systems is illegal.

## Features

- **Scoped API tokens** — server-generated, fine-grained scopes, full audit trail
- **Dual AI model**
  - External AI via restricted MCP tools (allow-listed, deterministic)
  - Server-side Admin AI (BYO LLM, sandboxed, prompt-injection shielded)
- **Listeners** — HTTP beacons, TCP, reverse shells (any port; no 80/443 requirement)
- **Sessions & tasking** — beacons and shells as first-class objects
- **Policy engine** — allow/deny, risk scores, human-in-the-loop
- **Observability** — metrics, immutable audit log, SSE event stream
- **Docker-first** — minimal image, low resource usage

## Quick Start (Docker)

```bash
docker compose up --build -d
curl -s http://127.0.0.1:8443/api/v1/health
docker compose exec squidc5 cat /data/admin_token.txt
```

## Quick Start (Local)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
uvicorn squidc5.main:create_app --factory --host 0.0.0.0 --port 8443
# Admin token printed path: data/admin_token.txt
```

## Standalone binaries (no venv)

Every successful push to `main`/`master`:

1. CI builds Linux + Windows executables  
2. CI publishes a **GitHub Release** (tag `v0.1.<run>-<sha>`) with assets  

**Download:** https://github.com/DotNetRussell/SquidC5/releases/latest  

| Asset | Purpose |
|-------|---------|
| `sc5-linux-x64` / `sc5-windows-x64.exe` | Operator CLI |
| `squidc5-linux-x64` / `squidc5-windows-x64.exe` | C2 server (includes `/ops` UI) |
| `SHA256SUMS.txt` | Checksums |

```bash
# Server (Linux release asset)
chmod +x squidc5-linux-x64 && ./squidc5-linux-x64
# token: ./data/admin_token.txt   console: http://HOST:8443/ops

# Operator CLI
./sc5-linux-x64 login --url http://HOST:8443 --token sc5_...
./sc5-linux-x64 sessions list
```

CI also uploads workflow Artifacts (30 days). Local build: `./scripts/build_binaries.sh`.

## Operator CLI (`sc5`)

Local harness to control a remote SquidC5 instance:

```bash
pip install -e .
# or use the standalone sc5 binary from CI artifacts
sc5 login --url http://YOUR_HOST:8443 --token sc5_...
sc5 health
sc5 sessions list
sc5 tasks create <session_id> "whoami"
sc5 listeners create http-1 9001 --kind http
sc5 payloads generate http_beacon_python YOUR_HOST 8443 --raw
sc5 ai recon_assist --data "windows domain"
sc5 repl   # interactive mode
```

Config is stored at `~/.config/squidc5/config.json` (mode 0600).  
Overrides: `--url` / `--token`, or env `SQUIDC5_URL` / `SQUIDC5_TOKEN`.

## API Overview

| Area | Path |
|------|------|
| Health | `GET /api/v1/health` |
| Tokens | `POST /api/v1/tokens` |
| Sessions | `GET /api/v1/sessions` |
| Tasks | `POST /api/v1/tasks` |
| Listeners | `POST /api/v1/listeners` |
| Payloads | `POST /api/v1/payloads/generate` |
| Metrics | `GET /api/v1/metrics` |
| Audit | `GET /api/v1/audit` |
| Events (SSE) | `GET /api/v1/events/stream` |
| Admin AI | `POST /api/v1/ai/run` |
| MCP tools | `GET /mcp/tools` · `POST /mcp/call` |
| Implant beacon | `POST /api/v1/implant/beacon` |

Auth header: `Authorization: Bearer <token>` or `X-API-Token: <token>`

**Documentation lives on GitHub only** (not on the running server — `/docs` stays disabled):

- **[User guide](docs/user-guide.md)** — features, why/how, examples  
- **[Docs index](docs/README.md)**

### Example: create operator token & task a session

```bash
ADMIN=$(cat data/admin_token.txt)

curl -s -X POST http://127.0.0.1:8443/api/v1/tokens \
  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops","scopes":["sessions:read","sessions:write","tasks:read","tasks:write","listeners:read","listeners:write","payloads:generate","metrics:read","audit:read"]}'
```

### Example: restricted external AI (MCP)

```bash
curl -s -X POST http://127.0.0.1:8443/api/v1/tokens \
  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"name":"ext-ai","scopes":["mcp:connect","sessions:read","tasks:read","tasks:write","metrics:read"],"mcp_tools":["list_sessions","get_session","list_tasks","create_task","get_metrics"]}'

# List only allow-listed tools
curl -s http://127.0.0.1:8443/mcp/tools -H "Authorization: Bearer $AI_TOKEN"
```

### Example: Admin AI (offline deterministic mode)

```bash
curl -s -X POST http://127.0.0.1:8443/api/v1/ai/run \
  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"capability":"shell_classify","user_data":"uid=0(root) gid=0(root)"}'
```

## Configuration

Environment variables (prefix `SQUIDC5_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8443` | API port |
| `DATA_DIR` | `data` | SQLite + token file |
| `MCP_ENABLED` | `true` | Enable MCP routes |
| `AI_ENABLED` | `true` | Enable Admin AI |
| `ADMIN_TOKEN_BOOTSTRAP` | _(empty)_ | Optional fixed bootstrap token |

## Security Model (summary)

1. **External AI** — only allow-listed MCP tools; chaining limited by policy
2. **Admin AI** — sandboxed capabilities; untrusted input sanitized; no raw free-form system access
3. **Policy engine** — risk scores + HITL for sensitive actions
4. **Audit** — immutable log of all significant actions

See:

- [AGENTS.md](AGENTS.md) — agent/project memory
- [docs/squidc5-vision.md](docs/squidc5-vision.md) — architecture
- [docs/operator-runbook.md](docs/operator-runbook.md) — operator CLI & reverse shells
- [docs/deployment.md](docs/deployment.md) — Docker / droplet deploy

## Development

```bash
pytest -q
ruff check src tests
```

## Responsible Disclosure

Report security issues privately to the repository maintainers. Do not open public issues for unpatched vulnerabilities.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This software is provided for authorized security testing and educational purposes. The authors are not responsible for misuse.
