# SquidSeC2

**Lightweight, security-first, AI-native Command & Control for authorized red team operations.**

[![CI](https://github.com/DotNetRussell/SquidSec2/actions/workflows/ci.yml/badge.svg)](https://github.com/DotNetRussell/SquidSec2/actions/workflows/ci.yml)

> ⚠️ **Authorized use only.** SquidSeC2 is intended for legitimate penetration testing and red team engagements with explicit permission. Unauthorized access to systems is illegal.

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
docker compose exec squidsec2 cat /data/admin_token.txt
```

## Quick Start (Local)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
uvicorn squidsec2.main:create_app --factory --host 0.0.0.0 --port 8443
# Admin token printed path: data/admin_token.txt
```

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

Interactive docs: `/docs`

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

Environment variables (prefix `SQUIDSEC2_`):

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

See [docs/squidsec2-vision.md](docs/squidsec2-vision.md) and [AGENTS.md](AGENTS.md).

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
