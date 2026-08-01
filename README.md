# SquidC5

<p align="center">
  <a href="https://squidoffense.com/">
    <img src="assets/squidsec-logo.png" alt="SquidSec logo" width="180">
  </a>
</p>

<p align="center">
  <strong>A SquidSec Open Source Project</strong><br>
  <a href="https://squidoffense.com/">SquidOffense.com</a> ·
  <a href="https://github.com/SquidSec/SquidC5">GitHub</a>
</p>

<p align="center">
  <a href="https://github.com/SquidSec/SquidC5/actions/workflows/ci.yml"><img src="https://github.com/SquidSec/SquidC5/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
  <a href="https://github.com/SquidSec/SquidC5/actions/workflows/squidgate.yml"><img src="https://img.shields.io/badge/SquidGate-enabled-red" alt="SquidGate"></a>
  <a href="https://github.com/SquidSec/SquidC5/releases/latest"><img src="https://img.shields.io/github/v/release/SquidSec/SquidC5?include_prereleases&sort=date&label=latest%20release&color=blue" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

**Command · Control · Cognitive · Collaborative · Coordination**

Security-first, AI-native C5 teamserver for **authorized** red team and penetration testing operations. Built and maintained by **[SquidSec](https://squidoffense.com/)**.

> **Authorized use only.** Unauthorized access to systems is illegal. Operators must have explicit permission.

### What C5 means

| Pillar | Role in SquidC5 |
|--------|-----------------|
| **Command** | Operator tasking of shells, beacons, and implants |
| **Control** | Scoped tokens, policy, feature flags, listeners |
| **Cognitive** | Sandboxed Admin AI + restricted external MCP tools |
| **Collaborative** | Multi-operator handoff, chat, shared sessions |
| **Coordination** | Profiles, task queues, timelines, audit, reports |

## Features

- **Scoped API tokens** with full audit trail
- **Dual AI model**
  - External AI via restricted MCP tools (allow-listed, off by default)
  - Server-side Admin AI (BYO LLM, sandboxed, prompt-injection shielded)
- **Listeners** - HTTP beacons, TCP, reverse shells, DNS/SMTP OAST (any port)
- **Sessions and tasking** - beacons and shells as first-class objects
- **Policy engine** - risk scores + **server-side HITL** approval queue
- **Implant AEAD** - ChaCha20-Poly1305 sealed beacons (PSK under `data/implant_psk.txt`)
- **Malleable transforms** - base64 / prepend / append / xor / netbios pipelines
- **File ops + SOCKS** - structured tasks and local SOCKS pivot broker
- **Native beacons** - Linux Go agent + Windows PowerShell generator
- **Secure defaults** - TLS on, empty CORS, no public OpenAPI, MCP off
- **Ops console** - `/ops` UI (admin JS server-gated)
- **Operator CLI** - `sc5` / `squidc5-cli`
- **Binary releases** - Linux/Windows teamserver + CLI from CI (+ SBOM)

## Quick Start (Docker lab)

```bash
docker compose up --build -d
# TLS on by default (self-signed under data/tls/)
curl -sk https://127.0.0.1:8443/api/v1/health
docker compose exec squidc5 cat /data/admin_token.txt
# Ops: https://127.0.0.1:8443/ops
```

## Quick Start (local)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
squidc5   # enables per-instance TLS under data/tls/
# token: data/admin_token.txt
```

## Standalone binaries

Every successful push to `master`:

1. CI builds Linux + Windows executables  
2. CI publishes a **GitHub Release** with checksums  

**Download:** https://github.com/SquidSec/SquidC5/releases/latest  

| Asset | Purpose |
|-------|---------|
| `sc5-linux-x64` / `sc5-windows-x64.exe` | Operator CLI |
| `squidc5-linux-x64` / `squidc5-windows-x64.exe` | C2 server (includes `/ops` UI) |
| `SHA256SUMS.txt` | Checksums |

```bash
chmod +x squidc5-linux-x64 && ./squidc5-linux-x64
# token: ./data/admin_token.txt
# console: https://HOST:8443/ops

./sc5-linux-x64 login --url https://HOST:8443 --token sc5_... --insecure
./sc5-linux-x64 sessions list
```

**Production deploy:** binary-only from main CI after green merge. See [docs/deployment.md](docs/deployment.md).

## Operator CLI (`sc5`)

```bash
pip install -e .
sc5 login --url https://YOUR_HOST:8443 --token sc5_... --insecure
sc5 health
sc5 sessions list
sc5 tasks create <session_id> "whoami"
sc5 listeners create http-1 9001 --kind http
sc5 payloads generate http_beacon_python YOUR_HOST 8443 --raw
sc5 policy hitl list
sc5 backup ./backup.db
sc5 ai recon_assist --data "windows domain"
sc5 repl
```

Config: `~/.config/squidc5/config.json` (mode 0600).  
Overrides: `--url` / `--token`, or `SQUIDC5_URL` / `SQUIDC5_TOKEN`.

## API overview

| Area | Path |
|------|------|
| Health | `GET /api/v1/health` (minimal) |
| Deep health | `GET /api/v1/health/deep` (auth) |
| Tokens / sessions / tasks / listeners | `/api/v1/...` |
| HITL queue | `GET/POST /api/v1/policy/hitl...` |
| Admin AI | `POST /api/v1/ai/run` |
| MCP | `GET /mcp/tools` · `POST /mcp/call` (off by default) |
| Implant beacon | `POST /api/v1/implant/beacon` |

Auth: `Authorization: Bearer <token>` or `X-API-Token: <token>`

**Docs are GitHub-only** - `/docs`, `/redoc`, `/openapi.json` stay disabled on the server.

## Documentation

| Doc | Purpose |
|-----|---------|
| [User guide](docs/user-guide.md) | Features, why/how, examples |
| [Operator runbook](docs/operator-runbook.md) | Shells, beacons, day-2 ops |
| [Deployment](docs/deployment.md) | Binary prod + Docker lab |
| [Threat model](docs/threat-model.md) | Trust boundaries and controls |
| [Roadmap](docs/roadmap-2026-2027.md) | 2026-2027 priorities |
| [Vision](docs/squidc5-vision.md) | Architecture |
| [Prod readiness plan](docs/prod-readiness-plan.md) | Execution checklist |
| [CONTRIBUTING](CONTRIBUTING.md) | PR / git cycle |
| [CHANGELOG](CHANGELOG.md) | Releases + OPSEC notes |
| [AGENTS.md](AGENTS.md) | Agent/operator memory |

## Configuration (selected)

Prefix `SQUIDC5_`. See [.env.example](.env.example).

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` / `PORT` | `0.0.0.0` / `8443` | API bind |
| `DATA_DIR` | `data` | DB, tokens, TLS, secrets |
| `TLS_ENABLED` | `true` | HTTPS |
| `MCP_ENABLED` | `false` | External MCP |
| `AI_ENABLED` | `true` | Admin AI |
| `PUBLIC_HOST` | empty | Stage-2 / implant callback host |
| `RATE_LIMIT_PER_MINUTE` | `60` | API rate limit |
| `LOG_JSON` | `false` | Structured logs |
| `SECRETS_KEY` | auto file | At-rest LLM key encryption |
| `PLUGIN_SIGNING_SECRET` | auto file | Plugin HMAC secret |

## Security model (summary)

1. **External AI** - MCP off by default; per-token tool allow-list  
2. **Admin AI** - capability allow-list + `sanitize_untrusted`  
3. **Policy + HITL** - server-side approval queue (client flags ignored)  
4. **Audit** - significant actions logged  
5. **Admin UI** - `/api/v1/ops/admin.js` requires admin scope  
6. **SquidGate** - PR security gate on this repo  

Report vulnerabilities via [GitHub Security Advisories](https://github.com/SquidSec/SquidC5/security). See [SECURITY.md](SECURITY.md).

## Development

```bash
pytest -q
ruff check src tests
```

Git cycle: feature branch → tests first → PR → green CI → merge. Never push straight to `master`. Details: [CONTRIBUTING.md](CONTRIBUTING.md).

## About SquidSec

SquidC5 is created and managed by **[SquidSec](https://squidoffense.com/)** - U.S. veteran-owned security company.

- Website: [https://squidoffense.com/](https://squidoffense.com/)  
- Sister project: [SquidGate](https://github.com/SquidSec/SquidGate) (PR security gate)

## License

MIT - see [LICENSE](LICENSE).

## Disclaimer

Provided for authorized security testing and education. Authors are not responsible for misuse.
