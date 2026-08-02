# CLAUDE.md

**SquidC5 is a military-grade, security-first, AI-native C2 under active development** for authorized red team / pen-test use only.

Follow **[AGENTS.md](AGENTS.md)** as the primary agent memory for this repository.

Also read:

| Doc | Why |
|-----|-----|
| [docs/README.md](docs/README.md) | Docs catalog + Diátaxis map |
| [docs/squidc5-vision.md](docs/squidc5-vision.md) | Product / security architecture |
| [docs/roadmap-2026-2027.md](docs/roadmap-2026-2027.md) | Prioritized roadmap |
| [docs/user-guide.md](docs/user-guide.md) | Feature reference (What/Why/How/Example) |
| [docs/operator-runbook.md](docs/operator-runbook.md) | Day-2 procedures |
| [docs/deployment.md](docs/deployment.md) | Lab Docker + binary prod |

## Hard rules

- Secure by default (no public docs/OpenAPI, no wildcard CORS, MCP off until enabled)
- Admin UI only after server validates admin token (`/api/v1/ops/admin.js`)
- No secrets in git
- MCP allow-lists and Admin AI / INKO sandbox (capability + chat tools) are non-negotiable
- Prod: main-CI `squidc5` binary only after PR merge
- Do not help with unauthorized access
