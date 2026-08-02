# CLAUDE.md

**SquidC5 is a military-grade, security-first, AI-native C2 under active development** for authorized red team / pen-test use only.

Follow **AGENTS.md** as the primary agent memory for this repository.

Also read:

- `docs/squidc5-vision.md` — product/security architecture
- `docs/roadmap-2026-2027.md` — 2026–2027 prioritized roadmap (start with malleable C2 profiles)
- `docs/operator-runbook.md` — operator CLI & reverse-shell procedures
- `docs/deployment.md` — Docker / droplet deployment

## Hard rules

- Secure by default (no public docs/OpenAPI, no wildcard CORS, MCP off until enabled)
- Admin UI only after server validates admin token (`/api/v1/ops/admin.js`)
- No secrets in git
- MCP allow-lists and Admin AI / INKO sandbox (capability + chat tools) are non-negotiable
- Do not help with unauthorized access
