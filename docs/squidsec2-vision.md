# SquidSeC2 Vision & System Specification

**Version:** 0.1.0  
**Status:** Active development  
**Purpose:** Authorized penetration testing and red team operations only

## Overview

SquidSeC2 is a professional, lightweight, security-first, AI-native Command & Control framework. It is designed open-source-ready from the first commit, with strong emphasis on AI restriction, determinism, auditability, and low resource usage.

## Dual AI Architecture

### 1. External AI Control (MCP-Driven Operator Model)

External AI agents connect using scoped API tokens and interact via the MCP-compatible HTTP interface (`/mcp/*`).

**Restrictions (architectural, non-negotiable):**

- Only explicitly allow-listed MCP tools per token are callable
- Prefer single-tool deterministic calls over autonomous chaining
- Policy engine enforces `max_chain_length` (default 1)
- All tool calls are audited

### 2. Server-Side Admin AI (Internal Intelligence Layer)

Administrators configure BYO LLM connections. The Admin AI supports limited capabilities:

- `payload_template`
- `phishing_asset`
- `doc_generate`
- `shell_classify`
- `recon_assist`

**Shielding:**

- Untrusted data sanitized and length-capped
- Injection markers filtered
- Fixed system prompts; user data in isolation blocks
- Offline deterministic fallback when no LLM configured
- Sandbox enforced by policy

## Authentication & Tokens

- Server-generated tokens only (`ss2_…`)
- Admin token bootstrapped on first start (written once to `data/admin_token.txt`)
- Fine-grained scopes; MCP tools separately allow-listed
- Full audit of create/revoke/use

## Core C2 Engine

- **Listeners:** `http`, `tcp`, `reverse_shell` — any port (no 80/443 requirement)
- **Sessions:** beacons and reverse shells as first-class objects
- **Tasking:** structured pending → running → completed
- **Payloads:** deterministic templates only
- **Files / phone operators:** scoped token model ready

## Observability

- SQLite-backed metrics counters
- Immutable audit log
- SSE event stream at `/api/v1/events/stream`

## Policy Engine

Governs humans, external AI, and admin AI:

- allow/deny lists
- risk scoring
- human-in-the-loop thresholds
- external AI determinism rules
- admin AI sandbox rules

## Operator CLI

`ss2` / `squidsec2-cli` (`src/squidsec2/cli.py`) is the primary local harness for remote C2 control. It stores non-secret path config under `~/.config/squidsec2/` (token local-only). Full command surface is documented in `AGENTS.md` and `docs/operator-runbook.md`.

## Technology Stack

| Layer | Choice |
|-------|--------|
| Language | Python 3.11+ |
| API | FastAPI + Uvicorn |
| Operator CLI | `ss2` (httpx) |
| MCP | HTTP MCP-lite (allow-listed tools) |
| DB | SQLite (aiosqlite) |
| Deploy | Docker host-network (primary), standalone binaries planned |
| Tests | pytest |
| CI | GitHub Actions |

## Design Goals

1. Lightweight footprint
2. Multi-thread / async safe shared state
3. Port-flexible listeners
4. Security and AI restriction first
5. Open-source readiness (README, CI, LICENSE, AGENTS.md, vision doc)

## Responsible Use

SquidSeC2 is intended solely for authorized security testing. Unauthorized access to computer systems is illegal. Operators are responsible for obtaining proper authorization before use.
