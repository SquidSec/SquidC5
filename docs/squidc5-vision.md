# SquidC5 Vision & System Specification

**Version:** 0.1.0  
**Status:** Active development — **military-grade, security-first C5**  
**Purpose:** Authorized penetration testing, red team, and defensive security operations only  
**C5:** Command • Control • Cognitive • Collaborative • Coordination  
**Roadmap:** See `docs/roadmap-2026-2027.md` (malleable profiles → implants → evasion → multi-op → AI → plugins → observability → deploy → testing → community)

## Overview

**C5** expands to **Command, Control, Cognitive, Collaborative, Coordination** — the five pillars SquidC5 is built around (tasking, authority rails, AI assist, multi-operator work, and engagement orchestration).

SquidC5 is a professional, lightweight, **military-grade**, security-first, AI-native C5 / command-and-control framework under active development. It is designed open-source-ready from the first commit, with strong emphasis on **secure defaults**, AI restriction, determinism, auditability, and low resource usage.

Hardened posture includes: no public API documentation surface, scoped tokens, server-gated admin UI, feature flags, false-shell filtering, shell exec verification, and dual AI controls (restricted MCP + sandboxed Admin AI).

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

- Server-generated tokens only (`sc5_…`)
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

`sc5` / `squidc5-cli` (`src/squidc5/cli.py`) is the primary local harness for remote C2 control. It stores non-secret path config under `~/.config/squidc5/` (token local-only). Full command surface is documented in `AGENTS.md` and `docs/operator-runbook.md`.

## Technology Stack

| Layer | Choice |
|-------|--------|
| Language | Python 3.11+ |
| API | FastAPI + Uvicorn |
| Operator CLI | `sc5` (httpx) |
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

SquidC5 is intended solely for authorized security testing. Unauthorized access to computer systems is illegal. Operators are responsible for obtaining proper authorization before use.
