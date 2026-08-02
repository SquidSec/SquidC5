# SquidC5 Vision & System Specification

**Version:** 0.1.x  
**Status:** Active development — **military-grade, security-first C5**  
**Purpose:** Authorized penetration testing, red team, and defensive security operations only  
**C5:** Command · Control · Cognitive · Collaborative · Coordination  

| Related | Link |
|---------|------|
| Roadmap | [roadmap-2026-2027.md](roadmap-2026-2027.md) |
| User guide | [user-guide.md](user-guide.md) |
| Threat model | [threat-model.md](threat-model.md) |
| Docs index | [README.md](README.md) |
| Agent memory | [../AGENTS.md](../AGENTS.md) |

---

## Overview

### What

**C5** expands to **Command, Control, Cognitive, Collaborative, Coordination** — the five pillars SquidC5 is built around (tasking, authority rails, AI assist, multi-operator work, and engagement orchestration).

SquidC5 is a professional, lightweight, **military-grade**, security-first, AI-native C5 / command-and-control framework. It is designed open-source-ready, with strong emphasis on **secure defaults**, AI restriction, determinism, auditability, and low resource usage.

### Why

Hardened posture includes: no public API documentation surface, scoped tokens, server-gated admin UI, feature flags, false-shell filtering, shell exec verification, dual AI controls (restricted MCP + sandboxed Admin AI / INKO), malleable profiles, OAST, and binary-only production deploys.

### How (architecture sketch)

```text
Operator (sc5 / /ops / INKO)
    → API (scopes + policy + audit)
        → Sessions · Tasks · Listeners · Payloads · Profiles · Assets
        → INKO chat tools + Admin AI capabilities
        → MCP (allow-listed, off by default)
        → SQLite data/
Implants / reverse shells / OAST callbacks → Listeners → Sessions
```

### See also

- [User guide — Overview](user-guide.md#overview)
- [Threat model](threat-model.md)

---

## Dual AI Architecture

### 1. External AI Control (MCP-Driven Operator Model)

External AI agents connect using scoped API tokens and interact via the MCP-compatible HTTP interface (`/mcp/*`).

**Restrictions (architectural, non-negotiable):**

- Only explicitly allow-listed MCP tools per token are callable
- Prefer single-tool deterministic calls over autonomous chaining
- Policy engine enforces `max_chain_length` (default 1)
- All tool calls are audited
- Feature often **off by default**

### 2. Server-Side Admin AI / INKO (Internal Intelligence Layer)

**INKO** (Intelligent Neural Kinetic Operator) is the operator-facing neural chat surface on top of the sandboxed Admin AI stack.

Administrators configure BYO LLM connections (Ops **Admin** UI or CLI). **INKO** exposes multi-turn chat with railed C5 tools (`POST /api/v1/ai/chat`), optional per-turn **model** override, and a system prompt that documents platform purpose and workflows. The Admin AI also supports limited structured capabilities (`POST /api/v1/ai/run`):

- `payload_template`, `phishing_asset`, `doc_generate`, `shell_classify`, `recon_assist`, …
- Chat tools: sessions, listeners, tasks, payloads, profiles, assets, metrics, shell (HITL when required), …

**Shielding:**

- Untrusted data sanitized and length-capped (`sanitize_untrusted`)
- Injection markers filtered
- Fixed system prompts; tool results re-sanitized before model re-entry
- Offline deterministic fallback when no LLM configured
- Sandbox enforced by policy; bounded tool rounds (no open agent loops)

### See also

- [User guide — INKO](user-guide.md#inko-intelligent-neural-kinetic-operator)
- [User guide — MCP tools](user-guide.md#mcp-tools)

---

## Authentication & Tokens

- Server-generated tokens only (`sc5_…`)
- Admin token bootstrapped on first start (written once to `data/admin_token.txt`)
- Fine-grained scopes; MCP tools separately allow-listed
- Full audit of create/revoke/use
- Admin UI JS served only after server-side admin scope check

### See also

- [User guide — Tokens](user-guide.md#tokens)
- [User guide — Security model](user-guide.md#security-model)

---

## Core C2 Engine

| Subsystem | Behavior |
|-----------|----------|
| **Listeners** | `http`, `https`, `tcp`, `reverse_shell`, `dns`, `smtp` — any port (no 80/443 requirement) |
| **Sessions** | Beacons and reverse shells as first-class objects; verify + reap |
| **Tasking** | Structured pending → running → completed |
| **Payloads** | Deterministic templates + custom templates + implant factory |
| **Profiles** | Malleable HTTP(S) surface; active profile contract |
| **Artifacts** | Saved payloads/templates/profiles for reuse |
| **OAST** | DNS/HTTP/SMTP collaborator hits |
| **Files / SOCKS** | Scoped post-ex on sessions |
| **Collab** | Claim, handoff, spectator, presence, team chat |

### See also

- [User guide](user-guide.md)
- [Roadmap 2026–2027](roadmap-2026-2027.md)

---

## Observability

- SQLite-backed metrics counters
- Immutable audit log with hash-chain verify (`sc5 audit-verify`)
- SSE / polled event stream for ops dock
- Timeline and engagement report export

### See also

- [User guide — Observability](user-guide.md#observability)

---

## Policy Engine

Governs humans, external AI, and admin AI:

- allow/deny lists
- risk scoring
- human-in-the-loop thresholds
- external AI determinism rules
- admin AI sandbox rules

### See also

- [User guide — Policy](user-guide.md#policy)

---

## Operator CLI

`sc5` / `squidc5-cli` (`src/squidc5/cli.py`) is the primary local harness for remote C2 control. It stores config under `~/.config/squidc5/` (token local-only).

**Full command surface:** [AGENTS.md](../AGENTS.md)  
**Day-2 procedures:** [operator-runbook.md](operator-runbook.md)  
**Feature reference:** [user-guide.md#cli-reference](user-guide.md#cli-reference)

---

## Technology Stack

| Layer | Choice |
|-------|--------|
| Language | Python 3.11+ |
| API | FastAPI + Uvicorn (HTTPS default) |
| Operator CLI | `sc5` (httpx) |
| MCP | HTTP MCP-lite (allow-listed tools) |
| DB | SQLite (aiosqlite) |
| Deploy | **Prod:** main-CI standalone binary + systemd · **Lab:** Docker host-network |
| Native implant | Go `agents/sc5beacon` |
| Tests | pytest |
| CI | GitHub Actions + SquidGate |

---

## Design Goals

1. Lightweight footprint
2. Multi-thread / async safe shared state
3. Port-flexible listeners
4. Security and AI restriction first
5. Open-source readiness (README, CI, LICENSE, AGENTS.md, vision doc)
6. Binary-only production path after merge to master

---

## Responsible Use

SquidC5 is intended solely for authorized security testing. Unauthorized access to computer systems is illegal. Operators are responsible for obtaining proper authorization before use.

### See also

- [SECURITY.md](../SECURITY.md)
- [User guide — Authorized use](user-guide.md#authorized-use-reminder)
