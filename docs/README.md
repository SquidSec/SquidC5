# SquidC5 documentation

<p align="center"><img src="squidc5-banner.png" alt="SquidC5" width="100%">
</p>

**[SquidSec](https://squidoffense.com/)** open-source C5 - [GitHub](https://github.com/SquidSec/SquidC5) - [Releases](https://github.com/SquidSec/SquidC5/releases/latest)

> **Authorized use only.** Public OpenAPI is **not** served by the running server (`/docs` on the C2 stays off). These guides live in GitHub.

---

## How docs are organized (Diátaxis)

| Need | Doc type | Where |
|------|----------|--------|
| Learn by doing | Tutorial / quickstart | [Root README](../README.md) - [Operator runbook](operator-runbook.md) |
| Solve a job | How-to | [Operator runbook](operator-runbook.md) - [Deployment](deployment.md) |
| Look up a feature | Reference | [User guide](user-guide.md) - [AGENTS.md](../AGENTS.md) (CLI surface) |
| Understand design | Explanation | [Vision](squidc5-vision.md) - [Threat model](threat-model.md) |

### Section templates (consistency)

**User guide** (every feature chapter):

```text
## Feature name <- match Ops nav label when possible
### What
### Why
### How
### Example
### Pitfalls <- optional table
### See also
```

**Operator runbook** (every procedure):

```text
## Procedure name
### Goal
### Prerequisites
### Steps
### Verify
### If it fails
### See also
```

**Deployment** (every topic):

```text
## Topic
### Context
### Configuration
### Commands
### Verify
### See also
```

---

## Start here

| Audience | Start with |
|----------|------------|
| New operator | [User guide - Overview](user-guide.md#overview) -> [Runbook - Connect CLI](operator-runbook.md#connect-cli-to-a-server) |
| Day-2 ops | [Operator runbook](operator-runbook.md) |
| Deploy / upgrade | [Deployment](deployment.md) |
| Security review | [Threat model](threat-model.md) - [SECURITY.md](../SECURITY.md) |
| AI agents / contributors | [AGENTS.md](../AGENTS.md) - [CONTRIBUTING.md](../CONTRIBUTING.md) |

---

## Catalog

### Operators

| Document | Description |
|----------|-------------|
| [User guide](user-guide.md) | Feature reference (What / Why / How / Example) - Ops UI, INKO, Profiles, Artifacts, OAST, CLI |
| [Operator runbook](operator-runbook.md) | Day-2 procedures: shells, beacons, OAST, implants, collab |
| [Deployment](deployment.md) | Docker lab, OAST, TLS, binary prod + systemd |

### Security & architecture

| Document | Description |
|----------|-------------|
| [Threat model](threat-model.md) | Assets, trust boundaries, STRIDE, controls |
| [Vision](squidc5-vision.md) | Product / security architecture |
| [SECURITY.md](../SECURITY.md) | Vulnerability disclosure |

### Planning (engineering)

| Document | Description |
|----------|-------------|
| [Roadmap 2026-2027](roadmap-2026-2027.md) | Long-range priorities (10 focus areas) |
| [Five-star program](roadmap-five-star.md) | Pack A-E status toward category leadership |
| [Prod readiness](prod-readiness-plan.md) | Phased security/ops execution checklist |

### Project

| Document | Description |
|----------|-------------|
| [Changelog](../CHANGELOG.md) | Releases + OPSEC notes |
| [Contributing](../CONTRIBUTING.md) | PR / git cycle |
| [AGENTS.md](../AGENTS.md) | Full CLI surface + agent operating memory |
| [Root README](../README.md) | Public quickstart |

### Implant & modules

| Path | Description |
|------|-------------|
| [agents/sc5beacon](../agents/sc5beacon/README.md) | Native Go beacon (Linux / Windows / macOS) |
| [agents/windows](../agents/windows/README.md) | Windows notes |
| [agents/linux](../agents/linux/README.md) | Linux notes |
| [modules/bof](../modules/bof/README.md) | BOF-style lab modules |

---

## Ops console map

Nav labels in `/ops` (match [User guide](user-guide.md#ops-console-layout)):

| Nav | Guide section |
|-----|---------------|
| Dashboard | [Status overview](user-guide.md#status-overview) |
| Sessions | [Sessions](user-guide.md#sessions) |
| Listeners | [Listeners](user-guide.md#listeners) |
| Payloads | [Payloads and implants](user-guide.md#payloads-and-implants) |
| Profiles | [C2 profiles](user-guide.md#c2-profiles-profiles) |
| Artifacts | [Artifacts](user-guide.md#artifacts) |
| Post-Ex | [Post-Ex](user-guide.md#post-ex) |
| Collab | [Multi-operator collab](user-guide.md#multi-operator-collab) |
| INKO | [INKO](user-guide.md#inko-intelligent-neural-kinetic-operator) |
| Observe | [Observability](user-guide.md#observability) |
| Admin | [Tokens](user-guide.md#tokens) - [LLM connections](user-guide.md#llm-connections) - [Feature toggles](user-guide.md#feature-toggles) - [TLS certificates](user-guide.md#tls-certificate-library) |

Top bar **INKO** opens the chat flyout (same INKO stack as the nav page).

---

## Link conventions

- Prefer relative paths: `user-guide.md#sessions`, `../AGENTS.md`
- Heading anchors: lowercase, hyphens for spaces; avoid em dashes in headings when deep-linking
- CLI full surface: **[AGENTS.md](../AGENTS.md)** is source of truth; user guide CLI section is a summary
- Never document live tokens, keys, or commit `data/`
