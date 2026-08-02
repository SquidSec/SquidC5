# SquidC5 documentation

<p align="center">
  <img src="squidc5-banner.png" alt="SquidC5" width="100%">
</p>

**[SquidSec](https://squidoffense.com/)** open-source C5 — [GitHub](https://github.com/SquidSec/SquidC5) · [Releases](https://github.com/SquidSec/SquidC5/releases/latest)

| Document | Description |
|----------|-------------|
| [User guide](user-guide.md) | Features, workflows, examples (includes **INKO** neural operator) |
| [Operator runbook](operator-runbook.md) | Day-2 shells, beacons, native implant, INKO chat |
| [Deployment](deployment.md) | Binary prod + Docker lab + systemd |
| [Threat model](threat-model.md) | Assets, adversaries, STRIDE |
| [Vision](squidc5-vision.md) | Architecture |
| [Roadmap 2026–2027](roadmap-2026-2027.md) | Long-range priorities |
| [Five-star program](roadmap-five-star.md) | Pack A–E to category leadership |
| [Prod readiness](prod-readiness-plan.md) | Security/ops checklist |
| [Changelog](../CHANGELOG.md) | Releases + OPSEC notes |
| [Contributing](../CONTRIBUTING.md) | PR / git cycle |
| [Security](../SECURITY.md) | Disclosure |
| [AGENTS](../AGENTS.md) | CLI + agent memory |

### Implant & modules

| Path | Description |
|------|-------------|
| [agents/sc5beacon](../agents/sc5beacon/README.md) | Native Go beacon (Linux/Windows/macOS) |
| [agents/windows](../agents/windows/README.md) | Windows notes |
| [modules/bof](../modules/bof/README.md) | BOF-style lab modules |

Public OpenAPI is **not** served by the running server (`/docs` stays off).
