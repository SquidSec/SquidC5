# Changelog

All notable changes to SquidC5 are documented here.  
Format inspired by [Keep a Changelog](https://keepachangelog.com/).  
**OPSEC notes** call out changes that affect detection surface or defaults.

## [Unreleased]

### Added
- Server-side HITL approval queue (`sc5 policy hitl …`); client `hitl_approved` ignored
- Listener restore on boot; clean shutdown keeps `running` for restart recovery
- DB schema migrations (`schema_version`)
- LLM API keys encrypted at rest
- API rate limit + max body size enforcement
- Deep health endpoint (`/api/v1/health/deep`)
- `sc5 backup` / `sc5 restore`
- Optional JSON logging (`SQUIDC5_LOG_JSON`)
- SquidGate PR security gate
- Startup config validation
- Plugin signing secret hardening (no legacy default in prod)
- Admin token file mode 0600; admin.js admin-only gate

### Security / OPSEC
- TLS-by-default docs and examples (`https://`, `sc5 --insecure` for lab)
- Docker compose healthcheck uses HTTPS
- CI `pip-audit` fails the build
- Rate limit defaults may need raising for chatty ops UIs (prod often 600/min)

### Docs
- SquidSec branding and logo on README
- Expanded threat model, systemd unit, CONTRIBUTING, this changelog

## [0.1.x] - 2026

Initial alpha line: FastAPI teamserver, reverse shells, HTTP beacons, OAST,
scoped tokens, dual AI, binary releases.
