# Changelog

All notable changes to SquidC5 are documented here.  
Format inspired by [Keep a Changelog](https://keepachangelog.com/).  
**OPSEC notes** call out changes that affect detection surface or defaults.

## [0.1.115] - 2026-08-01

### Added
- Malleable transforms (base64/prepend/append/xor/netbios)
- File ops API `/api/v1/files/op` (file:list/read/write/delete tasks)
- SOCKS pivot broker `/api/v1/pivot/socks`
- Caddy redirector generator; Windows PS beacon file ops
- profile_id/version on beacon check-in (runtime switch signal)
- Lab e2e + fuzz + beacon load tests; CI cov>=65%, mypy core, SBOM on release
- Implant router split (api/routers)

### Security / OPSEC
- Full parity batch toward best-in-class AI-native C5

## [0.1.107] - 2026-08-01

### Added
- Implant AEAD (ChaCha20-Poly1305) check-in auth (`implant_psk`, require auth default on)
- HTTPS-default HTTP beacon templates (system CA verify; lab uses redirector or `scheme=http`)
- Beacon `kill_date` enforcement
- Audit integrity chain (`chain_hash` / `prev_hash`, migration v3)
- Native Linux Go beacon scaffold (`agents/linux`)
- Listener crash supervision + audit retention purge
- Team RBAC on shell when session metadata has `team_id`
- Server-side HITL approval queue with command binding
- Listener restore on boot; `sc5 backup` / `restore`
- Deep health, rate limits, body limits, JSON logging
- SquidGate PR security gate
- SquidSec branding (logo), expanded threat model, systemd unit

### Security / OPSEC
- Client `hitl_approved` ignored; admin.js admin-only
- LLM keys encrypted at rest; plugin signing secret hardened
- TLS-by-default docs; binary-only prod deploy path
- Rate limit may need 600/min for ops UI

## [0.1.x] - 2026

Initial alpha line: FastAPI teamserver, reverse shells, HTTP beacons, OAST,
scoped tokens, dual AI, binary releases.
