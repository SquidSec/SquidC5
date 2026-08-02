# Changelog

All notable changes to SquidC5 are documented here.  
Format inspired by [Keep a Changelog](https://keepachangelog.com/).  
**OPSEC notes** call out changes that affect detection surface or defaults.

## [Unreleased]

### Added
- **INKO** (Intelligent Neural Kinetic Operator): rebrand of ops neural operator chat
- INKO opens from a **top-bar button** as a right flyout panel (full-screen on mobile); floating FAB removed
- SOCKS5 **duplex**: direct mode + implant reverse-dial bridge (`socks:connect`)
- Local Ollama path via `SQUIDC5_LOCAL_LLM_*` when no cloud LLM configured
- README badges fixed (live CI + SquidGate workflow shields)
- Docs: Diátaxis index, Artifacts / Profiles / OAST / TLS cert library chapters, Ops nav map

### Changed
- Ops UI and chat system prompt use **INKO** naming; user guide / runbook / README / AGENTS updated
- INKO chat: **persisted history** (browser localStorage), clear input on send, pending indicator, block send while waiting, **markdown** rendering for assistant replies
- **Documentation consistency pass:** user guide What/Why/How/Example/See also; runbook Goal/Prereqs/Steps/Verify; deployment Context/Config/Commands/Verify; fixed cross-links and Ops Docs menu anchors

### Security / OPSEC
- Native agent remains AEAD-only with full TLS verify

## [0.1.126] - 2026-08-01

### Added
- Audit verify, profile push, file chunks, native agent CI builds

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
