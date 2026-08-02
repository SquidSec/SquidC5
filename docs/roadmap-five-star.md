# Five-star C5 program

Goal: ***** across implants, traffic, post-ex, multi-player, AI, governance, CI.

**Process:** feature branch -> unit tests -> PR -> CI + SquidGate green -> merge `master` -> deploy **Release binary** to prod -> repeat.

| Related | Link |
|---------|------|
| Long-range roadmap | [roadmap-2026-2027.md](roadmap-2026-2027.md) |
| Prod readiness checklist | [prod-readiness-plan.md](prod-readiness-plan.md) |
| Docs index | [README.md](README.md) |

## Pack status (living)

| Pack | Focus | Status |
|------|--------|--------|
| **A** | Native agent, factory, lifecycle, BOF scaffold | **Landed** (sc5beacon v2, build API, CI artifacts) |
| **B** | Traffic, profile push, transforms, SOCKS duplex | **In progress** (transforms + push done; SOCKS reverse-dial duplex this PR) |
| **C** | File chunks, engagement ROE, multi-op | **Landed** (claim/handoff/spectator/presence/UI) |
| **D** | AI capability pack + local Ollama path | **Landed** (15 caps; local LLM URL/model) |
| **E** | CI proof, SBOM, audit verify, benchmarks | **Landed** (verify, cov, mypy, SBOM, agent CI) |

## Implant maturity I1-I6

| Pack | Focus | Status |
|------|--------|--------|
| **I1** | Jobs + config blob | **Landed** (sc5beacon v3) |
| **I2** | Native WS channel | **Landed** |
| **I3** | COFF parse + 5 BOFs | **Landed** (exec still lab/parse; catalog simulate) |
| **I4** | Stage0 bash/ps1 stagers | **Landed** |
| **I5** | Sleep/string OPSEC | **Landed** (mask + wipe) |
| **I6** | Lab soak CI matrix | **Landed** (go test + multi-arch + smoke) |

## Multi-op + ops UI (M/U packs)

| Pack | Status |
|------|--------|
| M1 claim/lock | **Landed** |
| M2 handoff pack | **Landed** |
| M3 spectator | **Landed** |
| M4 presence | **Landed** |
| M5 team chat | **Landed** |
| M6 per-op audit | **Landed** |
| U1 workbench | **Landed** |
| U2 events rail | **Landed** |
| U3 teams panel | **Landed** |
| U4 layout presets | **Landed** |
| U5 file crumbs | **Landed** |
| U6 pivot map | **Landed** |
| U7 mobile targets | **Landed** |
| U8 toasts | existing showOk/showError |

## Security hardening pack (landed)

Token grant subset - policy admin-only - MCP=REST gates - HITL single-use - HTTP/DNS/WS implant AEAD - task session bind - claim on mutators - team lead RBAC - SOCKS loopback - LLM SSRF block - CORS null denied - stage-2 host sanitize - multi-page ops UI

## Still climbing to full *****

- Full Windows COFF **mapped execute** (research build) 
- P2P / SMB / named pipe 
- Per-implant keys (still global PSK) 
- True SSE EventSource auth (today: metrics poll rail) 
- Multi-host lab soak numbers (overnight) 
- External security audit 

## Links

| Doc | Link |
|-----|------|
| User guide | [user-guide.md](user-guide.md) |
| Deployment | [deployment.md](deployment.md) |
| Native beacon | [../agents/sc5beacon/README.md](../agents/sc5beacon/README.md) |
| Root README | [../README.md](../README.md) |
| Vision | [squidc5-vision.md](squidc5-vision.md) |
