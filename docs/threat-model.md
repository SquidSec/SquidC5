# SquidC5 threat model (authorized lab / red team)

**Organization:** [SquidSec](https://squidoffense.com/)  
**Scope:** Teamserver, operator clients, implants/beacons on **authorized** targets only.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Operator and admin API tokens | Critical |
| Bootstrap `admin_token.txt` | Critical |
| Session/shell channels and task results | High |
| LLM API keys (server-side) | High |
| Plugin signing secret / secrets master key | High |
| C2 profile configuration | Medium |
| Audit log integrity | High |
| OAST interaction data | Medium |

## Trust boundaries

```text
[ Internet scanners ]
        |
        v
[ Redirector / TLS edge ] ---- optional
        |
        v
[ SquidC5 teamserver ]  <--- operators (sc5 /ops) with scoped tokens
        |
        +---> SQLite data/ (local disk)
        +---> BYO LLM API (egress)
        +---> Implants/beacons (authorized targets only)
        +---> MCP clients (external AI; off by default)
```

## Adversaries

1. Internet scanners and credential stuffing against the API  
2. Stolen operator tokens (scope abuse)  
3. Malicious external MCP clients  
4. Prompt injection via implant/session output into Admin AI  
5. Network observer on implant channel (if unauthenticated)  
6. Local host compromise of teamserver disk  
7. Insider operator exceeding engagement scope  

## Controls

| Threat | Control |
|--------|---------|
| API map disclosure | Public OpenAPI/docs hard-off |
| Cross-origin abuse | Empty CORS default; no wildcard |
| Token theft at rest | Hashed tokens; admin_token 0600 |
| Credential stuffing | Rate limit + stricter auth-fail bucket |
| Oversized bodies | `max_body_bytes` middleware |
| Admin UI leak | `/ops/admin.js` requires admin scope |
| MCP abuse | Off by default; per-token tool allow-list |
| Prompt injection | `sanitize_untrusted` + capability allow-list |
| HITL spoofing | Server-side queue; client flags ignored; command binding hash |
| LLM key theft from DB | Fernet at-rest (`secrets.key`) |
| Plugin forgery | Non-default HMAC secret required outside debug |
| Listener loss on restart | Restore `running` listeners on boot |
| False reverse shells | Classify + exec probe + stage-2 stabilize |
| Fingerprinting | Minimal public health; security headers |
| Supply chain | CI pip-audit gate; SquidGate on PRs |
| Prod drift | Binary-only deploy from main CI |

## STRIDE (summary)

| Category | Examples | Mitigations |
|----------|----------|-------------|
| Spoofing | Fake beacon registration | Implant channel crypto (roadmap A11); TLS for API |
| Tampering | Audit row edits | SQLite file perms; integrity chain (roadmap C08) |
| Repudiation | Operator denies action | Audit + policy checks |
| Info disclosure | OpenAPI, CORS *, admin JS | Locked defaults |
| DoS | Request floods | Rate limit, body limit |
| Elevation | Non-admin feature toggle | Scope checks server-side |

## Out of scope

- Unauthorized access to third-party systems  
- Guaranteeing implant evasion against all EDRs  
- Multi-region HA teamserver clustering (single-node SQLite)  

## Residual risks

- Script implants without AEAD remain forgeable until implant crypto lands  
- Single SQLite node is a availability and backup dependency (`sc5 backup`)  
- Redirector tier is operator-provided  

## Related

| Doc | Link |
|-----|------|
| Disclosure | [SECURITY.md](../SECURITY.md) |
| Deployment | [deployment.md](deployment.md) |
| Prod readiness | [prod-readiness-plan.md](prod-readiness-plan.md) |
| Vision | [squidc5-vision.md](squidc5-vision.md) |
| User guide — Security model | [user-guide.md#security-model](user-guide.md#security-model) |
| Docs index | [README.md](README.md) |
