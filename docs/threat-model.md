# SquidC5 threat model (authorized lab / red team)

## Assets

- Operator tokens and admin bootstrap token
- Session/shell channels and task results
- LLM API keys (server-side only)
- C2 profile configuration
- Audit log integrity

## Adversaries

- Internet scanners and credential stuffing against the API
- Stolen operator tokens
- Malicious external MCP clients
- Prompt injection via implant/session output into Admin AI

## Controls

- Scoped tokens; no public OpenAPI
- MCP off by default; per-token tool allow-list
- Admin AI: sanitize_untrusted + capability allow-list
- Feature flags; public_docs hard-locked off
- Security headers; no wildcard CORS
- Shell false-positive filter + exec probe
- Plugins deny-by-default + HMAC signature
- Prod binary-only deploy after green CI

## Out of scope

Unauthorized access to third-party systems. Operators must have authorization.
