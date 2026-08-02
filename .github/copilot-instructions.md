# GitHub Copilot instructions for SquidC5

Read and obey root **AGENTS.md**.

- Security-first C2 for authorized testing only
- Do not weaken MCP tool allow-lists or Admin AI `sanitize_untrusted` boundaries
- Do not commit tokens, API keys, or `data/` contents
- Prefer deterministic templates over autonomous agent loops
- Operator CLI is `sc5` - keep help/README/AGENTS in sync when adding commands
- Docker compose uses host networking for listener ports; document privileged-port sysctl for &lt;1024
