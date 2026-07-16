# AGENTS.md — Instructions for AI Agents Working on SquidSeC2

## Project

SquidSeC2 is a lightweight, security-first, AI-native C2 for **authorized** red team / pen-test use only.

## Non-Negotiable Security Rules

1. **External AI restriction**: MCP tools must remain allow-listed per token. Do not add open-ended autonomous agent loops for external models.
2. **Admin AI shielding**: Never feed raw session output into LLM prompts without `sanitize_untrusted()`. Keep capabilities allow-listed.
3. **Determinism preference**: Prefer templates, fixed prompts, and single-step tools over free-form agentic planning.
4. **Audit everything**: Operator, MCP, and Admin AI actions go through the policy engine / audit trail.
5. **No secrets in git**: Tokens, API keys, and `data/` contents stay out of the repository.
6. **Port flexibility**: Never hard-require ports 80 or 443 for listeners.

## Architecture Map

```
src/squidsec2/
  main.py           # FastAPI app + lifespan
  config.py         # Settings (SQUIDSEC2_* env)
  db/store.py       # SQLite schema + access
  auth/tokens.py    # Scoped tokens
  policy/engine.py  # Allow/deny, risk, HITL
  sessions/         # Beacon & shell sessions
  listeners/        # http/tcp/reverse_shell
  tasking/          # Structured tasks
  payloads/         # Deterministic templates
  mcp/server.py     # Restricted external AI tools
  ai/admin_ai.py    # Sandboxed internal AI
  api/routes.py     # REST API
  metrics/          # Counters + SSE events
  audit/            # Audit facade
```

## Dev Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest -q
ruff check src tests
uvicorn squidsec2.main:create_app --factory --host 0.0.0.0 --port 8443
```

Docker:

```bash
docker compose up --build -d
# Admin token: docker compose exec squidsec2 cat /data/admin_token.txt
```

## When Changing Code

- Keep changes small and auditable
- Add/adjust pytest coverage for auth, policy, MCP allow-lists, and AI sanitization
- Update `docs/squidsec2-vision.md` if behavior/spec changes
- Keep README accurate
- Do not weaken MCP tool restrictions or Admin AI sandbox without explicit human design review

## Testing Focus

- Token scope enforcement
- MCP tool allow-list denial paths
- Policy HITL / deny thresholds
- `sanitize_untrusted` injection filtering
- Listener port bind (non-privileged ports)
- Implant beacon task poll/complete cycle
