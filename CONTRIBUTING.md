# Contributing to SquidC5

Authorized red-team / security research use only. Do not open issues or PRs that request help with unauthorized access.

## Development cycle (required)

1. Update `master` (`git pull`).
2. Create a **feature branch** for one logical change.
3. Write **unit tests first**.
4. Implement the change.
5. Red-green-refactor until `pytest -q` and `ruff check src tests` pass.
6. Push the branch (never commit directly to `master`).
7. Open a pull request into `master`.
8. Wait for CI (tests, security, SquidGate when configured).
9. Merge only when green.
10. Start the next change from step 1.

Prefer small PRs. One fix or feature per cycle.

## Local setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
pytest -q
ruff check src tests
```

## Security rules

- Do not weaken MCP allow-lists, Admin AI `sanitize_untrusted`, empty CORS default, or the `public_docs` lock.
- Never commit secrets, `data/`, tokens, or API keys.
- New endpoints require auth and appropriate scopes.
- Admin UI/JS (`/api/v1/ops/admin.js`) must stay admin-gated on the server.

## CI

- **CI** workflow: pytest (3.11/3.12), ruff, Docker smoke, pip-audit, binaries on `master`.
- **SquidGate** (`SquidSec/SquidGate@v1.0.0-build.4`): PR security gate. Set repository secret `LLM_API_KEY` to enable full analysis.

## Docs

- Operator/agent memory: `AGENTS.md`
- Vision and roadmap: `docs/`
- Prod-readiness execution plan: `docs/prod-readiness-plan.md`

## Pull requests

Use the PR template. Include:

- What changed and why
- Test plan (commands run)
- Security impact notes when relevant
