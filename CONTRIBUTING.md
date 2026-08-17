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

- **CI** workflow: pytest (3.11/3.12), ruff, Docker smoke, pip-audit; Linux x64/ARM64 + Windows binaries + GitHub Release on push to `master`.
- **Public SquidC5 CI uses GitHub-hosted runners** (`ubuntu-latest` / `ubuntu-24.04-arm` / `windows-latest`). Org self-hosted runners do not accept public repos.
- Actions are **SHA-pinned**; fork PR jobs that touch secrets are still gated to same-repo PRs. Fork contributors: run the local checks above and note results in the PR.
- **`master` is protected**: PR required, status checks (`test (3.12)`, `security`), no force-push.
- **SquidGate** (when configured): optional PR security gate. Repository secret `LLM_API_KEY` enables full analysis when available.

## Docs

Catalog and section templates: [docs/README.md](docs/README.md) (Diátaxis: tutorials/how-tos vs reference vs explanation).

| Doc | Role |
|-----|------|
| [AGENTS.md](AGENTS.md) | Agent memory + full CLI surface |
| [docs/user-guide.md](docs/user-guide.md) | Feature reference (What/Why/How/Example) |
| [docs/operator-runbook.md](docs/operator-runbook.md) | Day-2 procedures |
| [docs/deployment.md](docs/deployment.md) | Lab + prod binary |
| [docs/squidc5-vision.md](docs/squidc5-vision.md) | Architecture |
| [docs/roadmap-2026-2027.md](docs/roadmap-2026-2027.md) | Long-range roadmap |
| [docs/prod-readiness-plan.md](docs/prod-readiness-plan.md) | Engineering checklist |

When you change operator-facing behavior, update the matching user-guide chapter and fix cross-links.
## Pull requests

Use the PR template. Include:

- What changed and why
- Test plan (commands run)
- Security impact notes when relevant
