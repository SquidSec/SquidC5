# SquidC5 Production-Readiness Execution Plan

**Goal:** Ship Phases A-D as a free, high-quality open-source C5 teamserver.  
**Repo:** `https://github.com/SquidSec/SquidC5` (default branch: `master`)  
**Status:** Alpha 0.1.x → target 1.0.0 after Phase C minimum; Phase D hardens OSS excellence.

## Mandatory git cycle (every change)

From SquidSec `AGENTS.md` + `knowledge-base/MEMORY.md` and SquidC5 `AGENTS.md`:

1. Checkout and update `master` (pull latest).
2. Create a **feature branch** named for the change only.
3. Write **unit tests first** (expected behavior).
4. Implement **code**.
5. **Red-green-refactor** until clean and all tests pass locally.
6. **Push** the feature branch only (never direct to `master`).
7. Open a **pull request** into `master`.
8. **Wait for CI** - do not merge red.
9. **Merge** when green.
10. Start over at step 1 for the next change.

**Rules:**

- One logical fix/feature per cycle (small PRs).
- Never commit secrets, `data/`, tokens, or API keys.
- Never weaken MCP rails, Admin AI sanitize, `public_docs` lock, or empty-CORS default.
- Prod deploy remains: merge `master` → CI binaries → deploy Linux `squidc5` binary only.
- After each merge: update this plan checklist (`[x]`) in a docs PR only if needed; prefer updating in the same PR that lands the work.
- Version bumps: patch for A/B hardening, minor for C features, `1.0.0` when MVP-prod exit criteria met.

## Exit criteria

### MVP-prod (claim "production-ready teamserver baseline")

- All Phase A items merged.
- All Phase B items merged.
- Phase C: C01 implant crypto + C02 HTTPS beacons + C03 kill/miss controls + C06 native beacon v1 (at least Linux).
- CI green on `master`; release notes honest; threat model updated.
- No known P0 security holes from the readiness assessment.

### Full OSS C5 (claim "high-quality free OSS C5")

- MVP-prod + remaining Phase C + Phase D.
- Coverage gate + mypy on core + load/fuzz smoke in CI.
- CONTRIBUTING, changelog OPSEC notes, SBOM on releases.

---

## Change catalog

Each **Change ID** = one git cycle (one branch, one PR).  
Branch naming: `feature/<id>-short-slug` or `fix/<id>-short-slug` or `docs/<id>-short-slug`.  
Depends-on must be merged first unless noted parallel-safe.

---

# PHASE A — Stop the bleeding (security baseline)

**Theme:** Internet-facing without embarrassment. No new major product features.

### A01 — API rate limiting enforcement
- **Branch:** `fix/a01-api-rate-limit`
- **Depends on:** none
- **Tests first:**
  - Burst over `SQUIDC5_RATE_LIMIT_PER_MINUTE` returns 429.
  - Authenticated vs unauthenticated buckets (stricter on auth failures).
  - Health endpoint either exempt or very high limit (no self-DoS from probes).
- **Code:**
  - Middleware using `Settings.rate_limit_per_minute` (today unused in `config.py`).
  - Per-IP and optional per-token counters; audit high-rate denials.
- **Files (likely):** `src/squidc5/main.py`, `src/squidc5/config.py`, new `src/squidc5/api/rate_limit.py`, `tests/test_rate_limit.py`
- **PR title:** `fix(api): enforce rate_limit_per_minute`

### A02 — Max body size middleware
- **Branch:** `fix/a02-max-body-bytes`
- **Depends on:** none (parallel with A01)
- **Tests first:**
  - Body over `max_body_bytes` → 413.
  - Normal API bodies still succeed.
- **Code:** middleware/ASGI check; wire `Settings.max_body_bytes`.
- **Files:** `main.py`, `config.py`, `tests/test_max_body.py`
- **PR title:** `fix(api): enforce max_body_bytes`

### A03 — Admin-only ops-admin.js gate
- **Branch:** `fix/a03-ops-admin-js-gate`
- **Depends on:** none
- **Tests first:**
  - Non-admin token → 403 on `/api/v1/ops/admin.js` (no JS body).
  - Admin token → 200 + JS.
  - Unauthenticated → 401/403.
- **Code:** change `Depends(get_auth)` to admin scope check; align with AGENTS.md contract.
- **Files:** `api/routes.py`, `api/deps.py`, `tests/test_ops_console_gate.py`
- **PR title:** `fix(ops): serve admin.js only to admin scope`

### A04 — Admin token file permissions
- **Branch:** `fix/a04-admin-token-chmod`
- **Depends on:** none
- **Tests first:**
  - After bootstrap, `admin_token.txt` mode is `0o600` (where OS allows).
- **Code:** write via temp + `chmod`/`open` with 0o600 (mirror `tls/certs.py`).
- **Files:** `main.py`, `tests/test_admin_token_perms.py`
- **PR title:** `fix(bootstrap): chmod 0600 admin_token.txt`

### A05 — Plugin signing secret hardening
- **Branch:** `fix/a05-plugin-signing-secret`
- **Depends on:** none
- **Tests first:**
  - Default hardcoded secret refused when `debug=False` / non-dev.
  - Secret from env or `data_dir` works; signature verify still passes for known fixtures.
- **Code:** remove usable default in prod; `SQUIDC5_PLUGIN_SIGNING_SECRET` or generated once under `data/`; document in `.env.example`.
- **Files:** `plugins/registry.py`, `config.py`, `.env.example`, `tests/test_plugins_signing.py`
- **PR title:** `fix(plugins): require non-default signing secret`

### A06 — Encrypt LLM API keys at rest
- **Branch:** `fix/a06-llm-keys-at-rest`
- **Depends on:** none (careful with DB column already named `api_key_enc`)
- **Tests first:**
  - Store key → DB blob is not plaintext.
  - Load connection → decrypted key works for outbound mock.
  - Missing master key → clear error / refuse start when LLMs configured.
- **Code:** Fernet (or equivalent) with key from env `SQUIDC5_SECRETS_KEY` / data file mode 0600; migrate existing plaintext rows on read/write.
- **Files:** `ai/admin_ai.py`, `db/store.py`, `config.py`, `tests/test_llm_key_encryption.py`
- **PR title:** `fix(ai): encrypt LLM API keys at rest`

### A07 — Docker healthcheck HTTPS
- **Branch:** `fix/a07-docker-healthcheck-https`
- **Depends on:** none
- **Tests first:** compose config review + CI smoke already uses `curl -k`; align compose healthcheck.
- **Code:** `docker-compose.yml` healthcheck `curl -sk https://127.0.0.1:8443/api/v1/health`; Dockerfile if needed.
- **Files:** `docker-compose.yml`, `Dockerfile`, maybe `.github/workflows/ci.yml`
- **PR title:** `fix(docker): HTTPS healthcheck with TLS default`

### A08 — CI pip-audit must fail
- **Branch:** `fix/a08-pip-audit-gate`
- **Depends on:** none
- **Tests:** CI workflow change; fix any current audit findings or pin allowlist with comment.
- **Code:** remove `|| true` from pip-audit step; document exceptions only if unavoidable.
- **Files:** `.github/workflows/ci.yml`
- **PR title:** `ci: fail on pip-audit findings`

### A09 — Docs/README TLS URL consistency
- **Branch:** `docs/a09-tls-url-defaults`
- **Depends on:** none (parallel)
- **Tests:** n/a or link check smoke.
- **Code/docs:** README, user-guide, deployment, release blurb examples use `https://` + note `--insecure`/self-signed for lab.
- **Files:** `README.md`, `docs/*.md`, maybe `AGENTS.md` quickstart lines
- **PR title:** `docs: align URLs with TLS-by-default`

### A10 — Real HITL approval queue (or honest demotion)
- **Branch:** `feature/a10-hitl-approval-queue`
- **Depends on:** none (prefer before policy-heavy work)
- **Decision in PR:** implement server-side queue (preferred) rather than remove HITL.
- **Tests first:**
  - High-risk action without approval → denied / pending.
  - `hitl_approved: true` from client alone does **not** bypass.
  - Admin (or designated approver scope) approves → action proceeds; audit both request and approval.
- **Code:**
  - Table `hitl_requests` (or reuse policy store).
  - API: list/approve/deny pending.
  - Policy engine ignores client-asserted approval; checks server record.
  - CLI: `sc5 policy hitl list|approve|deny`.
- **Files:** `policy/engine.py`, `db/store.py`, `api/routes.py`, `cli.py`, `tests/test_hitl_queue.py`
- **PR title:** `feat(policy): server-side HITL approval queue`

### A11 — Implant channel auth + AEAD (Phase A security critical)
- **Branch:** `feature/a11-implant-channel-crypto`
- **Depends on:** A02 helpful but not required
- **Tests first:**
  - Beacon without valid key/MAC → rejected; no session created.
  - Valid sealed check-in → session + task poll works.
  - Replay of old ciphertext rejected (nonce/counter/window).
  - Generator emits key material only once; server stores hash/wrapped secret.
- **Code:**
  - Per-implant or listener PSK; AEAD (e.g. ChaCha20-Poly1305) over beacon body.
  - Wire HTTP + WS paths; DNS label payload MAC where feasible.
  - Config: `SQUIDC5_IMPLANT_REQUIRE_AUTH=true` default **on** for new listeners; migration note for lab.
  - Docs: operator flow to mint implant key.
- **Files:** `implants/`, `listeners/http_listener.py`, `listeners/ws_beacon.py`, `profiles/`, `payloads/generator.py`, `api/routes.py`, `tests/test_implant_crypto.py`
- **PR title:** `feat(implant): authenticated AEAD check-in channel`
- **Note:** Largest A change; keep PR focused on HTTP beacon first if needed, follow-up A11b for DNS/WS.

### A11b — Implant crypto on DNS + WS (if split from A11)
- **Branch:** `feature/a11b-implant-crypto-dns-ws`
- **Depends on:** A11
- **Only if A11 scoped to HTTP only.**

---

# PHASE B — Teamserver production core

**Theme:** Survives restart, upgrades, and small-team ops.

### B01 — Schema migration framework
- **Branch:** `feature/b01-db-migrations`
- **Depends on:** none (do early in B; blocks many B items)
- **Tests first:**
  - Fresh DB applies all migrations.
  - Old DB fixture upgrades without data loss.
  - `schema_version` table present.
- **Code:** simple versioned SQL or light migrator in `db/migrate.py`; call from `Database.connect`; no silent column drift.
- **Files:** `db/store.py`, `db/migrate.py`, `tests/test_db_migrations.py`
- **PR title:** `feat(db): versioned schema migrations`

### B02 — Listener restore on boot
- **Branch:** `feature/b02-listener-restore`
- **Depends on:** B01 optional
- **Tests first:**
  - Listener row `status=running` → started after app lifespan.
  - Bind failure → status `error`, audit event, no crash loop of whole app.
- **Code:** `build_state` / lifespan calls `listeners.restore_running()`.
- **Files:** `main.py`, `listeners/manager.py`, `tests/test_listener_restore.py`
- **PR title:** `feat(listeners): restore running listeners on startup`

### B03 — Listener crash supervision
- **Branch:** `feature/b03-listener-supervision`
- **Depends on:** B02
- **Tests first:**
  - Simulated listener task death → restart with backoff; max retries then error status.
- **Code:** done-callbacks, exponential backoff, metrics counters.
- **Files:** `listeners/manager.py`, `tests/test_listener_supervision.py`
- **PR title:** `feat(listeners): supervise and restart crashed listeners`

### B04 — Backup and restore CLI
- **Branch:** `feature/b04-backup-restore`
- **Depends on:** B01 preferred
- **Tests first:**
  - `backup` creates consistent SQLite snapshot.
  - `restore` loads into empty data dir; app reads sessions/tokens.
- **Code:** `sc5 backup [path]`, `sc5 restore [path]` using SQLite backup API; document stop/start guidance.
- **Files:** `cli.py`, `db/store.py`, `docs/operator-runbook.md`, `tests/test_backup_restore.py`
- **PR title:** `feat(cli): backup and restore SQLite data`

### B05 — Deep health vs public health
- **Branch:** `feature/b05-deep-health`
- **Depends on:** none
- **Tests first:**
  - Public `/health` still minimal.
  - Authenticated `/health/deep` (admin or `metrics:read`) returns db/listeners/disk without secrets.
- **Code:** new route; never leak tokens/keys.
- **Files:** `api/routes.py`, `tests/test_health.py`
- **PR title:** `feat(api): authenticated deep health endpoint`

### B06 — Structured JSON logging
- **Branch:** `feature/b06-json-logging`
- **Depends on:** none
- **Tests first:**
  - With `SQUIDC5_LOG_JSON=true`, log line parses as JSON; no token fields.
- **Code:** configurable formatter; keep default human logs for lab.
- **Files:** `main.py`, `config.py`, `tests/test_logging_format.py`
- **PR title:** `feat(ops): optional JSON structured logging`

### B07 — Audit retention job
- **Branch:** `feature/b07-audit-retention`
- **Depends on:** B01
- **Tests first:**
  - Rows older than `audit_retention_days` pruned on schedule/startup option.
  - Recent rows kept.
- **Code:** honor existing config knob; optional periodic task.
- **Files:** `audit/`, `main.py`, `config.py`, `tests/test_audit_retention.py`
- **PR title:** `feat(audit): enforce audit_retention_days`

### B08 — Startup config validation
- **Branch:** `feature/b08-config-validation`
- **Depends on:** none
- **Tests first:**
  - TLS cert without key → fail fast.
  - Invalid port / empty required public_host when stabilize on → clear error.
- **Code:** pydantic validators + lifespan preflight.
- **Files:** `config.py`, `main.py`, `tests/test_config_validation.py`
- **PR title:** `feat(config): fail-fast startup validation`

### B09 — systemd unit + binary upgrade runbook
- **Branch:** `docs/b09-systemd-upgrade`
- **Depends on:** B01, B04 (reference them)
- **Code/docs:** `packaging/squidc5.service`, `docs/deployment.md` upgrade section (stop → replace binary → migrate → start).
- **Files:** `packaging/`, `docs/deployment.md`
- **PR title:** `docs(deploy): systemd unit and binary upgrade runbook`

### B10 — Split api/routes.py into routers
- **Branch:** `refactor/b10-split-api-routes`
- **Depends on:** avoid parallel large route PRs; land after A03/A10/A11 or rebase carefully
- **Tests first:** existing API tests must pass unchanged (behavior-preserving).
- **Code:** `api/routers/{sessions,tasks,listeners,tokens,ai,ops,...}.py`; `build_api_router` includes them.
- **Files:** `api/routes.py` → split, `tests/*` unchanged expectations
- **PR title:** `refactor(api): split routes into domain routers`

### B11 — Split listeners/manager.py
- **Branch:** `refactor/b11-split-listener-manager`
- **Depends on:** B02, B03 preferred first
- **Tests:** listener + shell tests green.
- **Code:** extract reverse_shell channel, restore/supervise, probe into modules under `listeners/`.
- **PR title:** `refactor(listeners): split manager responsibilities`

### B12 — Split db/store.py access layer
- **Branch:** `refactor/b12-split-db-store`
- **Depends on:** B01
- **Tests:** migration + store tests.
- **Code:** domain repos or mixin modules; keep `Database` facade.
- **PR title:** `refactor(db): split store by domain`

### B13 — Split cli.py into subcommand modules
- **Branch:** `refactor/b13-split-cli`
- **Depends on:** B04 (backup commands exist)
- **Tests:** CLI smoke tests / help tests.
- **Code:** `cli/commands/*.py`, thin `cli.py` entry.
- **PR title:** `refactor(cli): split subcommands into modules`

### B14 — Team RBAC enforced on sessions/shell
- **Branch:** `feature/b14-team-rbac`
- **Depends on:** B01
- **Tests first:**
  - Operator not on team cannot shell/session interact.
  - Admin bypass.
  - Handoff grants access.
- **Code:** enforce in deps/routes using `collab/teams.py`; audit denials.
- **Files:** `collab/teams.py`, `api/deps.py`, `api/routes.py`, `tests/test_team_rbac.py`
- **PR title:** `feat(collab): enforce team RBAC on session interact`

### B15 — CONTRIBUTING + PR template
- **Branch:** `docs/b15-contributing`
- **Depends on:** none
- **Files:** `CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md`, issue templates
- **PR title:** `docs: CONTRIBUTING and PR templates`

### B16 — Expanded threat model
- **Branch:** `docs/b16-threat-model`
- **Depends on:** A11, A10 (document real controls)
- **Files:** `docs/threat-model.md` (STRIDE, trust boundaries, implant, redirector, HITL)
- **PR title:** `docs: expand threat model for production posture`

---

# PHASE C — Real C2 parity

**Theme:** Operators can run authorized engagements on beacons, not only reverse shells.

### C01 — HTTPS-native beacon templates
- **Branch:** `feature/c01-https-beacon-templates`
- **Depends on:** A11
- **Tests:** generated payload uses `https://` when TLS on; verify flag documented.
- **Files:** `payloads/generator.py`, `implants/generators.py`, tests
- **PR title:** `feat(payloads): HTTPS-native beacon generation`

### C02 — Kill date + max missed check-ins
- **Branch:** `feature/c02-implant-lifecycle-controls`
- **Depends on:** A11
- **Tests:** expired kill date stops tasking; max misses marks session dead.
- **Files:** sessions, implants, profiles, tests
- **PR title:** `feat(implant): kill date and max missed check-ins`

### C03 — Profile transform subset (malleable depth)
- **Branch:** `feature/c03-profile-transforms`
- **Depends on:** none (profiles exist)
- **Tests:** encode/decode round-trip; unknown transform safe-fail.
- **Code:** small transform pipeline (base64, prepend/append, header map) server + generator.
- **Files:** `profiles/engine.py`, `profiles/models.py`, tests
- **PR title:** `feat(profiles): malleable transform pipeline v1`

### C04 — SOCKS proxy task type
- **Branch:** `feature/c04-socks-pivot`
- **Depends on:** A11, preferably C06
- **Tests:** unit protocol framing; integration lab optional.
- **Code:** task kind + teamserver side listener association; implant support in native beacon when ready.
- **PR title:** `feat(pivot): SOCKS proxy tasking v1`

### C05 — File ops task types
- **Branch:** `feature/c05-file-ops-tasks`
- **Depends on:** A11
- **Tests:** upload/download/ls task schema + beacon handler contract.
- **PR title:** `feat(tasking): file list/read/write task types`

### C06 — Native beacon v1 (Linux)
- **Branch:** `feature/c06-native-beacon-linux`
- **Depends on:** A11, C01, C02
- **Tests:** build script + protocol compatibility tests against teamserver; lab e2e optional in CI.
- **Code:** Go or Rust agent (pick one stack and stick); check-in, tasking, sleep/jitter; release artifact optional.
- **Files:** new `agents/linux/` (or `implant-native/`), CI job, docs
- **PR title:** `feat(implant): native Linux beacon v1`
- **Note:** largest C change; may split protocol client lib vs agent binary.

### C07 — Native beacon Windows v1
- **Branch:** `feature/c07-native-beacon-windows`
- **Depends on:** C06
- **PR title:** `feat(implant): native Windows beacon v1`

### C08 — Audit integrity chain or SIEM export
- **Branch:** `feature/c08-audit-integrity`
- **Depends on:** B07
- **Tests:** tamper detection on hash chain; export JSONL.
- **Code:** HMAC chain per row or signed batches; `sc5 audit export`.
- **PR title:** `feat(audit): integrity chain and export`

### C09 — Lab e2e victim harness
- **Branch:** `feature/c09-lab-e2e-harness`
- **Depends on:** A11, B02
- **Tests:** compose profile with victim container; scripted beacon + task whoami.
- **Files:** `tests/e2e/`, `docker-compose.lab.yml`, CI optional job
- **PR title:** `test(e2e): lab victim beacon playbook`

### C10 — Redirector automation depth
- **Branch:** `feature/c10-redirector-tier`
- **Depends on:** B09
- **Code:** generate + validate nginx/caddy configs; docs for tiered deploy.
- **PR title:** `feat(deploy): redirector tier generators and docs`

### C11 — Runtime profile switch to live implants
- **Branch:** `feature/c11-runtime-profile-switch`
- **Depends on:** C03, C06
- **Tests:** profile activate pushes next-check-in instructions.
- **PR title:** `feat(profiles): runtime profile switch for beacons`

---

# PHASE D — OSS excellence

**Theme:** Project quality bar for serious external contributors.

### D01 — Coverage gate in CI
- **Branch:** `ci/d01-coverage-gate`
- **Depends on:** none (raise threshold gradually)
- **Code:** pytest-cov `--cov-fail-under=70` then ratchet.
- **PR title:** `ci: enforce coverage minimum`

### D02 — mypy on core packages
- **Branch:** `ci/d02-mypy-core`
- **Depends on:** none
- **Code:** mypy `src/squidc5/{auth,policy,config,api}` first; expand later.
- **PR title:** `ci: mypy on core packages`

### D03 — Fuzz DNS/HTTP profile parsers
- **Branch:** `test/d03-fuzz-parsers`
- **Depends on:** C03 helpful
- **Code:** Hypothesis or atheris smoke in CI job (time-boxed).
- **PR title:** `test: fuzz DNS and profile parsers`

### D04 — Load/soak beacon storm test
- **Branch:** `test/d04-load-beacon-storm`
- **Depends on:** A01, A11
- **Code:** scripted N concurrent check-ins; assert no crash + p95 latency bound in lab.
- **PR title:** `test: beacon storm load profile`

### D05 — SBOM on release assets
- **Branch:** `ci/d05-release-sbom`
- **Depends on:** none
- **Code:** generate SBOM in release job; attach to GitHub Release.
- **PR title:** `ci: attach SBOM to releases`

### D06 — Changelog with OPSEC highlights
- **Branch:** `docs/d06-changelog`
- **Depends on:** none
- **Files:** `CHANGELOG.md` format; document process in CONTRIBUTING
- **PR title:** `docs: CHANGELOG with OPSEC section template`

### D07 — Version policy past 0.1.x
- **Branch:** `docs/d07-support-policy`
- **Depends on:** MVP-prod near
- **Files:** `SECURITY.md`, `pyproject.toml` version bump process
- **PR title:** `docs: supported versions and 1.0 policy`

### D08 — Dead code and deps cleanup
- **Branch:** `refactor/d08-deps-cleanup`
- **Depends on:** B10-B13 preferred
- **Code:** remove `NotImplementedError` stubs, unused deps, silent bare excepts in hot paths.
- **PR title:** `refactor: remove dead stubs and harden error paths`

---

## Execution order (serialized critical path)

Parallel tracks where noted. Always full git cycle per ID.

```text
WAVE 0 (parallel, start immediately)
  A01 rate limit
  A02 max body
  A03 admin.js gate
  A04 admin token chmod
  A05 plugin secret
  A07 docker healthcheck
  A08 pip-audit CI
  A09 docs TLS URLs
  B15 CONTRIBUTING

WAVE 1 (after Wave 0 merges; parallel)
  A06 LLM key encryption
  A10 HITL queue
  B01 DB migrations
  B05 deep health
  B06 JSON logging
  B08 config validation

WAVE 2 (depends Wave 1)
  A11 implant AEAD (HTTP)     [critical path]
  B02 listener restore
  B07 audit retention
  B04 backup/restore

WAVE 3
  A11b DNS/WS crypto (if split)
  B03 listener supervision
  B09 systemd + upgrade docs
  B16 threat model
  C01 HTTPS templates
  C02 kill date / max misses

WAVE 4 (refactors after security lands)
  B10 split routes
  B11 split listeners
  B12 split db
  B13 split cli
  B14 team RBAC

WAVE 5 (C2 depth)
  C03 profile transforms
  C05 file ops
  C06 native Linux beacon     [critical path]
  C08 audit integrity
  C09 lab e2e
  C10 redirector

WAVE 6
  C04 SOCKS
  C07 Windows beacon
  C11 runtime profile switch

WAVE 7 (OSS excellence)
  D01-D08

RELEASE
  tag 0.2.0 after Wave 2 (security+migrations baseline)
  tag 0.3.0 after Wave 4 (ops core + RBAC)
  tag 0.4.0 after C06 (native beacon)
  tag 1.0.0 when MVP-prod exit criteria met
```

## Agent operating procedure (this engagement)

For **each** Change ID:

1. `git checkout master && git pull origin master`
2. `git checkout -b <branch>`
3. Write failing tests.
4. Implement.
5. `pytest -q` and `ruff check src tests` (fix failures).
6. `git push -u origin <branch>`
7. `gh pr create` with summary + test plan.
8. Wait for CI; fix forward on same branch if red.
9. Merge via `gh pr merge` only when green (squash or repo default).
10. Mark Change ID done in this file in a tiny follow-up only if not updated in the feature PR.
11. Proceed to next ID (respect depends-on / waves).

**Do not** batch unrelated IDs into one PR.  
**Do not** push to `master` directly.  
**Do not** deploy feature-branch binaries to prod.

## Tracking table

| ID | Phase | Status | PR |
|----|-------|--------|-----|
| A01 | A | done | merged |
| A02 | A | done | merged |
| A03 | A | done | merged |
| A04 | A | done | merged |
| A05 | A | done | merged |
| A06 | A | pending | |
| A07 | A | done | merged |
| A08 | A | done | merged |
| A09 | A | done | merged |
| A10 | A | pending | |
| A11 | A | pending | |
| A11b | A | pending/optional | |
| B01 | B | pending | |
| B02 | B | pending | |
| B03 | B | pending | |
| B04 | B | pending | |
| B05 | B | pending | |
| B06 | B | pending | |
| B07 | B | pending | |
| B08 | B | pending | |
| B09 | B | pending | |
| B10 | B | pending | |
| B11 | B | pending | |
| B12 | B | pending | |
| B13 | B | pending | |
| B14 | B | pending | |
| B15 | B | in_progress | |
| B16 | B | pending | |
| C01 | C | pending | |
| C02 | C | pending | |
| C03 | C | pending | |
| C04 | C | pending | |
| C05 | C | pending | |
| C06 | C | pending | |
| C07 | C | pending | |
| C08 | C | pending | |
| C09 | C | pending | |
| C10 | C | pending | |
| C11 | C | pending | |
| D01 | D | pending | |
| D02 | D | pending | |
| D03 | D | pending | |
| D04 | D | pending | |
| D05 | D | pending | |
| D06 | D | pending | |
| D07 | D | pending | |
| D08 | D | pending | |

## Count

| Phase | Changes |
|-------|--------:|
| A | 12 (incl optional A11b) |
| B | 16 |
| C | 11 |
| D | 8 |
| **Total** | **~47 PR cycles** |

## Out of scope for this plan

- Unauthorized targeting or offensive use guidance beyond authorized lab harnesses.
- Weakening secure defaults for convenience.
- Direct commits to `master`.
- Prod deploy of non-`master` CI binaries.

---

*Plan created for full Phase A-D execution. Next action: start Wave 0 with A01 (or parallel Wave 0 set one-at-a-time per cycle).*
