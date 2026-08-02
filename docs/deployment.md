# SquidC5 Deployment

Lab (Docker) and production (CI binary) deployment. For day-2 operator procedures see [operator-runbook.md](operator-runbook.md). For features see [user-guide.md](user-guide.md).

| Related | Link |
|---------|------|
| Docs index | [README.md](README.md) |
| Prod readiness | [prod-readiness-plan.md](prod-readiness-plan.md) |
| Threat model | [threat-model.md](threat-model.md) |
| Env template | [../.env.example](../.env.example) |

---

## Docker lab

### Context

Primary **lab** path. Compose defaults to `network_mode: host` so reverse-shell/TCP listeners bind real host ports without republishing each port.

### Configuration

- Image/build via `docker-compose.yml`
- Data volume → `/data` (tokens, DB, TLS) — never commit
- TLS on by default (self-signed)

### Commands

```bash
docker compose up --build -d
docker exec squidc5 cat /data/admin_token.txt   # once; store securely
curl -sk https://127.0.0.1:8443/api/v1/health
```

#### Host networking (default)

`network_mode: host` — process binds host ports directly. Trade-off: less isolation; fine for single-purpose C2 lab hosts.

#### Bridge networking alternative

If using bridge, publish every listener port you need:

```yaml
ports:
  - "8443:8443"
  - "443:443"
  - "4444:4444"
```

### Verify

```bash
curl -skf https://127.0.0.1:8443/api/v1/health
# Ops UI: https://127.0.0.1:8443/ops
```

### See also

- [Root README — Quick start (Docker)](../README.md#quick-start-docker-lab)
- [Privileged ports](#privileged-ports)

---

## Privileged ports

### Context

App user is non-root. Binding listeners on ports &lt; 1024 requires host capability.

### Configuration

```bash
sysctl -w net.ipv4.ip_unprivileged_port_start=0
echo "net.ipv4.ip_unprivileged_port_start=0" | sudo tee /etc/sysctl.d/99-squidc5.conf
```

### Commands

Apply sysctl, then start/restart SquidC5 and create low-port listeners.

### Verify

```bash
sc5 listeners create rev443 443 --kind reverse_shell
sc5 listeners start <id>
sc5 listeners list   # status running
```

### See also

- [User guide — Listeners](user-guide.md#listeners)
- [Firewall](#firewall)

---

## Firewall

### Context

Dedicated C2 lab host pattern: allow inbound so reverse-shell listener ports work without re-opening UFW each time. Only SSH + SquidC5 should listen publicly on a hardened prod host (tighten as required by your ROE).

### Configuration

Lab-permissive example:

```bash
ufw --force reset
ufw default allow incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw --force enable
```

### Commands

```bash
ss -tulnp | grep -v 127.0.0
```

Disable unused host services that might bind ports. DNS (`systemd-resolved`) on `127.0.0.53` only is fine.

### Verify

Public listeners are only expected services (sshd + squidc5).

### See also

- [OAST Collaborator](#oast-collaborator-dns-http-smtp) (ports 53/25/80/…)

---

## Cloud lab pattern

### Context

Typical single-droplet lab (any cloud). Paths below match common SquidC5 installs.

### Configuration

| Item | Suggested |
|------|-----------|
| Size | 1 vCPU / 1 GB RAM minimum |
| Image | Ubuntu LTS |
| Install path | `/opt/squidc5` |
| SSH | Operator key registered with provider — never commit private keys |
| Env | `SQUIDC5_*` from [.env.example](../.env.example) |

### Commands

Follow [Production binary deploy](#production-binary-only-deploy) or Docker lab on the droplet.

### Verify

```bash
curl -skf https://127.0.0.1:8443/api/v1/health
```

### See also

- [Production binary-only deploy](#production-binary-only-deploy)

---

## OAST Collaborator (DNS + HTTP + SMTP)

### Context

Authorized out-of-band interaction capture (Collaborator / Interactsh style). Values below are **illustrative** — use your own zone, host, and IP.

### Configuration

| Var | Example (replace) | Purpose |
|-----|-------------------|---------|
| `SQUIDC5_OAST_ZONE` | `oast.example.com` | Authoritative OAST zone |
| `SQUIDC5_PUBLIC_HOST` | `oast.example.com` | Hostnames in payload URLs |
| `SQUIDC5_PUBLIC_IP` | `203.0.113.10` | A-record answers for DNS OAST |
| `SQUIDC5_OAST_ENABLED` | `true` | Gate feature |
| `SQUIDC5_OAST_HTTP_PORT` | `80` | Port shown in HTTP payload URLs |

#### DNS delegation (subdomain only — do not change apex NS)

Example for `oast.example.com` → teamserver `203.0.113.10`:

| Type | Name | Data |
|------|------|------|
| A | ns1.oast | 203.0.113.10 (glue) |
| A | oast | 203.0.113.10 |
| NS | oast | ns1.oast.example.com |
| MX | oast | oast.example.com (priority 0) |

Leave apex `@` A (website) and apex NS (registrar) alone.

#### Firewall ports (teamserver)

Open at minimum for full OAST: **53/udp, 53/tcp, 25/tcp, 80/tcp, 443/tcp, 8443/tcp**.

Port 53 needs root or `ip_unprivileged_port_start=0`. Port 25 is often blocked by cloud providers — use 2525 for lab SMTP OAST if needed.

### Commands

```bash
# DNS OAST + beacon (mode both|oast|beacon)
sc5 --insecure listeners create oast-dns 53 --kind dns --zone oast.example.com --dns-mode both
sc5 --insecure listeners start <id>

# HTTP OAST catch-all
sc5 --insecure listeners create oast-http 80 --kind http
sc5 --insecure listeners start <id>

# SMTP OAST (enable feature first; never relays)
# PUT /api/v1/features {"features":{"smtp_oast":true}}
sc5 --insecure listeners create oast-smtp 25 --kind smtp
```

### Verify

```bash
sc5 --insecure login --url https://TEAM:8443 --token sc5_...
sc5 --insecure oast token create --note "xss"
# TOKEN=... from response
dig @8.8.8.8 "$TOKEN.oast.example.com" A
curl -sS "http://oast.example.com/$TOKEN/"
# optional: swaks --to "$TOKEN@oast.example.com" --server TEAM_IP
sc5 --insecure oast hits --token "$TOKEN"
```

CLI: global `--insecure` / config `verify_ssl: false` for self-signed API TLS.

### See also

- [User guide — OAST](user-guide.md#oast-collaborator)
- [Operator runbook — OAST](operator-runbook.md#oast-collaborator-http-dns-smtp)

---

## TLS (HTTPS) default on new instances

### Context

On first start, SquidC5 generates a **unique self-signed certificate** under the data dir and serves ops UI, REST API, and MCP over **HTTPS**.

```text
$SQUIDC5_DATA_DIR/tls/server.crt
$SQUIDC5_DATA_DIR/tls/server.key
$SQUIDC5_DATA_DIR/tls/instance_id
```

### Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `SQUIDC5_TLS_ENABLED` | `true` | Serve TLS |
| `SQUIDC5_TLS_CERT_FILE` / `SQUIDC5_TLS_KEY_FILE` | unset | Use auto paths under `data/tls/` |
| `SQUIDC5_TLS_FORCE_NEW` | `false` | Regenerate cert/key on next start |
| `SQUIDC5_PUBLIC_HOST` | empty | Added to cert SAN when set |

Browsers warn on self-signed certs — expected. For production, put a real cert on a redirector or override cert/key paths with CA-issued material. Ops **Admin → TLS certificate library** can upload/activate PEMs; **restart the process** after activate.

Disable only for lab debugging: `SQUIDC5_TLS_ENABLED=false` (plaintext — not recommended).

### Commands

```bash
curl -k https://127.0.0.1:8443/api/v1/health
# Ops: https://HOST:8443/ops  (accept warning)
```

### Verify

```bash
curl -skf https://127.0.0.1:8443/api/v1/health
openssl s_client -connect 127.0.0.1:8443 -servername HOST </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

### See also

- [User guide — TLS certificate library](user-guide.md#tls-certificate-library)
- [User guide — Security model](user-guide.md#security-model)
- [Production binary-only deploy](#production-binary-only-deploy)

---

## Production binary-only deploy

### Context

Prod is **not** updated from a local working tree or Docker rebuild of WIP.

Pipeline:

1. Open PR → CI tests must pass
2. Merge to `main` / `master`
3. Main CI builds standalone binaries (`sc5`, `squidc5`) and publishes a GitHub Release
4. Download **Linux `squidc5-linux-x64`** from that Release
5. Deploy **only that executable**; keep `data/` intact

**Forbidden on prod:** rsync of WIP source, `docker compose up --build` from dirty checkout, feature-branch-only binaries.

**Allowed:** install/restart main-built binary; preserve data dir; `SQUIDC5_*` env.

### Configuration

- Install dir e.g. `/opt/squidc5/bin/squidc5`
- Data dir e.g. `/opt/squidc5/data`
- Unit: [`packaging/squidc5.service`](../packaging/squidc5.service)

### Commands

#### First install

```bash
install -d /opt/squidc5/bin /opt/squidc5/data
install -m 755 squidc5-linux-x64 /opt/squidc5/bin/squidc5
cp packaging/squidc5.service /etc/systemd/system/squidc5.service
# Optional drop-ins: /etc/systemd/system/squidc5.service.d/*.conf
systemctl daemon-reload
systemctl enable --now squidc5
```

#### Binary upgrade (preserve data)

```bash
# 1. Download latest Linux squidc5 from GitHub Release (main CI)
# 2. Backup DB
sc5 backup /opt/squidc5/backups/pre-upgrade.db --data-dir /opt/squidc5/data

scp -i <key> squidc5-linux-x64 root@HOST:/opt/squidc5/bin/squidc5.new
ssh -i <key> root@HOST '
  set -e
  systemctl stop squidc5
  install -m 755 /opt/squidc5/bin/squidc5.new /opt/squidc5/bin/squidc5
  rm -f /opt/squidc5/bin/squidc5.new
  systemctl start squidc5
  curl -skf https://127.0.0.1:8443/api/v1/health
'
```

Listeners marked `running` are restored after restart. Prefer stopping via systemd (not operator `listeners stop`) when you want auto-restore.

#### Recommended prod env drop-ins

```ini
# /etc/systemd/system/squidc5.service.d/rate.conf
[Service]
Environment=SQUIDC5_RATE_LIMIT_PER_MINUTE=600
Environment=SQUIDC5_AUTH_FAIL_LIMIT_PER_MINUTE=60
```

```ini
# /etc/systemd/system/squidc5.service.d/tls.conf  (real certs)
[Service]
Environment=SQUIDC5_TLS_ENABLED=true
Environment=SQUIDC5_TLS_CERT_FILE=/etc/letsencrypt/live/HOST/fullchain.pem
Environment=SQUIDC5_TLS_KEY_FILE=/etc/letsencrypt/live/HOST/privkey.pem
```

### Verify

```bash
systemctl is-active squidc5
curl -skf https://127.0.0.1:8443/api/v1/health
```

### See also

- [AGENTS.md — Production deploy policy](../AGENTS.md)
- [Prod readiness](prod-readiness-plan.md)
- [Secrets hygiene](#secrets-hygiene)

---

## Secrets hygiene

### Context

Tokens, DB files, and API keys must never enter git or public artifacts.

### Configuration

Never commit:

- `data/admin_token.txt`
- `data/*.db`
- `data/tls/*.key`
- `~/.config/squidc5/config.json`
- `.env` with real tokens
- LLM API keys

### Commands

Rotate bootstrap admin token after first login by creating a new admin-scoped token and revoking the bootstrap id if desired.

```bash
sc5 tokens create admin2 --scopes "admin"
sc5 tokens revoke <bootstrap_id>
```

### Verify

```bash
git status   # no data/ or .env secrets
git check-ignore -v data/admin_token.txt
```

### See also

- [SECURITY.md](../SECURITY.md)
- [Threat model](threat-model.md)
- [.gitignore](../.gitignore)
