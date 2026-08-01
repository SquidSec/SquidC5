# SquidC5 Deployment

## Docker (primary)

```bash
docker compose up --build -d
docker exec squidc5 cat /data/admin_token.txt   # once; store securely
# TLS on by default (self-signed) — use -k for lab probes
curl -sk https://127.0.0.1:8443/api/v1/health
```

### Host networking (default in compose)

`network_mode: host` so TCP/reverse-shell listeners bind real host ports without listing each port in `ports:`.

Trade-off: less isolation; fine for single-purpose C2 droplets.

### Bridge networking alternative

If using bridge, publish every listener port:

```yaml
ports:
  - "8443:8443"
  - "443:443"
  - "4444:4444"
```

## Privileged ports

App user is non-root. For listeners on ports &lt; 1024:

```bash
sysctl -w net.ipv4.ip_unprivileged_port_start=0
echo "net.ipv4.ip_unprivileged_port_start=0" | sudo tee /etc/sysctl.d/99-squidc5.conf
```

## Firewall

Dedicated C2 lab droplet pattern: **allow all inbound** so any reverse-shell listener port works without re-opening UFW each time. Only SquidC5 + SSH should listen publicly.

```bash
ufw --force reset
ufw default allow incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw --force enable
```

Verify public listeners are only `sshd` + SquidC5 (`python`):

```bash
ss -tulnp | grep -v 127.0.0
```

Disable unused services that might bind ports (ModemManager, etc.) on the host. DNS (`systemd-resolved`) may listen on `127.0.0.53` only — that is fine.

## DigitalOcean lab pattern

- Size: `s-1vcpu-1gb` (practical minimum)
- Image: Ubuntu LTS
- Install path: `/opt/squidc5`
- SSH deploy key: use operator machine key already registered with DO (do not commit private keys)

Environment variables: see `.env.example` (`SQUIDC5_*`).

## OAST Collaborator (DNS + HTTP + SMTP)

Authorized out-of-band interaction capture (Burp Collaborator / Interactsh style).

### Env

| Var | Example | Purpose |
|-----|---------|---------|
| `SQUIDC5_OAST_ZONE` | `oast.squidoffense.com` | Authoritative OAST zone |
| `SQUIDC5_PUBLIC_HOST` | `oast.squidoffense.com` | Hostnames in payload URLs |
| `SQUIDC5_PUBLIC_IP` | `159.203.99.184` | A-record answers for DNS OAST |
| `SQUIDC5_OAST_ENABLED` | `true` | Gate feature |
| `SQUIDC5_OAST_HTTP_PORT` | `80` | Port shown in HTTP payload URLs |

### DNS delegation (subdomain only — do not change apex NS)

Example for `oast.squidoffense.com` → teamserver `159.203.99.184`:

| Type | Name | Data |
|------|------|------|
| A | ns1.oast | 159.203.99.184 (glue) |
| A | oast | 159.203.99.184 |
| NS | oast | ns1.oast.squidoffense.com |
| MX | oast | oast.squidoffense.com (priority 0) |

Leave apex `@` A (website) and apex NS (registrar) alone.

### Firewall ports (teamserver)

Open at minimum: **53/udp, 53/tcp, 25/tcp, 80/tcp, 443/tcp, 8443/tcp**.

Port 53 needs root or `ip_unprivileged_port_start=0`. Port 25 is often blocked by cloud providers — use 2525 for lab SMTP OAST if needed.

### Listeners

```bash
# DNS OAST + beacon (mode both|oast|beacon)
sc5 --insecure listeners create oast-dns 53 --kind dns --zone oast.squidoffense.com --dns-mode both
sc5 --insecure listeners start <id>

# HTTP OAST catch-all
sc5 --insecure listeners create oast-http 80 --kind http
sc5 --insecure listeners start <id>

# SMTP OAST (enable feature first; never relays)
# PUT /api/v1/features {"features":{"smtp_oast":true}}
sc5 --insecure listeners create oast-smtp 25 --kind smtp
```

### Operator verify

```bash
sc5 --insecure login --url https://159.203.99.184:8443 --token sc5_...
sc5 --insecure oast token create --note "xss"
# TOKEN=... from response
dig @8.8.8.8 $TOKEN.oast.squidoffense.com A
curl -sS "http://oast.squidoffense.com/$TOKEN/"
# swaks --to $TOKEN@oast.squidoffense.com --server 159.203.99.184
sc5 --insecure oast hits --token $TOKEN
```

CLI: global `--insecure` / config `verify_ssl: false` for self-signed API TLS.

## TLS (HTTPS) — default on new instances

On first start, SquidC5 generates a **unique self-signed certificate** under:

```text
$SQUIDC5_DATA_DIR/tls/server.crt
$SQUIDC5_DATA_DIR/tls/server.key
$SQUIDC5_DATA_DIR/tls/instance_id
```

All traffic on the process port (ops UI, REST API, MCP) is served over **HTTPS** via uvicorn.

| Env | Default | Meaning |
|-----|---------|---------|
| `SQUIDC5_TLS_ENABLED` | `true` | Serve TLS |
| `SQUIDC5_TLS_CERT_FILE` / `SQUIDC5_TLS_KEY_FILE` | unset | Use auto paths under `data/tls/` |
| `SQUIDC5_TLS_FORCE_NEW` | `false` | Regenerate cert/key on next start |
| `SQUIDC5_PUBLIC_HOST` | empty | Added to cert SAN when set |

Browsers will warn on self-signed certs — expected. For production, put a real cert on a redirector (see Redirector / cert plan in ops) or override cert/key paths with CA-issued material.

```bash
# After start
curl -k https://127.0.0.1:8443/api/v1/health
# Ops: https://HOST:8443/ops  (accept warning)
```

Disable only for lab debugging: `SQUIDC5_TLS_ENABLED=false` (plaintext — not recommended).

## Production: binary-only deploy (required)

Prod is **not** updated from a local working tree or Docker rebuild of WIP.

Pipeline:

1. Open PR → CI tests must pass  
2. Merge to `main` / `master`  
3. Main CI builds standalone binaries (`sc5`, `squidc5`)  
4. Download **Linux `squidc5`** from that Actions run’s artifacts  
5. Deploy **only that executable** to the droplet; keep `data/` intact  

```bash
scp -i <key> squidc5 root@<droplet>:/opt/squidc5/bin/squidc5.new
ssh -i <key> root@<droplet> '
  systemctl stop squidc5 || true
  install -m 755 /opt/squidc5/bin/squidc5.new /opt/squidc5/bin/squidc5
  systemctl start squidc5
'
```

Do **not** rsync source or `docker compose up --build` for production once this path is active. Docker remains for local/lab only.

## Secrets hygiene

Never commit:

- `data/admin_token.txt`
- `data/*.db`
- `~/.config/squidc5/config.json`
- `.env` with real tokens
- LLM API keys

Rotate bootstrap admin token after first login by creating a new admin-scoped token and revoking the bootstrap id if desired.
