# SquidC5 Deployment

## Docker (primary)

```bash
docker compose up --build -d
docker exec squidc5 cat /data/admin_token.txt   # once; store securely
curl -s http://127.0.0.1:8443/api/v1/health
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

- Size: `s-1vcpu-1gb` (practical minimum for Docker)
- Image: Ubuntu LTS + Docker
- Install path: `/opt/squidc5`
- Update: rsync tree + `docker compose up -d --build --force-recreate`
- SSH deploy key: use operator machine key already registered with DO (do not commit private keys)

Environment variables: see `.env.example` (`SQUIDC5_*`).

## Secrets hygiene

Never commit:

- `data/admin_token.txt`
- `data/*.db`
- `~/.config/squidc5/config.json`
- `.env` with real tokens
- LLM API keys

Rotate bootstrap admin token after first login by creating a new admin-scoped token and revoking the bootstrap id if desired.
