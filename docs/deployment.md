# SquidSeC2 Deployment

## Docker (primary)

```bash
docker compose up --build -d
docker exec squidsec2 cat /data/admin_token.txt   # once; store securely
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
echo "net.ipv4.ip_unprivileged_port_start=0" | sudo tee /etc/sysctl.d/99-squidsec2.conf
```

## Firewall

```bash
ufw allow OpenSSH
ufw allow 8443/tcp
# plus any reverse-shell / TCP listener ports
ufw allow 443/tcp
ufw --force enable
```

## DigitalOcean lab pattern

- Size: `s-1vcpu-1gb` (practical minimum for Docker)
- Image: Ubuntu LTS + Docker
- Install path: `/opt/squidsec2`
- Update: rsync tree + `docker compose up -d --build --force-recreate`
- SSH deploy key: use operator machine key already registered with DO (do not commit private keys)

Environment variables: see `.env.example` (`SQUIDSEC2_*`).

## Secrets hygiene

Never commit:

- `data/admin_token.txt`
- `data/*.db`
- `~/.config/squidsec2/config.json`
- `.env` with real tokens
- LLM API keys

Rotate bootstrap admin token after first login by creating a new admin-scoped token and revoking the bootstrap id if desired.
