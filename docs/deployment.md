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

- Size: `s-1vcpu-1gb` (practical minimum)
- Image: Ubuntu LTS
- Install path: `/opt/squidc5`
- SSH deploy key: use operator machine key already registered with DO (do not commit private keys)

Environment variables: see `.env.example` (`SQUIDC5_*`).

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
