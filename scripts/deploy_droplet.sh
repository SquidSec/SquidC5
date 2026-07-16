#!/usr/bin/env bash
# Deploy SquidSeC2 to a DigitalOcean droplet (Docker)
set -euo pipefail

DROPLET_IP="${1:?Usage: $0 <droplet-ip> [ssh-user]}"
SSH_USER="${2:-root}"
REMOTE_DIR="/opt/squidsec2"

echo "==> Deploying SquidSeC2 to ${SSH_USER}@${DROPLET_IP}"

ssh -o StrictHostKeyChecking=accept-new "${SSH_USER}@${DROPLET_IP}" bash -s <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi
# docker compose plugin
if ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq docker-compose-plugin || true
fi
mkdir -p /opt/squidsec2
ufw allow OpenSSH || true
ufw allow 8443/tcp || true
ufw --force enable || true
REMOTE

rsync -az --delete \
  --exclude '.venv' \
  --exclude 'data' \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '.pytest_cache' \
  ./ "${SSH_USER}@${DROPLET_IP}:${REMOTE_DIR}/"

ssh "${SSH_USER}@${DROPLET_IP}" bash -s <<REMOTE
set -euo pipefail
cd ${REMOTE_DIR}
docker compose down || true
docker compose up --build -d
sleep 5
docker compose ps
echo "---- admin token ----"
docker compose exec -T squidsec2 cat /data/admin_token.txt || \
  docker exec squidsec2 cat /data/admin_token.txt
echo "---- health ----"
curl -sf http://127.0.0.1:8443/api/v1/health
echo
REMOTE

echo "==> Deployed: http://${DROPLET_IP}:8443"
echo "    Docs:     http://${DROPLET_IP}:8443/docs"
