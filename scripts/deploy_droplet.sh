#!/usr/bin/env bash
# Lab-only: rsync source + Docker Compose to a cloud VM.
# NOT for production. Prod = main CI squidc5 binary only (docs/deployment.md).
set -euo pipefail

DROPLET_IP="${1:?Usage: $0 <host-ip> [ssh-user]}"
SSH_USER="${2:-root}"
REMOTE_DIR="/opt/squidc5"

echo "==> [LAB] Deploying SquidC5 (Docker) to ${SSH_USER}@${DROPLET_IP}"

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
mkdir -p /opt/squidc5
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
echo "---- admin token (lab only; written once under data/) ----"
echo "(retrieve with: docker compose exec -T squidc5 cat /data/admin_token.txt)"
echo "---- health ----"
curl -skf https://127.0.0.1:8443/api/v1/health || curl -sf http://127.0.0.1:8443/api/v1/health || true
echo
REMOTE

echo "==> Lab deploy: https://${DROPLET_IP}:8443/ops"
echo "    Docs (GitHub): https://github.com/SquidSec/SquidC5/blob/master/docs/README.md"
echo "    Note: server has no public /docs or OpenAPI (by design)."
echo "    Prod path is binary-from-Release only — see docs/deployment.md"
