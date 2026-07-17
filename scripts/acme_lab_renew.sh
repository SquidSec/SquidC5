#!/usr/bin/env bash
# Lab ACME helper — authorized environments only. Does not commit secrets.
# Requires: certbot (or compatible), nginx/caddy already on the host.
set -euo pipefail

DOMAINS="${DOMAINS:-}"
EMAIL="${EMAIL:-admin@example.invalid}"
WEBROOT="${WEBROOT:-/var/www/html}"
CERT_DIR="${CERT_DIR:-/etc/letsencrypt/live}"

if [[ -z "$DOMAINS" ]]; then
  echo "Usage: DOMAINS=cdn.example.com,api.example.com EMAIL=you@example.com $0"
  echo "Optional: WEBROOT=/var/www/html"
  exit 1
fi

if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot not found. Install certbot first."
  exit 1
fi

IFS=',' read -r -a DOM_ARR <<< "$DOMAINS"
ARGS=()
for d in "${DOM_ARR[@]}"; do
  d="$(echo "$d" | xargs)"
  [[ -n "$d" ]] && ARGS+=(-d "$d")
done

echo "==> Requesting/renewing certs for: $DOMAINS"
certbot certonly --webroot -w "$WEBROOT" --email "$EMAIL" --agree-tos --non-interactive "${ARGS[@]}"

echo "==> Certs under $CERT_DIR (never commit private keys)"
echo "==> Next: update redirector ssl_certificate paths and reload nginx"
echo "    systemctl reload nginx"
echo "==> Then: update SQUIDC5_PUBLIC_HOST / profile host and regenerate implants"
