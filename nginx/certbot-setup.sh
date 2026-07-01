#!/usr/bin/env bash
# One-time setup: obtain Let's Encrypt certificate for the Byzantium gateway.
# Run this BEFORE starting nginx in production.
# Usage: DOMAIN=api.yourdomain.com EMAIL=admin@yourdomain.com bash nginx/certbot-setup.sh

set -euo pipefail

DOMAIN="${DOMAIN:?Set DOMAIN=api.yourdomain.com}"
EMAIL="${EMAIL:?Set EMAIL=admin@yourdomain.com}"

echo "Obtaining Let's Encrypt certificate for $DOMAIN..."

# Install certbot if not present
if ! command -v certbot &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx
fi

# Obtain certificate (standalone mode — nginx must be stopped first)
certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN"

echo "Certificate obtained. Files at:"
echo "  /etc/letsencrypt/live/$DOMAIN/fullchain.pem"
echo "  /etc/letsencrypt/live/$DOMAIN/privkey.pem"
echo ""
echo "Update nginx/nginx.conf ssl_certificate paths to point to these files."
echo "Then start nginx: docker compose up -d"
echo ""
echo "Auto-renewal is handled by certbot's systemd timer (certbot.timer)."
echo "Verify with: systemctl status certbot.timer"
