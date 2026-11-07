#!/bin/sh
# Install the lander systemd unit and env file. Idempotent. Run as root.
set -eu

UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
ENV_DIR="${ENV_DIR:-/etc/lander}"
ENV_FILE="$ENV_DIR/lander.env"
here="$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
id lander >/dev/null 2>&1 || { echo "user 'lander' missing: run vps-bootstrap with LANDER_DOMAIN first" >&2; exit 1; }
[ -x /usr/local/sbin/lander-certbot ] || { echo "warning: /usr/local/sbin/lander-certbot missing" >&2; }

install -d -m 0750 -o root -g root "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  install -m 0600 -o root -g root "$here/lander.env.example" "$ENV_FILE"
  echo "created $ENV_FILE: set LANDER_SECRET_TOKEN (openssl rand -hex 32)"
fi
install -m 0644 "$here/lander.service" "$UNIT_DIR/lander.service"
systemctl daemon-reload
systemctl enable lander

if grep -q '^LANDER_SECRET_TOKEN=replace-with' "$ENV_FILE"; then
  echo "LANDER_SECRET_TOKEN is still the placeholder: not starting. Edit $ENV_FILE then: systemctl restart lander"
else
  systemctl restart lander
  systemctl --no-pager --full status lander | head -n 5
fi
