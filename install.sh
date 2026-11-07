#!/usr/bin/env bash
# lander installer for the VPS. Idempotent. Needs root for install/upgrade/uninstall.
#
#   curl -fsSL https://github.com/yogaagungk/lander/releases/latest/download/install.sh | sudo bash
#   curl -fsSL https://github.com/yogaagungk/lander/releases/latest/download/install.sh | sudo bash -s -- --version v1.0.0
#
# Usage: install.sh [install|upgrade|uninstall|status] [--version vX.Y.Z] [--dry-run] [--purge]
# Self-contained: installs nginx+certbot (apt) if missing and creates the 'lander' user, sudoers
# rule and certbot wrapper itself. It does not touch ufw, SSH, vhosts or certificates
# (orbit-suite/vps-bootstrap/bootstrap.sh remains the way to harden the host and add the TLS vhost).
# Env: LANDER_REPO (default yogaagungk/lander), LANDER_BASE_URL (override download base, for tests).
set -euo pipefail

REPO="${LANDER_REPO:-yogaagungk/lander}"
NAME=lander
BIN=/usr/local/bin/$NAME
ENV_DIR=/etc/$NAME
CMD=install VERSION=latest DRY=0 PURGE=0

log() { printf '[lander-install] %s\n' "$*"; }
die() { printf '[lander-install] ERROR: %s\n' "$*" >&2; exit 1; }
run() { if ((DRY)); then log "DRY-RUN: $*"; else "$@"; fi; }

while (($#)); do
  case "$1" in
    install|upgrade|uninstall|status) CMD=$1 ;;
    --version) VERSION=${2:?--version needs a value}; shift ;;
    --dry-run) DRY=1 ;;
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,11p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

VFILE=/usr/local/share/$NAME/VERSION
installed_version() { if [[ -x $BIN && -f $VFILE ]]; then cat "$VFILE"; fi; }  # the binary has no --version flag (it would start the server)

listen_addr() { local a; a=$(sed -n 's/^LANDER_LISTEN_ADDR=//p' "$ENV_DIR/$NAME.env" 2>/dev/null | tail -n1); echo "${a:-127.0.0.1:8080}"; }
# 200 = healthy, 503 = lander up but nginx inactive (still counts as running), 000 = unreachable.
health_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$(listen_addr)/healthz" 2>/dev/null || true; }

# Self-contained prerequisites (same owners/modes as orbit-suite vps-bootstrap, idempotent):
# packages nginx+certbot, group deploy, user lander, dirs, certbot wrapper, sudoers (visudo-checked).
# Does NOT touch ufw, SSH, the deploy user, vhosts or certificates.
ensure_prereqs() {
  local missing=()
  command -v nginx >/dev/null || missing+=(nginx)
  command -v certbot >/dev/null || missing+=(certbot python3-certbot-nginx)
  if ((${#missing[@]})); then
    command -v apt-get >/dev/null || die "missing ${missing[*]} and no apt-get: install nginx and certbot first"
    log "installing packages: ${missing[*]}"
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  fi
  [[ -x /usr/sbin/nginx || $DRY == 1 ]] || die "/usr/sbin/nginx not found (sudoers rule expects this path)"
  getent group deploy >/dev/null 2>&1 || run groupadd deploy
  id $NAME >/dev/null 2>&1 || run useradd --system --home-dir /var/lib/$NAME --shell /usr/sbin/nologin $NAME
  run usermod -aG deploy $NAME
  run install -d -m 0750 -o $NAME -g $NAME /var/lib/$NAME
  run install -d -m 0755 -o $NAME -g $NAME /var/log/$NAME
  run install -d -m 2750 -o $NAME -g deploy /var/lib/$NAME/env
  run install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled
  run chgrp $NAME /etc/nginx/sites-available /etc/nginx/sites-enabled
  run chmod 2775 /etc/nginx/sites-available /etc/nginx/sites-enabled

  local wrapper=/usr/local/sbin/lander-certbot sudoers=/etc/sudoers.d/lander tmp
  if ((DRY)); then log "DRY-RUN: write $wrapper (root 0755) and $sudoers (0440, visudo -c)"; return 0; fi
  cat >"$wrapper" <<'WRAP'
#!/usr/bin/env bash
# Root-owned wrapper: lander calls `sudo -n lander-certbot <domain> <email>`.
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: lander-certbot <domain> <email>" >&2; exit 2; }
domain="$1"; email="$2"
re_dom="^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
re_mail="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
[[ "$domain" =~ $re_dom && ${#domain} -le 253 ]] || { echo "invalid domain" >&2; exit 2; }
[[ "$email" =~ $re_mail && ${#email} -le 254 ]] || { echo "invalid email" >&2; exit 2; }
exec /usr/bin/certbot certonly --nginx -d "$domain" --non-interactive --agree-tos --email="$email" --keep-until-expiring
WRAP
  chown root:root "$wrapper"; chmod 0755 "$wrapper"
  tmp=$(mktemp)
  printf '%s\n' '# Managed by lander install.sh. No wildcards.' \
    "$NAME ALL=(root) NOPASSWD: /usr/sbin/nginx -t -c /etc/nginx/nginx.conf" \
    "$NAME ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx" \
    "$NAME ALL=(root) NOPASSWD: $wrapper" >"$tmp"
  if visudo -cf "$tmp" >/dev/null; then install -m 0440 -o root -g root "$tmp" "$sudoers"; rm -f "$tmp"
  else rm -f "$tmp"; die "generated sudoers failed visudo check"; fi
  # Let lander traverse letsencrypt live/archive if certbot already ran (private keys stay root-only).
  if [[ -d /etc/letsencrypt/live && -d /etc/letsencrypt/archive ]]; then
    chgrp $NAME /etc/letsencrypt/live /etc/letsencrypt/archive; chmod 750 /etc/letsencrypt/live /etc/letsencrypt/archive
    for k in /etc/letsencrypt/archive/*/privkey*.pem; do [[ -e $k ]] || continue; chown root:root "$k"; chmod 600 "$k"; done
  fi
  # Renewal hook keeps those permissions after each renewal.
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/lander-perms.sh <<'HOOK'
#!/bin/sh
chgrp lander /etc/letsencrypt/live /etc/letsencrypt/archive
chmod 750 /etc/letsencrypt/live /etc/letsencrypt/archive
for k in /etc/letsencrypt/archive/*/privkey*.pem; do
  [ -e "$k" ] || continue
  chown root:root "$k"
  chmod 600 "$k"
done
exit 0
HOOK
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/lander-perms.sh
}

if [[ $CMD == status ]]; then
  log "binary: $([[ -x $BIN ]] && echo "$BIN ($(installed_version))" || echo missing)"
  log "service: $(systemctl is-active $NAME 2>/dev/null || true) / enabled: $(systemctl is-enabled $NAME 2>/dev/null || true)"
  log "healthz: $(health_code) (200 ok, 503 nginx inactive, 000 unreachable) at $(listen_addr)"
  exit 0
fi

((DRY)) || [[ $EUID -eq 0 ]] || die "run as root (sudo)"

if [[ $CMD == uninstall ]]; then
  log "removing service and binary (env file and data kept unless --purge)"
  run systemctl disable --now $NAME 2>/dev/null || true
  run rm -rf /etc/systemd/system/$NAME.service $BIN "$BIN.prev" /usr/local/share/$NAME
  run systemctl daemon-reload
  if ((PURGE)); then run rm -rf "$ENV_DIR" /var/lib/$NAME /var/log/$NAME; else log "kept $ENV_DIR, /var/lib/$NAME, /var/log/$NAME"; fi
  exit 0
fi

# install / upgrade
for c in curl tar sha256sum uname systemctl; do command -v "$c" >/dev/null || die "missing command: $c"; done
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
[[ $(uname -s) == Linux ]] || die "Linux only"

if [[ $VERSION == latest ]]; then
  base="${LANDER_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
  VERSION=$(curl -fsSL --max-time 20 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null | sed 's#.*/##' || true)
else
  [[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || die "invalid version: $VERSION"
  base="${LANDER_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
fi
[[ $VERSION =~ ^v[0-9] ]] || VERSION=latest
ASSET="${NAME}_${VERSION#v}_linux_${ARCH}.tar.gz"
if [[ $VERSION == latest ]]; then die "could not resolve the latest version; pass --version vX.Y.Z"; fi

old=$(installed_version)
if [[ $CMD == upgrade || -n $old ]]; then log "installed: ${old:-none} -> target: $VERSION"; fi
[[ $CMD == upgrade && -z $old ]] && die "nothing installed; use install"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
log "downloading $ASSET ($VERSION, $ARCH)"
if ((DRY)); then
  log "DRY-RUN: would fetch $base/$ASSET and $base/checksums.txt, verify sha256, then install atomically to $BIN"
  ensure_prereqs
  log "DRY-RUN: would keep the previous binary as $BIN.prev and run deploy/install-systemd.sh from the tarball"
  exit 0
fi
curl -fsSL --retry 3 -o "$tmp/$ASSET" "$base/$ASSET"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt"
(cd "$tmp" && grep -F " $ASSET" checksums.txt | sha256sum -c -) || die "checksum verification failed; nothing installed"

mkdir "$tmp/x" && tar -xzf "$tmp/$ASSET" -C "$tmp/x"
[[ -f $tmp/x/$NAME && -f $tmp/x/deploy/install-systemd.sh ]] || die "unexpected tarball layout"

log "ensuring prerequisites (nginx, certbot, user $NAME, sudoers, certbot wrapper)"
ensure_prereqs

[[ -x $BIN ]] && cp -p "$BIN" "$BIN.prev"
install -m 0755 "$tmp/x/$NAME" "$BIN.new" && mv -f "$BIN.new" "$BIN"   # atomic replace

if ! (cd "$tmp/x/deploy" && sh ./install-systemd.sh); then
  if [[ -x $BIN.prev ]]; then log "unit install failed, restoring previous binary"; mv -f "$BIN.prev" "$BIN"; systemctl restart $NAME || true; fi
  die "install-systemd.sh failed"
fi

# Record the version as soon as the binary and unit are in place, even when the service is
# deliberately not started yet (token still a placeholder); otherwise status/upgrade lose track.
install -d -m 0755 "$(dirname "$VFILE")"; printf '%s\n' "$VERSION" > "$VFILE"

if systemctl is-active --quiet $NAME; then
  ok=0; for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ $(health_code) =~ ^(200|503)$ ]] && { ok=1; break; }; sleep 1
  done
  if ((ok)); then log "healthz ok: lander $VERSION running"
  else
    log "health check failed"
    if [[ -x $BIN.prev ]]; then log "rolling back to previous binary"; mv -f "$BIN.prev" "$BIN"; printf '%s\n' "$old" > "$VFILE"; systemctl restart $NAME || true; fi
    die "lander did not become healthy; see: journalctl -u $NAME"
  fi
else
  log "installed $VERSION but service not started: set LANDER_SECRET_TOKEN in $ENV_DIR/$NAME.env (openssl rand -hex 32), then: systemctl restart $NAME"
fi
