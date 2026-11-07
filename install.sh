#!/usr/bin/env bash
# lander installer for the VPS. Idempotent. Needs root for install/upgrade/uninstall.
#
#   curl -fsSL https://github.com/yogaagungk/lander/releases/latest/download/install.sh | sudo bash
#   curl -fsSL https://github.com/yogaagungk/lander/releases/latest/download/install.sh | sudo bash -s -- --version v1.0.0
#
# Usage: install.sh [install|upgrade|uninstall|status] [--version vX.Y.Z] [--dry-run] [--purge]
# Prerequisite: orbit-suite/vps-bootstrap/bootstrap.sh with LANDER_DOMAIN (creates the
# 'lander' user, sudoers rule, nginx and the certbot wrapper).
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
  log "DRY-RUN: would keep the previous binary as $BIN.prev and run deploy/install-systemd.sh from the tarball"
  exit 0
fi
curl -fsSL --retry 3 -o "$tmp/$ASSET" "$base/$ASSET"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt"
(cd "$tmp" && grep -F " $ASSET" checksums.txt | sha256sum -c -) || die "checksum verification failed; nothing installed"

mkdir "$tmp/x" && tar -xzf "$tmp/$ASSET" -C "$tmp/x"
[[ -f $tmp/x/$NAME && -f $tmp/x/deploy/install-systemd.sh ]] || die "unexpected tarball layout"

# Prerequisite check before touching anything (same as deploy/install-systemd.sh).
id $NAME >/dev/null 2>&1 || die "user '$NAME' missing: run orbit-suite vps-bootstrap with LANDER_DOMAIN first"

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
