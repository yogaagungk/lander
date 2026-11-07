# lander

ORBIT Suite VPS daemon: manages Nginx virtual hosts, certificates and app env
files behind a local, bearer-token-authenticated REST API. Standalone: it
needs no other ORBIT tool to function.

Status: L1 scaffold + L2 Nginx service (template rendering, validation,
atomic apply with rollback, reload). HTTP site routes, SSL, env and stats are
L3; systemd packaging is finalized by Palugada in L4.

## Requirements

- Go 1.22+ (repo is pinned to the toolchain in `go.mod`)
- nginx, certbot and systemd on the target host
- A dedicated `lander` user, group-write access to the Nginx site
  directories, and a sudoers drop-in for the exact privileged commands
  (ADR-002; installed in L4)

## Build and test

```sh
make build          # bin/lander
make test           # go test -race ./...
make vet
make lint           # golangci-lint
make install-systemd  # binary + provisional systemd unit (run as root)
```

## Configuration

Configuration comes from environment variables; see
`deploy/lander.env.example`. `LANDER_SECRET_TOKEN` is required and must be at
least 32 bytes. The daemon refuses to start with a weak or missing token.

The default listener is `127.0.0.1:8080`. Expose it only through a TLS Nginx
vhost or an SSH tunnel (ADR-002).

| Variable | Default | Purpose |
| --- | --- | --- |
| `LANDER_SECRET_TOKEN` | — (required) | Bearer token, ≥32 bytes |
| `LANDER_LISTEN_ADDR` | `127.0.0.1:8080` | HTTP listen address |
| `LANDER_SITES_AVAILABLE` | `/etc/nginx/sites-available` | Managed configs |
| `LANDER_SITES_ENABLED` | `/etc/nginx/sites-enabled` | Symlinks |
| `LANDER_NGINX_CONF` | `/etc/nginx/nginx.conf` | Passed to `nginx -t -c` |
| `LANDER_WEB_ROOT_BASE` | `/var/www` | Allowed static roots |
| `LANDER_ALLOW_PUBLIC_UPSTREAM` | `false` | Permit public `proxy_target` hosts |
| `LANDER_ENV_DIR` | `/var/lib/lander/env` | App env files (L3) |

## Safety model (ADR-002)

- No shell: `os/exec` with fixed binaries and argument slices only.
- Input is rejected, never repaired: RFC-1123 domains, validated proxy
  targets (loopback/private by default), web roots under the base directory
  with symlink-escape checks, an allow-list for `custom_rules`, and a
  denylist+`server_name` check for `raw_config`.
- Apply pipeline: render → temp file → backup → rename → symlink →
  `nginx -t` → `systemctl reload nginx`. Any failure restores the previous
  file and symlink, so a rejected config leaves the system unchanged.
- Files lander did not create (no `# Managed by lander` marker) are never
  overwritten or deleted.
- Per-domain locks plus a global lock around `nginx -t`/reload.

## Layout

```text
cmd/lander            entrypoint and graceful shutdown
internal/config       environment parsing and validation
internal/domain       API structs
internal/handler      HTTP handlers (healthz in L1)
internal/service      Nginx rendering, validation, apply/rollback
deploy/               provisional systemd unit and env example
openapi.yaml          API contract (copied from the suite docs)
```
