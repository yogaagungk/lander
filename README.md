# lander

ORBIT Suite VPS daemon: manages Nginx virtual hosts, certificates and app env
files behind a local, bearer-token-authenticated REST API. Standalone: it
needs no other ORBIT tool to function.

Status: L1 scaffold, L2 Nginx service (rendering, strict validation, atomic
apply with rollback, reload) and L3 HTTP API (bearer auth, rate limit, sites,
validate, SSL, env, stats). systemd packaging is finalized by Palugada in L4.

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
| `LANDER_SUDO` | `false` | Prefix privileged commands with `sudo -n`; the unit sets `true` |
| `LANDER_TRUSTED_PROXY` | `false` | Trust X-Forwarded-For/X-Real-IP only when the peer is loopback |
| `LANDER_ENV_DIR` | `/var/lib/lander/env` | App env files |

## API

All `/api/v1/*` routes need `Authorization: Bearer <LANDER_SECRET_TOKEN>`.
Errors use `{"error":{"code","message","request_id"}}`; validation errors add
`issues`. Ten failed auth attempts per IP and minute return 429 with
`Retry-After`. Request ids are echoed in `X-Request-Id`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | Liveness (no auth, 503 when nginx is down) |
| GET | `/api/v1/system/stats` | CPU, memory, nginx, uptime |
| GET | `/api/v1/nginx/sites` | Managed site summaries |
| GET | `/api/v1/nginx/site?domain=` | Structured + raw config and ETag |
| POST | `/api/v1/nginx/site` | Upsert (honours `If-Match`; 409 on stale) |
| DELETE | `/api/v1/nginx/site?domain=` | Remove site and reload |
| POST | `/api/v1/nginx/validate` | Dry-run `nginx -t` (advisory) |
| POST | `/api/v1/nginx/ssl` | Issue/renew via certbot |
| POST | `/api/v1/env` | Write-only app env (merge/replace) |

`POST /nginx/site` is idempotent: identical content returns 200 with
`changed:false`, a new site returns 201. `GET` returns the stored file as
`raw_config`; `ETag` is its sha256, so houston can POST it back with the same
`If-Match`.

SSL is a two-step flow: `POST /nginx/ssl` issues the certificate, then re-post
the site with `enable_ssl:true` so the generator adds the 443 block. certbot
runs as `certonly --nginx`, so it never rewrites the managed vhost.

`POST /api/v1/env` accepts `merge` (default) or `replace`, validates key names,
never returns or logs values, and writes `0640` files under `LANDER_ENV_DIR`.

## Safety model (ADR-002)

- No shell: `os/exec` with fixed binaries and argument slices only.
- Input is rejected, never repaired: RFC-1123 domains, validated proxy
  targets (loopback/RFC1918 by default; no link-local or metadata ranges),
  web roots under the base directory with symlink-escape checks, strict
  allow-lists for `custom_rules` and `raw_config` (parsed with an Nginx-style
  tokenizer), structural checks (one server block, exact `server_name`) and
  `nginx -t`.
- Dry-run validation wraps the candidate in a temporary config and is
  advisory only; cross-file references such as shared `limit_req` zones are
  checked by the real apply.
- Apply pipeline: render → temp file → backup → rename → symlink →
  `nginx -t` → `systemctl reload nginx`. Any failure restores the previous
  file and symlink, so a rejected config leaves the system unchanged.
- Files lander did not create (no `# Managed by lander` marker) are never
  overwritten or deleted.
- Per-domain locks plus a global lock held from the file swap through
  `nginx -t` and reload.
- Privileged commands go through `sudo -n` when `LANDER_SUDO=true` (set by
  the unit); the sudoers drop-in allows only the exact forms lander uses.

## Privileges and filesystem (L4 packaging)

- Never use wildcard certbot sudoers. A `certbot ... -d *` entry also matches
  extra arguments such as `--pre-hook` or `--deploy-hook`, giving root code
  execution. Install a root-owned wrapper `/usr/local/sbin/lander-certbot
  <domain> <email>` that re-validates both arguments against the same regexes
  and execs certbot with fixed flags; name the wrapper in sudoers with no
  wildcards.
- certbot runs as root, so `/etc/letsencrypt/live` and `archive` are `0700`
  and unreadable by `lander`. Then `CertExists`/cert expiry stay false and the
  443 block is never rendered. Grant group read (for example `chgrp lander`,
  `chmod 750`, re-applied by a certbot deploy-hook) or add a privileged
  cert-status helper. The L4 smoke test must show a 443 block and
  `expires_at` after issuance.
- `/var/lib/lander/env` needs group `deploy` and the setgid bit; the `lander`
  user must be in `deploy` so the `0640` env files are group-readable by the
  deploy user.
- The nginx vhost in front of lander should set `X-Forwarded-For`; enable
  `LANDER_TRUSTED_PROXY` so the auth rate limit sees per-client addresses
  instead of only `127.0.0.1`.

## Layout

```text
cmd/lander            entrypoint and graceful shutdown
internal/config       environment parsing and validation
internal/domain       API structs
internal/handler      HTTP API, bearer auth, rate limiting, errors
internal/service      Nginx rendering, validation, apply/rollback
deploy/               provisional systemd unit and env example
openapi.yaml          API contract (copied from the suite docs)
```
