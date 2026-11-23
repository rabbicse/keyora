# Deployment

## Choosing a setup

For experiments there is also an in-memory store (`KEYORA_DB_DRIVER=memory`), which
loses everything on exit.

| | SQLite | PostgreSQL (direct or through PgBouncer) |
|---|---|---|
| Moving parts | One binary, one data directory | Keyora plus a database server |
| Instances | Exactly one | One or more behind a load balancer |
| Backups | Copy a file | Your existing Postgres tooling |
| Fits | Small and medium installations, internal tools, edge | Anything needing redundancy or more than one instance |

Both use the same schema and pass the same storage test suite.

## Running it

### Binary

Build from a checkout (Go 1.26+ for the server binary):

```sh
make build                      # → bin/keyora, static, no cgo
set -a; . ./.env; set +a
./bin/keyora
```

A systemd unit:

```ini
[Unit]
Description=Keyora identity server
After=network-online.target

[Service]
User=keyora
EnvironmentFile=/etc/keyora/keyora.env
ExecStart=/usr/local/bin/keyora serve
Restart=on-failure
StateDirectory=keyora
WorkingDirectory=/var/lib/keyora
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/keyora

[Install]
WantedBy=multi-user.target
```

`/etc/keyora/keyora.env` should be readable only by root and the `keyora` user.

### Container

```sh
docker build -t keyora:0.1.0 --build-arg VERSION=0.1.0 .
docker run -d --name keyora -p 8080:8080 -v keyora-data:/data \
  -e KEYORA_ADMIN_KEY="$KEYORA_ADMIN_KEY" -e KEYORA_ISSUER=https://id.example.com keyora:0.1.0
```

The image is distroless, runs as a non-root user, keeps all state under `/data`, and
has a health check. Compose files: [`docker-compose.yml`](../docker-compose.yml)
(PostgreSQL) and [`deploy/docker-compose.sqlite.yml`](../deploy/docker-compose.sqlite.yml).

### Kubernetes probes

```yaml
livenessProbe:  { httpGet: { path: /livez,  port: 8080 } }
readinessProbe: { httpGet: { path: /readyz, port: 8080 } }
terminationGracePeriodSeconds: 30    # above KEYORA_SHUTDOWN_TIMEOUT (20s)
```

Mount the signing keys from a Secret at `KEYORA_KEYS_DIR`.

## Reverse proxy and TLS

Keyora speaks plain HTTP and expects a proxy to terminate TLS. Examples:
[`deploy/nginx.conf`](../deploy/nginx.conf), [`deploy/Caddyfile`](../deploy/Caddyfile).

1. Set `KEYORA_ISSUER` to the public `https://` URL. This also turns on HSTS.
2. Bind Keyora to localhost or a private network (`KEYORA_HTTP_ADDR=127.0.0.1:8080`).
3. Set `KEYORA_TRUST_PROXY_HEADERS=true` and make the proxy **overwrite**
   `X-Forwarded-For` with the address it saw. Keyora uses the right-most entry; if the
   proxy merely appends to a client-supplied header behind another hop, rate limiting
   and audit IPs can be wrong.
4. Block `/metrics` from the internet.

## Several instances

With PostgreSQL you can run any number of instances. They must share:

- the database;
- **the same signing keys** — distribute `KEYORA_KEYS_DIR` to every instance (a
  read-only secret mount works well). Keyora generates a key only when the directory
  is empty, so provision keys before first start to avoid each instance inventing its
  own;
- the same `KEYORA_ISSUER` and `KEYORA_ADMIN_KEY`.

Migrations take a PostgreSQL advisory lock, so instances starting together do not race.
The rate limiter is per instance.

## PostgreSQL behind PgBouncer

Keyora works through PgBouncer in **transaction pooling** mode, which lets many Keyora
connections share a small number of PostgreSQL connections. Point the DSN at PgBouncer
and set one flag:

```sh
KEYORA_DB_DRIVER=postgres
KEYORA_DB_DSN=postgres://keyora:…@pgbouncer:6432/keyora
KEYORA_DB_PGBOUNCER=true
```

A complete stack is in [`deploy/docker-compose.pgbouncer.yml`](../deploy/docker-compose.pgbouncer.yml).

What the flag changes, and why it is needed: in transaction mode two consecutive
statements can run on different PostgreSQL connections, so nothing may depend on
session state.

| Session feature | Keyora |
|---|---|
| Named prepared statements | Not used when `KEYORA_DB_PGBOUNCER=true`. Parameters are still bound, never interpolated. |
| Session advisory locks | Not used. Migrations take a transaction-level lock inside one transaction. |
| `SET`, temporary tables, `LISTEN` | Never used. |
| Multi-statement transactions | Used, and safe: PgBouncer pins a connection for the duration of a transaction. |

Without the flag, expect errors such as `prepared statement "stmtcache_…" already
exists`. PgBouncer 1.21+ can track prepared statements itself
(`max_prepared_statements`); the flag makes Keyora independent of that setting and of
the pooler's version.

Sizing: `KEYORA_DB_MAX_OPEN_CONNS` may exceed PgBouncer's `default_pool_size`; it must
stay within `max_client_conn` across all Keyora instances. The storage test suite runs
through PgBouncer with prepared-statement support disabled and more client connections
than server connections.

## Signing keys

Losing the keys invalidates every access token in circulation (sessions survive:
clients refresh and get tokens signed by the new key). Leaking them lets an attacker
mint tokens for any user of any tenant. Back them up, and restrict who can read them.

Rotate:

```sh
keyora keygen           # adds <UTC timestamp>.pem; the newest name signs
# distribute the new file to every instance, then restart them
```

Old keys remain in the JWKS, so existing tokens keep verifying. Verifiers pick up the
new key when they meet its `kid`. Remove an old key file only after your longest
access-token lifetime has elapsed since the rotation.

If a key is compromised: generate a new one, **delete** the compromised file, restart.
Tokens signed with it stop verifying as soon as verifiers refresh their JWKS cache
(up to five minutes with the default cache headers).

## Secrets

| Secret | Where it should live |
|---|---|
| `KEYORA_ADMIN_KEY` | Secret manager or orchestrator secret, injected as an environment variable. |
| Database password (in `KEYORA_DB_DSN`) | Same. |
| `KEYORA_SMTP_PASSWORD` | Same. |
| Signing keys | A mounted secret or an encrypted volume. |
| Application client secrets | In each application's own secret store. Keyora cannot show them again. |

Do not bake any of these into images or commit them. `.env` files are for development.
To rotate the admin key, restart with a new value; the old one stops working at once.

## Upgrades and migrations

Migrations are embedded in the binary, numbered, and **forward-only**; there are no
down migrations.

1. Back up the database.
2. Read the changelog for the versions you are crossing.
3. Either start the new version (it migrates on startup), or run `keyora migrate`
   first with `KEYORA_AUTO_MIGRATE=false`.

To roll back a release that migrated the schema, restore the backup.

## Backup and restore

Back up two things together: **the database** and **the signing keys**.

**SQLite.** The database runs in WAL mode, so do not copy the file while Keyora is
running unless you use SQLite's online backup:

```sh
sqlite3 /var/lib/keyora/data/keyora.db ".backup '/backups/keyora-$(date +%F).db'"
tar -czf /backups/keyora-keys-$(date +%F).tar.gz -C /var/lib/keyora/data keys
```

Or stop Keyora and copy `keyora.db`, `keyora.db-wal` and `keyora.db-shm` together.

**PostgreSQL.**

```sh
pg_dump --format=custom --file=keyora-$(date +%F).dump "$DATABASE_URL"
pg_restore --clean --if-exists --dbname="$DATABASE_URL" keyora-2026-11-23.dump
```

Use continuous archiving for point-in-time recovery if you need it.

**Restore.** Stop Keyora, restore the database and the keys directory, start Keyora.
Sessions created after the backup are gone, so those users sign in again. If you
restore the database but not the keys, sign-in works and all previously issued access
tokens fail until clients refresh.

Encrypt backups: they contain personal data, and the key archive is a master
credential. Test a restore before you need one.

## Monitoring

- **Probes:** `/livez` (process up), `/readyz` (database reachable).
- **Metrics** at `/metrics`: `keyora_http_requests_total{method,route,status}`,
  `keyora_http_request_duration_seconds` (histogram), `keyora_uptime_seconds`.
- **Logs:** one JSON line per request with `request_id`, `route`, `status`,
  `duration_ms`, `ip`.

Worth alerting on: 5xx rate, `/readyz` failing, a rise in `401`/`423`/`429` on
`/api/v1/auth/login` (credential stuffing), and the audit events
`token.reuse_detected` and `user.locked`.

Expired tokens and sessions are purged hourly by the server itself.

## Sizing note

Each login computes one PBKDF2 hash (600,000 iterations), which is deliberately
expensive — tens to a few hundred milliseconds of one CPU core, depending on hardware.
Login throughput is therefore bounded by CPU: roughly cores divided by that time.
Token verification, refresh and everything else are cheap by comparison. Measure on
your own hardware before sizing; no load testing has been published for this release.
