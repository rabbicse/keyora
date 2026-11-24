# Plain PHP example

A small notes API protected by Keyora, written in PHP with no framework and no Composer
packages. It shows the two things an application has to do:

- call Keyora's REST API from the server (register, login, refresh, logout, introspection);
- verify the access token (an RS256 JWT) locally and check its roles and permissions.

The JWT is verified by hand with the `openssl` extension, so you can see every step.
If you use Composer, a maintained library such as `firebase/php-jwt` does the same job;
the [Laravel example](../laravel) uses it.

| File | Purpose |
|---|---|
| `index.php` | Router script and the route handlers. |
| `src/Keyora.php` | HTTP client for Keyora's API, using HTTP Basic client credentials. |
| `src/Jwt.php` | Token verification: algorithm, signature, `exp`, `iss`, `aud`, `token_use`. |
| `src/Jwks.php` | Fetches and caches Keyora's public keys. |
| `src/Notes.php` | The application's own data (a JSON file). Unrelated to Keyora. |

## Prerequisites

- A running Keyora and the `examples/.env` file written by `examples/setup.sh`.
  See [examples/README.md](../../README.md) for both steps.
- Either Docker, or PHP 8.1 or newer with the `openssl`, `curl` and `json` extensions
  (check with `php -m`). APCu is used for the key cache when it is loaded; it is optional.

## Installation

There is nothing to install: no Composer packages, no build step.

With Docker, build the image from the repository root:

```sh
docker build -t keyora-example-php-plain examples/php/plain-php
```

## Configuration

The example reads its settings from environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where this application reaches Keyora (API calls and JWKS). |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | The `iss` value required in tokens. Must equal Keyora's own issuer setting. |
| `KEYORA_CLIENT_ID` | none, required | The application's client ID. Also the `aud` value required in tokens. |
| `KEYORA_CLIENT_SECRET` | none, required | The application's secret. Server-side only. |
| `PORT` | `9008` | Port to listen on (used by the Docker image; with a local PHP you pass the port to `php -S`). |
| `PHP_CLI_SERVER_WORKERS` | `4` in the Docker image | Number of worker processes of PHP's built-in server. Without it the server handles one request at a time. Not available on Windows. |

## How to run

### With Docker

Inside a container, `localhost` is the container itself, so Keyora on your machine is
reached at `host.docker.internal`. Tokens still say `iss = http://localhost:8080`, which
is why `KEYORA_ISSUER` is set separately. From the repository root:

```sh
docker run --rm --name keyora-example-php-plain -p 9008:9008 \
  --env-file examples/.env \
  -e KEYORA_URL=http://host.docker.internal:8080 \
  -e KEYORA_ISSUER=http://localhost:8080 \
  keyora-example-php-plain
```

On Linux, add `--add-host=host.docker.internal:host-gateway`.

Without building an image, the official PHP image can run the source directly:

```sh
docker run --rm --name keyora-example-php-plain -p 9008:9008 \
  --env-file examples/.env \
  -e KEYORA_URL=http://host.docker.internal:8080 \
  -e KEYORA_ISSUER=http://localhost:8080 \
  -e PHP_CLI_SERVER_WORKERS=4 \
  -v "$PWD/examples/php/plain-php:/app:ro" -w /app \
  php:8.3-cli php -S 0.0.0.0:9008 index.php
```

### With a local PHP

```sh
cd examples/php/plain-php
set -a; . ../../.env; set +a
php -S 0.0.0.0:9008 index.php
```

`php -S` is PHP's built-in development server. It is fine for trying the example; for
real use, put the same files behind PHP-FPM or another production server. If your web
server does not pass the `Authorization` header to PHP, see Troubleshooting.

### Check it

```sh
python3 examples/verify.py http://localhost:9008
```

It should end with `35 passed, 0 failed`.

## Example API requests

Register a user and sign in:

```sh
curl -s -X POST http://localhost:9008/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
```

```json
{"id":"20a1e13a-b10b-475b-bce3-5b74f9e5b39f","tenant_id":"9276cb35-e993-4b32-a25c-a52306b98780","email":"ada@example.com","name":"Ada","status":"active","email_verified":false,"created_at":"2026-11-23T15:14:30.369Z","updated_at":"2026-11-23T15:14:30.369Z"}
```

```sh
curl -s -X POST http://localhost:9008/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
```

```json
{"access_token":"eyJhbGciOiJS...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_sQZ_IKf3...","refresh_expires_in":2591999,"session_id":"0c21bb97-2906-4d22-a377-56951fe800da","user":{"id":"20a1e13a-...","email":"ada@example.com","name":"Ada","status":"active"}}
```

Keep the two tokens in shell variables for the next requests:

```sh
ACCESS=eyJhbGciOiJS...     # access_token from the login response
REFRESH=kyr_sQZ_IKf3...    # refresh_token from the login response
```

Call a protected endpoint. The token is verified locally:

```sh
curl -s http://localhost:9008/me -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"20a1e13a-b10b-475b-bce3-5b74f9e5b39f","email":"ada@example.com","roles":[],"permissions":[]}
```

A new user has no roles, so the permission check refuses the request with `403`:

```sh
curl -s http://localhost:9008/notes -H "Authorization: Bearer $ACCESS"
```

```json
{"error":{"code":"forbidden","message":"missing permission: notes:read"}}
```

Grant the `editor` role with Keyora's admin API (this call goes to Keyora, not to the
example; the IDs are in `examples/.env`, the user ID is `id` from the register response),
then refresh to get a token that contains the new role:

```sh
set -a; . examples/.env; set +a
curl -s -X PUT -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "http://localhost:8080/api/v1/tenants/$KEYORA_TENANT_ID/users/<user id>/roles/$KEYORA_EDITOR_ROLE_ID"

curl -s -X POST http://localhost:9008/refresh \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"
```

The refresh response has the same shape as the login response. Update `ACCESS` and
`REFRESH` from it (the old refresh token is now used up), then:

```sh
curl -s -X POST http://localhost:9008/notes -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"text":"buy milk"}'
```

```json
{"text":"buy milk","author":"ada@example.com"}
```

```sh
curl -s http://localhost:9008/notes -H "Authorization: Bearer $ACCESS"
curl -s http://localhost:9008/reports -H "Authorization: Bearer $ACCESS"
curl -s http://localhost:9008/me/live -H "Authorization: Bearer $ACCESS"
```

```json
{"notes":[{"text":"Welcome to Keyora","author":"system"},{"text":"buy milk","author":"ada@example.com"}]}
{"total_notes":2}
{"sub":"20a1e13a-b10b-475b-bce3-5b74f9e5b39f","email":"ada@example.com","roles":["editor","reader"],"permissions":["notes:read","notes:write"]}
```

(The last line was observed for a user who had been granted both the `reader` and the
`editor` role.)

Sign out. The answer is `204` with no body:

```sh
curl -s -i -X POST http://localhost:9008/logout \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"
```

```
HTTP/1.1 204 No Content
```

Error responses always have the same shape:

```sh
curl -s http://localhost:9008/me
curl -s http://localhost:9008/me -H 'Authorization: Bearer not-a-token'
curl -s -X POST http://localhost:9008/login -H 'Content-Type: application/json' \
  -d '{"email":"nobody@example.com","password":"wrong"}'
```

```json
{"error":{"code":"missing_token","message":"a bearer access token is required"}}
{"error":{"code":"invalid_token","message":"the access token is malformed"}}
{"error":{"code":"invalid_credentials","message":"invalid email or password"}}
```

After the access token's 60 seconds are over, `/me` answers `401` with code
`token_expired`; call `/refresh` to get a new one.

## How it works

**Calls that go to Keyora.** `/register`, `/login`, `/refresh` and `/logout` forward the
JSON body to `POST /api/v1/auth/...` on Keyora, adding the application's
`client_id:client_secret` as HTTP Basic credentials (`src/Keyora.php`). Keyora answers
with an envelope, `{"data": ...}` or `{"error": ...}`; the example returns the `data`
object on success and passes Keyora's status and error code through on failure.
`/me/live` sends the token to `POST /api/v1/auth/introspect` and trusts Keyora's answer;
`active: false` becomes `401 invalid_token`.

The client secret is the reason these calls are made from the server. Never put it in
JavaScript, a mobile app or anything else that is shipped to users. If you have no
server at all, register a `public` application in Keyora instead.

**Checks made locally.** `/me`, `/notes` and `/reports` do not call Keyora per request.
`src/Jwt.php` verifies the token itself:

1. The header's `alg` must be exactly `RS256`. The token does not get to choose.
2. The signature must verify against the JWKS key whose `kid` matches the header.
   The key is built from the JWK's `n` and `e` and checked with `openssl_verify`,
   whose result must be exactly `1`.
3. `exp` must be in the future.
4. `iss` must equal `KEYORA_ISSUER`.
5. `aud` must equal `KEYORA_CLIENT_ID`. Without this check, a token issued to any other
   application on the same Keyora would be accepted.
6. `token_use` must equal `access`. An OIDC ID token has the same issuer and audience as
   an access token; without this check it would be accepted as one.

Then the handler checks the token's `permissions` (all listed ones are required) or
`roles` (any listed one is enough) and answers `403 forbidden` if they are missing.

**Key cache.** The JWKS is fetched from `${KEYORA_URL}/.well-known/jwks.json` and cached
for five minutes: in APCu when that extension is loaded, otherwise in a file in the
system temp directory. If a token names a `kid` that is not in the cache, the keys are
fetched again (at most once every ten seconds), so a key rotation in Keyora needs no
restart. If Keyora is down, the cached keys keep being used.

**Local verification or introspection?** Local verification costs no network call but
only learns about a logout or a role change when the token expires or is refreshed.
Introspection sees both immediately and costs one call per request. Compare `/me` and
`/me/live` after a logout.

## Troubleshooting

**Every protected request answers `401 invalid_token`, although login works.** Look at
the `message`:

- `the access token has the wrong issuer`: `KEYORA_ISSUER` differs from the `iss` in the
  token. This is the usual result of running the example in a container: the example
  reaches Keyora at `http://host.docker.internal:8080`, but Keyora signs tokens with its
  own issuer, `http://localhost:8080`. `KEYORA_ISSUER` exists for this case. Set it to
  Keyora's issuer and leave `KEYORA_URL` at the address the container can reach.
- `the access token was issued to another application`: the token's `aud` is not this
  application's `KEYORA_CLIENT_ID`. The token came from a different application, or
  `examples/.env` is out of date (run `examples/setup.sh` again).

To see what a token contains, decode its middle part:

```sh
python3 -c 'import sys,base64; p=sys.argv[1].split(".")[1]; print(base64.urlsafe_b64decode(p+"="*(-len(p)%4)).decode())' "$ACCESS"
```

**`502 identity_unavailable`.** The example cannot reach Keyora at `KEYORA_URL`. The
server log shows the reason. Check that Keyora is running
(`curl http://localhost:8080/.well-known/jwks.json`). From a container, `localhost` does
not work; use `http://host.docker.internal:8080` (on Linux with
`--add-host=host.docker.internal:host-gateway`).

**`500 misconfigured`, or `401 invalid_client` from `/login`.** `KEYORA_CLIENT_ID` or
`KEYORA_CLIENT_SECRET` is missing or wrong. `examples/.env` is created by
`examples/setup.sh`; load it with `set -a; . examples/.env; set +a` or pass it to Docker
with `--env-file examples/.env`.

**`403 forbidden` on `/notes` or `/reports`.** The user has no role yet. Grant one with
the admin API, then call `/refresh` (roles are copied into the token when it is issued,
so the old token still has none):

```sh
curl -X PUT -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/<user id>/roles/$KEYORA_READER_ROLE_ID"
```

`reader` gives `notes:read`; `editor` gives `notes:read` and `notes:write` and satisfies `/reports`.

**`401 token_expired` sooner or later than expected, or `invalid_token` with
`the access token is not valid yet`.** The clocks of this machine and of Keyora
disagree. Synchronise them (NTP). If a small difference is unavoidable, raise `LEEWAY`
in `src/Jwt.php` by a few seconds; keep it small.

**`401 missing_token` although the header is sent.** Behind Apache with CGI/FastCGI the
`Authorization` header may not reach PHP. Add
`SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1` to the virtual host or `.htaccess`.
PHP's built-in server and the Docker image are not affected.

**Requests hang while another one is running.** PHP's built-in server handles one
request at a time. Set `PHP_CLI_SERVER_WORKERS=4` (the Docker image does).
