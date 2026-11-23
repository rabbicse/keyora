# Keyora example: TypeScript script with built-in fetch

A single command-line script that walks through the whole [Keyora](../../../README.md)
flow and prints every HTTP request and response: register, log in, verify the access
token by hand, call a protected endpoint, refresh, trigger refresh-token reuse detection,
log out and introspect.

It is meant for reading. If you want to see exactly which calls an application makes and
what a correct token verification consists of, without a framework or a JWT library in
the way, read [`src/main.ts`](src/main.ts) next to its output.

About the name: the directory is called `node-fetch` for the concept, a Node program that
talks to Keyora with `fetch`. The script uses the `fetch` that is built into Node.js. It
does not use the `node-fetch` npm package, and it has no runtime dependencies at all;
signature verification uses the built-in `node:crypto` module.

This is a script, not a server: it listens on no port and `examples/verify.py` does not
apply to it. The script checks its own results and exits with status 0 only if every
step behaved as documented.

## Prerequisites

- Node.js 20 or newer (developed and tested with Node 26) and npm.
- A running Keyora. The commands below assume `http://localhost:8080`.
- `examples/.env`, written by `examples/setup.sh`. See
  [`examples/README.md`](../../README.md#run-an-example).

## Installation

```sh
cd examples/typescript/node-fetch
npm install
```

This installs development tools only: `typescript`, `tsx` (runs the `.ts` file directly)
and `@types/node`.

## Configuration

Settings come from environment variables. The script does not read `.env` files itself,
so load `examples/.env` into your shell first.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `KEYORA_URL` | no | `http://localhost:8080` | Where the script reaches Keyora, for API calls and for the JWKS. |
| `KEYORA_ISSUER` | no | value of `KEYORA_URL` | The `iss` claim to require in access tokens. Must equal the `KEYORA_ISSUER` that Keyora itself runs with. |
| `KEYORA_CLIENT_ID` | yes | | The application's client ID. Also the `aud` claim to require in access tokens. |
| `KEYORA_CLIENT_SECRET` | yes | | The application's secret. |

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a
cd examples/typescript/node-fetch
npm start
```

Each run registers a new user with a random address
(`walkthrough-<random>@example.com`) and a random password, so it can be repeated. The
users stay in the examples tenant.

`npm run typecheck` type-checks the script without running it.

The exit status is `0` when all steps behaved as expected and `1` otherwise, so the
script can serve as a smoke test: `npm start && echo ok`.

## Example API requests

The script prints each request as `>` and each response as `<`. Tokens and passwords are
shortened in the output. These are the same calls written as `curl` commands, in the
order the script makes them, followed by the output of a real run.

```sh
# 1. Register. The application authenticates with HTTP Basic: client_id:client_secret.
curl -s -X POST "$KEYORA_URL/api/v1/auth/register" \
  -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada Lovelace"}'

# 2. Log in. The answer contains access_token and refresh_token.
curl -s -X POST "$KEYORA_URL/api/v1/auth/login" \
  -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'

# 3. The public keys used to verify the access token. No credentials needed.
curl -s "$KEYORA_URL/.well-known/jwks.json"

# 4. A protected Keyora endpoint, called as the user.
curl -s "$KEYORA_URL/api/v1/users/me" -H "Authorization: Bearer $ACCESS"

# 6. Refresh. Returns a new access token and a new refresh token.
# 7. Sending the same refresh token a second time answers 401 refresh_token_reused.
curl -s -X POST "$KEYORA_URL/api/v1/auth/refresh" \
  -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"

# 9. Log out. Answers 204 with no body.
curl -s -X POST "$KEYORA_URL/api/v1/auth/logout" \
  -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"

# 8, 10, 11. Introspection: ask Keyora whether a token is valid right now.
curl -s -X POST "$KEYORA_URL/api/v1/auth/introspect" \
  -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ACCESS\"}"
```

Called directly, Keyora wraps every answer in an envelope, `{"data": {...}, "meta":
{"request_id": "..."}}` on success and `{"error": {"code": "...", "message": "..."},
"meta": {...}}` on failure. The script prints the `data` or `error` part.

### Expected responses

Output of `npm start`, with long lines trimmed (`...`):

```
Keyora at http://localhost:8080 (issuer http://localhost:8080), application app_ba6ba87721084f8db75a7cf017cc6b63

1. Register a user
  The application authenticates with its client_id and client_secret (HTTP Basic).
  > POST /api/v1/auth/register  [Authorization: Basic client_id:client_secret]
    {"email":"walkthrough-1a8158c6f443@example.com","password":"***","name":"Walkthrough User"}
  < 201 {"id":"e4e8f834-2389-416d-a96d-f6cab81813c8","tenant_id":"9276cb35-...","email":"walkthrough-1a8158c6f443@example.com","name":"Walkthrough User","status":"active","email_verified":false,...}
  ok: Keyora answered 201

2. Log in
  > POST /api/v1/auth/login  [Authorization: Basic client_id:client_secret]
    {"email":"walkthrough-1a8158c6f443@example.com","password":"***"}
  < 200 {"access_token":"eyJhbGciOiJSUzI1...(1124 chars)","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_IxXlMDWBWU4C...(47 chars)","refresh_expires_in":2591999,"session_id":"5cdd6709-...","user":{...}}
  ok: Keyora answered 200
  The access token is an RS256 JWT valid for 60s; the refresh token is opaque and single-use.

3. Verify the access token locally
  Checks: alg is RS256, signature against the JWKS key named by kid, exp, iss, aud.
  > GET /.well-known/jwks.json
  < 200 1 RSA key(s): kid=20261123T150337Z
  claims: {
    "iss": "http://localhost:8080",
    "sub": "e4e8f834-2389-416d-a96d-f6cab81813c8",
    "aud": "app_ba6ba87721084f8db75a7cf017cc6b63",
    "exp": 1795446765,
    "nbf": 1795446705,
    "iat": 1795446705,
    "jti": "e9ddc4b0-3f60-4ea2-9262-6496983e464d",
    "sid": "5cdd6709-a164-4a67-98c1-99057f51e8a0",
    "tid": "9276cb35-e993-4b32-a25c-a52306b98780",
    "client_id": "app_ba6ba87721084f8db75a7cf017cc6b63",
    "email": "walkthrough-1a8158c6f443@example.com"
  }
  ok: sub is the ID of the user registered in step 1
  ok: email is the address that logged in
  A second verification used the cached key: no request to Keyora was made.

4. Call a protected Keyora endpoint with the access token
  > GET /api/v1/users/me  [Authorization: Bearer <token>]
  < 200 {"id":"e4e8f834-2389-416d-a96d-f6cab81813c8",...,"email":"walkthrough-1a8158c6f443@example.com",...,"roles":[],"permissions":[]}
  ok: Keyora answered 200
  ok: Keyora returns the profile of the token's user

5. Tampered tokens are rejected locally
  a) Payload edited to add an admin role, original signature kept:
  ok: the edited token is rejected locally: the signature does not verify
  b) Header changed to "alg":"none" and the signature removed:
  ok: the unsigned token is rejected locally: unexpected algorithm "none", only RS256 is accepted
  c) One character of the signature changed:
  ok: the token with a damaged signature is rejected locally: the signature does not verify
  d) The genuine token, checked as if the clock were two hours ahead:
  ok: the expired token is rejected locally: the token expired 7140s ago

6. Refresh (token rotation)
  > POST /api/v1/auth/refresh  [Authorization: Basic client_id:client_secret]
    {"refresh_token":"kyr_IxXlMDWBWU4C...(47 chars)"}
  < 200 {"access_token":"eyJhbGciOiJSUzI1...(1124 chars)","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_GfC154UJkGGh...(47 chars)","refresh_expires_in":2591999,"session_id":"5cdd6709-..."}
  ok: Keyora answered 200
  ok: a new refresh token was issued; the old one is now spent
  ok: the new access token verifies locally

7. Replay the old refresh token
  A refresh token works once. Seeing it a second time means two parties hold it,
  so Keyora treats it as stolen and revokes the whole session.
  > POST /api/v1/auth/refresh  [Authorization: Basic client_id:client_secret]
    {"refresh_token":"kyr_IxXlMDWBWU4C...(47 chars)"}
  < 401 {"code":"refresh_token_reused","message":"refresh token was already used; the session has been revoked"}
  ok: Keyora answered 401 refresh_token_reused
  The session is revoked: the refresh token issued in step 6 no longer works either.
  > POST /api/v1/auth/refresh  [Authorization: Basic client_id:client_secret]
    {"refresh_token":"kyr_GfC154UJkGGh...(47 chars)"}
  < 401 {"code":"invalid_refresh_token","message":"refresh token is invalid or expired"}
  ok: Keyora answered 401 invalid_refresh_token
  The user has to log in again. Never retry a refresh with the same token.

8. Log in again
  > POST /api/v1/auth/login  [Authorization: Basic client_id:client_secret]
    {"email":"walkthrough-1a8158c6f443@example.com","password":"***"}
  < 200 {"access_token":"eyJhbGciOiJSUzI1...(1124 chars)",...}
  ok: Keyora answered 200
  > POST /api/v1/auth/introspect  [Authorization: Basic client_id:client_secret]
    {"token":"eyJhbGciOiJSUzI1...(1124 chars)"}
  < 200 {"active":true,"sub":"e4e8f834-2389-416d-a96d-f6cab81813c8","tid":"9276cb35-...","client_id":"app_ba6ba87721084f8db75a7cf017cc6b63","sid":"8a3504d8-...","email":"walkthrough-1a8158c6f443@example.com","iss":"http://localhost:8080","exp":1795446765,"iat":1795446705}
  ok: Keyora answered 200
  ok: introspection reports active:true while the session is open

9. Log out
  > POST /api/v1/auth/logout  [Authorization: Basic client_id:client_secret]
    {"refresh_token":"kyr_qNZ7ow42tw71...(47 chars)"}
  < 204 (no body)
  ok: Keyora answered 204

10. Introspection sees the logout; local verification does not
  > POST /api/v1/auth/introspect  [Authorization: Basic client_id:client_secret]
    {"token":"eyJhbGciOiJSUzI1...(1124 chars)"}
  < 200 {"active":false}
  ok: Keyora answered 200
  ok: introspection reports active:false for the logged-out token
  ok: the same token still verifies locally, and will until it expires
  Local verification only proves the token was issued and has not expired. Keep
  access tokens short-lived, and introspect before operations that must not run
  on a revoked session.

11. Handle an invalid token
  ok: a garbage token is rejected locally: not a JWT: expected three dot-separated parts
  > POST /api/v1/auth/introspect  [Authorization: Basic client_id:client_secret]
    {"token":"***"}
  < 200 {"active":false}
  ok: Keyora answered 200
  ok: introspection answers 200 with active:false, not an error
  > GET /api/v1/users/me  [Authorization: Bearer <token>]
  < 401 {"code":"invalid_token","message":"token is invalid or expired"}
  ok: Keyora answered 401 invalid_token

All 11 steps behaved as expected.
```

When a step does not behave as expected the script stops there, prints the reason and
exits with status 1. For example, with a wrong client secret:

```
  < 401 {"code":"invalid_client","message":"client authentication failed"}

FAILED at step 1: expected Keyora to answer 201, got 401 invalid_client
```

## How it works

### Calls that go to Keyora

| Step | Call | Credential |
|---|---|---|
| 1 | `POST /api/v1/auth/register` | application (HTTP Basic) |
| 2, 8 | `POST /api/v1/auth/login` | application |
| 3 | `GET /.well-known/jwks.json` (once, then cached in memory) | none |
| 4, 11 | `GET /api/v1/users/me` | the user's access token (Bearer) |
| 6, 7 | `POST /api/v1/auth/refresh` | application |
| 8, 10, 11 | `POST /api/v1/auth/introspect` | application |
| 9 | `POST /api/v1/auth/logout` | application |

The application credential is HTTP Basic authentication with `client_id` as the username
and `client_secret` as the password. The client secret identifies your application to
Keyora and must never be shipped to a browser or a mobile app. This script holds it
because it plays the part of your server. Code that runs on a user's device should call
your server, which then calls Keyora, as the [Express example](../express) does.

### What is checked locally

`verifyAccessToken` in [`src/main.ts`](src/main.ts) makes no request to Keyora once the
keys are cached. It performs these checks, in this order:

1. Split the token into header, payload and signature, and decode the header.
2. Require `alg` to be exactly `RS256`. The header is written by whoever made the token,
   so the algorithm is never taken from it. This is what rejects `"alg":"none"`.
3. Look up the public key whose `kid` equals the header's `kid` in the JWKS. An unknown
   `kid` triggers one refetch, in case Keyora rotated its key.
4. Verify the RSASSA-PKCS1-v1_5 SHA-256 signature over the ASCII bytes of
   `<header>.<payload>` with `crypto.verify`, using a key built with
   `crypto.createPublicKey({ key: jwk, format: "jwk" })`.
5. Only then decode the payload, and require `exp` to be in the future (and `nbf`, if
   present, not to be), `iss` to equal `KEYORA_ISSUER`, and `aud` to equal
   `KEYORA_CLIENT_ID`.

Step 5 of the walkthrough runs this function against forged and damaged tokens to show
each check refusing them.

The verification is written out so that it can be read. In an application, use a
maintained JWT library and configure the same five checks, as the Express example does
with `jose`.

### What local verification cannot see

Step 10 shows the limit: after logout, the access token still passes every local check
until it expires, because nothing in the token changes. Introspection asks Keyora, which
knows the session was revoked and answers `{"active": false}`. The same applies to role
changes, which reach a token only when it is next issued by login or refresh.

## Troubleshooting

**`ERROR: KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required`.**
`examples/.env` is missing or was not loaded into this shell. Run `examples/setup.sh`
(it needs `KEYORA_ADMIN_KEY`), then `set -a; . examples/.env; set +a` in the same shell
that runs `npm start`.

**`ERROR at step 1: Keyora is not reachable at ...`.**
Nothing answers at `KEYORA_URL`. Check `curl $KEYORA_URL/readyz` and the variable's
value. Inside a container, `localhost` is the container itself.

**`FAILED at step 1: expected Keyora to answer 201, got 401 invalid_client`.**
The client ID or secret is not the one Keyora has, usually because Keyora's database was
recreated after `examples/.env` was written. Re-run `examples/setup.sh` and load the new
file.

**`ERROR at step 3: unexpected issuer "...", want "..."`.**
`KEYORA_ISSUER` (or `KEYORA_URL`, when the former is unset) differs from the `iss` that
Keyora writes into tokens. The message shows both values; they must match exactly,
including the scheme, port and any trailing slash. This happens when Keyora is reached on
an internal address: keep `KEYORA_URL` as the address you can reach and set
`KEYORA_ISSUER` to Keyora's own `KEYORA_ISSUER`. In a server, the same mistake shows up
as every request answering 401.

**`ERROR at step 3: unexpected audience "...", want "..."`.**
The token was issued to a different application than `KEYORA_CLIENT_ID`. In this script
that can only happen if the environment changes between calls; in a server it is the
check that rejects, with a 401, tokens meant for another application.

**`ERROR at step 3: the token expired ...` or `the token is not valid yet (nbf)`.**
The clock of this machine and the clock of the Keyora host differ. Access tokens here
live for 60 seconds, so a drift of a minute is enough. Synchronise the clocks (NTP). The
script allows no tolerance; a real application may allow a few seconds.

**`403 forbidden` from your own application, although the token verifies.**
This script does not use roles: a fresh user has none, which is why `roles` and
`permissions` are empty in step 4 and absent from the claims in step 3. An application
that requires a permission or role answers 403 until one is granted. Grant it with the
admin API, then refresh or log in again so that a new token is issued with it:

```sh
# USER_ID is the "id" printed in step 1. The other values come from examples/.env.
curl -X PUT \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_EDITOR_ROLE_ID" \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"
```

The call answers `204`. Tokens issued afterwards contain
`"roles":["editor"],"permissions":["notes:read","notes:write"]`.

**`429 rate_limited` at any step.**
Keyora limits `/api/v1/auth/*` per client IP. Running the script many times in quick
succession can reach the limit; wait a moment and run it again.
