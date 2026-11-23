# Keyora with plain Java

A single-file command-line program that walks through the Keyora authentication flow
using only the JDK: `java.net.http.HttpClient` for the HTTP calls and `java.security` for
verifying the access token. No dependencies and no build tool.

Unlike the server examples, it does not listen on a port. It calls Keyora directly,
prints each step, and exits. Read [`KeyoraDemo.java`](KeyoraDemo.java) alongside the
output to see exactly what a Keyora integration consists of, without a framework in
between.

## Prerequisites

- JDK 17 or newer (`java -version`).
- A running Keyora, and the `examples/.env` file written by `examples/setup.sh`. Steps 1
  and 2 of [`examples/README.md`](../../README.md#run-an-example) cover both.

## Installation

There is nothing to install or compile. `java` runs a single source file directly.

## Configuration

Settings come from environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where the program reaches Keyora, for API calls and for the JWKS. |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | The `iss` value required in access tokens. Must equal the `KEYORA_ISSUER` that Keyora itself runs with. |
| `KEYORA_CLIENT_ID` | none, required | The application's client ID. Also the `aud` value required in access tokens. |
| `KEYORA_CLIENT_SECRET` | none, required | The application's secret. |

`examples/.env` contains all four. Load it into your shell first:

```sh
set -a; . examples/.env; set +a      # run from the repository root
```

## How to run

```sh
set -a; . examples/.env; set +a      # from the repository root
cd examples/java/plain-java
java KeyoraDemo.java
```

Exit code: `0` when every step behaved as expected, `1` when any step did not, `2` when
the configuration is missing.

Each run registers a new user with a random email address, so it can be repeated.

## Example API requests

The program makes the requests itself. This is the output of a real run, with nothing
removed. Lines starting with `POST` or `GET` are calls to Keyora; lines starting with `ok`
are results the program checked.

```
Keyora at http://localhost:8080, issuer http://localhost:8080, application app_ba6ba87721084f8db75a7cf017cc6b63

1. Register a user
  POST /api/v1/auth/register
  ok    201 Created
  user id: 2ef94e49-1d10-4b87-a7cc-b2c05bb7b4ab, email: demo-f5b3825a-ffb@example.com

2. Log in with email and password
  POST /api/v1/auth/login
  ok    200 OK
  access_token:  eyJhbGciOiJSUzI1NiIsInR5... (1115 chars)  (RS256 JWT, expires in 60s)
  refresh_token: kyr_zM8joOx_kvMnjSGvGUEm... (47 chars)  (opaque, single use)

3. Verify the access token locally (no call to Keyora except fetching the JWKS once)
  fetched JWKS: 1 key(s), kid [20261123T150337Z]
  signature, exp, iss and aud are all valid. Claims:
    iss:         "http://localhost:8080"
    aud:         "app_ba6ba87721084f8db75a7cf017cc6b63"
    sub:         "2ef94e49-1d10-4b87-a7cc-b2c05bb7b4ab"
    email:       "demo-f5b3825a-ffb@example.com"
    roles:       null
    permissions: null
    exp:         1795446855
  (roles and permissions are null until an administrator assigns the user a role)
  ok    sub is the id of the user registered in step 1

4. Call a Keyora endpoint protected by the access token: GET /api/v1/users/me
  GET /api/v1/users/me
  ok    200 OK with our profile
  profile: email=demo-f5b3825a-ffb@example.com roles=[] permissions=[]

5. A tampered token is rejected locally
  ok    one character of the signature changed: rejected (invalid_signature: the signature does not match the token's content)
  ok    payload edited to add an "admin" role: rejected (invalid_signature: the signature does not match the token's content)

6. Refresh: exchange the refresh token for new tokens (rotation)
  POST /api/v1/auth/refresh
  ok    200 OK
  ok    the refresh token changed: the old one is now spent
  new access_token verifies locally: eyJhbGciOiJSUzI1NiIsInR5... (1115 chars)

7. Replay the OLD refresh token
  POST /api/v1/auth/refresh
  ok    401 refresh_token_reused
  A refresh token works once. Keyora cannot tell whether the second use came from
  the real client or from someone who stole the token, so it treats it as theft
  and revokes the whole session, including the tokens issued in step 6:
  POST /api/v1/auth/refresh
  ok    the NEW refresh token from step 6 is refused too (401)
  POST /api/v1/auth/introspect
  ok    introspection reports the step 6 access token as active=false
  The user has to log in again. So: store the new refresh token before using the
  new access token, and never retry a refresh with a token you already sent.

8. Log in again
  POST /api/v1/auth/login
  ok    200 OK
  POST /api/v1/auth/introspect
  ok    introspection reports the new access token as active=true

9. Log out (revokes the session)
  POST /api/v1/auth/logout
  ok    204 No Content

10. After logout: introspection against local verification
  POST /api/v1/auth/introspect
  ok    introspection reports active=false
  ok    local verification still accepts the token for another 60s:
        a signed token cannot be recalled. Keep access tokens short-lived and use
        introspection where acting on a revoked session would be unacceptable.

11. A garbage token is rejected
  ok    local verification of "not-a-token": rejected (malformed_token: expected three dot-separated parts, found 1)
  POST /api/v1/auth/introspect
  ok    introspection reports active=false
  GET /api/v1/users/me
  ok    GET /api/v1/users/me answers 401

All steps behaved as expected.
```

To make one of these calls by hand, this is the login request from step 2 as `curl`
(with `examples/.env` loaded):

```sh
curl -s -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo-f5b3825a-ffb@example.com","password":"correct horse battery staple"}' \
  "$KEYORA_URL/api/v1/auth/login"
```

Keyora wraps every `/api/v1` response in an envelope. Success carries `data`, failure
carries `error`, and both carry `meta`:

```json
{"data":{"access_token":"eyJhbGciOiJSUzI1NiIs...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_...","refresh_expires_in":2592000,"session_id":"...","user":{"id":"...","email":"demo-f5b3825a-ffb@example.com"}},"meta":{"request_id":"..."}}
```

```json
{"error":{"code":"invalid_credentials","message":"invalid email or password"},"meta":{"request_id":"..."}}
```

## How it works

**Calls that go to Keyora.** Register, login, refresh, logout and introspect are `POST`
requests to `/api/v1/auth/*`, each authenticated with the application's client ID and
secret as HTTP Basic credentials. `GET /api/v1/users/me` is authenticated with the user's
access token as a bearer token. `GET /.well-known/jwks.json` needs no credentials and is
fetched once.

The client secret identifies your application to Keyora. This program holds it because it
stands in for your server. Never ship it to a browser or a mobile app: anyone who has it
can act as your application.

**Checks made locally.** `verifyAccessToken` in [`KeyoraDemo.java`](KeyoraDemo.java) does
what a JWT library would do, in this order:

1. Split the token into header, payload and signature, and base64url-decode them.
2. Require the header's `alg` to be exactly `RS256`. The algorithm is fixed by the
   program and never chosen by the token.
3. Find the key in the JWKS whose `kid` equals the header's `kid`, and build an
   `RSAPublicKey` from its `n` and `e` values with `RSAPublicKeySpec`.
4. Verify the signature over `header.payload` with `Signature.getInstance("SHA256withRSA")`.
5. Only after the signature holds, check the claims: `exp` is in the future, `iss` equals
   `KEYORA_ISSUER`, and `aud` equals `KEYORA_CLIENT_ID`.

Skipping the audience check is the most common mistake. Without it, a token that Keyora
issued to any other application would be accepted by yours.

**Local verification or introspection.** Local verification needs no network call, but it
only knows what was true when the token was signed. Step 10 shows the consequence: after
logout, introspection reports the token inactive at once, while local verification accepts
it until it expires. Keep access tokens short-lived, verify locally by default, and use
introspection for the few operations where acting on a just-revoked session would be
unacceptable.

**JSON.** The JDK has no JSON parser, so the file contains a small one (class `Json`): a
recursive-descent reader for objects, arrays, strings with escapes, numbers, booleans and
null, plus a writer for request bodies. It is enough for Keyora's responses. In a real
project, use a JSON library and a JWT library.

## Troubleshooting

**"KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required" (exit code 2).**
The environment is not loaded. Run `set -a; . examples/.env; set +a` from the repository
root, in the same terminal. If `examples/.env` does not exist, run `examples/setup.sh`
first (see [`examples/README.md`](../../README.md)).

**"stopped by an unexpected error: java.net.ConnectException".**
Keyora is not reachable at `KEYORA_URL`. Check the value and that Keyora is up:
`curl -s $KEYORA_URL/readyz`.

**Step 1 or 2 fails with `401` and `invalid_client`.**
Keyora rejected the application's credentials. `KEYORA_CLIENT_ID` or `KEYORA_CLIENT_SECRET`
is wrong or out of date, for example after `setup.sh` was run again. Reload `examples/.env`.

**Step 3 stops with `TokenRejected: iss is "...", expected "..."`.**
`KEYORA_ISSUER` does not match the issuer Keyora puts into tokens. The two values in the
message must be equal character for character. They differ when you reach Keyora on an
internal address, for example `KEYORA_URL=http://host.docker.internal:8080` while Keyora's
own issuer is `http://localhost:8080`. Set `KEYORA_ISSUER` to the value the token contains.
A server that enforces this check answers such a token with `401`.

**Step 3 stops with `TokenRejected: aud is "...", expected "..."`.**
The token was issued to a different application than `KEYORA_CLIENT_ID`. This cannot
happen within one run of the program; in your own code it means the token came from
another client. Refusing it is the correct behaviour.

**Step 3 stops with `TokenRejected: the token expired ...` or `the token is not valid yet`.**
The clocks of this machine and of the Keyora host disagree. The example setup issues
access tokens that live for 60 seconds, so a difference of a minute is enough. Compare
`date -u` on both and synchronise them (NTP). The program allows no tolerance; a
production verifier usually accepts a few seconds.

**The profile in step 4 shows `roles=[] permissions=[]`, or your own API answers `403`.**
A newly registered user has no roles, so a token for that user carries no permissions.
Grant a role with Keyora's admin API, using the user id printed in step 1:

```sh
# reader: notes:read            editor: notes:read, notes:write and the "editor" role
curl -X PUT -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_READER_ROLE_ID"
```

It answers `204`. The variables other than `USER_ID` are in `examples/.env`. Roles are
copied into the access token when it is issued, so they appear after the next login or
refresh, not in a token you already hold. Introspection and `GET /api/v1/users/me` show
them immediately.

**A step fails with `429` and `rate_limited`.**
Keyora limits `/api/v1/auth/*` per client IP. Wait for the number of seconds in the
`Retry-After` response header and run the program again.

**`error: class found on application class path: KeyoraDemo`.**
A compiled `KeyoraDemo.class` is in the directory. Delete it, or run `java KeyoraDemo`
after compiling with `javac KeyoraDemo.java`.
