# Keyora with Spring Boot

A small notes API that uses Keyora for sign-in and access control, built with
Spring Boot 3 and Spring Security's OAuth2 resource server support.

It does two things:

- It forwards `/register`, `/login`, `/refresh` and `/logout` to Keyora, adding the
  application's client secret on the way.
- It protects `/me`, `/notes` and `/reports` by verifying Keyora's access token (an RS256
  JWT) locally and checking the permissions and roles inside it.

It implements the same HTTP contract as every other server example; see
[`examples/README.md`](../../README.md).

## Prerequisites

- JDK 17 or newer (`java -version`).
- A running Keyora, and the `examples/.env` file written by `examples/setup.sh`. Steps 1
  and 2 of [`examples/README.md`](../../README.md#run-an-example) cover both.
- `curl` for the requests below. `python3` if you want to run the shared verification script.

You do not need Maven. The project includes the Maven Wrapper (`./mvnw`), which downloads
Maven 3.9 on first use. If you have Maven 3.6.3 or newer installed, `mvn` works the same way.

## Installation

From the repository root:

```sh
cd examples/java/spring-boot
./mvnw -DskipTests package
```

The first build downloads Maven and the dependencies, so it needs internet access.
The result is `target/keyora-spring-boot-example-0.1.0.jar`.

## Configuration

All settings come from environment variables (mapped in
[`application.properties`](src/main/resources/application.properties)).

| Variable | Default | Meaning |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where this application reaches Keyora, for API calls and for the JWKS. |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | The `iss` value required in access tokens. Must equal the `KEYORA_ISSUER` that Keyora itself runs with. |
| `KEYORA_CLIENT_ID` | none, required | The application's client ID. Also the `aud` value required in access tokens. |
| `KEYORA_CLIENT_SECRET` | none, required | The application's secret. Server-side only. |
| `PORT` | `9006` | Port the example listens on. |

`examples/.env` contains the four `KEYORA_*` values. Load it into your shell before
starting the application:

```sh
set -a; . examples/.env; set +a      # run from the repository root
```

## How to run

```sh
set -a; . examples/.env; set +a      # from the repository root
cd examples/java/spring-boot
./mvnw spring-boot:run
```

Or run the jar built during installation: `java -jar target/keyora-spring-boot-example-0.1.0.jar`.

The application is ready when it logs `Tomcat started on port 9006`.

To check the whole contract, run the shared verification script from the repository root
in a second terminal:

```sh
python3 examples/verify.py http://localhost:9006
```

It ends with `35 passed, 0 failed`. It takes a little over a minute because it waits for
an access token to expire; add `--skip-expiry` to skip that.

## Example API requests

Run these in a second terminal. The responses shown are output from a real run, with tokens shortened, the email address
simplified and the notes list reduced to what a fresh start returns.
The last two commands of the walkthrough need `examples/.env` loaded in that terminal too.

**A public endpoint**

```sh
curl -s http://localhost:9006/public
```

```json
{"message":"anyone can read this"}
```

**Register a user** (`201`)

```sh
curl -s -X POST http://localhost:9006/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada Lovelace"}'
```

```json
{"id":"19355cc0-6a2f-4335-9004-aa355a2909e0","tenant_id":"9276cb35-e993-4b32-a25c-a52306b98780","email":"ada@example.com","name":"Ada Lovelace","status":"active","email_verified":false,"created_at":"2026-11-23T15:13:45.094Z","updated_at":"2026-11-23T15:13:45.094Z"}
```

Keep the `id`; you need it to grant a role. Registering the same email again answers
`409` with `{"error":{"code":"email_taken", ...}}`.

**Log in** (`200`)

```sh
curl -s -X POST http://localhost:9006/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
```

```json
{"access_token":"eyJhbGciOiJSUzI1NiIs...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_-Q0h2kfkhGYm4ZP4...","refresh_expires_in":2591999,"session_id":"0c87503e-d436-41db-982d-7c1427893d6c","user":{"id":"19355cc0-...","email":"ada@example.com", ...}}
```

Put the two tokens in shell variables for the next requests:

```sh
ACCESS='eyJhbGciOi...'      # access_token
REFRESH='kyr_...'           # refresh_token
```

The application that `setup.sh` creates issues access tokens that live for 60 seconds, so
that expiry is easy to observe. When requests start answering `token_expired`, refresh.

**Who am I, from the token** (`200`)

```sh
curl -s http://localhost:9006/me -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"19355cc0-6a2f-4335-9004-aa355a2909e0","email":"ada@example.com","roles":[],"permissions":[]}
```

**Without a token, or with a bad one** (`401`)

```sh
curl -s http://localhost:9006/me
curl -s http://localhost:9006/me -H 'Authorization: Bearer not-a-token'
```

```json
{"error":{"code":"missing_token","message":"a bearer access token is required"}}
{"error":{"code":"invalid_token","message":"the access token is invalid"}}
```

An expired token answers `401` with code `token_expired`.

**A protected endpoint before any role is granted** (`403`)

```sh
curl -s http://localhost:9006/notes -H "Authorization: Bearer $ACCESS"
```

```json
{"error":{"code":"forbidden","message":"you do not have access to this resource"}}
```

**Grant a role, then refresh**

Roles are managed in Keyora, with its admin API. This call goes to Keyora, not to the
example, and uses the admin key from `examples/.env`. It answers `204` with no body.

```sh
USER_ID='19355cc0-6a2f-4335-9004-aa355a2909e0'      # the id from /register
curl -s -o /dev/null -w '%{http_code}\n' -X PUT \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_EDITOR_ROLE_ID"
```

The token you already hold does not change. Refresh to get one that contains the new role:

```sh
curl -s -X POST http://localhost:9006/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

```json
{"access_token":"eyJhbGciOiJSUzI1NiIs...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_cZ72K-uWNrEXUsfv...","refresh_expires_in":2592000,"session_id":"0c87503e-d436-41db-982d-7c1427893d6c"}
```

Update `ACCESS` and `REFRESH` with the new values. A refresh token works once: sending the
old one again answers `401` and revokes the whole session.

```json
{"error":{"code":"refresh_token_reused","message":"refresh token was already used; the session has been revoked"}}
```

**With the `editor` role** (permissions `notes:read` and `notes:write`)

```sh
curl -s http://localhost:9006/notes -H "Authorization: Bearer $ACCESS"
curl -s -X POST http://localhost:9006/notes -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"text":"hello"}'
curl -s http://localhost:9006/reports -H "Authorization: Bearer $ACCESS"
```

```json
{"notes":[{"text":"Welcome to Keyora","author":"system"}]}
{"text":"hello","author":"ada@example.com"}
{"total_notes":2}
```

**Who am I, according to Keyora right now** (`200`)

```sh
curl -s http://localhost:9006/me/live -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"19355cc0-6a2f-4335-9004-aa355a2909e0","email":"ada@example.com","roles":["editor"],"permissions":["notes:read","notes:write"]}
```

**Log out** (`204`, no body), then compare the two ways of checking the token

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:9006/logout \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"
curl -s http://localhost:9006/me/live -H "Authorization: Bearer $ACCESS"
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9006/me -H "Authorization: Bearer $ACCESS"
```

```
204
{"error":{"code":"invalid_token","message":"the access token is no longer active"}}
200
```

`/me/live` sees the logout immediately. `/me` keeps accepting the token until it expires,
because local verification does not ask Keyora.

## How it works

**Calls that go to Keyora.** [`KeyoraClient`](src/main/java/com/example/notes/KeyoraClient.java)
sends `POST /api/v1/auth/register`, `/login`, `/refresh`, `/logout` and `/introspect`, each
with the client ID and secret as HTTP Basic credentials.
[`AuthController`](src/main/java/com/example/notes/AuthController.java) relays the answer.
Keyora wraps every response in an envelope, `{"data": ..., "meta": ...}` or
`{"error": ..., "meta": ...}`; the controller returns the `data` object on success and
`{"error": ...}` on failure, with Keyora's status and error code unchanged.

The client secret is the reason these calls are made by your server. Never ship it to a
browser or a mobile app: anyone who has it can act as your application.

**Checks made locally.** For `/me`, `/notes` and `/reports`, Keyora is not contacted per
request. [`SecurityConfig`](src/main/java/com/example/notes/SecurityConfig.java) builds a
`NimbusJwtDecoder` from Keyora's JWKS URL (`KEYORA_URL/.well-known/jwks.json`); the key set
is fetched on first use and cached. For every request the decoder checks:

1. the algorithm is RS256 (pinned in code, not taken from the token);
2. the signature, against the JWKS key whose `kid` matches;
3. `exp` is in the future;
4. `iss` equals `KEYORA_ISSUER`;
5. `aud` equals `KEYORA_CLIENT_ID`;
6. `token_use` equals `access`, so an OIDC ID token, which has the same issuer and
   audience, is not accepted as an access token.

Spring Security does not check the audience unless you add a validator, so the
configuration adds one. Without it, a token that Keyora issued to a different application
would be accepted. The decoder is configured with the JWKS URL directly and not with
Spring's `issuer-uri` property, because that property relies on OIDC discovery and Keyora
does not serve a discovery document.

**Authorization.** A `JwtAuthenticationConverter` turns the token's claims into Spring
Security authorities: each entry of `permissions` keeps its name (`notes:read`) and each
entry of `roles` gets the `ROLE_` prefix (`ROLE_editor`).
[`NotesController`](src/main/java/com/example/notes/NotesController.java) then uses
`@PreAuthorize("hasAuthority('notes:read')")` and `@PreAuthorize("hasRole('editor')")`.

**Errors.** A custom `AuthenticationEntryPoint` and `AccessDeniedHandler` produce the
contract's error body: `401 missing_token`, `401 token_expired`, `401 invalid_token` and
`403 forbidden`.

**Introspection.** `/me/live` does not use the local decoder. It sends the token to
Keyora's `POST /api/v1/auth/introspect` and answers `401 invalid_token` when Keyora reports
`"active": false`. That costs one network call per request, but it reflects logouts,
disabled users and role changes immediately. Use it for the few operations where acting on
a just-revoked session would be unacceptable, and local verification for everything else.

**Other settings.** The application is stateless (no HTTP session). CSRF protection is
disabled because it defends cookie-based authentication, and this API accepts only bearer
tokens that the client adds to each request explicitly. Spring Security's built-in logout
filter is disabled so that `POST /logout` reaches the controller.

## Troubleshooting

**Startup fails with "KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required".**
The environment is not loaded. Run `set -a; . examples/.env; set +a` from the repository
root, in the same terminal that starts the application. If `examples/.env` does not exist,
run `examples/setup.sh` first (see [`examples/README.md`](../../README.md)).

**Every protected request answers `401 invalid_token`, although login works.**
The token is genuine but fails the issuer or audience check. Decode it and compare:

```sh
echo "$ACCESS" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

- `iss` must equal `KEYORA_ISSUER` exactly, character for character (scheme, host, port, no
  trailing slash). This differs from `KEYORA_URL` when the example reaches Keyora on an
  internal address, for example `http://host.docker.internal:8080` from a container while
  Keyora's issuer is `http://localhost:8080`. Set `KEYORA_ISSUER` to the value in the token.
- `aud` must equal `KEYORA_CLIENT_ID`. A token obtained through a different Keyora
  application is refused on purpose. Check that the example and whatever obtained the token
  use the same `examples/.env`; rerunning `setup.sh` can create a new application, after
  which the example must be restarted with the new values.

**`502 identity_unavailable`.**
The example could not reach Keyora, either for an API call or to fetch the JWKS. Check
`KEYORA_URL` and that Keyora is up: `curl -s $KEYORA_URL/readyz`. Once the JWKS has been
fetched, local verification keeps working while Keyora is down; the forwarding endpoints
and `/me/live` do not.

**`401 invalid_client` from `/login` or `/register`.**
Keyora rejected the application's credentials. `KEYORA_CLIENT_ID` or `KEYORA_CLIENT_SECRET`
is wrong or out of date; reload `examples/.env` and restart.

**`401 token_expired` sooner than expected, or tokens rejected right after login.**
Access tokens from the example setup live for 60 seconds, so `token_expired` after a minute
is normal: call `/refresh`. If fresh tokens are rejected, compare the clocks of the two
machines (`date -u` on each). A token is refused when this machine's clock is past its
`exp`, or before its `nbf`. The example allows no tolerance; raise `CLOCK_SKEW` in
`SecurityConfig` to a few seconds if your clocks cannot be kept in sync, and prefer fixing
the clocks (NTP).

**`403 forbidden` on `/notes` or `/reports`.**
A newly registered user has no roles. Grant one with Keyora's admin API, then refresh or
log in again, because roles are copied into the token when it is issued:

```sh
# reader: notes:read            editor: notes:read, notes:write and the "editor" role
curl -X PUT -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_READER_ROLE_ID"
```

`USER_ID` is the `id` returned by `/register` and the `sub` returned by `/me`. The other
variables are in `examples/.env`. Use `$KEYORA_EDITOR_ROLE_ID` for the editor role.

**`401 refresh_token_reused`.**
A refresh token was sent twice. Keyora treats that as theft and revokes the session; log
in again. Always replace the stored refresh token with the one from the latest response.

**`429 rate_limited`.**
Keyora limits `/api/v1/auth/*` per client IP. Wait for the number of seconds in the
`Retry-After` header of Keyora's response.

**Port 9006 is already in use.**
Start with another port: `PORT=9016 ./mvnw spring-boot:run`.
