# Keyora with ASP.NET Core

A small notes API written as an ASP.NET Core minimal API (C#, .NET 8). Users register and
sign in through Keyora; the API then verifies Keyora's access tokens itself and decides,
from the roles and permissions inside the token, which requests to allow.

It implements the contract shared by all examples (see [`examples/README.md`](../../README.md)):

| Endpoint | Auth | Behaviour |
|---|---|---|
| `GET /public` | none | `200` |
| `POST /register` `{email, password, name}` | none | Forwards to Keyora. `201` with the user. |
| `POST /login` `{email, password}` | none | Forwards to Keyora. `200` with tokens. |
| `POST /refresh` `{refresh_token}` | none | Forwards to Keyora. `200` with new tokens. |
| `POST /logout` `{refresh_token}` | none | Forwards to Keyora. `204`. |
| `GET /me` | access token, verified locally | `200` `{sub, email, roles, permissions}` from the token. |
| `GET /me/live` | access token, verified by introspection | Same shape, from Keyora's live state. |
| `GET /notes` | permission `notes:read` | `200` |
| `POST /notes` `{text}` | permission `notes:write` | `201` |
| `GET /reports` | role `editor` | `200` |

The files:

| File | Contents |
|---|---|
| `Program.cs` | Configuration, service registration and the endpoints. |
| `KeyoraAuth.cs` | JwtBearer setup (JWKS download, the six token checks, error responses) and the `RequirePermission` / `RequireRole` helpers. |
| `KeyoraClient.cs` | Typed `HttpClient` for Keyora's REST API. |

## Prerequisites

- .NET SDK 8.0 (`dotnet --version` prints `8.0.x`).
- A running Keyora, and `examples/.env` created by `examples/setup.sh`. Both are described
  in [`examples/README.md`](../../README.md#run-an-example).
- `curl` for the requests below; Python 3 if you want to run `examples/verify.py`.

## Installation

```sh
cd examples/dotnet/aspnet-core
dotnet restore
```

The only package is `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.11.

## Configuration

All settings come from environment variables. `examples/setup.sh` writes the first four
to `examples/.env`.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `KEYORA_URL` | no | `http://localhost:8080` | Where this application reaches Keyora (API calls and JWKS). |
| `KEYORA_ISSUER` | no | value of `KEYORA_URL` | The `iss` value tokens must carry. Set it when the application reaches Keyora on a different address than the one Keyora puts in its tokens, for example from inside a container. |
| `KEYORA_CLIENT_ID` | yes | – | The application's client ID. Also the `aud` value tokens must carry. |
| `KEYORA_CLIENT_SECRET` | yes | – | The application's secret. Server-side only. |
| `PORT` | no | `9007` | Port to listen on. |

The application exits immediately with a message if the client ID or secret is missing.

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a
cd examples/dotnet/aspnet-core
dotnet run
```

```text
info: KeyoraNotes[0]
      Notes API starting (Keyora at http://localhost:8080, issuer http://localhost:8080)
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://[::]:9007
```

To check it against the shared test (35 checks, about 70 seconds because it waits for a
token to expire), run this from the repository root in another terminal:

```sh
python3 examples/verify.py http://localhost:9007
```

## Example API requests

Responses below are real output, with tokens and long fields shortened.

**A public endpoint**

```sh
curl http://localhost:9007/public
```

```json
{"message":"anyone can read this"}
```

**Register**

```sh
curl -X POST http://localhost:9007/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"correct horse battery staple","name":"Demo User"}'
```

`201`:

```json
{"id":"71897357-0f22-43bf-a30a-ee02bbe5755b","tenant_id":"9276cb35-...","email":"demo@example.com","name":"Demo User","status":"active","email_verified":false,"created_at":"2026-11-23T15:11:35.828Z","updated_at":"2026-11-23T15:11:35.828Z"}
```

Registering the same address again gives `409` with Keyora's own error code, `email_taken`.

**Log in**

```sh
curl -X POST http://localhost:9007/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"correct horse battery staple"}'
```

`200`:

```json
{"access_token":"eyJhbGciOiJSUzI1NiIs...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_tgOE1C4hGVBv...","refresh_expires_in":2591999,"session_id":"56da0bdb-...","user":{"id":"71897357-...","email":"demo@example.com", "...": "..."}}
```

A wrong password gives `401`:

```json
{"error":{"code":"invalid_credentials","message":"invalid email or password"}}
```

Keep the tokens for the next requests. The access token set up by `setup.sh` lives for 60
seconds, so refresh it (below) if a request answers `token_expired`.

```sh
ACCESS=eyJhbGciOiJSUzI1NiIs...
REFRESH=kyr_tgOE1C4hGVBv...
```

**Who am I (verified locally)**

```sh
curl http://localhost:9007/me -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"71897357-0f22-43bf-a30a-ee02bbe5755b","email":"demo@example.com","roles":[],"permissions":[]}
```

Without a token, with a broken one, and with an expired one (all `401`):

```json
{"error":{"code":"missing_token","message":"a bearer access token is required"}}
{"error":{"code":"invalid_token","message":"the access token is invalid"}}
{"error":{"code":"token_expired","message":"the access token has expired"}}
```

**Read the notes**

```sh
curl http://localhost:9007/notes -H "Authorization: Bearer $ACCESS"
```

A new user has no roles, so this is `403`:

```json
{"error":{"code":"forbidden","message":"the access token does not allow this request"}}
```

Grant the user the `reader` and `editor` roles (see
[403 until a role is granted](#403-on-notes-or-reports) below), then get a new access
token. Roles are copied into the token when it is issued, so the old one still has none.

**Refresh**

```sh
curl -X POST http://localhost:9007/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

`200` with a new `access_token` and a new `refresh_token`. The old refresh token is now
used up; presenting it again gives `401` `refresh_token_reused`. With the new access token:

```sh
curl http://localhost:9007/notes -H "Authorization: Bearer $ACCESS"
```

```json
{"notes":[{"text":"Welcome to Keyora","author":"system"}]}
```

**Write a note** (permission `notes:write`)

```sh
curl -X POST http://localhost:9007/notes \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"text":"hello"}'
```

`201`:

```json
{"text":"hello","author":"demo@example.com"}
```

**Reports** (role `editor`)

```sh
curl http://localhost:9007/reports -H "Authorization: Bearer $ACCESS"
```

```json
{"total_notes":2}
```

**Log out, then compare local verification with introspection**

```sh
curl -i -X POST http://localhost:9007/logout \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

`204` with no body. The access token has not expired yet, so `/me` still answers `200`,
while `/me/live` asks Keyora and learns that the session is gone:

```sh
curl http://localhost:9007/me/live -H "Authorization: Bearer $ACCESS"
```

`401`:

```json
{"error":{"code":"invalid_token","message":"the access token is no longer active"}}
```

## How it works

**Calls that go to Keyora.** `/register`, `/login`, `/refresh` and `/logout` are relayed
by `KeyoraClient` to `POST /api/v1/auth/...` on Keyora. The client attaches the
application's `client_id` and `client_secret` as HTTP Basic credentials. Keyora answers
with an envelope, `{"data": ...}` on success or `{"error": {"code", "message"}}` on
failure; the example returns the `data` object on success and the error with Keyora's
status code otherwise. `/me/live` calls `POST /api/v1/auth/introspect`, which reports
whether the token is active right now together with the user's current roles and
permissions.

The client secret is the reason these calls go through a server. It must never be
shipped to a browser or a mobile app. If you have no server, register a `public`
application in Keyora instead, which has no secret.

**Checks done locally.** `/me`, `/notes` and `/reports` make no call to Keyora per
request. `Microsoft.AspNetCore.Authentication.JwtBearer` verifies the access token:

1. the algorithm is RS256 (`ValidAlgorithms`), whatever the token's header claims;
2. the signature matches the Keyora key with the token's `kid`;
3. `exp` is in the future, with no tolerance (`ClockSkew = TimeSpan.Zero`);
4. `iss` equals `KEYORA_ISSUER`;
5. `aud` equals `KEYORA_CLIENT_ID`, so tokens issued to another application are refused;
6. `token_use` equals `access` (the `OnTokenValidated` event in `KeyoraAuth.cs`), so an
   OIDC ID token, which has the same issuer and audience, is not accepted as an access token.

Keyora publishes its public keys at `/.well-known/jwks.json` but has no OpenID Connect
discovery document, so `options.Authority` is not used. `KeyoraAuth.cs` gives the handler
a `ConfigurationManager` with a small retriever that downloads the JWKS directly. The
keys are cached in memory (the library re-downloads them every 12 hours). When a token
names a `kid` that is not in the cache, the handler asks for a fresh download, at most
once every 30 seconds; that one request is answered `401` and the next one is checked
against the new keys.

`MapInboundClaims = false` keeps Keyora's claim names. The `roles` and `permissions`
arrays in the token become one claim per element, and the two helpers build
authorization policies on them:

```csharp
app.MapGet("/notes", ...).RequirePermission("notes:read");   // every listed permission
app.MapGet("/reports", ...).RequireRole("editor");            // any of the listed roles
```

The handler's `OnChallenge` and `OnForbidden` events turn failures into the contract's
error body: no token is `missing_token`, an expired one `token_expired`, anything else
`invalid_token` (all `401`), and a valid token without the required permission or role
is `403` `forbidden`.

Local verification cannot see a logout or a role change until the token expires or is
refreshed. Introspection can, at the price of a network call per request. Use it for the
few operations where that matters.

## Troubleshooting

**The application exits with "KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required".**
The environment is not loaded. Run `examples/setup.sh` once to create `examples/.env`,
then `set -a; . examples/.env; set +a` in the same shell you start `dotnet run` from.
`dotnet run` does not read `.env` files by itself.

**Every protected request is `401` `invalid_token`, although login works.** The token is
failing the issuer or audience check. The application log names the reason, for example:

```text
IDX10205: Issuer validation failed. Issuer: 'http://localhost:8080'. Did not match: validationParameters.ValidIssuer: 'http://wrong.example' ...
```

- `IDX10205` (issuer): `KEYORA_ISSUER` must equal the `iss` claim in the token, which is
  the issuer Keyora itself is configured with. It is compared as a string, so
  `http://localhost:8080` and `http://127.0.0.1:8080` are different, as are values with
  and without a trailing slash.
- `IDX10214` (audience): the token was issued to a different application.
  `KEYORA_CLIENT_ID` must be the client ID that was used to log in.

To see what a token contains, decode its middle part:
`echo "$ACCESS" | cut -d. -f2 | base64 -d` (add `=` padding if `base64` complains).

**`502` `identity_unavailable`.** The application cannot reach Keyora at `KEYORA_URL`, or
has never been able to download the signing keys. Check that
`curl $KEYORA_URL/.well-known/jwks.json` works from the machine (or container) the
application runs on. Inside a container, `localhost` is the container itself: point
`KEYORA_URL` at an address that reaches Keyora, and set `KEYORA_ISSUER` to the issuer in
the tokens. Once the keys have been downloaded, the locally verified endpoints keep
working while Keyora is down; the forwarded endpoints and `/me/live` do not.

**Tokens are rejected as `token_expired` too early, or accepted after they expire.**
Expiry is checked against this machine's clock. This example sets
`ClockSkew = TimeSpan.Zero`, so a clock that runs ahead of Keyora's makes tokens expire
early; synchronise both machines with NTP, or allow a few seconds of skew in
`KeyoraAuth.cs`. The opposite surprise comes from the library default: if you remove the
`ClockSkew` line, tokens are accepted for 5 minutes past `exp`, which is longer than the
whole lifetime of a short-lived Keyora token.

<a id="403-on-notes-or-reports"></a>
**`403` `forbidden` on `/notes` or `/reports`.** A new user has no roles. Grant one with
Keyora's admin API; the IDs are in `examples/.env`, and the user ID is the `id` returned
by `/register` (also the `sub` shown by `/me`):

```sh
USER_ID=71897357-0f22-43bf-a30a-ee02bbe5755b
# reader carries notes:read; editor carries notes:read and notes:write
curl -i -X PUT -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_READER_ROLE_ID"
curl -i -X PUT -H "Authorization: Bearer $KEYORA_ADMIN_KEY" \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_EDITOR_ROLE_ID"
```

Each answers `204`. The access token you already hold does not change: call `/refresh`
(or log in again) and use the new access token.

**`401` `refresh_token_reused` on `/refresh`.** Each refresh token works once. Always
store the `refresh_token` from the latest `/refresh` response and discard the previous
one.

**"Failed to bind to address ... address already in use".** Another process is using the
port. Start with a different one: `PORT=9017 dotnet run`.
