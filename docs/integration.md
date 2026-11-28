# Integration guide

How to add Keyora to an application, in any language. For complete programs, see
[`examples/`](../examples).

## The six steps

1. **Run Keyora** — [README quick start](../README.md#quick-start).
2. **Create a tenant** (once per organisation or environment).
3. **Register your application** and note its `client_id` and `client_secret`.
4. **Configure your application** with four values (below).
5. **Wire up sign-in**: your backend forwards credentials to Keyora and returns tokens.
6. **Protect endpoints**: verify the access token and check permissions.

## What you configure

| Setting | Value |
|---|---|
| Keyora URL | Where your application reaches Keyora, e.g. `https://id.example.com`. |
| Issuer | Keyora's `KEYORA_ISSUER`. Usually the same as the URL. |
| Client ID | From step 3. Not secret. |
| Client secret | From step 3. **Server-side only.** Keep it in your secret store. |

## Which side does what

| Operation | Where | Needs the client secret |
|---|---|---|
| Register, login, refresh, logout | Your server → Keyora | Yes (confidential apps) |
| Password reset, email verification | Your server → Keyora | Request: yes. Confirm: no. |
| Verify an access token | **Inside your application** | No |
| Check roles and permissions | **Inside your application** | No |
| Introspect a token (optional) | Your server → Keyora | Yes |
| Manage users, roles, applications | Admin tooling → Keyora | Admin credential |

## Step 5: sign-in

Your backend exposes its own `/login` and forwards to Keyora with its credentials:

```http
POST /api/v1/auth/login HTTP/1.1
Host: id.example.com
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/json

{"email": "ada@example.com", "password": "correct horse battery"}
```

```json
{
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIs…",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_token": "kyr_…",
    "refresh_expires_in": 2592000,
    "session_id": "c2a1…",
    "user": { "id": "8fa1…", "email": "ada@example.com", "name": "Ada", "email_verified": false }
  },
  "meta": { "request_id": "…" }
}
```

Client credentials may go in the JSON body (`client_id`, `client_secret`) instead of
the `Authorization` header.

Then:

- Give the **access token** to the client to send as `Authorization: Bearer …`.
- Keep the **refresh token** somewhere safer than the access token — for a web app,
  an `HttpOnly`, `Secure`, `SameSite` cookie set by *your* backend is a good choice;
  for mobile, the platform keystore.
- When a request fails with an expired token, call `/api/v1/auth/refresh`, **store the
  new refresh token**, and retry. Never reuse a refresh token: see
  [reuse detection](authentication.md#refresh).

## Step 6: protect endpoints

On every request to a protected endpoint:

1. Read the token from `Authorization: Bearer <token>`. None → `401`.
2. Verify it:
   - algorithm is **RS256** (pin it; do not trust the token's own `alg`),
   - signature against the JWKS key with the token's `kid`,
   - `exp` in the future,
   - `iss` equals your issuer,
   - **`aud` equals your client ID**.

   Any failure → `401`.
3. Check `permissions` or `roles` for what the endpoint needs. Missing → `403`.

Fetch `GET /.well-known/jwks.json` once and cache it (the response allows five
minutes). On an unknown `kid`, refetch — at most once every 30 seconds.

Use an established JWT library; do not write the verification yourself unless you have
to. Ones used in the examples:

| Language | Library | Note |
|---|---|---|
| Go | `github.com/rabbicse/keyora/guard` | No dependencies. Handles JWKS caching and rotation. |
| TypeScript / JavaScript | `jose` | `createRemoteJWKSet` + `jwtVerify` with `issuer`, `audience`, `algorithms`. |
| Python | `PyJWT[crypto]` | `PyJWKClient`; pass `algorithms=["RS256"]`, `audience`, `issuer`. |
| Java | Spring Security resource server (Nimbus) | Add an audience validator; it is not checked by default. |
| .NET | `Microsoft.AspNetCore.Authentication.JwtBearer` | Supply the JWKS keys yourself; lower `ClockSkew` from its 5-minute default. |
| PHP | `firebase/php-jwt` | Check `iss` and `aud` yourself; the library does not. |

> When verifying **access tokens**, configure the JWKS URL, issuer and audience
> explicitly, and reject tokens whose `token_use` claim is `id`: ID tokens are signed by
> the same keys. OpenID Connect and OAuth client libraries can discover Keyora through
> `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`.

## Browser-only and mobile applications

If there is no backend to hold a secret, register a **public** application and use the
[authorization code flow with PKCE](authentication.md#authorization-code-flow-with-pkce):
your app requests a one-time code from Keyora with the user's credentials and a PKCE
challenge, and exchanges the code for tokens. No client
secret is involved. This is the recommended setup for single-page and mobile apps.

```sh
curl -X POST localhost:8080/api/v1/tenants/$TENANT_ID/applications \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name": "web-app", "type": "public",
       "redirect_uris": ["https://app.example.com/callback"],
       "allowed_origins": ["https://app.example.com"]}'
```

`redirect_uris` lists the callback addresses a code may be issued for;
`allowed_origins` lets the page's JavaScript call the authorization and token
endpoints. For a native app, use a claimed `https`
link or a private-use scheme such as `com.example.app:/callback`.

A public application can also call the direct login endpoint with only its
`client_id`, if you prefer your own login form:

```js
const res = await fetch("https://id.example.com/api/v1/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ client_id: "app_…", email, password }),
});
```

Rules that follow from having no secret:

- **Never put a `client_secret` in frontend code, a mobile binary or a public
  repository.** Anything shipped to a user's device is public.
- Keyora enforces `allowed_origins` on the server for requests that carry an `Origin`
  header, and sets CORS headers only for those origins.
- A public application cannot introspect tokens or use the client-credentials grant.
- Tokens held in browser JavaScript are exposed to any XSS in the page. Prefer the
  backend-holds-the-refresh-token arrangement when you have a backend at all.

## Several applications, one identity

Register each application separately in the same tenant. A user registered through
one can sign in through any of them with the same password. Each application:

- has its own `client_id`, so its tokens have their own `aud` and are not accepted by
  the others;
- can have its own token lifetimes;
- gets its own sessions, visible and revocable individually.

If service A calls service B on a user's behalf, B must accept A's audience
explicitly, or A should authenticate to B as itself with a
[client-credentials token](authentication.md#service-to-service-tokens).

## Handling errors

Every error has this shape; branch on `error.code`, never on `message`:

```json
{ "error": { "code": "invalid_credentials", "message": "invalid email or password" },
  "meta": { "request_id": "5b0c…" } }
```

| Situation | What to do |
|---|---|
| `401 invalid_credentials` | Show a generic "wrong email or password". |
| `423 account_locked` | Tell the user to wait; `Retry-After` has the seconds. Offer password reset. |
| `401` from your own token check, token expired | Refresh once, then retry the request. |
| `401 invalid_refresh_token` / `refresh_token_reused` | The session is gone. Send the user to sign in. |
| `403 forbidden` | The user lacks the permission. Do not retry. |
| `409 email_taken` | On registration: the account exists. |
| `429 rate_limited` | Back off for `Retry-After` seconds. |
| `5xx` or no response | Keyora is unavailable. Local token verification keeps working with cached keys; sign-in does not. |

Log `meta.request_id` (also in the `X-Request-ID` response header) with your own
errors; it finds the matching line in Keyora's logs. You can send your own
`X-Request-ID` and Keyora will use it.

The full list of codes is in [api.md](api.md#error-codes).
