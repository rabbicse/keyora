# GraphQL API

Keyora serves the operations of the versioned REST API (`/api/v1`) as GraphQL too.
Both run on the same service, identify callers the same way and report the same error
codes; pick whichever fits your client.

The schema is [`transport/graphql/schema.graphql`](../transport/graphql/schema.graphql).
Every type and field in it is described, and a running server answers introspection
queries unless that is switched off.

Not available over GraphQL: the health and metrics endpoints, the `/.well-known`
documents (JWKS, OAuth and OpenID Connect metadata) and the OpenAPI description. Fetch
those over plain HTTP.

## Endpoint

```
POST /graphql
Content-Type: application/json

{"query": "...", "operationName": "...", "variables": { ... }}
```

- Only `POST` with a JSON body is served. The `Content-Type` header is required.
- `operationName` and `variables` are optional.
- One request carries one document. A JSON array of requests is refused.
- There are no subscriptions and no file uploads.
- Keyora serves no pages, so there is no query editor at this address. Point a GraphQL
  client at the endpoint instead.

The response is `application/json` with the usual `data` and `errors` members.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `KEYORA_GRAPHQL_ENABLED` | `true` | Serve `POST /graphql` on the HTTP listener. `false` removes the route. |
| `KEYORA_GRAPHQL_INTROSPECTION` | `true` | Answer schema introspection (`__schema`, `__type`). |

With introspection off, `__schema` and `__type` are left out of the result (a query for
nothing else returns `{"data":{}}`), and error messages no longer suggest field or
argument names. `__typename` keeps working. This reduces what the endpoint volunteers;
it does not make the schema secret, since the schema file is public.

The GraphQL transport is a separate Go module. The official binary links it; a custom
build may leave it out, in which case these variables have no effect.

## Authentication

Credentials travel in HTTP headers, exactly as for REST.

| Fields | Credential |
|---|---|
| Self-service: `me`, `mySessions`, `updateMe`, `changePassword`, `revokeMySession`, `userinfo` | `Authorization: Bearer <access token>` |
| Management: tenants, applications, users, roles, permissions, sessions, audit events | `Authorization: Bearer <root admin key>`, or the access token of a user who administers the tenant named in `tenantId`. `tenants`, `createTenant` and `updateTenant` need the root admin key. |
| Application: `register`, `login`, `refresh`, `logout`, `introspectToken`, `requestEmailVerification`, `forgotPassword`, `token` | HTTP Basic `client_id:client_secret`, or the `clientId` and `clientSecret` arguments. HTTP Basic wins when both are present. Public applications send only the client ID. |
| `confirmEmail`, `resetPassword` | None; the emailed token is the credential. |
| `authorize` | The application's `clientId` and the user's email and password, in the input. |

An OpenID Connect ID token is not accepted as a bearer credential.

`logout` works two ways: with a refresh token and application credentials, or with no
arguments and the bearer access token of the session to end.

The request's `Origin` header, when present, is checked against the application's
allowed origins by the same rules as for REST.

A request carries one `Authorization` header, so it cannot hold both a bearer token and
HTTP Basic credentials. To combine application fields and self-service fields in one
document, send the bearer token in the header and the application's credentials as
arguments.

## Conventions

- **Fields are nullable at the root.** A field that fails resolves to `null` and adds an
  entry to `errors`; the other fields of the same request are unaffected.
- **Mutations with nothing to return** (`logout`, `deleteUser`, `assignRole`, …) resolve
  to `true`.
- **The fields of a mutation run in order, one at a time**, and each one identifies the
  caller again. After `logout`, later fields of the same document that need the access
  token fail with `invalid_token`.
- **Lists** take `limit` (1 to 100, default 20) and `offset` (default 0) and return
  `{ items, total, limit, offset }`. `total` counts all matching records.
- **Updates** change only the arguments or input fields that are present. `null` is the
  same as leaving the value out.
- **Timestamps** are the `Time` scalar: RFC 3339 strings in UTC.
- **Durations and counts** are GraphQL `Int` (32-bit).
- **Names** are camelCase versions of the REST names: `tenant_id` is `tenantId`,
  `access_token_ttl_seconds` is `accessTokenTtlSeconds`.

## Errors

Every error has `extensions.code`, the same machine-readable code REST puts in
`error.code`, and `extensions.request_id`, which also appears in the server's logs and
in the `X-Request-ID` response header. Validation failures add `extensions.details`
with one message per field; the keys are the REST field names.

```json
{
  "errors": [
    {
      "message": "request validation failed",
      "path": ["register"],
      "extensions": {
        "code": "validation_failed",
        "details": { "email": "must be a valid email address" },
        "request_id": "2579cf15-c1ef-4ca5-8c48-7c42630ea5e5"
      }
    }
  ],
  "data": { "register": null }
}
```

`path` names the field that failed, by its alias if it has one.

### HTTP status

| Status | When |
|---|---|
| `200` | The request was a JSON object with a `query`. This includes documents that fail to parse or validate, and fields that fail: look at `errors`, not at the status. |
| `400` | The body is not a single JSON object (`invalid_json`), or has no `query` (`validation_failed`). |
| `413` | The body is larger than 1 MiB (`payload_too_large`). |
| `415` | `Content-Type` is not `application/json` (`unsupported_media_type`). |
| `405` | Any method other than `POST`. The HTTP router answers this one, in the REST error envelope. |

The `400`, `413` and `415` responses have the GraphQL shape, without `data`:

```
HTTP/1.1 415 Unsupported Media Type
Content-Type: application/json; charset=utf-8

{"errors":[{"message":"Content-Type must be application/json","extensions":{"code":"unsupported_media_type","request_id":"e0fd8668-861f-4c67-8f3a-be1172a12f08"}}]}
```

Because field errors are `200`, the `WWW-Authenticate` and `Retry-After` headers of the
REST API are not sent. A rate-limited field carries the wait in
`extensions.details.retry_after_seconds`.

### Codes

Fields report the codes of the REST API: `unauthenticated`, `invalid_token`,
`forbidden`, `not_found`, `validation_failed`, `invalid_credentials`, `invalid_client`,
`account_locked`, `rate_limited`, `invalid_grant` and so on. Two cases are specific to
GraphQL:

| Code | Meaning |
|---|---|
| `invalid_query` | The document was refused before execution: a syntax error, an unknown field or argument, a value of the wrong type, or one of the limits below. `message` says which. The response has no `data`. |
| `internal_error` | Something failed inside Keyora. The message is always `an internal error occurred`; the cause is in the server log under the same request ID. |

A document that is refused looks like this:

```json
{
  "errors": [
    {
      "message": "Cannot query field \"passwordHash\" on type \"User\".",
      "locations": [{ "line": 1, "column": 15 }],
      "extensions": {
        "code": "invalid_query",
        "request_id": "d5cebddb-8787-4ab4-99bf-3667f319d8a0"
      }
    }
  ]
}
```

## Limits

| Limit | Value | When exceeded |
|---|---|---|
| Request body | 1 MiB | `413 payload_too_large` |
| Document (`query`) length | 16 KiB | `invalid_query` |
| Nesting depth | 16 levels | `invalid_query` |
| Fields after fragments are expanded | 2,000 | `invalid_query` |
| Resolvers of one query running at once | 4 | The rest wait. |

The API's own types nest at most three levels. The depth allowance is for introspection
queries.

### Rate limiting

The fields that take credentials are rate limited per client address, with the budget
set by `KEYORA_RATE_LIMIT_PER_MINUTE` and `KEYORA_RATE_LIMIT_BURST`: `register`,
`login`, `refresh`, `logout`, `introspectToken`, `requestEmailVerification`,
`confirmEmail`, `forgotPassword`, `resetPassword`, `authorize`, `token` and `userinfo`.

The limit is counted **per field, not per HTTP request**. A document that repeats
`login` under 25 aliases spends 25 units, and the budget is shared with the REST API.
Once it is spent, the remaining fields fail without looking at their arguments:

```json
{
  "message": "too many requests",
  "path": ["a25"],
  "extensions": {
    "code": "rate_limited",
    "details": { "retry_after_seconds": "1" },
    "request_id": "a41400a2-4e3e-43c2-a30b-fd768664b4a5"
  }
}
```

The account lockout after repeated wrong passwords applies as well, as it does for REST.

## Examples

The examples assume Keyora on `localhost:8080` and `KEYORA_ADMIN_KEY` in the
environment. Responses are formatted for reading and long tokens are cut with `...`.

### Create a tenant and an application

```sh
curl -s localhost:8080/graphql \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"query": "mutation { createTenant(slug: \"acme\", name: \"Acme\") { id slug name status createdAt } }"}'
```

```json
{
  "data": {
    "createTenant": {
      "id": "50acb8fe-8e52-488c-97a9-da945b22bb38",
      "slug": "acme",
      "name": "Acme",
      "status": "active",
      "createdAt": "2026-11-28T02:10:22.892Z"
    }
  }
}
```

Put the tenant ID in `TENANT_ID`, then register a server-side application. Values go in
`variables`, which keeps the document itself free of quoting.

```sh
curl -s localhost:8080/graphql \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"query": "mutation($t: ID!, $in: ApplicationInput!) { createApplication(tenantId: $t, input: $in) { application { id clientId type status } clientSecret } }",
       "variables": {"t": "'$TENANT_ID'", "in": {"name": "backend"}}}'
```

```json
{
  "data": {
    "createApplication": {
      "application": {
        "id": "878a00ef-ce44-4333-a44c-42944bea8afe",
        "clientId": "app_0d9513e9c4f94021bf6ad6cf5ab6fdfd",
        "type": "confidential",
        "status": "active"
      },
      "clientSecret": "kys_6y4asKSazRSpg4abkTXnxVpGiTFdKCw7rRe-0OUlxks"
    }
  }
}
```

`clientSecret` is returned here and by `rotateApplicationSecret`, and nowhere else.
Keyora stores only a hash of it. Put the two values in `CLIENT_ID` and `CLIENT_SECRET`.

### Register and sign in

```sh
curl -s localhost:8080/graphql -u "$CLIENT_ID:$CLIENT_SECRET" -H "Content-Type: application/json" \
  -d '{"query": "mutation($email: String!, $password: String!) { register(email: $email, password: $password, name: \"Ada\") { id email emailVerified } }",
       "variables": {"email": "ada@example.com", "password": "correct horse battery"}}'
```

```json
{
  "data": {
    "register": {
      "id": "623b83bf-0eb4-412c-a868-c25126bf865e",
      "email": "ada@example.com",
      "emailVerified": false
    }
  }
}
```

```sh
curl -s localhost:8080/graphql -u "$CLIENT_ID:$CLIENT_SECRET" -H "Content-Type: application/json" \
  -d '{"query": "mutation($email: String!, $password: String!) { login(email: $email, password: $password) { tokens { accessToken tokenType expiresIn refreshToken refreshExpiresIn sessionId } user { id email } } }",
       "variables": {"email": "ada@example.com", "password": "correct horse battery"}}'
```

```json
{
  "data": {
    "login": {
      "tokens": {
        "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...",
        "tokenType": "Bearer",
        "expiresIn": 900,
        "refreshToken": "kyr_1g57LV7o87D3knGU...",
        "refreshExpiresIn": 2592000,
        "sessionId": "5b460ac4-72cf-452f-a2a7-97f62f275ed1"
      },
      "user": {
        "id": "623b83bf-0eb4-412c-a868-c25126bf865e",
        "email": "ada@example.com"
      }
    }
  }
}
```

The same call with the credentials as arguments instead of HTTP Basic:

```sh
curl -s localhost:8080/graphql -H "Content-Type: application/json" \
  -d '{"query": "mutation($id: String, $secret: String) { login(email: \"ada@example.com\", password: \"correct horse battery\", clientId: $id, clientSecret: $secret) { tokens { tokenType expiresIn } } }",
       "variables": {"id": "'$CLIENT_ID'", "secret": "'$CLIENT_SECRET'"}}'
```

```json
{
  "data": {
    "login": {
      "tokens": {
        "tokenType": "Bearer",
        "expiresIn": 900
      }
    }
  }
}
```

### Read the signed-in user

With the access token in `ACCESS_TOKEN`, one request can read the profile and the
sessions:

```sh
curl -s localhost:8080/graphql -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"query": "{ me { user { id email name emailVerified lastLoginAt } roles permissions } mySessions { total items { id ip createdAt } } }"}'
```

```json
{
  "data": {
    "me": {
      "user": {
        "id": "623b83bf-0eb4-412c-a868-c25126bf865e",
        "email": "ada@example.com",
        "name": "Ada",
        "emailVerified": false,
        "lastLoginAt": "2026-11-28T02:10:23.287Z"
      },
      "roles": [],
      "permissions": []
    },
    "mySessions": {
      "total": 2,
      "items": [
        {
          "id": "12880486-08f1-48fd-bd8d-6455a7eb3ffd",
          "ip": "127.0.0.1",
          "createdAt": "2026-11-28T02:10:23.287Z"
        },
        {
          "id": "5b460ac4-72cf-452f-a2a7-97f62f275ed1",
          "ip": "127.0.0.1",
          "createdAt": "2026-11-28T02:10:23.159Z"
        }
      ]
    }
  }
}
```

There are two sessions because the user signed in twice above.

### Authorization code with PKCE

This flow is for public applications, which hold no secret. Register one with the
redirect URI it uses:

```sh
curl -s localhost:8080/graphql \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"query": "mutation($t: ID!, $in: ApplicationInput!) { createApplication(tenantId: $t, input: $in) { application { clientId type redirectUris allowedOrigins } clientSecret } }",
       "variables": {"t": "'$TENANT_ID'", "in": {"name": "web-app", "type": "public",
         "redirectUris": ["https://app.example.com/callback"], "allowedOrigins": ["https://app.example.com"]}}}'
```

```json
{
  "data": {
    "createApplication": {
      "application": {
        "clientId": "app_290edd5fbf8a4d6a8f255fa2d59b507a",
        "type": "public",
        "redirectUris": ["https://app.example.com/callback"],
        "allowedOrigins": ["https://app.example.com"]
      },
      "clientSecret": null
    }
  }
}
```

Put its client ID in `PUBLIC_CLIENT_ID`. The application makes a random code verifier
and sends its SHA-256 digest as the challenge:

```sh
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=\n')
```

`authorize` takes the authorization request together with the user's email and
password, and returns the code:

```sh
curl -s localhost:8080/graphql -H "Content-Type: application/json" \
  -d '{"query": "mutation($in: AuthorizeInput!) { authorize(input: $in) { code state redirectUri redirectTo expiresIn iss } }",
       "variables": {"in": {"clientId": "'$PUBLIC_CLIENT_ID'", "redirectUri": "https://app.example.com/callback",
         "state": "af0ifjsldkj", "scope": "openid profile",
         "codeChallenge": "'$CHALLENGE'", "codeChallengeMethod": "S256",
         "email": "ada@example.com", "password": "correct horse battery"}}}'
```

```json
{
  "data": {
    "authorize": {
      "code": "kyc_SCAWrWA8LJKxL9HoI2NUuPL60-gHz77j0hbgTqZDMFA",
      "state": "af0ifjsldkj",
      "redirectUri": "https://app.example.com/callback",
      "redirectTo": "https://app.example.com/callback?code=kyc_SCAWrWA8LJKxL9HoI2NUuPL60-gHz77j0hbgTqZDMFA&iss=http%3A%2F%2Flocalhost%3A8080&state=af0ifjsldkj",
      "expiresIn": 60,
      "iss": "http://localhost:8080"
    }
  }
}
```

The code is valid for 60 seconds and for one use. With it in `CODE`, exchange it and the
verifier for tokens:

```sh
curl -s localhost:8080/graphql -H "Content-Type: application/json" \
  -d '{"query": "mutation($in: TokenInput!) { token(input: $in) { accessToken tokenType expiresIn refreshToken idToken scope } }",
       "variables": {"in": {"grantType": "AUTHORIZATION_CODE", "clientId": "'$PUBLIC_CLIENT_ID'", "code": "'$CODE'",
         "redirectUri": "https://app.example.com/callback", "codeVerifier": "'$VERIFIER'"}}}'
```

```json
{
  "data": {
    "token": {
      "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...",
      "tokenType": "Bearer",
      "expiresIn": 900,
      "refreshToken": "kyr_xJDxGrhlzJd2aztC...",
      "idToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...",
      "scope": "openid profile"
    }
  }
}
```

`idToken` is present because the `openid` scope was requested. Sending the same request
again fails, and revokes the tokens issued from the code:

```json
{
  "errors": [
    {
      "message": "authorization code is invalid, expired, already used, or does not match this request",
      "path": ["token"],
      "extensions": {
        "code": "invalid_grant",
        "request_id": "84d9f7cf-6a15-47d4-8e29-fbdb77fabc9e"
      }
    }
  ],
  "data": { "token": null }
}
```

`token` also takes `grantType: REFRESH_TOKEN` with `refreshToken`, and
`grantType: CLIENT_CREDENTIALS` with the credentials of a confidential application.

### List users

```sh
curl -s localhost:8080/graphql \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"query": "query($t: ID!) { users(tenantId: $t, limit: 10) { items { id email status emailVerified } total limit offset } }",
       "variables": {"t": "'$TENANT_ID'"}}'
```

```json
{
  "data": {
    "users": {
      "items": [
        {
          "id": "623b83bf-0eb4-412c-a868-c25126bf865e",
          "email": "ada@example.com",
          "status": "active",
          "emailVerified": false
        }
      ],
      "total": 1,
      "limit": 10,
      "offset": 0
    }
  }
}
```

### A partial result

The same query sent with an ordinary user's access token, together with `me`. The user
may read their own profile but not the tenant's users, so one field has data and the
other an error. The status is `200`.

```sh
curl -s -i localhost:8080/graphql -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" -H "X-Request-ID: demo-1" \
  -d '{"query": "query($t: ID!) { me { user { email } } users(tenantId: $t) { total } }", "variables": {"t": "'$TENANT_ID'"}}'
```

```
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Content-Type: application/json; charset=utf-8
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Request-Id: demo-1
Content-Length: 214

{"errors":[{"message":"you do not have permission to perform this action","path":["users"],"extensions":{"code":"forbidden","request_id":"demo-1"}}],"data":{"me":{"user":{"email":"ada@example.com"}},"users":null}}
```

## Differences from REST

The operations and their rules are the same. The wire format differs in these ways:

- **Status codes.** Field errors are `200` with an `errors` entry; REST uses `4xx`.
- **Token errors.** REST's `/api/v1/oauth/token` uses the OAuth 2.0 error format. The
  `token` field uses GraphQL errors, with the same codes: `invalid_client` when the
  application cannot be authenticated, and `invalid_grant` for every unusable code or
  refresh token, without saying why.
- **Unknown input.** REST answers `invalid_json` for an unknown body field. GraphQL
  refuses an unknown argument or input field with `invalid_query`, and nothing in the
  document runs.
- **What cannot be changed.** REST rejects `email` and `password` in a user update and
  `slug` in a tenant update. `updateUser` and `updateTenant` have no such arguments.
- **Content type.** A wrong `Content-Type` is `415` here and `400` for REST, and here
  the header may not be omitted.
- **Token introspection.** `introspectToken` returns `subject`, `tenantId`,
  `sessionId`, `issuer`, `expiresAt` and `issuedAt` (as `Time`) where REST returns
  `sub`, `tid`, `sid`, `iss`, `exp` and `iat` (as Unix seconds).
- **Pagination.** `limit`, `offset` and `total` are fields of the list result; REST puts
  them in `meta.pagination`.

## References

- [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)
