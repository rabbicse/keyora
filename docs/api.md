# API conventions

The complete reference is the OpenAPI description: [`api/openapi.yaml`](../api/openapi.yaml),
also served by a running Keyora at `/api/v1/openapi.yaml`. Load it into Swagger UI,
Redoc, Postman or a client generator. A test keeps it in step with the server's
routes, in both directions.

This page covers what is common to all endpoints.

## Versioning

Everything under `/api/v1` is versioned. Within `v1`, changes are additive: new
endpoints, new optional request fields, new response fields, new error codes. Clients
should ignore response fields they do not know. Anything that would break a client
goes to `/api/v2`.

Until Keyora reaches 1.0 this is a goal, not yet a guarantee; breaking changes are
called out in the [changelog](../CHANGELOG.md).

Operational and discovery endpoints (`/livez`, `/readyz`, `/healthz`, `/metrics`,
`/.well-known/jwks.json`, `/.well-known/oauth-authorization-server`) are unversioned
and do not use the envelope.

## Endpoint map

| Area | Base path | Caller |
|---|---|---|
| Sign-up, sign-in, tokens | `/api/v1/auth/*` | Application credentials |
| OAuth 2.0: browser sign-in (PKCE), token endpoint | `/api/v1/oauth/authorize`, `/api/v1/oauth/token` | Browser; application |
| A user's own account | `/api/v1/users/me*` | User access token |
| Tenants | `/api/v1/tenants` | Root admin key |
| Applications, users, roles, permissions, sessions, audit | `/api/v1/tenants/{tenant_id}/*` | Root admin key or tenant administrator |

## Requests

- Bodies are JSON with `Content-Type: application/json`, at most 1 MiB.
- **Unknown fields are rejected** (`400 invalid_json`), so a misspelt field fails
  loudly instead of being ignored.
- `PATCH` changes only the fields present.
- IDs are UUIDs, except `client_id` (`app_…`).
- Timestamps are RFC 3339 in UTC.

## Responses

Success:

```json
{ "data": { "id": "…", "email": "ada@example.com" }, "meta": { "request_id": "…" } }
```

A list:

```json
{ "data": [ … ],
  "meta": { "request_id": "…", "pagination": { "limit": 20, "offset": 0, "total": 57 } } }
```

Failure:

```json
{ "error": { "code": "validation_failed", "message": "request validation failed",
             "details": { "password": "must be at least 8 characters" } },
  "meta": { "request_id": "…" } }
```

Operations with nothing to return answer `204 No Content` (or `202 Accepted` for the
email-sending endpoints) with an empty body.

The endpoints under `/api/v1/oauth/` are the exception to the envelope: they use the
OAuth 2.0 wire formats (RFC 6749) so that standard OAuth clients work with them. The
token endpoint answers `{"error": "invalid_grant", "error_description": "…"}`, and the
authorization endpoint serves HTML or redirects.

## Status codes

| Status | Meaning |
|---|---|
| `200` | Success with a body |
| `201` | Created |
| `202` | Accepted; an email may be sent |
| `204` | Success, no body |
| `400` | Malformed or invalid request |
| `401` | Missing or invalid credentials |
| `403` | Authenticated but not allowed |
| `404` | No such resource in this tenant, or no such route |
| `405` | Method not allowed (`Allow` header lists the valid ones) |
| `409` | Uniqueness conflict |
| `413` | Body larger than 1 MiB |
| `423` | Account locked (`Retry-After`) |
| `429` | Rate limited (`Retry-After`) |
| `500` | Internal error. The body never contains internals; use the request ID. |
| `503` | From `/readyz` only: the database is unreachable |

## Error codes

`error.code` is the stable contract. Messages are for humans and may change.

| Code | Status | When |
|---|---|---|
| `invalid_json` | 400 | Not JSON, wrong types, unknown field, or more than one JSON value |
| `unsupported_media_type` | 400 | `Content-Type` is not `application/json` |
| `validation_failed` | 400 | A field is invalid; `details` maps field → reason |
| `invalid_input` | 400 | The input contains characters the database cannot store |
| `invalid_verification_token` | 400 | Email-verification or reset token unknown, used or expired |
| `not_confidential` | 400 | Secret rotation on a public application |
| `payload_too_large` | 413 | Body over 1 MiB |
| `unauthenticated` | 401 | No bearer token |
| `invalid_token` | 401 | Access token invalid, expired, or its session was revoked |
| `invalid_client` | 401 | Application credentials missing or wrong, or application/tenant disabled |
| `invalid_credentials` | 401 | Wrong email or password |
| `invalid_refresh_token` | 401 | Refresh token unknown, expired, or from another application |
| `refresh_token_reused` | 401 | Refresh token used twice; the session is now revoked |
| `forbidden` | 403 | Caller lacks the right to do this |
| `origin_not_allowed` | 403 | Public application called from an unregistered origin |
| `account_disabled` | 403 | The user is disabled |
| `email_not_verified` | 403 | Verification is required and not done |
| `reserved` | 403 | Attempt to alter the built-in admin role or permission |
| `not_found` | 404 | Resource does not exist in this tenant |
| `route_not_found` | 404 | No such endpoint |
| `method_not_allowed` | 405 | Endpoint exists, method does not |
| `email_taken` | 409 | A user with this email exists in the tenant |
| `slug_taken` | 409 | A tenant with this slug exists |
| `name_taken` | 409 | An application, role or permission with this name exists in the tenant |
| `account_locked` | 423 | Too many failed sign-ins |
| `rate_limited` | 429 | Too many requests from this IP |
| `internal_error` | 500 | Unexpected failure |

## Pagination and filtering

List endpoints take `limit` (1–100, default 20) and `offset` (default 0) and return
newest first. `meta.pagination.total` is the count before paging.

Filters are query parameters and are specific to each list:

| List | Filters |
|---|---|
| Users | `email` (case-insensitive substring), `status` |
| Sessions | `user_id`, `active=true` |
| Audit events | `type` (exact), `actor_id` |

## Request correlation

Every response has an `X-Request-ID` header, repeated as `meta.request_id` and in
Keyora's access log. Send your own `X-Request-ID` (letters, digits, `.`, `_`, `-`; up
to 64 characters) and Keyora uses it, so one ID follows a request across your services
and Keyora. Anything else is replaced with a generated ID.

## Idempotency

- `PUT` and `DELETE` are idempotent by construction: assigning an assigned role, or
  setting the same permissions twice, changes nothing.
- `POST /api/v1/auth/logout` with a refresh token always answers `204`.
- Creation with a natural key (tenant slug, user email, application/role/permission
  name) is safe to retry: the second attempt gets `409`, not a duplicate.
- `POST /api/v1/auth/refresh` is deliberately **not** safe to retry with the same
  token — see [reuse detection](authentication.md#refresh).

There is no `Idempotency-Key` header support.

## Rate limits and CORS

`/api/v1/auth/*` and `/api/v1/oauth/*` are limited per client IP; a `429` carries
`Retry-After`. Other endpoints are not limited by Keyora.

Cross-origin browser requests are allowed from origins listed in
`KEYORA_CORS_ALLOWED_ORIGINS` and from every active application's `allowed_origins`.
Credentials mode is never enabled — tokens travel in the `Authorization` header, not
in cookies — which is also why the JSON API needs no CSRF tokens. The one HTML form
Keyora serves, the sign-in page, has its own CSRF protection.
