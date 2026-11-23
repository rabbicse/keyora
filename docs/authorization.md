# Authorization and administration

Who may do what — in your applications, and in Keyora itself.

## The model

```
Tenant
 ├── Applications        clients that sign users in
 ├── Users
 ├── Permissions         names you define:  orders:read, invoices:approve
 └── Roles               named sets of permissions:  viewer, editor
      └── assigned to users
```

- A **permission** is a string you choose. Keyora attaches no meaning to it; your
  application does. `resource:action` is a good convention.
- A **role** groups permissions. Users get roles, never permissions directly.
- A user's effective permissions are the union over their roles.

Everything is scoped to one tenant. Two tenants can each have a role called `editor`
with different permissions.

## Set it up

All of this uses the management API; `$T` is `/api/v1/tenants/$TENANT_ID` and `$AUTH`
is an administrator credential (see [below](#who-can-administer)).

```sh
# 1. Define permissions
curl -X POST localhost:8080$T/permissions -H "Authorization: Bearer $AUTH" \
  -H "Content-Type: application/json" -d '{"name": "orders:read", "description": "View orders"}'
curl -X POST localhost:8080$T/permissions -H "Authorization: Bearer $AUTH" \
  -H "Content-Type: application/json" -d '{"name": "orders:write"}'

# 2. Create a role with them
curl -X POST localhost:8080$T/roles -H "Authorization: Bearer $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"name": "editor", "permissions": ["orders:read", "orders:write"]}'
# → {"data": {"id": "<ROLE_ID>", …}}

# 3. Assign the role to a user
curl -X PUT localhost:8080$T/users/$USER_ID/roles/$ROLE_ID -H "Authorization: Bearer $AUTH"
```

Change a role's permissions later with `PUT $T/roles/{id}/permissions`; it replaces the
whole set.

## Enforce it in your application

Roles and permissions arrive in the access token:

```json
{ "roles": ["editor"], "permissions": ["orders:read", "orders:write"] }
```

Check them after verifying the token. **Prefer permissions over roles** in code:
`orders:write` keeps meaning the same thing when you later reorganise which roles
have it.

```go
mux.Handle("POST /orders", g.Middleware(guard.RequirePermission("orders:write")(createOrder)))
mux.Handle("GET /reports", g.Middleware(guard.RequireRole("editor", "admin")(reports)))
```

`RequirePermission` needs every listed permission; `RequireRole` needs any one listed
role. The examples show the same two checks in each language.

### When changes take effect

The token carries a snapshot.

| Change | Seen by local token verification | Seen by introspection and by Keyora's own API |
|---|---|---|
| Role assigned or removed | At the next refresh or login (within the access-token lifetime) | Immediately |
| Role's permissions changed | Same | Immediately |
| User disabled / session revoked | When the token expires | Immediately |

For checks that cannot tolerate the delay, use `POST /api/v1/auth/introspect`, which
returns the user's current roles and permissions.

### Resource-level rules

"Editors can edit orders" is RBAC and belongs in Keyora. "Users can edit *their own*
orders" depends on your data and belongs in your application: verify the token, then
compare `sub` with the owner of the row. Keyora does not model your resources.

## Who can administer

| Credential | Scope | Typical use |
|---|---|---|
| **Root admin key** — `Authorization: Bearer $KEYORA_ADMIN_KEY` | Every tenant. The only credential that can create, list or suspend tenants. | Bootstrap, automation, break-glass. |
| **Tenant administrator** — the access token of a user who has the `keyora:admin` permission | That user's own tenant only. Everything under `/api/v1/tenants/{their tenant}`. | Day-to-day administration, an admin console. |

Every tenant is created with a `keyora-admin` role holding `keyora:admin`. Make
someone a tenant administrator by assigning that role:

```sh
curl localhost:8080$T/roles -H "Authorization: Bearer $KEYORA_ADMIN_KEY"     # find the keyora-admin role id
curl -X PUT localhost:8080$T/users/$USER_ID/roles/$ADMIN_ROLE_ID \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"
```

For management calls Keyora reads the caller's roles from the database on every
request, so granting or removing `keyora:admin` takes effect on the very next call,
even for an access token issued earlier.

Guard rails:

- The `keyora:` permission prefix is reserved; tenants cannot define `keyora:anything`.
- The `keyora-admin` role cannot be deleted, renamed, or stripped of `keyora:admin`.
- A tenant administrator can grant `keyora-admin` to others in the tenant. That is
  intended: they administer the tenant. They cannot reach any other tenant.
- The root key has no user identity: it cannot call `/api/v1/users/me`.

Treat the root key like a database superuser password. Prefer tenant administrators
for routine work, since their actions are attributed to a person in the audit trail.

## Applications

An application is a client of Keyora within a tenant.

| Type | For | Credentials | Extra protection |
|---|---|---|---|
| `confidential` | Anything with a server: web backends, APIs, workers | `client_id` + `client_secret` | The secret. |
| `public` | Code that cannot keep a secret: single-page apps, mobile apps | `client_id` only | Requests carrying a browser `Origin` are accepted only from `allowed_origins`. |

```sh
# A backend
curl -X POST localhost:8080$T/applications -H "Authorization: Bearer $AUTH" \
  -H "Content-Type: application/json" -d '{"name": "orders-api", "type": "confidential"}'

# A single-page app
curl -X POST localhost:8080$T/applications -H "Authorization: Bearer $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"name": "web-app", "type": "public", "allowed_origins": ["https://app.example.com"]}'
```

Per-application settings:

| Field | Effect |
|---|---|
| `allowed_origins` | Browser origins that may call Keyora for this application. Also drives CORS. |
| `redirect_uris` | Where the authorization code flow may send users back. Matched exactly. Required to use that flow. |
| `access_token_ttl_seconds` | 60 – 86400. Shorter means faster revocation, more refreshes. |
| `refresh_token_ttl_seconds` | How long an unused session survives. |
| `status` | `disabled` rejects the application's credentials at once. |

Rotate a leaked secret with `POST $T/applications/{id}/rotate-secret`. The old secret
stops working immediately, so deploy the new one right away. Only confidential
applications can call introspection or use the client-credentials grant.

Deleting an application deletes its sessions.

## Users, sessions and the audit trail

| Task | Call |
|---|---|
| Create a user directly | `POST $T/users` |
| Find users | `GET $T/users?email=ada&status=active` |
| Disable a user (revokes their sessions) | `PATCH $T/users/{id}` `{"status": "disabled"}` |
| Clear a lockout | `POST $T/users/{id}/unlock` |
| See where a user is signed in | `GET $T/sessions?user_id=…&active=true` |
| Sign a device out | `DELETE $T/sessions/{id}` |
| Review security events | `GET $T/audit-events?type=user.login.failed` |

Audit event types include `user.registered`, `user.login.succeeded`,
`user.login.failed`, `user.locked`, `user.logout`, `token.refreshed`,
`token.reuse_detected`, `user.password.changed`, `user.password.reset`,
`user.email.verified`, `session.revoked`, and `application.*`, `role.*`,
`permission.*`, `user.role.*`, `tenant.*` for administrative changes. Each records the
actor, target, IP address, user agent and request ID.
