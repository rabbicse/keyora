# Roadmap

What Keyora does not do yet, roughly in order of priority. Nothing here is promised
for a date. Items move to the [changelog](../CHANGELOG.md) when they ship.

## Next

- **More of OpenID Connect.** The core is in place (ID tokens, `nonce`, userinfo,
  discovery). Still missing: `prompt` and `max_age`, `at_hash`, RP-initiated logout,
  and formal OpenID certification.
- **Single sign-on.** Signing in to a second application in the same tenant without
  asking for the password again, with single logout. Keyora is API only, so this is an
  API feature: the authorization request accepts proof of an existing session.
- **Consent as an API**, for when applications are not all first-party: the sign-in
  screen asks, Keyora records the answer.
- **Multi-factor authentication.** TOTP first (RFC 6238), then recovery codes.
- **Passkeys / WebAuthn.**

## After that

- **Social and external identity providers** (sign in with an upstream OAuth/OIDC provider).
- **Memory-hard password hashing** (Argon2id) as an opt-in, via a build that accepts
  the dependency.
- **MySQL** support in the SQL store.
- **Scopes and permissions for machine clients**, so client-credentials tokens can
  carry authority of their own.
- **Token revocation endpoint** (RFC 7009) and RFC 7662-format introspection alongside
  the current enveloped one.
- **Shared rate-limit state** for multi-instance deployments.
- **Per-tenant policies**: password rules, lockout thresholds, signing keys, issuers.
- **Webhooks and audit export** for SIEM integration.
- **`Idempotency-Key`** support on creation endpoints.
- **An admin console** (web UI) over the management API.
- **Published SDKs** for languages other than Go; today the other languages are served
  by documented examples.

## Process and assurance

- An independent security review before 1.0.
- Load testing with published numbers.
- Signed release artifacts and an SBOM.

## Explicitly not planned

- **The OAuth implicit flow and the resource-owner password grant.** Both are removed
  from OAuth 2.1 for good reasons.
- **PKCE `plain`.** Only `S256`.
- **Symmetric (HMAC) token signing.** Verifiers should never hold a key that can mint
  tokens.
- **Third-party dependencies in the core module.**
