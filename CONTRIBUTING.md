# Contributing to Keyora

Thank you for considering a contribution. This document explains how to get set up
and what a change needs before it can be merged.

Security problems are the exception to everything here: report them privately, as
described in [SECURITY.md](SECURITY.md).

## Getting set up

You need Go 1.26 or newer (the core module itself needs only 1.24) and, optionally,
Docker for the PostgreSQL tests and Node.js for the OpenAPI lint.

```sh
git clone https://github.com/rabbicse/keyora && cd keyora
make check       # format check, vet, zero-dependency check, all tests with -race
make run         # build and start on :8080 with SQLite in ./data
```

`make help` lists every task. [docs/architecture.md](docs/architecture.md) explains
the layout; [docs/testing.md](docs/testing.md) explains the tests.

## Ground rules

1. **The core module has no third-party dependencies.** `make check-deps` enforces it.
   If a change seems to need one, open an issue first. Code that needs a dependency
   belongs in its own module, as the database drivers and the Gin adapter are.
2. **Security before convenience.** If a design decision has a security trade-off,
   say so in the pull request and in the docs.
3. **Do not claim what is not implemented.** Protocol names (OAuth 2.0, OpenID Connect,
   PKCE) appear in docs only for the parts that exist and are tested.
4. **Small changes.** One concern per pull request.

## What a change needs

- **Tests.** New behaviour is tested. A security rule comes with a test that fails
  when the rule is removed — try it.
- **Storage changes** go through `internal/store/storetest` so every backend must pass
  them, and come with a **new numbered migration**. Migrations that have shipped are
  never edited. Keep the SQL portable between SQLite and PostgreSQL.
- **API changes** are reflected in `api/openapi.yaml` (a test fails otherwise) and in
  `docs/`. Within `/api/v1`, changes are additive.
- **Formatting and vet**: `gofmt`, `go vet`. Nothing else is required; please do not
  add linters' opinions in unrelated lines.
- **A changelog entry** under "Unreleased" in [CHANGELOG.md](CHANGELOG.md) for anything
  a user would notice.

## Code style

- Standard Go style; names over comments, and comments that explain *why*.
- Errors that reach a client are `*domain.Error` values with a stable `Code`. Never
  return raw internal errors to clients, and never log secrets, tokens or passwords.
- Prefer a concrete type until there are two implementations.
- Time comes from the injected clock in services, never `time.Now()` directly.

## Commits and pull requests

- Write commit messages in the imperative: "Add session revocation endpoint".
- Describe what changed, why, and how you verified it. The pull request template has
  the checklist.
- CI must pass. A maintainer reviews; expect questions on anything touching
  authentication, tokens or tenant isolation.

## Versioning and releases

Keyora follows [Semantic Versioning](https://semver.org). Before 1.0, minor versions
may contain breaking changes, and the changelog calls them out.

The repository holds three Go modules, each tagged with its path prefix:

| Module | Tag |
|---|---|
| Core | `v0.2.0` |
| Server binary | `cmd/keyora/v0.2.0` |
| Gin adapter | `adapters/gin/v0.2.0` |

Pushing a `vX.Y.Z` tag runs the release workflow, which builds binaries and a
container image. The nested modules use `replace` directives for in-repository
development; to publish them for `go get`, the directive is replaced by a `require`
on the tagged core version in the release commit.

## License

By contributing you agree that your contributions are licensed under the project's
[GPL-3.0 license](LICENSE).
