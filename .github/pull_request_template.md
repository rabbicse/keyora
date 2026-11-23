## What does this change, and why?

<!-- The problem being solved and the approach taken. Link the issue if there is one. -->

## How was it verified?

<!-- Commands you ran and what they showed. "make check" at minimum. -->

## Checklist

- [ ] `make check` passes (formatting, vet, zero core dependencies, tests with the race detector)
- [ ] New behaviour has tests; security-relevant behaviour has a test that fails without the change
- [ ] Storage changes pass the conformance suite on SQLite and PostgreSQL, and come with a new numbered migration (existing migrations are never edited)
- [ ] API changes are reflected in `api/openapi.yaml` (`make lint-openapi`) and in the docs
- [ ] No new dependency in the core module; any dependency elsewhere is justified in the description
- [ ] `CHANGELOG.md` updated under "Unreleased"
