# Security policy

Keyora is identity infrastructure, so security reports get priority over everything
else.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:

**[Report a vulnerability](https://github.com/rabbicse/keyora/security/advisories/new)**
(repository → Security → Advisories → Report a vulnerability)

Please include:

- what an attacker can do, and what they need to do it;
- the Keyora version or commit, database, and relevant configuration;
- steps or a proof of concept — exact requests and responses are ideal;
- any suggested fix.

Remove real secrets, tokens and personal data from anything you send.

## What to expect

- An acknowledgement within 3 working days.
- An initial assessment within 10 working days.
- A fix developed privately, then released with an advisory that credits you unless
  you prefer otherwise.

Please allow a reasonable time for a fix before disclosing publicly. This is a
volunteer-maintained project; these are targets, not a contractual commitment.

## Supported versions

Keyora is pre-1.0. Security fixes are applied to the latest release only.

## Scope

In scope: the Keyora server, the `jwt` and `guard` packages, the Gin adapter, the
container image, and the configuration examples in `deploy/`.

Especially interesting:

- authentication or authorization bypass; privilege escalation;
- crossing tenant boundaries;
- token forgery, or acceptance of a token that should be rejected;
- defeating refresh-token or authorization-code single use, or PKCE;
- open redirects or CSRF in the authorization flow;
- injection, or leakage of secrets into logs or responses.

Out of scope:

- vulnerabilities in the example applications under `examples/` (report them as
  ordinary bugs — they are teaching code, though a mistake that teaches something
  insecure is worth fixing quickly);
- findings that require a compromised host, database or signing key;
- missing features already listed in the [roadmap](docs/roadmap.md), such as MFA;
- the documented trade-offs in [docs/security.md](docs/security.md#known-trade-offs),
  unless you can show they are worse than described;
- volumetric denial of service.

## Security model

How Keyora is designed to resist attack, and where its limits are, is described in
[docs/security.md](docs/security.md). Keyora has not yet had an independent audit.
