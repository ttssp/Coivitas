# Security Policy

We take security issues in Coivitas seriously. This document explains how to
report a vulnerability, what to expect after you do, and which versions are
currently receiving security fixes.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.0-alpha.x | ✓ current |
| < 0.1.0-alpha  | ✗         |

Coivitas is pre-1.0, experimental alpha software. Until a stable release
lands, only the latest `0.1.0-alpha.x` is supported. We may issue fixes as new
alpha releases, and APIs may change between them.

## Reporting a vulnerability

**Do not file a public GitHub issue, pull request, or discussion for a
security report.** Public disclosure of an unpatched vulnerability puts
every user at risk.

Instead, email the maintainer privately:

**`sundevil0405@gmail.com`**

> This project is currently maintained by an individual. Please use the email
> address above until a project alias is published; you may also use GitHub's
> private "Security Advisories" workflow on the repository.

Include as much of the following as you can:

- A description of the vulnerability and its impact.
- The affected component (e.g. `packages/policy/`, `packages/crypto/`) and
  version or commit.
- Step-by-step reproduction instructions or a minimal proof-of-concept.
- Any suggested mitigation, if you have one.
- Whether you would like to be credited in the public advisory (and how —
  name, handle, organization).

If you need to send sensitive information, ask in your first email and we
will arrange an encrypted channel. A project PGP key may be published here
in the future; until then, please request an out-of-band channel.

## What to expect

- **Acknowledgement**: within 5 business days of your initial email.
- **Initial assessment**: within 14 business days — we will confirm the
  report, ask follow-up questions, and share our severity assessment.
- **Fix & coordinated disclosure**: timing depends on severity and
  complexity. For critical issues we aim to ship a fix within 30 days of
  confirmation; less severe issues may take longer.

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):
please give us a reasonable window to ship a fix before disclosing the
vulnerability publicly. If you have a hard disclosure deadline (for
example, a conference talk), let us know in your first email so we can
plan around it.

## Scope

In scope:

- Cryptographic flaws in `packages/crypto/`, including signature
  verification, hashing, and canonicalization.
- Authorization bypasses in `packages/policy/` (scope escalation,
  delegation flaws, ledger tamper).
- Identity-layer issues in `packages/identity/` (DID forgery, token
  replay, federation trust failures).
- Transport / envelope vulnerabilities in `packages/communication/`.
- SDK or CLI bugs in `packages/sdk/` and `packages/sdk-python/` that
  enable a privilege escalation or information leak.
- Build-time supply-chain risks (lockfile drift, malicious dependency
  pull-through).

Out of scope:

- Findings from automated scanners without a working proof-of-concept.
- Denial of service from unbounded inputs in example code clearly marked
  as illustrative.
- Issues that require a malicious local environment (compromised
  developer machine, malicious editor extension, etc.).
- Vulnerabilities in dependencies — please report those upstream and let
  us know so we can pin or patch.

## After a fix ships

Once a fix is released we will:

- Publish a GitHub Security Advisory describing the issue and the fix.
- Credit the reporter in the advisory unless you asked to remain
  anonymous.
- Note the CVE (if one was assigned) in the changelog.

Thank you for helping keep Coivitas and its users safe.
