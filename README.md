# Coivitas

> Verifiable identity, scoped authorization, auditable behavior, and accountable
> governance — the protocol substrate for a human-agent co-existence society.

> ⚠️ **Status: experimental alpha (`v0.1.0-alpha.1`, pre-1.0).** Coivitas is an
> early reference implementation published for research and evaluation. APIs and
> wire formats may change without notice between releases. It is **not
> production-ready** — do not use it for security-critical deployments yet.

Coivitas is an open protocol for environments where humans and autonomous
agents act side by side and every action must be attributable, bounded, and
auditable. It does not assume trust; it produces evidence.

## Capabilities

The protocol is organized into six composable layers:

- **L0 — Types & schemas.** JSON Schema + AJV validation for every wire object.
- **L1 — Crypto primitives.** Ed25519 signing, deterministic hashing, and
  RFC 8785 canonicalization on top of `@noble/curves` and `@noble/hashes`.
- **L2 — Identity.** Decentralized identifiers (DIDs), capability tokens, and
  cross-domain federation.
- **L3 — Policy & audit.** Runtime guards that gate actions against declared
  scopes, plus a tamper-evident audit ledger.
- **L4 — Communication.** Signed envelopes with end-to-end encryption and a
  pluggable transport layer.
- **L5 — SDK & orchestration.** TypeScript SDK, CLI, and a golden-path demo;
  a 1:1 Python binding exposes the same surface to data-science workflows.

## Quickstart

```bash
# Requires Node.js >= 20 and pnpm >= 9
pnpm install
pnpm build
pnpm run golden-path
```

`golden-path` exercises the full stack — issuing a DID, minting a scoped
token, signing an envelope, evaluating policy, and writing an audit entry —
in roughly five minutes.

For database-backed examples:

```bash
docker compose up -d    # starts Postgres 16 with the default coivitas role
pnpm run db:setup       # creates schemas in the coivitas_dev database
pnpm run db:migrate     # applies SQL migrations under packages/*/sql/
```

The default `docker-compose.yml` provisions a Postgres role named `coivitas`
(matching `PGUSER` in `scripts/db-setup.sh`). If you connect to an existing
Postgres instance instead, ensure a role named `coivitas` exists before
running migrations — otherwise `packages/policy/sql/004-enhance-action-records.sql`
silently skips its `REVOKE UPDATE, DELETE` (the SQL-layer append-only guard).
To use a different role name, override `PGUSER` in `.env` and patch the
REVOKE target accordingly.

## Repository layout

| Path | Purpose |
|---|---|
| `packages/types/` | L0 schemas |
| `packages/crypto/` | L1 primitives |
| `packages/identity/` | L2 DIDs, tokens, federation |
| `packages/policy/` | L3 guards & audit ledger |
| `packages/communication/` | L4 envelopes & transport |
| `packages/sdk/` | L5 TypeScript SDK + CLI |
| `packages/sdk-python/` | L5 Python binding |
| `examples/` | Runnable end-to-end scenarios |
| `tests/` | Unit, integration, conformance, interop, e2e |

## Testing

```bash
pnpm test                  # unit + package tests
pnpm run test:integration  # cross-package integration
pnpm run test:interop      # conformance + interop suites
pnpm run test:coverage     # coverage report
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
the DCO sign-off, commit conventions, and PR workflow, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.

To report a vulnerability privately, see [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
Copyright 2026 Coivitas Foundation Contributors.
