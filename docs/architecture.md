# Coivitas Architecture

Coivitas is organized into six composable layers. Each layer ships as a
separate package under `packages/` and can be consumed independently.

## L0 — Types & Schemas (`packages/types/`)

JSON Schema definitions plus AJV strict-mode validation for every wire-format
object. Provides the canonical TypeScript types consumed by every higher
layer.

Key surfaces: `validateActionRecord()`, `validateHashChainEntry()`,
`HCC_VERSION_CURRENT` (Hash Chain Canonicalize protocol version).

## L1 — Crypto Primitives (`packages/crypto/`)

Ed25519 signing, deterministic SHA-256 / Keccak hashing, and RFC 8785 JCS
canonicalization. Built on `@noble/curves` and `@noble/hashes`. No async I/O
and no runtime configuration — every operation is pure.

## L2 — Identity (`packages/identity/`)

Decentralized identifiers (DIDs), capability tokens, and cross-domain
federation. DID methods are pluggable; the default is `did:key` for
self-sovereign identifiers.

## L3 — Policy & Audit (`packages/policy/`)

Runtime guards that gate actions against declared scopes, plus a
tamper-evident audit ledger backed by `policy.action_records` and a Hash
Chain Canonicalize chain. See [`packages/policy/sql/README.md`](../packages/policy/sql/README.md)
for the migration index.

## L4 — Communication (`packages/communication/`)

Signed envelopes with end-to-end encryption and a pluggable transport layer.
Bridges between MCP-style outbox semantics and Coivitas wire format.

## L5 — SDK & Orchestration (`packages/sdk/`, `packages/sdk-python/`)

TypeScript SDK plus CLI plus a golden-path demo (`pnpm run golden-path`).
A 1:1 Python binding (`packages/sdk-python/`) exposes the same surface to
data-science workflows.

## Layer dependencies

```
L5 ──► L4 ──► L3 ──► L2 ──► L1 ──► L0
                                    ▲
                                    │
        (all higher layers depend on L0 schemas)
```

Higher layers never depend on layers above them. The Python SDK consumes
schemas from L0 directly but does not import any TypeScript runtime — see
the **Firewall** section of [`packages/sdk-python/README.md`](../packages/sdk-python/README.md).
