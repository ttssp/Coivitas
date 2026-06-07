# Changelog

All notable changes to Coivitas will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] - 2026-06-07

Initial public alpha release. Experimental; APIs and wire formats may change
before a stable 0.1.0.

### Added

- **L0 — Types & schemas.** JSON Schema definitions for every wire object,
  with AJV-based runtime validation across the stack.
- **L1 — Crypto primitives.** Ed25519 signing, deterministic hashing, and
  RFC 8785 JSON canonicalization built on `@noble/curves` and
  `@noble/hashes`.
- **L2 — Identity.** Decentralized identifier (DID) issuance and
  resolution, capability-scoped tokens, and cross-domain federation
  primitives.
- **L3 — Policy & audit.** Runtime guards that gate actions against
  declared scopes, with a tamper-evident audit ledger backing every
  decision.
- **L4 — Communication.** Signed envelopes with end-to-end encryption and
  a pluggable transport layer.
- **L5 — SDK & orchestration.** TypeScript SDK and CLI, golden-path demo
  exercising the full stack, plus a 1:1 Python binding for
  data-science workflows.
- Conformance and interoperability test suites covering the protocol
  surface.
- Apache 2.0 license, DCO sign-off workflow, and Contributor Covenant 2.1
  code of conduct.

[0.1.0-alpha.1]: https://github.com/ttssp/Coivitas/releases/tag/v0.1.0-alpha.1
