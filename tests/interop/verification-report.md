# Interop Verification Report

**Date** 2026-04-03 
**Implementation A** `@coivitas` reference implementation (TypeScript, v0.1.0) 
**Implementation B** Node.js standard library / OpenSSL Ed25519 verifier

## Scope

This report covers the interop verification parts that can be executed inside the repository without an external partner implementation

- wire-format conformance validation for the four frozen root fixtures
- independent Ed25519 signature verification against generated interop vectors

It does not claim completion of the full two-stack handshake scenario. That step still requires an external implementation or independent verifier process outside this workspace.

## Executed Suites

### 1. Conformance suite

Test file

- `tests/interop/conformance-suite.test.ts`

Validated fixture sets

- `tests/fixtures/conformance/agent-identity-document.json`
- `tests/fixtures/conformance/capability-token.json`
- `tests/fixtures/conformance/negotiation-envelope.json`
- `tests/fixtures/conformance/action-record.json`

Validation behavior

- valid samples must pass the frozen schema
- invalid samples must fail the frozen schema or parser contract
- boundary samples must match the `valid` flag declared in the fixture

### 2. Ed25519 cross-library verification

Test file

- `tests/interop/ed25519-cross-library.test.ts`

Vector source

- `tests/fixtures/interop/ed25519-vectors.json`

Method

- vectors are generated from the Alpha-owned signing fixture
- signatures are verified with Node's built-in Ed25519 implementation rather than the repository's `@noble/curves` path

## Result Summary

| Suite | Total | Passed | Failed | Status |
| --------------------- | ----: | -----: | -----: | ------ |
| Conformance valid | 12 | 12 | 0 | PASS |
| Conformance invalid | 15 | 15 | 0 | PASS |
| Conformance boundary | 9 | 9 | 0 | PASS |
| Ed25519 cross-library | 2 | 2 | 0 | PASS |

## Conclusion

The repository now has a runnable interoperability support package for

- the four frozen wire-format fixture families are exercised from a single interop suite
- an independent verifier path exists for Ed25519 signatures using Node/OpenSSL
- machine-readable summary data is available in `tests/fixtures/interop/interop-summary-2026-04-03.json`

## Remaining Work

To fully close the two-stack interoperability goal, the project still needs

1. a genuinely external implementation or verifier process
2. a recorded or CI-captured handshake + negotiation exchange between the two implementations
3. a follow-up report that adds full protocol-flow interoperability evidence
