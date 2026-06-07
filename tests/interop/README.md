# Interop Tests

This directory contains interoperability support artifacts.

## Contents

- `conformance-suite.test.ts`
 validates the four frozen root wire-format fixture families
- `ed25519-cross-library.test.ts`
 verifies Ed25519 signatures with Node's standard library instead of the repository crypto path
- `verification-report.md`
 summarizes the executed suites and current conclusion

## Run

```bash
pnpm test:interop
```

## Related Data

- `tests/fixtures/interop/ed25519-vectors.json`
- `tests/fixtures/interop/interop-summary-2026-04-03.json`
