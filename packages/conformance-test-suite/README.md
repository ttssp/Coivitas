# @coivitas/conformance-test-suite

A standalone, publishable Coivitas conformance test package that provides the `coivitas-conformance` CLI tool.

## Installation

```bash
# Inside the monorepo
pnpm add @coivitas/conformance-test-suite

# Global install (after publishing)
npm install -g @coivitas/conformance-test-suite
```

## CLI usage

### `coivitas-conformance run`

Run the full conformance test suite against a target:

```bash
coivitas-conformance run --target <endpoint> [--fixture <path>] [--report <format>] [--mode <schema|endpoint>] [--allow-skip]
```

Options:

| Option | Description | Default |
| -------------- | ------------------------------------------------------------ | ----------------------- |
| `--target` | Endpoint URL (in schema mode, only written into report metadata, advisory) | `http://localhost:3000` |
| `--fixture` | JSON fixture path (single file or directory) | built-in full v0.3.0 fixture set |
| `--report` | Output format: `json` or `markdown` | `json` |
| `--mode` | Run mode: `schema` (local validation) or `endpoint` (HTTP POST, implemented in v0.2) | `schema` |
| `--allow-skip` | A SKIP result does not trigger exit 1 (default: SKIP → exit 1) | `false` |

**About `--target` and `--mode` (important v0.1 note)**

- `--mode schema` (default): all fixtures are validated locally against the schema. `--target` is only written into report metadata and **no HTTP request is made**.
- `--mode endpoint`: fixtures are sent as HTTP POST to `--target` and the responses are validated. **Not yet implemented in v0.1** (fixture POST format TBD in v0.2); specifying it makes the CLI exit 2.
- This design ensures `coivitas-conformance run --target https://does-not-exist.invalid` is unaffected by endpoint reachability in schema mode and behaves fully deterministically.

Exit codes:

- `0`: all fixtures pass (PASS), with no SKIP (or `--allow-skip` is set)
- `1`: there is a FAIL, or there is a SKIP and `--allow-skip` is not set
- `2`: configuration error (fixture missing, malformed, `--mode endpoint` not implemented, etc.)

Examples:

```bash
# Run with the default fixtures, output a JSON report (schema mode, no HTTP request)
coivitas-conformance run --target http://my-endpoint:3000

# Specify a single fixture file, output Markdown
coivitas-conformance run \
 --target http://my-endpoint:3000 \
 --fixture ./tests/fixtures/conformance/v0.3.0/dual-key-rotation.v0.3.json \
 --report markdown

# Allow SKIP without failing (useful when fixtures contain DEFER cases)
coivitas-conformance run --target http://my-endpoint:3000 --allow-skip

# endpoint mode is unavailable in v0.1 (exits 2 and explains why)
coivitas-conformance run --target http://my-endpoint:3000 --mode endpoint # exit 2

# Show help
coivitas-conformance run --help
```

### Markdown report example

```markdown
# Coivitas Conformance Report

**Target** http://localhost:3000
**Date** 2026-01-01T00:00:00.000Z
**Result** FAIL (3 passed, 1 failed)

## Results

| Fixture ID | Status | Latency | Error |
| ---------- | ------ | ------- | ----- |
| xv-01 | PASS | 42ms | |
| xv-02 | PASS | 38ms | |
| xv-03 | FAIL | 51ms | schema validation failed |
| xv-04 | PASS | 45ms | |
```

## Three-tier certification process

`@coivitas/conformance-test-suite` is the core execution tool of the Coivitas certification process.

See: [conformance-certification-process.md](../../docs/governance/conformance-certification-process.md)

### Certification levels

| Level | Method | Certificate issuance |
| ---- | ---- | -------- |
| **Self-Assessed** | The implementer runs `coivitas-conformance` themselves + self-reports | no third-party issuance |
| **Verified** | A foundation-designated verifier runs `coivitas-conformance` + a verifier statement | verifier-signed statement |
| **Certified** | A foundation audit-run + certificate issuance | certificate issued by the foundation (once established) |

## Library API

```typescript
import { ConformanceRunner, generateReport } from '@coivitas/conformance-test-suite';

// Run the conformance tests
const runner = new ConformanceRunner({
 target: 'http://localhost:3000',
 fixturePaths: ['./fixtures/v0.3.0'],
});
const results = await runner.run();

// Generate a report
const jsonReport = generateReport(results, 'json');
const mdReport = generateReport(results, 'markdown');
```

## Development

```bash
# Build
pnpm --filter @coivitas/conformance-test-suite build

# Test
pnpm --filter @coivitas/conformance-test-suite test

# Coverage
pnpm --filter @coivitas/conformance-test-suite test:coverage
```

## Version compatibility

This package is aligned with the v0.3.0 wire format. Fixture sources:

- `tests/fixtures/conformance/v0.3.0/` (v0.3.0 batch, 8 fixture files)
- `tests/fixtures/conformance/` (historical baselines, v0.1.0 / v0.2.0)

No new wire-format fields are introduced.
