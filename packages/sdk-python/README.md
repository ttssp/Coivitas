# coivitas (Python)

Python SDK for Coivitas — 1:1 binding for `@coivitas/sdk` (TypeScript).

## Status

**Alpha (`0.1.0a1`)** — pre-1.0; the public API may still change.

The full public surface is implemented and exported (see `__all__` in
`coivitas/__init__.py`): `Orchestrator`, `ManagedServiceClient`,
`ScenarioRunner`, `run_golden_path`, the brand validators, and the
strict-mode `BaseModel` set, all in 1:1 correspondence with `@coivitas/sdk`.

One deliberate extension point remains open: `ManagedServiceClient` does not
ship a built-in HTTP transport. Its `resolve_did()` / `check_revocation()`
paths fail closed with `NotImplementedError` until you inject a transport or
subclass the client — see the class docstring for the override contract. This
is by design (the SDK consumes wire format; it does not mandate a network
stack), not a missing feature.

## Install (development)

```bash
cd packages/sdk-python
pip install -e ".[dev]"
```

## Verification

```bash
# Run from the repository root.
python -m pytest tests/python/conformance/test_basic.py -v
```

## Design principles

- **Wire format consume-only** — the Python SDK consumes wire-format
  definitions; it does not define them.
- **Strong brand validation** — every Brand type is
  `Annotated[str, AfterValidator(...)]`. `typing.cast` to bypass a brand
  validator is forbidden.
- **Strict mode** — every `BaseModel` uses `model_config = ConfigDict(strict=True)`.
  Implicit type coercion is forbidden.
- **Cross-language alignment** — the API surface is `snake_case` (PEP 8);
  the wire format is `camelCase`. Bridge via `Field(alias=...)` plus
  `model_dump(by_alias=True)`.

## Firewall (no TypeScript dependency)

This package does **not** depend on any TypeScript implementation:

- No imports from `packages/sdk/`, `packages/types/`, `packages/crypto/`, etc.
- Pattern values for brand validators are mirrored from the TypeScript
  schema definitions (`schemas.ts`).
- These mirrored pattern values live in `_brands.py` and are kept in sync
  with the TypeScript schemas manually; the cross-language interop tests
  (`tests/python/interop/`) guard against drift.
