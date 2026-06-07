# Scenario Fixtures

This directory contains scenario fixtures that turn narrative usage scenarios into structured test data.

## Goals

- keep scenario inputs concrete enough for future `ScenarioRunner` and E2E use
- keep fixtures aligned with the current L0 JSON Schemas
- record forward-looking cases without forcing premature schema changes

## Files

- `scenario-1-data.json`: B2B procurement golden-path-aligned fixture
- `scenario-2-data.json`: content publishing fixture using the `PUBLISH` action
- `scenario-3-data.json`: query boundary-study fixture

## Validation Model

Today, the repository validates these fixtures in two layers

1. `pnpm docs:check`
2. `pnpm test`

The Vitest suite performs the schema assertions through `validateAgainstSchema`, while `docs:check` verifies that the scenario fixtures, the TypeDoc config, and the core documentation artifacts stay in place.

## Notes

`scenario-1` and `scenario-2` are intended to be directly reusable by future automated tests.

`scenario-3` is intentionally split

- the principal, agent document, and envelope artifacts remain schema-compatible
- the requested `QUERY` capability is preserved as structured pending data because `QUERY` is not yet part of the current action vocabulary

This keeps the fixture useful for design and future implementation without weakening the current L0 contract.
