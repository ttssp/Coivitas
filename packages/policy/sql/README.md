# `packages/policy/sql/` — SQL Migration Index

PostgreSQL migrations for `@coivitas/policy`. Migrations are applied in
numeric order by `scripts/db-migrate.sh` (see the root `README.md` for the
BYO-Postgres workflow).

## Constraints

- Migration numbers are append-only — never reuse a slot once published.
- Numbers are allocated by repository maintainers; coordinate via a pull
  request before claiming a new slot.

## Applied migrations

| # | Purpose | File |
|---|---|---|
| 001 | Create `policy.action_records` | `001-create-action-records.sql` |
| 002 | Create `policy.token_store` | `002-create-token-store.sql` |
| 003 | Add delegation-session columns to `action_records` | `003-add-delegation-session.sql` |
| 004 | Enhance `action_records` + append-only `REVOKE` | `004-enhance-action-records.sql` |
| 005 | Promote `action_records.id` to BIGINT | `005-action-records-id-bigint.sql` |
| 006 | Create `policy.envelope_ledger` (atomic claim/finalize) | `006-create-envelope-ledger.sql` |
| 007 | Create `policy.policy_change_records` | `007-create-policy-change-records.sql` |
| 008 | Create `policy.managed_service_tenants` | `008-create-managed-service-tenants.sql` |
| 010 | Create `policy.audit_side_table` (governor-lane shadow audit) | `010_audit_side_table.sql` |
| 011 | Create `policy.arbitration_records` (operator arbitration state machine) | `011_arbitration_records.sql` |
| 021 | Create `policy.hash_chain_entries` | `021_hash_chain_entries.sql` |
| 023 | Create `policy.revocation_records` | `023_revocation_records.sql` |
| 026 | Create `policy.atp_audit_events` | `026_atp_audit_events.sql` |
| 027 | Add FK + RLS to `atp_audit_events` | `027_atp_audit_events_fk_and_rls.sql` |
| 028a / 028a-bis / 028c | Hash Chain Canonicalize v0.2 schema migration | `028a_hcc_v0.2_pre_backfill.sql`, `028a-bis_hcc_v0.2_pre_backfill_index.sql`, `028c_hcc_v0.2_post_backfill.sql` |

> Slot `009` is intentionally reserved (was scoped to a feature that did not
> land).

## Reserved (planned)

| # | Purpose | Status |
|---|---|---|
| 012+ | Future migrations | Allocated by maintainers as features land |
