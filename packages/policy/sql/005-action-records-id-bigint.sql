-- 005-action-records-id-bigint.sql
-- promote policy.action_records.id from SERIAL (int4, max 2.1B) to BIGINT

-- Background:
-- - The ledger system is append-only and immutable; row count grows without bound. The int4 ceiling of 2_147_483_647 is unacceptable.
-- - The routing layer (action-record-routes.ts) already assumes BIGSERIAL:
-- * rowToRecord uses BigInt(row.id)
-- * snapshotMaxId / cursorId are all bigint
-- Passing the tests only via the pg driver's implicit cast is not true type safety.

-- Operations:
-- 1) Promote the column type from INTEGER to BIGINT (data preserved, indexes rebuilt automatically).
-- 2) Promote the associated sequence (action_records_id_seq) to BIGINT in sync.
-- 3) Ceiling: 2^63 - 1 = 9.2 × 10^18, effectively unbounded for a ledger.

-- Note: ALTER COLUMN TYPE requires an ACCESS EXCLUSIVE LOCK on large tables; production deployments should schedule
-- a low-traffic window or use pg_repack/online migration (this repository's current data volume can run it directly).

ALTER TABLE policy.action_records
    ALTER COLUMN id TYPE BIGINT;

ALTER SEQUENCE policy.action_records_id_seq AS BIGINT;
