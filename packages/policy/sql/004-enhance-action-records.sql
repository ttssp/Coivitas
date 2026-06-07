-- 004-enhance-action-records.sql
-- Enforce ledger immutability -- only INSERT and SELECT are allowed
-- The ledger is an append-only system; UPDATE/DELETE would violate audit-chain integrity
-- Use a DO block to avoid an error if the role does not exist (idempotent migration)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coivitas') THEN
        REVOKE UPDATE, DELETE ON policy.action_records FROM coivitas;
    END IF;
END
$$;

-- Cursor-pagination composite index -- (created_at, id) supports keyset queries in O(log N)
-- Use the integer id as the secondary sort key (not record_id TEXT) to keep insertion order stable
CREATE INDEX IF NOT EXISTS idx_action_records_cursor
    ON policy.action_records (created_at ASC, id ASC);
