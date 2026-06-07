-- 028a-bis_hcc_v0.2_pre_backfill_index.sql — hcc v0.2 Step A.2: CREATE INDEX CONCURRENTLY on chain_identity_jcs

-- Design intent:
-- Step A.2 (CREATE INDEX CONCURRENTLY; production-safe; does not lock the table for writes).
-- IMPORTANT: CREATE INDEX CONCURRENTLY is not allowed inside a transaction block — this file runs standalone; no BEGIN/COMMIT wrapper.
-- (PostgreSQL constraint: CONCURRENTLY requires an autocommit context; inside a transaction block it errors out)

-- Run-order constraints:
-- Run after 028a_hcc_v0.2_pre_backfill.sql (the chain_identity_jcs column already exists)
-- Run before the application script backfill (build the index first; the backfill UPDATE then performs better)
-- No strict ordering dependency with 028a — either may run in any order before the backfill.

-- Performance notes:
-- CREATE INDEX CONCURRENTLY = does not acquire an ACCESS EXCLUSIVE lock; does not block table writes
-- production-safe for large-table scenarios ( production-safe ).

-- Step A.2: index on the chain_identity_jcs column (CONCURRENTLY; no table lock; production-safe)
-- Note: this file contains no BEGIN/COMMIT — CREATE INDEX CONCURRENTLY cannot run inside a transaction block
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_hash_chain_entries_chain_identity_jcs
    ON hash_chain_entries (chain_identity_jcs);
