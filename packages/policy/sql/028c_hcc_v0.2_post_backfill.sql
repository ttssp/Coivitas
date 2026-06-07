-- 028c_hcc_v0.2_post_backfill.sql — hcc v0.2 Step C: post-backfill DDL

-- Design intent:
-- Step C DDL (post-backfill; NOT VALID + VALIDATE + SET NOT NULL; split across 5 transactions).
-- Never run this file before the application script has completed 100% of the backfill:
-- if any NULL row exists at SET NOT NULL time → ALTER fails closed → migration blocked (not rollback-able).

-- Completion-condition check (confirm manually before running this file):
-- SELECT COUNT(*) FROM hash_chain_entries
-- WHERE chain_identity_jcs IS NULL OR hcc_version = '1.0.0'
-- -- expect a return of 0; otherwise this file must not run

-- Performance notes (NOT VALID + VALIDATE lock-window split):
-- Step C.1: ADD CONSTRAINT NOT VALID — does not scan existing rows; only takes an ACCESS EXCLUSIVE lock on the catalog; short lock
-- Step C.2: VALIDATE CONSTRAINT — scans the whole table; only an ACCESS SHARE lock (does not block writes; slow but production-safe)
-- Step C.3: ADD CONSTRAINT NOT VALID + VALIDATE — same pattern as above
-- Step C.5: SET NOT NULL — a VALIDATED CHECK constraint already exists → PostgreSQL 12+ fast path (no further row scan)

-- Run-order constraints:
-- Run after scripts/migrations/028-hcc-v0.2-backward-compatibility.ts has completed 100% of the backfill
-- Run after 028a_hcc_v0.2_pre_backfill.sql (the chain_identity_jcs column already exists)
-- Run order: C.1 → C.2 → C.3 → C.4 → C.5 (run in the transaction order below).

-- Step C #1 C1 patch (NOT VALID + VALIDATE SOP; reduces locking; production-safe).

-- Step C.1: hcc_version v0.2 upgrade CHECK
-- DROP the old v0.1 CHECK (if present); ADD the new v0.2 CHECK as NOT VALID
-- NOT VALID = does not scan existing rows; takes effect immediately (production-safe; short lock)
BEGIN;

ALTER TABLE hash_chain_entries
    DROP CONSTRAINT IF EXISTS chk_hash_chain_entries_hcc_version_v1;

-- Idempotency guard: on a rerun after a partial commit the constraint already exists → ADD would abort.
-- DROP IF EXISTS first (same pattern as the v1 DROP above) to make this transaction re-entrant.
ALTER TABLE hash_chain_entries
    DROP CONSTRAINT IF EXISTS chk_hash_chain_entries_hcc_version_v2;

ALTER TABLE hash_chain_entries
    ADD CONSTRAINT chk_hash_chain_entries_hcc_version_v2
    CHECK (hcc_version = '2.0.0') NOT VALID;

COMMIT;

-- Step C.2: VALIDATE hcc_version v0.2 CHECK
-- Separate transaction — scans existing rows (slow; but only an ACCESS SHARE lock; does not block writes)
BEGIN;

ALTER TABLE hash_chain_entries
    VALIDATE CONSTRAINT chk_hash_chain_entries_hcc_version_v2;

COMMIT;

-- Step C.3: chain_identity_jcs NOT NULL CHECK (ADD NOT VALID first)
-- NOT VALID — does not scan existing rows; sets up the PostgreSQL 12+ fast path for the subsequent SET NOT NULL
-- Depends on the backfill being 100% complete (if any NULL row exists this condition holds but VALIDATE will fail)
BEGIN;

-- Idempotency guard: same as above — re-entrant on a rerun after a partial commit.
ALTER TABLE hash_chain_entries
    DROP CONSTRAINT IF EXISTS chk_hash_chain_entries_chain_identity_jcs_not_null;

ALTER TABLE hash_chain_entries
    ADD CONSTRAINT chk_hash_chain_entries_chain_identity_jcs_not_null
    CHECK (chain_identity_jcs IS NOT NULL) NOT VALID;

COMMIT;

-- Step C.4: VALIDATE chain_identity_jcs NOT NULL CHECK
-- Separate transaction — scans existing rows; ACCESS SHARE lock (does not block writes)
-- If the backfill is incomplete (NULL rows present) → VALIDATE fails closed → migration aborts
BEGIN;

ALTER TABLE hash_chain_entries
    VALIDATE CONSTRAINT chk_hash_chain_entries_chain_identity_jcs_not_null;

COMMIT;

-- Step C.5: chain_identity_jcs SET NOT NULL (fast path)
-- PostgreSQL 12+ optimized path:
-- the CHECK constraint is already VALIDATED (Step C.4) → SET NOT NULL takes the fast path (no further row scan; short lock)
-- Retain the Step C.3/C.4 CHECK constraint — defense-in-depth; no performance impact
BEGIN;

ALTER TABLE hash_chain_entries
    ALTER COLUMN chain_identity_jcs SET NOT NULL;

COMMIT;
