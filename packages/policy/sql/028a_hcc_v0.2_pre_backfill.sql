-- 028a_hcc_v0.2_pre_backfill.sql — hcc v0.2 Step A: add the chain_identity_jcs column (nullable; no DEFAULT; no CHECK)

-- Design intent:
-- Step A DDL (production-safe; no sentinel default; no CHECK).
-- Never add NOT NULL DEFAULT '**MIGRATION_PENDING**' + CHECK '!= **MIGRATION_PENDING**' in the same transaction:
-- a PostgreSQL DDL CHECK validates immediately → existing rows OR the new sentinel default trigger a CHECK fail → migration blocked
-- .

-- Performance notes:
-- ADD COLUMN nullable with no DEFAULT = PostgreSQL 11+ metadata-only operation (O(1) DDL; no table rewrite; no row scan)
-- no lag in production for large tables (millions of rows) ( production-safe note).

-- Run-order constraints:
-- Run after 021_hash_chain_entries.sql (the table already exists)
-- Run before the application script backfill
-- 028a-bis (CREATE INDEX CONCURRENTLY) has no transaction dependency — may run in any order relative to this file.

-- Subsequent steps:
-- Step B: scripts/migrations/028-hcc-v0.2-backward-compatibility.ts (application script backfill)
-- Step C: 028c_hcc_v0.2_post_backfill.sql (SET NOT NULL + NOT VALID CHECK + VALIDATE)

BEGIN;

-- Step A.1: add the chain_identity_jcs column (nullable; no DEFAULT; no CHECK)
-- Performance: ADD COLUMN nullable with no DEFAULT = PostgreSQL 11+ metadata-only (no row scan; no rewrite; O(1) DDL)
ALTER TABLE hash_chain_entries
    ADD COLUMN chain_identity_jcs TEXT;

COMMIT;
