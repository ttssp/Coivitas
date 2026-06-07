-- 021_hash_chain_entries.sql — hash_chain_entries table v0.1 baseline DDL

-- Design intent:
-- hash-chain-canonicalize sub-protocol (hcc v0.1 ACCEPTED; DDL).
-- Uses number 021 rather than the spec candidate 029, because: packages/*/sql/*.sql runs in full-path sort-z order
-- the policy package path prefix packages/policy/... sorts alphabetically before packages/sdk/...
-- 028a_hcc_v0.2_pre_backfill.sql must run after this DDL (its ALTER TABLE depends on the table already existing)
-- 021 falls within the policy package's 012-022 number range, guaranteeing it runs before the 028a file.

-- Three-way consistency guard:
-- this file's field set ↔ the HashChainEntry interface in packages/types/src/hash-chain-canonicalize/types.ts ↔
-- the JSON Schema hash-chain-entry-v0.2.schema.json must stay consistent across all three dimensions
-- a field change is a breaking-format-change and must be reviewed carefully.

-- Run-order constraints:
-- runs before 028a_hcc_v0.2_pre_backfill.sql (CREATE TABLE first; ALTER TABLE after)
-- runs after 027_atp_audit_events_fk_and_rls.sql (number guarantees it).

-- hcc v0.1 DDL (a COALESCE-based unique index implements chain uniqueness).

-- hash chain entries table (hash-chain-canonicalize sub-protocol)
-- chain identity is explicit (tenantId, auditClass, chain_namespace); aligns with atp expectations
CREATE TABLE IF NOT EXISTS hash_chain_entries (
    entry_id               UUID        NOT NULL DEFAULT gen_random_uuid(),
    canonical_payload      TEXT        NOT NULL,
    canonical_payload_hash CHAR(64)    NOT NULL
        CHECK (canonical_payload_hash ~ '^[a-f0-9]{64}$'),
    previous_hash          CHAR(64)    NOT NULL
        CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
    chain_position         BIGINT      NOT NULL CHECK (chain_position >= 0),
    timestamp              TIMESTAMPTZ NOT NULL DEFAULT now(),
    hcc_version            TEXT        NOT NULL CHECK (hcc_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    -- Dropped the 'audit' default; require it explicitly; supports multiple chain namespaces (atp / policy / governance, etc.)
    chain_namespace        TEXT        NOT NULL,
    -- tenantId + auditClass explicitly modeled for atp compatibility; optionally NULL to support non-atp upstreams; required when atp invokes
    tenant_id              UUID,
    audit_class            TEXT        CHECK (audit_class IS NULL OR audit_class IN ('L1', 'L2', 'L3')),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT hash_chain_entries_pkey PRIMARY KEY (entry_id)
    -- uniqueness scope: a composite 4-dimensional key (tenant_id, audit_class, chain_namespace, chain_position)
    -- the UNIQUE table constraint is replaced by a COALESCE-based unique index (CREATE UNIQUE INDEX below)
    -- root cause: PostgreSQL's NULL-distinct semantics mean (NULL, NULL, 'audit', 1) can be inserted repeatedly → chain integrity break
    -- approach: COALESCE NULL → sentinel UUID '00000000-0000-0000-0000-000000000000' + sentinel TEXT '__NULL__'
    -- non-atp upstreams (NULL + NULL + chain_namespace + chain_position) stay unique after coalesce
    -- COALESCE partial unique index: PG 16 compatible + does not break the calling contract + strict chain integrity
);

-- COALESCE-based composite 4-dimensional unique index (replaces the original UNIQUE table constraint)
-- sentinel: tenant_id NULL → '00000000-0000-0000-0000-000000000000' UUID; audit_class NULL → '__NULL__' TEXT
-- The COALESCE sentinel is defense-in-depth only; the primary line of defense is the spec-layer ChainIdentity contract
-- + the L3 manager toChainIdentity() boundary rejecting sentinel values (atp callers must supply non-NULL, non-sentinel values)
CREATE UNIQUE INDEX IF NOT EXISTS uidx_hash_chain_entries_chain_pos
    ON hash_chain_entries (
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::UUID),
        COALESCE(audit_class, '__NULL__'),
        chain_namespace,
        chain_position
    );

-- previousHash fork prevention: the same COALESCE-based composite unique index
CREATE UNIQUE INDEX IF NOT EXISTS uidx_hash_chain_entries_prev_hash
    ON hash_chain_entries (
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::UUID),
        COALESCE(audit_class, '__NULL__'),
        chain_namespace,
        previous_hash
    );

-- composite index: aligns with the hash chain's high-frequency query path (tenant_id, audit_class, chain_namespace, chain_position)
-- Note: no COALESCE; high-frequency atp upstreams have non-NULL tenant_id + audit_class and hit it directly
-- non-atp upstreams fall back to uidx_hash_chain_entries_chain_pos (COALESCE-based)
CREATE INDEX IF NOT EXISTS idx_hash_chain_entries_chain_identity
    ON hash_chain_entries (tenant_id, audit_class, chain_namespace, chain_position);

CREATE INDEX IF NOT EXISTS idx_hash_chain_entries_payload_hash
    ON hash_chain_entries (canonical_payload_hash);

COMMENT ON TABLE hash_chain_entries IS
    'Hash chain entries — hash-chain-canonicalize sub-protocol v0.1 baseline';
