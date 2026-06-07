-- 010_audit_side_table.sql -- shadow-audit side table

-- Governor lane full protocol.
-- Pre-allocated migration number 010 (see the audit side-table spec).

-- Design:
-- - append-only constraint (INSERT only, no UPDATE / DELETE)
-- - row hash chain + tamper-evidence anchor
-- - each row's rowHash = SHA-256(prevRowHash || recordId || recordHash || agentDid || createdAt)

-- Created inside the policy schema (same schema as action_records)
CREATE TABLE IF NOT EXISTS policy.audit_side_table (
    -- Auto-increment primary key
    id              BIGSERIAL PRIMARY KEY,

    -- Link to the action_records main table
    record_id       TEXT NOT NULL,
    record_hash     TEXT NOT NULL,

    -- The side-table row's agent DID (matches the main-table row)
    agent_did       TEXT NOT NULL,

    -- Timestamp (matches the main-table row's created_at)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- hash chain: current row hash
    row_hash        TEXT NOT NULL,

    -- hash chain: previous row hash (first row = SHA-256(''))
    prev_row_hash   TEXT NOT NULL,

    -- Unique constraint: each recordId may have only one side-table row (append-only)
    CONSTRAINT uq_audit_side_table_record_id UNIQUE (record_id)
);

-- Index: lookup by agent_did + chain verification
CREATE INDEX IF NOT EXISTS idx_audit_side_table_agent_did
    ON policy.audit_side_table (agent_did, created_at ASC, id ASC);

-- Index: tamper-evidence check by record_hash
CREATE INDEX IF NOT EXISTS idx_audit_side_table_record_hash
    ON policy.audit_side_table (record_hash);

-- Index: chain-integrity verification by row_hash
CREATE INDEX IF NOT EXISTS idx_audit_side_table_row_hash
    ON policy.audit_side_table (row_hash);

-- append-only constraint: forbid UPDATE and DELETE via trigger
-- (implemented with PostgreSQL 16 BEFORE trigger)
CREATE OR REPLACE FUNCTION policy.audit_side_table_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_side_table is append-only: % not allowed',
        TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

-- Forbid UPDATE
DROP TRIGGER IF EXISTS trg_audit_side_table_no_update ON policy.audit_side_table;
CREATE TRIGGER trg_audit_side_table_no_update
    BEFORE UPDATE ON policy.audit_side_table
    FOR EACH ROW
    EXECUTE FUNCTION policy.audit_side_table_immutable();

-- Forbid DELETE
DROP TRIGGER IF EXISTS trg_audit_side_table_no_delete ON policy.audit_side_table;
CREATE TRIGGER trg_audit_side_table_no_delete
    BEFORE DELETE ON policy.audit_side_table
    FOR EACH ROW
    EXECUTE FUNCTION policy.audit_side_table_immutable();

-- Comment
COMMENT ON TABLE policy.audit_side_table IS
    'Shadow-audit side table (append-only, tamper-evidence hash chain).';
