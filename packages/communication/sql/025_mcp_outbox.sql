-- 025_mcp_outbox.sql

-- MCP Bridge outbox storage

-- Design notes:
-- - persist the owner subject + explicit ownership check (guards against IDOR-style status/receipt disclosure)
-- - CHECK excludes the 'tokenId' kind (tokenId is visible in envelope/audit = IDOR disclosure risk)
-- only PoP-based subjects are kept (agentDid / mcpClientId)
-- - the owner_token_id column is kept = chain audit linkage (**NOT used as the ownership authorization field**;
-- the ownership check goes **only** through (owner_subject_kind, owner_subject_value))

-- Create the communication.mcp_outbox table (same schema as the existing communication.sessions)
CREATE TABLE IF NOT EXISTS communication.mcp_outbox (
    outbox_id              UUID PRIMARY KEY,
    envelope_id            UUID NOT NULL,
    status                 TEXT NOT NULL CHECK (status IN ('pending', 'settled', 'error')),
    settlement_receipt     JSONB,
    error_object           JSONB,
    created_at             TIMESTAMPTZ NOT NULL,
    completed_at           TIMESTAMPTZ,

    -- owner subject (kind + value): IDOR protection
    -- the tokenId kind is **removed** (IDOR risk; tokenId is not a secret)
    -- only PoP-based subjects are kept; the ownership check uses this pair of fields
    owner_subject_kind     TEXT NOT NULL CHECK (owner_subject_kind IN ('agentDid', 'mcpClientId')),
    owner_subject_value    TEXT NOT NULL,

    -- owner_token_id: records the SD-Token id that triggered this outbox
    -- **used only for chain audit linkage**; **NOT** used as the ownership authorization field
    owner_token_id         UUID NOT NULL
);

-- index idx_envelope_id (look up outbox by envelope_id)
CREATE INDEX IF NOT EXISTS idx_mcp_outbox_envelope_id
    ON communication.mcp_outbox (envelope_id);

-- index idx_owner (kind, value)
-- for fast lookups on the ownership check path (the primary OPS path)
CREATE INDEX IF NOT EXISTS idx_mcp_outbox_owner
    ON communication.mcp_outbox (owner_subject_kind, owner_subject_value);

-- index idx_token (owner_token_id) — for chain audit
-- Note: this index does **not** back the ownership check query path (authorization goes through idx_owner)
CREATE INDEX IF NOT EXISTS idx_mcp_outbox_token
    ON communication.mcp_outbox (owner_token_id);

COMMENT ON TABLE communication.mcp_outbox IS
    'MCP Bridge outbox (ownership goes through owner_subject_*; owner_token_id is only chain audit linkage)';

COMMENT ON COLUMN communication.mcp_outbox.owner_token_id IS
    'chain audit linkage field; NOT used as the ownership authorization field (avoids IDOR disclosure)';
