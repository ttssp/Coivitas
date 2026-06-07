-- 026_mcp_binding_revocations.sql

-- MCP Bridge holder binding revocation table

-- Design notes:
-- - binding lookup must consult revocations
-- one resolver option is a DB query against the mcp_binding_revocations table (self-hosted)
-- - fields: mcp_client_id PK + revoked_at + reason + principal_signature
-- - principalSignature: Ed25519 over canonical {mcp_client_id, revoked_at, reason}
-- **never purged** (audit-critical record)

CREATE TABLE IF NOT EXISTS communication.mcp_binding_revocations (
    mcp_client_id          TEXT PRIMARY KEY,
    revoked_at             TIMESTAMPTZ NOT NULL,
    reason                 TEXT,
    -- Ed25519 over canonical {mcp_client_id, revoked_at, reason} (Base64Url)
    principal_signature    TEXT NOT NULL
);

COMMENT ON TABLE communication.mcp_binding_revocations IS
    'MCP Bridge holder binding revocation table; never purged (audit-critical)';
