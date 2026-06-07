-- 029_mcp_quota_idempotency.sql

-- MCP Bridge quota idempotency

-- Design notes:
-- - prevents double-counting on retry — INSERT ON CONFLICT DO NOTHING RETURNING claims the slot
-- - cached_result has a 'pending' intermediate state — a successful INSERT claim = 'pending'
-- once the counter is actually written, UPDATE it to 'ok'/'fail' (cached_code + cached_mcp_code are filled only on fail)
-- - Retention: purged after 24h

CREATE TABLE IF NOT EXISTS communication.mcp_quota_idempotency (
    idempotency_key  TEXT NOT NULL,
    token_id         UUID NOT NULL,
    -- 'pending' intermediate state — guards against cached_result being inconsistent with the counter state
    cached_result    TEXT NOT NULL CHECK (cached_result IN ('ok', 'fail', 'pending')),
    -- filled only on fail (internal code)
    cached_code      TEXT,
    -- filled only on fail (mcp wire code)
    cached_mcp_code  TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (idempotency_key, token_id)
);

COMMENT ON TABLE communication.mcp_quota_idempotency IS
    'MCP Bridge quota idempotency (includes pending state); 24h retention';
