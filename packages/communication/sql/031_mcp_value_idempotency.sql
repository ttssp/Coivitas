-- 031_mcp_value_idempotency.sql

-- MCP Bridge value idempotency

-- Design notes:
-- - guards against the attack surface where a client retries with the same idempotency key to reuse the cached call quota
-- yet still increments total_value — same pattern as mcp_quota_idempotency
-- - PK tuple (idempotency_key, token_id, currency) — currency is part of the PK
-- because each currency is counted independently
-- - cached_result likewise has a 'pending' intermediate state (consistent with the quota idempotency pattern)
-- - the three value-idempotency steps and the three quota-idempotency steps
-- live inside a single outer SERIALIZABLE transaction (not "parallel independent transactions"),
-- enforcing atomic semantics — an outer tx ROLLBACK undoes all counter changes
-- - Retention: purged after 24h

CREATE TABLE IF NOT EXISTS communication.mcp_value_idempotency (
    idempotency_key  TEXT NOT NULL,
    token_id         UUID NOT NULL,
    currency         TEXT NOT NULL,                       -- ISO-4217 string
    cached_result    TEXT NOT NULL CHECK (cached_result IN ('ok', 'fail', 'pending')),
    cached_code      TEXT,                                -- filled only on fail (internal code)
    cached_mcp_code  TEXT,                                -- filled only on fail (wire code)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (idempotency_key, token_id, currency)
);

COMMENT ON TABLE communication.mcp_value_idempotency IS
    'MCP Bridge value idempotency; PK tuple includes currency; 24h retention';
