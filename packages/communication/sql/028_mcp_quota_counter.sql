-- 028_mcp_quota_counter.sql

-- MCP Bridge durable quota counter

-- Design notes:
-- - the earlier session-local counting (a single per-bridge, per-session counter) had a bypass:
-- the same token could circumvent the daily quota simply by opening across multiple sessions / multiple bridge instances
-- - changed to durable: keyed on (token_id, day), the counter is shared across sessions / across bridges
-- - uses Postgres atomic UPDATE ... RETURNING for check-and-increment
-- - retries use an idempotency key to prevent double-counting (see 029_mcp_quota_idempotency.sql)

-- (token_id, day) is the partition key — UTC midnight roll-over; day uses the DATE type

CREATE TABLE IF NOT EXISTS communication.mcp_quota_counter (
    token_id      UUID NOT NULL,
    day           DATE NOT NULL,
    calls_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id, day)
);

COMMENT ON TABLE communication.mcp_quota_counter IS
    'MCP Bridge durable quota counter; (token_id, day) partition key';
