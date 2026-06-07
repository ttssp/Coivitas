-- 030_mcp_value_counter.sql

-- MCP Bridge durable value counter

-- Design notes:
-- - max_total_value needs a durable counter (similar to the quota counter)
-- - each currency is counted independently — the (token_id, currency) tuple (unlike quota, which buckets only by day)
-- - NUMERIC(20, 2): supports high-precision DECIMAL accumulation (avoids float error)
-- - archived after 30d

CREATE TABLE IF NOT EXISTS communication.mcp_value_counter (
    token_id      UUID NOT NULL,
    currency      TEXT NOT NULL,                        -- ISO-4217 string (USD / EUR / ...)
    total_value   NUMERIC(20, 2) NOT NULL DEFAULT 0,    -- accumulated amount; NUMERIC avoids float error
    PRIMARY KEY (token_id, currency)
);

COMMENT ON TABLE communication.mcp_value_counter IS
    'MCP Bridge durable value counter; NUMERIC supports high precision';
