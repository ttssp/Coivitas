-- 006-create-envelope-ledger.sql -- EnvelopeLedger ledger table

-- Envelope-ledger production migration, migration number 006.

-- Design:
-- - 4-state state machine: PENDING → COMMITTED (terminal)
-- PENDING → REJECTED (terminal)
-- PENDING → EXPIRED (reclaimable, non-terminal)
-- - Partial unique indexes guarantee:
-- * A single envelope cannot have two PENDING rows
-- * A single envelope cannot have two COMMITTED rows
-- * A single envelope cannot have two REJECTED rows
-- - EXPIRED rows are not subject to the uniqueness constraint, allowing the same envelope to EXPIRED multiple times → claim again
-- - Atomic claim + TTL lease: claimed_at + ttl_seconds * interval '1 second' < NOW()
-- - Same-transaction finalize: finalize + ActionRecord INSERT share the same pg.PoolClient

CREATE SCHEMA IF NOT EXISTS policy;

CREATE TABLE IF NOT EXISTS policy.envelope_ledger (
    -- Auto-increment primary key (BigSerial guarantees monotonic increase, used for chain-order verification)
    id              BIGSERIAL PRIMARY KEY,

    -- Envelope ID (unique business identifier)
    envelope_id     TEXT NOT NULL,

    -- 4-state state machine
    -- Valid values: PENDING | COMMITTED | REJECTED | EXPIRED
    status          TEXT NOT NULL,

    -- TTL lease (seconds), set at claim time
    -- After COMMITTED / REJECTED / EXPIRED this field no longer carries meaning, but the historical value is retained
    ttl_seconds     INTEGER NOT NULL DEFAULT 30,

    -- Claim timestamp (DB server-side time, to avoid app clock drift)
    claimed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- finalize / reject timestamp (terminal-state write time, nullable = not yet terminal)
    finalized_at    TIMESTAMPTZ,

    -- Final result summary (written on COMMITTED, NULL otherwise)
    result_summary  JSONB,

    -- Claimer identity (optional, passed by the claim() caller, used by finalize/reject to verify ownership)
    -- NULL means no ownership binding (backward compatible)
    claimer_id      TEXT,

    -- Write timestamp (row creation time)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Status constraint: only the 4 valid values are allowed (fail-closed)
    CONSTRAINT ck_envelope_ledger_status CHECK (
        status IN ('PENDING', 'COMMITTED', 'REJECTED', 'EXPIRED')
    ),

    -- TTL positive-value constraint
    CONSTRAINT ck_envelope_ledger_ttl CHECK (ttl_seconds > 0)
);

-- Partial unique index: at most one PENDING row per envelope_id
-- EXPIRED is not constrained (allows the expire → re-claim cycle)
CREATE UNIQUE INDEX IF NOT EXISTS uq_envelope_ledger_pending
    ON policy.envelope_ledger (envelope_id)
    WHERE status = 'PENDING';

-- Partial unique index: at most one COMMITTED row per envelope_id (guarantees idempotent finalize)
CREATE UNIQUE INDEX IF NOT EXISTS uq_envelope_ledger_committed
    ON policy.envelope_ledger (envelope_id)
    WHERE status = 'COMMITTED';

-- Partial unique index: at most one REJECTED row per envelope_id (guarantees idempotent reject)
CREATE UNIQUE INDEX IF NOT EXISTS uq_envelope_ledger_rejected
    ON policy.envelope_ledger (envelope_id)
    WHERE status = 'REJECTED';

-- Query index: look up the latest status by envelope_id
CREATE INDEX IF NOT EXISTS idx_envelope_ledger_envelope_id
    ON policy.envelope_ledger (envelope_id, id DESC);

-- TTL expiry-scan index: batch-reclaim timed-out PENDING rows
-- The WHERE clause restricts to PENDING rows, reducing index size
CREATE INDEX IF NOT EXISTS idx_envelope_ledger_pending_claimed_at
    ON policy.envelope_ledger (claimed_at ASC)
    WHERE status = 'PENDING';

-- Comment
COMMENT ON TABLE policy.envelope_ledger IS
    'EnvelopeLedger ledger table (4-state state machine: PENDING→COMMITTED/REJECTED/EXPIRED). Envelope-ledger production migration, migration number 006.';
