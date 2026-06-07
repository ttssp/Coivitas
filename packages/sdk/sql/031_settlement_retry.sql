-- migration 031: CREATE TABLE for the three tables settlement_operations + settlement_retries + idempotency_records
-- SR v0.1 SQL DDL

-- Sequence-number chain (migration freeze ledger):
-- atp 026 = events table ALTER ADD tenant_id + index (ACCEPTED)
-- atp 027 = federation_identity_links.user_id FK (ACCEPTED)
-- tb 028 = trust_boundary table (ACCEPTED; hcc line 663 freeze)
-- hcc 029 = hash_chain_entries table (ACCEPTED; hcc line 663+902 freeze)
-- CR 030 = federation_identity_links schema breaking change (ACCEPTED)
-- SR 031 = settlement_operations + settlement_retries + idempotency_records (this file)

-- Cross-migration FK reconciliation:
-- settlement_operations.tenant_id → managed_service.tenants(id) [existing in atp 026/027]
-- settlement_retries.operation_id → settlement_operations(id) [this migration]
-- idempotency_records.operation_id → settlement_operations(id) [this migration]
-- audit_event_id → atp events.id [weak reference; no FK constraint]

-- A42 guard: the three field-reconciliation dimensions (types brand ↔ JSON Schema ↔ SQL DDL) see SR

BEGIN;

-- ─── Step 1: CREATE TABLE settlement_operations ────────────────────────────

CREATE TABLE settlement_operations (
    id                 UUID            PRIMARY KEY,
    sr_version         TEXT            NOT NULL CHECK (sr_version = '1.0.0'),
    tenant_id          UUID            NOT NULL REFERENCES managed_service.tenants(id) ON DELETE RESTRICT,
    idempotency_key    TEXT            NOT NULL,  -- SHA-256 hex 64 characters (CHECK constraint step 5)
    settlement_type    TEXT            NOT NULL CHECK (settlement_type IN ('fiat_transfer', 'digital_wallet')),
    principal_did      TEXT            NOT NULL CHECK (principal_did LIKE 'did:%'),
    counterparty_did   TEXT            NOT NULL CHECK (counterparty_did LIKE 'did:%'),
    amount             BIGINT          NOT NULL CHECK (amount >= 1),           -- minor unit; never 0 / negative
    currency           CHAR(3)         NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    signed_payload     JSONB           NOT NULL,                               -- SettlementOperationSignedPayload
    current_state      TEXT            NOT NULL CHECK (current_state IN (
                           'PENDING', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'DEAD_LETTER'
                       )),
    attempt_count      INTEGER         NOT NULL DEFAULT 0 CHECK (attempt_count >= 0 AND attempt_count <= 5),
    revoked            BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    finalized_at       TIMESTAMPTZ     NULL
);

-- ─── Step 2: CREATE TABLE idempotency_records ─────────────────────────────

CREATE TABLE idempotency_records (
    key                TEXT            PRIMARY KEY CHECK (key ~ '^[0-9a-f]{64}$'),  -- SHA-256 hex
    tenant_id          UUID            NOT NULL REFERENCES managed_service.tenants(id) ON DELETE RESTRICT,
    operation_id       UUID            NOT NULL REFERENCES settlement_operations(id) ON DELETE RESTRICT,
    current_state      TEXT            NOT NULL CHECK (current_state IN (
                           'PENDING', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'DEAD_LETTER'
                       )),
    created_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    finalized_at       TIMESTAMPTZ     NULL
);

-- ─── Step 3: CREATE TABLE settlement_retries ───────────────────────────────

CREATE TABLE settlement_retries (
    id                 UUID            PRIMARY KEY,
    operation_id       UUID            NOT NULL REFERENCES settlement_operations(id) ON DELETE RESTRICT,
    attempt_number     INTEGER         NOT NULL CHECK (attempt_number >= 1 AND attempt_number <= 5),
    from_state         TEXT            NOT NULL CHECK (from_state IN (
                           'PENDING', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'DEAD_LETTER'
                       )),
    to_state           TEXT            NOT NULL CHECK (to_state IN (
                           'PENDING', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'DEAD_LETTER'
                       )),
    attempted_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    completed_at       TIMESTAMPTZ     NULL,
    result_summary     TEXT            NULL,
    failure_reason     TEXT            NULL CHECK (failure_reason IS NULL OR failure_reason IN (
                           'SR_PROVIDER_UNAVAILABLE',
                           'SR_PROVIDER_TIMEOUT',
                           'SR_PROVIDER_DECLINED',
                           'SR_INSUFFICIENT_FUNDS',
                           'SR_REGULATORY_REJECTED',
                           'SR_INTERNAL_ERROR'
                       )),
    backoff_delay_ms   INTEGER         NOT NULL CHECK (backoff_delay_ms >= 0 AND backoff_delay_ms <= 60000),
    audit_event_id     UUID            NOT NULL  -- weak reference to atp events.id (no FK; cross-table soft association)
);

-- ─── Step 4: idempotency_key UNIQUE constraint ─────────────────────────────────────
-- Primary double-spend defense path; PostgreSQL 23505 unique_violation → SR_IDEMPOTENCY_VIOLATION

ALTER TABLE settlement_operations
    ADD CONSTRAINT settlement_operations_idempotency_unique
    UNIQUE (tenant_id, idempotency_key);

-- ─── Step 5: idempotency_key SHA-256 hex format CHECK constraint ──────────────────────

ALTER TABLE settlement_operations
    ADD CONSTRAINT settlement_operations_idempotency_format
    CHECK (idempotency_key ~ '^[0-9a-f]{64}$');

-- ─── Step 6: High-frequency query indexes ─────────────────────────────────────────────────────

-- (a) scheduler querying PENDING / FAILED state: tenant_id + current_state composite index
CREATE INDEX idx_settlement_operations_state_lookup
    ON settlement_operations (tenant_id, current_state, created_at DESC);

-- (b) DEAD_LETTER manual review queue: tenant_id + finalized_at partial index
CREATE INDEX idx_settlement_operations_dead_letter
    ON settlement_operations (tenant_id, finalized_at DESC)
    WHERE current_state = 'DEAD_LETTER';

-- (c) idempotency lookup: the UNIQUE constraint already implicitly created a (tenant_id, idempotency_key) index; do not duplicate

-- (d) settlement_retries operation_id + attempt_number composite index
CREATE INDEX idx_settlement_retries_operation
    ON settlement_retries (operation_id, attempt_number ASC);

-- (e) idempotency_records operation_id FK query index
CREATE INDEX idx_idempotency_records_operation
    ON idempotency_records (operation_id);

COMMIT;
