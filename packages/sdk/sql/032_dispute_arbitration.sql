-- Migration 032: Dispute Arbitration v0.1 DDL
-- Sub-protocol — dispute-arbitration v0.1

-- Three-layer enforce (SQL DDL layer):
-- multisig_pool_size CHECK (multisig_pool_size >= 3 AND multisig_pool_size <= 5)
-- This CHECK is a hard constraint and must not be omitted

-- Table list:
-- managed_service.disputes — dispute records primary table
-- managed_service.arbitration_decisions — arbitration decisions table
-- managed_service.arbitrator_pool — arbitrator pool table

-- 1. disputes primary table
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS managed_service.disputes (
    dispute_id              UUID            PRIMARY KEY,
    tenant_id               UUID            NOT NULL
                                            REFERENCES managed_service.tenants(id)
                                            ON DELETE RESTRICT,
    -- 3-state: FILED (in progress) / RESOLVED (terminal state with a verdict) / EXPIRED (timeout terminal state)
    current_state           TEXT            NOT NULL
                                            CHECK (current_state IN (
                                                'FILED',
                                                'RESOLVED',
                                                'EXPIRED'
                                            )),
    dispute_type            TEXT            NOT NULL
                                            CHECK (dispute_type IN (
                                                'SETTLEMENT_FAILED',
                                                'SCOPE_VIOLATION',
                                                'IDENTITY_FRAUD',
                                                'DELEGATION_REVOCATION_ABUSE',
                                                'DATA_ACCESS_BREACH'
                                            )),
    claimant_did            TEXT            NOT NULL CHECK (claimant_did LIKE 'did:%'),
    respondent_did          TEXT            NOT NULL CHECK (respondent_did LIKE 'did:%'),
    -- SHA-256/JCS canonical hash (64 hex chars); UNIQUE ensures idempotency
    dispute_filing_canonical_hash
                            TEXT            NOT NULL UNIQUE,
    -- Optional associated settlement operation ID (UUID format; NULL = non-settlement dispute)
    settlement_operation_ref
                            UUID            NULL,
    -- Evidence URI list (JSONB array)
    evidence_uris           JSONB           NOT NULL DEFAULT '[]',
    csp_version             TEXT            NOT NULL,
    da_version              TEXT            NOT NULL,
    -- filedAt + 14 days → EXPIRED; requires an application-layer check (checkAndExpireDispute)
    filed_at                TIMESTAMPTZ     NOT NULL,
    resolved_at             TIMESTAMPTZ     NULL,
    expired_at              TIMESTAMPTZ     NULL,
    attempted_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Index: query by tenant_id + current_state (common admin query path)
CREATE INDEX IF NOT EXISTS idx_disputes_tenant_state
    ON managed_service.disputes (tenant_id, current_state);

-- Index: query by claimant_did (dispute history)
CREATE INDEX IF NOT EXISTS idx_disputes_claimant_did
    ON managed_service.disputes (claimant_did);

-- 2. arbitration_decisions arbitration decisions table
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS managed_service.arbitration_decisions (
    decision_id             UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    -- UNIQUE: each dispute can have only one final decision
    dispute_id              UUID            NOT NULL UNIQUE
                                            REFERENCES managed_service.disputes(dispute_id)
                                            ON DELETE RESTRICT,
    verdict                 TEXT            NOT NULL
                                            CHECK (verdict IN (
                                                'CLAIMANT_PREVAILS',
                                                'RESPONDENT_PREVAILS',
                                                'NO_FAULT'
                                            )),
    -- SQL DDL layer (layer 2 of the three-layer enforce; works with the spec-layer MIN=3 + algorithm-layer computeThreshold)
    multisig_threshold      INTEGER         NOT NULL
                                            CHECK (multisig_threshold >= 2 AND multisig_threshold <= 5),
    -- Three-layer enforce — SQL DDL layer hard constraint ≥3:
    multisig_pool_size      INTEGER         NOT NULL
                                            CHECK (multisig_pool_size >= 3 AND multisig_pool_size <= 5),
    -- Arbitration decision canonical hash
    decision_canonical_hash TEXT            NOT NULL UNIQUE,
    -- Arbitrator signature set (JSONB array of {arbitratorDid, signature})
    arbitrator_signatures   JSONB           NOT NULL,
    decided_at              TIMESTAMPTZ     NOT NULL,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- 3. arbitrator_pool arbitrator pool table
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS managed_service.arbitrator_pool (
    arbitrator_did          TEXT            PRIMARY KEY CHECK (arbitrator_did LIKE 'did:%'),
    tenant_id               UUID            NOT NULL
                                            REFERENCES managed_service.tenants(id)
                                            ON DELETE RESTRICT,
    public_key              TEXT            NOT NULL,
    is_active               BOOLEAN         NOT NULL DEFAULT TRUE,
    registered_at           TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_updated_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Index: query by tenant_id + is_active (arbitrator selection path)
CREATE INDEX IF NOT EXISTS idx_arbitrator_pool_tenant_active
    ON managed_service.arbitrator_pool (tenant_id, is_active);
