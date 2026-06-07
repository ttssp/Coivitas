-- 028_delegated_audit_keys.sql — DelegatedAuditKey delegated audit key table + audit access log table

-- Interlock: multi-tenant audit isolation enforcement

-- Design principles (fail-closed + strong multi-tenant isolation):
-- - delegated_audit_keys: DelegatedAuditKey delegated audit key primary table.
-- tenant_id FK REFERENCES tenants(id) — multi-tenant FK constraint.
-- cross-tenant insert → FK violation reject (DB-layer strong isolation).
-- - audit_share_access_log: cross-domain audit-share access audit log table.
-- Each verifyAuditRequest call (whether success/failure) writes one record.
-- - tenant_audit_share_policy: cross-tenant whitelist (audit-share v0.2 step 8).
-- which tenantIds principal_did is allowed to initiate cross-domain audit-share requests against.

-- SQL migration sequence-number discipline: range 030-039 (020-029 already used up to 025).
-- This migration uses sequence number 028; no number conflict with the tb spec (029 candidate).

-- pgcrypto: gen_random_uuid() dependency (same idempotent declaration as 025/031/032).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- managed_service schema: unified home together with the existing 025/031/032.
CREATE SCHEMA IF NOT EXISTS managed_service;

-- =====================================================================
-- Table 1: managed_service.delegated_audit_keys
-- =====================================================================
-- Each row represents a delegated audit key (DelegatedAuditKey) issued by a principal to an auditor.
-- Serves as the verifier data source.

-- multi-tenant FK constraint design:
-- tenant_id REFERENCES managed_service.tenants(id) — only a delegator within the same tenant may insert.
-- cross-tenant insert → FK violation reject (DB-layer strong isolation, not reliant on the application-layer guard).

-- Incremental fields vs original field set reconciliation:
-- - id (UUID PK): new (PK = audit_key_id; a surrogate PK is added here)
-- - tenant_id (UUID NOT NULL FK): multi-tenant isolation literal requirement
-- - delegated_from (TEXT NOT NULL): spec.delegatedFrom DID
-- - delegated_to (TEXT NOT NULL): spec.delegatedTo DID
-- - audit_key_id (UUID UNIQUE NOT NULL): spec.auditKeyId business primary key (globally unique)
-- - scope (JSONB NOT NULL): AuditShareScope{tenantId,auditClass,chainNamespace}
-- - valid_from / valid_until (TIMESTAMPTZ NOT NULL): spec fields
-- - proof_signature (TEXT NOT NULL): spec DelegatedAuditKeyProof.signature
-- - proof_signed_by (TEXT NOT NULL): spec DelegatedAuditKeyProof.signedBy DID
-- - proof_signed_at (TIMESTAMPTZ NOT NULL): spec DelegatedAuditKeyProof.signedAt
-- - revoked (BOOLEAN NOT NULL DEFAULT false): spec field
-- - purpose (TEXT NOT NULL DEFAULT 'AUDIT'): spec fixed-value constraint field
-- - created_at / updated_at (TIMESTAMPTZ NOT NULL DEFAULT NOW()): audit timestamps
CREATE TABLE IF NOT EXISTS managed_service.delegated_audit_keys (
    -- Surrogate primary key (surrogate PK; internal use)
    id                  UUID        NOT NULL DEFAULT gen_random_uuid(),

    -- multi-tenant FK constraint (cross-tenant insert → FK reject)
    tenant_id           UUID        NOT NULL
                            REFERENCES managed_service.tenants(id)
                            ON DELETE RESTRICT,

    -- Delegator DID (DelegatedAuditKey.delegatedFrom = principal DID)
    delegated_from      TEXT        NOT NULL,

    -- Delegatee DID (DelegatedAuditKey.delegatedTo = auditor/requester DID)
    delegated_to        TEXT        NOT NULL,

    -- Business unique primary key (auditKeyId; referenced by VerifiedAuditRequest.token)
    audit_key_id        UUID        NOT NULL,

    -- AuditShareScope JSONB ({tenantId, auditClass, chainNamespace?})
    -- Stores the scope boundary authorized by the delegator (atp v0.1 interlock)
    scope               JSONB       NOT NULL,

    -- Validity window
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,

    -- DelegatedAuditKeyProof fields (delegator signature proof)
    proof_signature     TEXT        NOT NULL,
    proof_signed_by     TEXT        NOT NULL,   -- must === delegated_from (CHECK constraint)
    proof_signed_at     TIMESTAMPTZ NOT NULL,

    -- Revocation flag (the production verifier: revoked=true → AUDIT_SHARE_TOKEN_INVALID)
    revoked             BOOLEAN     NOT NULL DEFAULT false,

    -- Key purpose (fixed to 'AUDIT'; enforced by CHECK constraint)
    purpose             TEXT        NOT NULL DEFAULT 'AUDIT',

    -- Audit timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ── Primary key constraint ──────────────────────────────────────────
    CONSTRAINT delegated_audit_keys_pk
        PRIMARY KEY (id),

    -- ── Business uniqueness constraint ──────────────────────────────────
    -- audit_key_id globally unique (referenced by VerifiedAuditRequest.token)
    CONSTRAINT delegated_audit_keys_audit_key_id_unique
        UNIQUE (audit_key_id),

    -- ── validity window constraint ──────────────────────────────────────
    -- valid_until must be strictly greater than valid_from (DB-layer guard ahead of step 4 verify)
    CONSTRAINT delegated_audit_keys_validity_window
        CHECK (valid_until > valid_from),

    -- ── proof_signed_by must match delegated_from ──────────────────────
    -- Prevents delegator forgery (DB-layer guard; the application-layer step 3 validates in sync)
    CONSTRAINT delegated_audit_keys_signed_by_matches
        CHECK (proof_signed_by = delegated_from),

    -- ── purpose fixed-value constraint ───────────────────────────────────
    CONSTRAINT delegated_audit_keys_purpose_audit
        CHECK (purpose = 'AUDIT')
);

-- Query delegated keys by tenant_id (admin console + L2 resolver multi-tenant isolation query)
CREATE INDEX IF NOT EXISTS idx_delegated_audit_keys_tenant_id
    ON managed_service.delegated_audit_keys (tenant_id);

-- Query by delegated_to (VerifiedAuditRequest step 5 requesterDid match)
CREATE INDEX IF NOT EXISTS idx_delegated_audit_keys_delegated_to
    ON managed_service.delegated_audit_keys (delegated_to);

-- Partial index on the validity window (unrevoked rows only; audit-share verifier step 3 high-frequency path)
CREATE INDEX IF NOT EXISTS idx_delegated_audit_keys_valid_until_active
    ON managed_service.delegated_audit_keys (valid_until)
    WHERE revoked = false;

COMMENT ON TABLE managed_service.delegated_audit_keys IS
    'DelegatedAuditKey delegated audit key primary table.'
    'multi-tenant FK: tenant_id REFERENCES tenants(id) — cross-tenant insert → FK reject.'
    'audit-trail-protocol multi-tenant isolation enforcement interlock.'
    '-share multi-tenant isolation.'
    'SQL migration sequence number 028.';

-- =====================================================================
-- Table 2: managed_service.audit_share_access_log
-- =====================================================================
-- Each AuditShareManager.verifyAuditRequest call writes one access record (whether success/failure).
-- Corresponds to the audit-share v0.2 spec cross-domain auditable access log requirement.
-- Supports cross-domain audit access auditing + regulatory compliance (GDPR Art. 30 processing records).

-- Field set (Table 2):
-- id / tenant_id / audit_key_id / requester_did / audience_did /
-- challenge / accessed_at / scope / verify_outcome / audit_event_ids
CREATE TABLE IF NOT EXISTS managed_service.audit_share_access_log (
    -- Primary key UUID (each access record has its own ID)
    id                  UUID        NOT NULL DEFAULT gen_random_uuid(),

    -- multi-tenant FK (the access log is associated with a tenant; cross-tenant records use the delegator tenant)
    tenant_id           UUID        NOT NULL
                            REFERENCES managed_service.tenants(id)
                            ON DELETE RESTRICT,

    -- References the delegated key (audit_key_id FK → delegated_audit_keys.audit_key_id)
    -- NULL allowed: when verifyAuditRequest step 3 finds no key, audit_key_id cannot be referenced
    audit_key_id        UUID
                            REFERENCES managed_service.delegated_audit_keys(audit_key_id)
                            ON DELETE SET NULL,

    -- Requester DID (VerifiedAuditRequest.requesterDid)
    requester_did       TEXT        NOT NULL,

    -- Audience DID (VerifiedAuditRequest.audience = target domain DID)
    audience_did        TEXT        NOT NULL,

    -- challenge UUID (VerifiedAuditRequest.challenge; anti-replay tracking)
    challenge           UUID        NOT NULL,

    -- Access timestamp (verifyAuditRequest call time)
    accessed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Requested scope (VerifiedAuditRequest.requestedScope JSONB)
    scope               JSONB       NOT NULL DEFAULT '{}',

    -- Verification outcome (14 error codes + SUCCESS)
    verify_outcome      TEXT        NOT NULL,

    -- The audit event IDs matched by this access (verifyAuditRequest step 11 selective disclosure result)
    -- Empty array allowed (when verify fails)
    audit_event_ids     UUID[]      NOT NULL DEFAULT '{}',

    -- ── Primary key constraint ──────────────────────────────────────────
    CONSTRAINT audit_share_access_log_pk
        PRIMARY KEY (id),

    -- ── verify_outcome value constraint ──────────────────────────────────
    -- 14 error codes + SUCCESS; fail-closed semantics (the 14-item AUDIT_SHARE_* namespace)
    CONSTRAINT audit_share_access_log_verify_outcome_valid
        CHECK (verify_outcome IN (
            'SUCCESS',
            'AUDIT_SHARE_TOKEN_INVALID',
            'AUDIT_SHARE_TOKEN_EXPIRED',
            'AUDIT_SHARE_AUDIENCE_MISMATCH',
            'AUDIT_SHARE_CHALLENGE_INVALID',
            'AUDIT_SHARE_NOT_AFTER_EXPIRED',
            'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
            'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            'AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH',
            'AUDIT_SHARE_SCOPE_INVALID',
            'AUDIT_SHARE_CROSS_TENANT_REJECT',
            'AUDIT_SHARE_HASH_CHAIN_INVALID',
            'AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID',
            'AUDIT_SHARE_VERSION_UNSUPPORTED',
            'AUDIT_SHARE_SCHEMA_INVALID'
        ))
);

-- Query the access log by tenant_id (admin console multi-tenant audit view)
CREATE INDEX IF NOT EXISTS idx_audit_share_access_log_tenant_id
    ON managed_service.audit_share_access_log (tenant_id);

-- Query by audit_key_id (trace the usage history of a single delegated key)
CREATE INDEX IF NOT EXISTS idx_audit_share_access_log_audit_key_id
    ON managed_service.audit_share_access_log (audit_key_id);

-- Query by requester_did (trace the cross-domain access records of a specific requester)
CREATE INDEX IF NOT EXISTS idx_audit_share_access_log_requester_did
    ON managed_service.audit_share_access_log (requester_did);

-- Query by access time descending (admin console audit view + regulatory compliance reports)
CREATE INDEX IF NOT EXISTS idx_audit_share_access_log_accessed_at
    ON managed_service.audit_share_access_log (accessed_at DESC);

COMMENT ON TABLE managed_service.audit_share_access_log IS
    'cross-domain audit-share access audit log table.'
    'Each verifyAuditRequest call writes one record (whether success/failure; regulatory compliance GDPR Art.30).'
    'verify_outcome: 14 error codes + SUCCESS (namespace isolation).'
    'SQL migration sequence number 028.';

-- =====================================================================
-- Table 3: managed_service.tenant_audit_share_policy
-- =====================================================================
-- cross-tenant whitelist (audit-share v0.2 step 8 data source).
-- which tenantIds principal_did is allowed to initiate cross-domain audit-share requests against.
-- atp v0.1 multi-tenant isolation enforcement interlock (the L2 audit-share-tenant-resolver queries this table).

-- Note: granted_by admin DID trust construction is deferred to sdk v0.2.
-- Alpha stage: granted_by accepts any DID + a procedural weak constraint (step 8).
CREATE TABLE IF NOT EXISTS managed_service.tenant_audit_share_policy (
    -- principal DID (DelegatedAuditKey.delegatedFrom; cross-domain delegation initiator)
    principal_did           TEXT        NOT NULL,

    -- Target tenantId allowed for cross-domain audit-share reads
    allowed_tenant_id       TEXT        NOT NULL,

    -- Allowed audit class range (L1/L2/L3 three tiers; spec AuditClass enum)
    audit_class             TEXT        NOT NULL,

    -- Granting source admin DID (alpha: accepts any DID; cryptographic enforce deferred to a later release)
    granted_by              TEXT        NOT NULL,

    -- Grant timestamp
    granted_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ── Primary key constraint ((principal_did, allowed_tenant_id, audit_class) triple is unique) ────
    CONSTRAINT tenant_audit_share_policy_pk
        PRIMARY KEY (principal_did, allowed_tenant_id, audit_class),

    -- ── audit_class value constraint (reconciled with the atp v0.1 AuditClass enum) ────────────────
    CONSTRAINT tenant_audit_share_policy_audit_class_valid
        CHECK (audit_class IN ('L1', 'L2', 'L3'))
);

COMMENT ON TABLE managed_service.tenant_audit_share_policy IS
    'cross-tenant audit-share whitelist policy table.'
    'multi-tenant isolation enforcement interlock.'
    'The L2 audit-share-tenant-resolver queries this table to perform the cross-tenant whitelist check.'
    'granted_by: alpha accepts any DID; sdk v0.2 cryptographic enforce deferred to a later release.'
    'SQL migration sequence number 028.';

-- =====================================================================
-- schema_migrations version record
-- =====================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'schema_migrations'
    ) THEN
        INSERT INTO schema_migrations (version, applied_at)
        VALUES ('028', NOW())
        ON CONFLICT (version) DO NOTHING;
    END IF;
END;
$$;
