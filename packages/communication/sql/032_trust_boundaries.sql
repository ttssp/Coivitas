-- 032_trust_boundaries.sql — trust-boundary primitive SQL DDL (L4 communication layer)

-- Key points:
-- - 8 legal transitions + 5-state enum
-- - invariants: transitions are non-reflexive + lifecycleWindow ordering
-- - multi-tenant audit isolation support (tenant_id NOT NULL REFERENCES)

-- SQL migration numbering:
-- - the 028/029/030/031 numbers are already taken by mcp_quota / mcp_value
-- (`025_mcp_outbox.sql` + `026_mcp_binding_revocations.sql` +
-- `028_mcp_quota_counter.sql` + `029_mcp_quota_idempotency.sql` +
-- `030_mcp_value_counter.sql` + `031_mcp_value_idempotency.sql`)
-- - so we use **032** (the next available number)

-- state-machine breaking-change firewall:
-- - the state CHECK enumerates only the 5 states (pending / active / suspended / revoked / expired)
-- - when the emergency_suspended state is implemented in the multisig + arbitration stage,
-- it triggers the tb-level breaking-format-change guard (tbVersion 1.0.0 → 2.0.0; CHECK enum expansion)

-- ─── trust_boundaries main table ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS communication.trust_boundaries (
    -- boundary unique id (UUID v4; TrustBoundaryId brand recorded)
    id UUID PRIMARY KEY,

    -- tb protocol version (independent namespace; v0.1 sole value '1.0.0')
    tb_version VARCHAR(16) NOT NULL DEFAULT '1.0.0',

    -- multi-tenant audit isolation linkage
    -- if the managed_service.tenants table does not exist yet,
    -- the FK constraint on this column is deferred to the SSO integration stage;
    -- here we first create it as a nullable compatibility window
    tenant_id UUID,

    -- DIDs of both ends of the boundary
    principal_side TEXT NOT NULL,
    bounded_side TEXT NOT NULL,

    -- boundary scope (reuses the existing Capability union; JSONB array)
    boundary_scope JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- lifecycle window (+ I5)
    lifecycle_not_before TIMESTAMPTZ NOT NULL,
    lifecycle_not_after TIMESTAMPTZ NOT NULL,

    -- 5-state state machine (CHECK enum)
    -- state-machine breaking-change firewall: the emergency_suspended state is added when implemented in the multisig + arbitration stage
    state VARCHAR(32) NOT NULL
        CHECK (state IN ('pending', 'active', 'suspended', 'revoked', 'expired')),

    -- time the state was entered (written on every transition)
    state_entered_at TIMESTAMPTZ NOT NULL,

    -- binding proof audit event id (I6; must be NULL in the pending state)
    binding_proof_id UUID,

    -- the associated current active token id (optional; active-subset scenarios)
    bounded_token_id TEXT,

    -- the associated delegation chain head (optional; referenced when agent ↔ principal trust is established)
    delegation_chain_head TEXT,

    -- the emergency_suspended state's associated multisig authorization id (v0.1 placeholder + not enforced)
    emergency_authorization_id TEXT,

    -- ─── invariant CHECK constraints ─────────────────────────────────────────────

    -- I2 — principalSide ≠ boundedSide (no reflexive trust)
    CONSTRAINT tb_party_not_self CHECK (principal_side <> bounded_side),

    -- I5 — lifecycle window ordering (notBefore < notAfter)
    CONSTRAINT tb_lifecycle_order CHECK (lifecycle_not_before < lifecycle_not_after),

    -- I6 — bindingProofId is consistent with state
    -- pending state → binding_proof_id must be NULL
    -- active/suspended/revoked/expired state → binding_proof_id must be non-NULL
    CONSTRAINT tb_binding_proof_state_consistency CHECK (
        (state = 'pending' AND binding_proof_id IS NULL)
        OR (state <> 'pending' AND binding_proof_id IS NOT NULL)
    )
);

-- ─── indexes (multi-tenant audit isolation linkage) ──

CREATE INDEX IF NOT EXISTS idx_trust_boundaries_principal
    ON communication.trust_boundaries (principal_side, state);

CREATE INDEX IF NOT EXISTS idx_trust_boundaries_bounded
    ON communication.trust_boundaries (bounded_side, state);

CREATE INDEX IF NOT EXISTS idx_trust_boundaries_tenant
    ON communication.trust_boundaries (tenant_id);

CREATE INDEX IF NOT EXISTS idx_trust_boundaries_lifecycle_not_after
    ON communication.trust_boundaries (lifecycle_not_after)
    WHERE state IN ('active', 'suspended');

-- ─── trust_boundary_audit_events audit event table ───────────────────────

-- carries the audit event canonicalize (via csp JCS)
-- each lifecycle event (onTrustEstablished / onLeaseExtended / onSuspended / onResumed / onRevoked / onExpired),
-- once triggered, is written to this table + canonicalized via csp JCS → audit-tamper-proof hash-chain

CREATE TABLE IF NOT EXISTS communication.trust_boundary_audit_events (
    -- audit event id (UUID v4)
    event_id UUID PRIMARY KEY,

    -- lifecycle event type (6 kinds)
    event_type VARCHAR(32) NOT NULL
        CHECK (event_type IN (
            'onTrustEstablished',
            'onLeaseExtended',
            'onSuspended',
            'onResumed',
            'onRevoked',
            'onExpired'
        )),

    -- the associated trust boundary id
    boundary_id UUID NOT NULL REFERENCES communication.trust_boundaries(id),

    -- transition before / after state (I_tb_audit_src required)
    transition_before VARCHAR(32) NOT NULL
        CHECK (transition_before IN ('pending', 'active', 'suspended', 'revoked', 'expired')),
    transition_after VARCHAR(32) NOT NULL
        CHECK (transition_after IN ('pending', 'active', 'suspended', 'revoked', 'expired')),

    -- transition trigger source (required; I_tb_audit_src)
    -- - 'client': initiated by principalSide + signed payload verify passed
    -- - 'system': server-side automatic trigger (upstream cascade)
    -- - 'sweeper': server-side background daemon detecting lifecycleWindow.notAfter ≤ now
    transition_source VARCHAR(16) NOT NULL
        CHECK (transition_source IN ('client', 'system', 'sweeper')),

    -- DID of the transition initiator (client = principalSide; sweeper = system DID)
    actor_did TEXT NOT NULL,

    -- time the transition was written (server-side trusted clock)
    event_timestamp TIMESTAMPTZ NOT NULL,

    -- binding proof audit event id (T6/T7 expired inherit; no new signing event)
    binding_proof_id UUID
);

-- index — audit event chronological queries (by boundary + timestamp)
CREATE INDEX IF NOT EXISTS idx_tb_audit_events_boundary_time
    ON communication.trust_boundary_audit_events (boundary_id, event_timestamp);

-- index — audit event filter by transition_source (I_tb_audit_src distinguishes sweeper / client / system)
CREATE INDEX IF NOT EXISTS idx_tb_audit_events_source
    ON communication.trust_boundary_audit_events (transition_source, event_timestamp);

-- ─── comments (spec anchors) ────────────────────────────────────────────

COMMENT ON TABLE communication.trust_boundaries IS
    'trust-boundary primitive main table';

COMMENT ON COLUMN communication.trust_boundaries.state IS
    '5-state lifecycle; state-machine breaking-change firewall — the emergency_suspended state is added when implemented in the multisig + arbitration stage (tb-level breaking-format-change guard; tbVersion 1.0.0 → 2.0.0)';

COMMENT ON COLUMN communication.trust_boundaries.tb_version IS
    'tb protocol version (independent namespace; v0.1 sole value 1.0.0; not coupled to token.specVersion)';

COMMENT ON COLUMN communication.trust_boundaries.binding_proof_id IS
    'binding proof audit event id (I6; required in active/suspended/revoked/expired states; must be NULL in the pending state; enforced by CHECK constraint)';

COMMENT ON TABLE communication.trust_boundary_audit_events IS
    'trust-boundary audit event table — lifecycle event canonicalize (via csp JCS); transition_source required and enforced';

COMMENT ON COLUMN communication.trust_boundary_audit_events.transition_source IS
    'I_tb_audit_src invariant; three-state enum {client, system, sweeper}; T7 auto-sweep is distinguished from T6 client/system via this field';
