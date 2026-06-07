-- tb-fixture.sql

-- trust-boundary primitive v0.1 SQL fixture (for tests + acceptance script)

-- Carries over:
-- - tb-fixture.json same-source data (same fixture set; JSON for app-layer + SQL for DB-layer)
-- - reconciles with SQL migration 032_trust_boundaries.sql (state + binding_proof_id consistency CHECK)

-- Usage:
-- - test setup: after truncating the trust-boundaries table, run \i tb-fixture.sql to load the base fixture
-- - acceptance script verify: fixture data verifies that the SQL DDL CHECK constraints take effect

BEGIN;

-- ─── Cleanup (inter-test isolation) ────────────────────────────────────────────────

TRUNCATE TABLE communication.trust_boundary_audit_events CASCADE;
TRUNCATE TABLE communication.trust_boundaries CASCADE;

-- ─── 5 state lifecycle fixtures ( + 8 legal transitions) ─

-- pending state (T1 starting point)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440001',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read", "scope:write:limit:1000"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-06-17T10:00:00.000Z',
    'pending',
    '2026-05-18T10:00:00.000Z',
    NULL  -- I6: in pending state binding_proof_id must be NULL (enforced by CHECK constraint)
);

-- active state (T1 after onTrustEstablished)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440002',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-06-17T10:00:00.000Z',
    'active',
    '2026-05-18T10:00:01.000Z',
    '660e8400-e29b-41d4-a716-446655440101'  -- I6: active must carry binding_proof_id
);

-- active state (T2 after onLeaseExtended; notAfter pushed back)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440003',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-07-17T10:00:00.000Z',  -- lease pushed back to July
    'active',
    '2026-05-19T10:00:00.000Z',
    '660e8400-e29b-41d4-a716-446655440102'
);

-- suspended state (T3 after onSuspended; lifecycleWindow unchanged)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440004',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-06-17T10:00:00.000Z',  -- same as active (T3 last line "lifecycleWindow.notAfter unchanged")
    'suspended',
    '2026-05-19T15:00:00.000Z',
    '660e8400-e29b-41d4-a716-446655440103'
);

-- revoked state (T5 terminal state)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440006',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-06-17T10:00:00.000Z',
    'revoked',
    '2026-05-21T10:00:00.000Z',
    '660e8400-e29b-41d4-a716-446655440105'
);

-- expired state (T6 client/system actively declared)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440007',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-06-17T10:00:00.000Z',
    'expired',
    '2026-06-17T10:00:01.000Z',
    '660e8400-e29b-41d4-a716-446655440106'
);

-- expired state (T7 auto-sweep triggered by sweeper)
INSERT INTO communication.trust_boundaries (
    id, tb_version, principal_side, bounded_side, boundary_scope,
    lifecycle_not_before, lifecycle_not_after, state, state_entered_at,
    binding_proof_id
) VALUES (
    '550e8400-e29b-41d4-a716-446655440008',
    '1.0.0',
    'did:agent:principal-alice',
    'did:agent:bounded-bob',
    '["scope:read"]'::jsonb,
    '2026-05-18T10:00:00.000Z',
    '2026-06-17T10:00:00.000Z',
    'expired',
    '2026-06-17T10:00:30.000Z',
    '660e8400-e29b-41d4-a716-446655440107'
);

-- ─── audit event fixtures (6 kinds of lifecycle event + 3 kinds of transitionSource)

-- T1 onTrustEstablished (transitionSource = 'client')
INSERT INTO communication.trust_boundary_audit_events (
    event_id, event_type, boundary_id, transition_before, transition_after,
    transition_source, actor_did, event_timestamp, binding_proof_id
) VALUES (
    '770e8400-e29b-41d4-a716-446655440201',
    'onTrustEstablished',
    '550e8400-e29b-41d4-a716-446655440002',
    'pending',
    'active',
    'client',
    'did:agent:principal-alice',
    '2026-05-18T10:00:01.000Z',
    '660e8400-e29b-41d4-a716-446655440101'
);

-- T2 onLeaseExtended (transitionSource = 'client')
INSERT INTO communication.trust_boundary_audit_events (
    event_id, event_type, boundary_id, transition_before, transition_after,
    transition_source, actor_did, event_timestamp, binding_proof_id
) VALUES (
    '770e8400-e29b-41d4-a716-446655440202',
    'onLeaseExtended',
    '550e8400-e29b-41d4-a716-446655440003',
    'active',
    'active',
    'client',
    'did:agent:principal-alice',
    '2026-05-19T10:00:00.000Z',
    '660e8400-e29b-41d4-a716-446655440102'
);

-- T6 onExpired (transitionSource = 'client'; actively declared)
INSERT INTO communication.trust_boundary_audit_events (
    event_id, event_type, boundary_id, transition_before, transition_after,
    transition_source, actor_did, event_timestamp, binding_proof_id
) VALUES (
    '770e8400-e29b-41d4-a716-446655440206',
    'onExpired',
    '550e8400-e29b-41d4-a716-446655440007',
    'active',
    'expired',
    'client',
    'did:agent:principal-alice',
    '2026-06-17T10:00:01.000Z',
    '660e8400-e29b-41d4-a716-446655440106'
);

-- T7 auto-sweep onExpired (transitionSource = 'sweeper'; independent audit source; 2 patches)
INSERT INTO communication.trust_boundary_audit_events (
    event_id, event_type, boundary_id, transition_before, transition_after,
    transition_source, actor_did, event_timestamp, binding_proof_id
) VALUES (
    '770e8400-e29b-41d4-a716-446655440207',
    'onExpired',
    '550e8400-e29b-41d4-a716-446655440008',
    'active',
    'expired',
    'sweeper',
    'did:system:trust-boundary-sweeper',
    '2026-06-17T10:00:30.000Z',
    '660e8400-e29b-41d4-a716-446655440107'
);

COMMIT;
