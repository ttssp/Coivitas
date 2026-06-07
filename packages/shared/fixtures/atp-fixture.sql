-- atp-fixture.sql -- atp v0.1 audit_events fixture seed SQL

-- priority 4 sub-protocol L3 implementation

-- Purpose:
-- - acceptance test injects a known tenant + audit_event chain
-- - 3 audit_class L1/L2 chains demonstrate a separate hash chain per (tenantId, audit_class)
-- - tamper_proof_hash true values use a placeholder (in production the L3 writer computes them and then INSERTs)

-- Prerequisite: 026_atp_audit_events.sql + 027_atp_audit_events_fk_and_rls.sql migrations complete
-- 008-create-managed-service-tenants.sql tenants primary table exists

-- Anti hard-delete guard:
-- - this fixture does not delete tenants; reset requires truncate audit_events + DELETE tenants (fails under the RESTRICT constraint)
-- - dev / test environments only; never run in production.

-- Inject tenant_a / tenant_b (if absent; reuses the existing 008 tenants schema)
INSERT INTO managed_service.tenants (id, name, code, status, contact_email)
VALUES
    ('11111111-aaaa-4bbb-8ccc-111111111111', 'Tenant A (atp fixture)', 'TENANT_A_ATP', 'ACTIVE', 'tenant-a@atp.fixture'),
    ('22222222-aaaa-4bbb-8ccc-222222222222', 'Tenant B (atp fixture)', 'TENANT_B_ATP', 'ACTIVE', 'tenant-b@atp.fixture')
ON CONFLICT (id) DO NOTHING;

-- Inject the audit_events chains (tenant_a L1 chain; tenant_a L2 chain; tenant_b L1 chain)
-- Note: tamper_proof_hash uses placeholder hex (in production the L3 writer computes it; on the test side it can be
-- replaced with the real hash produced after the acceptance test runs through the L3 writer)

-- Anti-phantom defense: even a fixture INSERT goes through schema validation (CHECK constraints)
-- placeholder hex must be 64-char lowercase hex (CHECK chk_audit_events_tamper_proof_hash_hex)

-- tenant_a L1 chain (GENESIS + 1 child)
INSERT INTO managed_service.audit_events
    (atp_version, event_id, tenant_id, audit_class, actor_did, action, target,
     canonical_payload, tamper_proof_hash, previous_hash, created_at)
VALUES
    -- chain[0] GENESIS
    ('1.0.0',
     '11111111-bbbb-4ccc-8ddd-000000000001',
     '11111111-aaaa-4bbb-8ccc-111111111111',
     'L1',
     'did:key:z6MkAliceFixture',
     'TOKEN_VERIFY',
     'token-id-001',
     '{"requesterId":"agent-a","tokenId":"token-id-001"}',
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     NULL,
     '2026-05-13T00:00:00.000Z'),
    -- chain[1] non-GENESIS; previous_hash = chain[0] placeholder
    ('1.0.0',
     '11111111-bbbb-4ccc-8ddd-000000000002',
     '11111111-aaaa-4bbb-8ccc-111111111111',
     'L1',
     'did:key:z6MkAliceFixture',
     'ENVELOPE_RECORDED',
     'envelope-id-100',
     '{"envelopeId":"envelope-id-100","sender":"agent-a"}',
     'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     '2026-05-13T00:00:01.000Z')
ON CONFLICT (event_id) DO NOTHING;

-- tenant_a L2 chain (independent chain; not linked to the L1 chain; verification anchor)
INSERT INTO managed_service.audit_events
    (atp_version, event_id, tenant_id, audit_class, actor_did, action, target,
     canonical_payload, tamper_proof_hash, previous_hash, created_at)
VALUES
    ('1.0.0',
     '11111111-bbbb-4ccc-8ddd-000000000010',
     '11111111-aaaa-4bbb-8ccc-111111111111',
     'L2',
     'did:key:z6MkAliceFixture',
     'REVOCATION_PUBLISHED',
     'revocation-list-001',
     '{"listId":"revocation-list-001","items":3}',
     'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
     NULL,
     '2026-05-13T00:01:00.000Z')
ON CONFLICT (event_id) DO NOTHING;

-- tenant_b L1 chain (independent tenant; multi-tenant isolation; verification anchor)
INSERT INTO managed_service.audit_events
    (atp_version, event_id, tenant_id, audit_class, actor_did, action, target,
     canonical_payload, tamper_proof_hash, previous_hash, created_at)
VALUES
    ('1.0.0',
     '22222222-bbbb-4ccc-8ddd-000000000001',
     '22222222-aaaa-4bbb-8ccc-222222222222',
     'L1',
     'did:key:z6MkBobFixture',
     'TOKEN_VERIFY',
     'token-id-901',
     '{"requesterId":"agent-b","tokenId":"token-id-901"}',
     'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
     NULL,
     '2026-05-13T00:02:00.000Z')
ON CONFLICT (event_id) DO NOTHING;
