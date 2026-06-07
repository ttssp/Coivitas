-- 027_atp_audit_events_fk_and_rls.sql -- audit_events FK + Row-Level Security policy

-- Design principles:
-- - FK REFERENCES managed_service.tenants(id) ON DELETE RESTRICT (prevents cascade from wiping audit history)
-- - Row-Level Security policy: enforced per tenant_id (multi-tenant DB-layer backstop)
-- - DB role separation: audit_writer_l1 (L1 only) + audit_writer_l2 (L2/L3)

-- Anti hard-delete guard:
-- - tenant hard-delete permanently fails (RESTRICT + audit_events immutability)
-- - only tenant soft-delete is supported (reuses the existing status enum from 008-create-managed-service-tenants.sql)
-- - tenants.status = 'DELETED' is treated as a soft-deleted state; the audit chain persists and FK integrity remains intact.

-- multi-tenant audit isolation
-- (audit_events primary table) + 008-create-managed-service-tenants.sql (tenants primary table)

-- =====================================================================
-- FK constraint: audit_events.tenant_id → managed_service.tenants(id) ON DELETE RESTRICT
-- =====================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_schema = 'managed_service'
          AND table_name = 'audit_events'
          AND constraint_name = 'fk_audit_events_tenant_id'
    ) THEN
        ALTER TABLE managed_service.audit_events
            ADD CONSTRAINT fk_audit_events_tenant_id
            FOREIGN KEY (tenant_id)
            REFERENCES managed_service.tenants(id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- =====================================================================
-- Row-Level Security policy: enforced per tenant_id (multi-tenant DB-layer backstop)
-- =====================================================================
ALTER TABLE managed_service.audit_events ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'managed_service'
          AND tablename = 'audit_events'
          AND policyname = 'audit_events_tenant_isolation'
    ) THEN
        CREATE POLICY audit_events_tenant_isolation
            ON managed_service.audit_events
            USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
    END IF;
END $$;

-- =====================================================================
-- DB role separation (implemented later; v0.1 declaration only)
-- =====================================================================
-- Note: role creation requires superuser privileges; this migration only performs GRANT; roles are created ahead of time by the DBA
-- audit_writer_l1 → L1 events only; audit_writer_l2 → L2/L3 events

-- The application-layer assertDbRoleMatchesAuditClass guard is in place;
-- DB-layer GRANT is configured by the DBA at the production deployment stage; this migration provides a reference

-- Example GRANT (reference only; actual production deployment is performed by the DBA):
-- GRANT INSERT (atp_version, event_id, tenant_id, audit_class, actor_did, action
-- target, canonical_payload, tamper_proof_hash, previous_hash, signature)
-- ON managed_service.audit_events TO audit_writer_l1
-- GRANT INSERT (atp_version, event_id, tenant_id, audit_class, actor_did, action
-- target, canonical_payload, tamper_proof_hash, previous_hash, signature)
-- ON managed_service.audit_events TO audit_writer_l2
-- GRANT SELECT ON managed_service.audit_events TO audit_reader

-- Anti hard-delete guard: do not GRANT DELETE / UPDATE to any role (audit immutability).
-- A DBA superuser can bypass this with a direct UPDATE / DELETE (but the reverse hash chain replay guard will detect it)
-- The v0.1 hash chain is only tamper-evident (a DBA UPDATE can alter a row, but the chain breaks → detected when the next event is verified).

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
        VALUES ('027_atp_audit_events_fk_and_rls', NOW())
        ON CONFLICT (version) DO NOTHING;
    END IF;
END $$;
