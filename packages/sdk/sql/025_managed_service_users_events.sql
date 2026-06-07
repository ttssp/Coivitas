-- 025_managed_service_users_events.sql -- JIT provisioning users table + events table

-- tenant-federation.ts L519+584+625 query
-- managed_service.users + managed_service.events but earlier migrations did not create them.
-- This migration adds the two tables required for JIT provisioning (associated with 008 managed_service.tenants).

-- Design principles (fail-closed + strong multi-tenant isolation):
-- - managed_service.users: user principals auto-created by JIT (CASCADE to tenant soft-delete).
-- - managed_service.events: JIT provisioning behavioral audit events (payload JSONB stores external IDP metadata).
-- - all primary keys are UUID: gen_random_uuid() (pgcrypto extension).

-- (tenants primary table) + 024_sso_federation.sql (federation_* association)

-- pgcrypto: gen_random_uuid() dependency (same idempotent declaration as 008 / 024).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- managed_service schema: unified home together with 008 + 024.
CREATE SCHEMA IF NOT EXISTS managed_service;

-- =====================================================================
-- Table 1: users (JIT provisioning user principals)
-- =====================================================================
-- Each row represents an internal user (auto-created by JIT OR manually created by an admin).
-- federation_identity_links links to this table via the user_id FK.
-- Delete policy: CASCADE to tenant soft-delete (DELETED status); hard delete goes through the GDPR process.
CREATE TABLE IF NOT EXISTS managed_service.users (
    -- Primary key UUID
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Owning tenant (FK → managed_service.tenants.id; CASCADE delete)
    tenant_id       UUID NOT NULL REFERENCES managed_service.tenants(id)
                       ON DELETE CASCADE,

    -- User role (resolved by application-layer RBAC; consistent with the packages/sdk admin console)
    -- member / admin / owner / ... (no DB-layer CHECK; guarded by application-layer parseRole)
    role            TEXT NOT NULL,

    -- Creation time + last update time
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- High-frequency query path: list users by tenant_id (admin console)
CREATE INDEX IF NOT EXISTS ix_users_tenant_id
    ON managed_service.users (tenant_id);

COMMENT ON TABLE managed_service.users IS
    'JIT provisioning internal user principals table.'
    'All users are associated with managed_service.tenants (strong multi-tenant isolation).'
    'Pre-allocated sequence number 025.';

-- =====================================================================
-- Table 2: events (JIT provisioning + SSO behavioral audit events)
-- =====================================================================
-- Each row represents an audit event (JIT user creation / role change / IDP registration / etc.).
-- payload JSONB: stores external IDP metadata + operation context (no strict schema constraint; defined by the application layer).
CREATE TABLE IF NOT EXISTS managed_service.events (
    -- Primary key UUID
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Event type (application-layer enum; no strict DB-layer CHECK constraint)
    -- USER_PROVISIONED / USER_ROLE_UPDATED / IDP_REGISTERED / ...
    event_type      TEXT NOT NULL,

    -- Event payload (JSONB; stores structured fields such as idp_identifier / external_subject / before/after)
    payload         JSONB NOT NULL DEFAULT '{}',

    -- Creation time
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- High-frequency query path: by event_type with descending time (admin console audit view)
CREATE INDEX IF NOT EXISTS ix_events_type_created_at
    ON managed_service.events (event_type, created_at DESC);

-- Query by payload subfields (JSONB GIN index; admin console queries audit events by idp_identifier)
CREATE INDEX IF NOT EXISTS ix_events_payload_gin
    ON managed_service.events USING GIN (payload);

COMMENT ON TABLE managed_service.events IS
    'JIT provisioning + SSO behavioral audit events table.'
    'payload JSONB stores external IDP metadata + operation context.';

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
        VALUES ('025', NOW())
        ON CONFLICT (version) DO NOTHING;
    END IF;
END;
$$;
