-- 008-create-managed-service-tenants.sql -- managed-service multi-tenant / API Key / usage-log tables

-- Managed-service launch (DID resolution + revocation service, free tier + pro tier).
-- Pre-allocated number 008.

-- Design principles:
-- - Three separate tables: tenants (tenant entity) / api_keys (pro-tier credentials) / usage_log (per-day aggregate).
-- - API keys are not stored directly: only a SHA-256 hex hash + 8-character prefix (for identification) are stored.
-- The raw key is returned only once at issuance (fail-closed).
-- - usage_log per-day aggregate: avoids the storage explosion of writing one row per request; uses
-- INSERT...ON CONFLICT...DO UPDATE...request_count = request_count + N to implement INCR.
-- - tenant_id / api_key_id in usage_log use ON DELETE SET NULL:
-- historical usage is retained after a tenant / API key is deleted (accountable governance, pillar 4).
-- - The status column is a tri-state machine: ACTIVE / SUSPENDED / DELETED (tenants) + ACTIVE / REVOKED / EXPIRED (api_keys).

-- Scope limits (alpha phase):
-- - No payment integration (Stripe etc. deferred to a later release).
-- - Do not store sensitive tenant information such as payment credentials / billing address (table extension added later).
-- - No organization / project hierarchy (single tenant = single billing entity).

-- pgcrypto: this migration's primary key depends on gen_random_uuid().
-- Earlier migrations (001-007/009-011) did not enable this extension; this file, as the first consumer, is responsible for declaring it.
-- IF NOT EXISTS ensures idempotency: re-running does not error and coexists with an already-enabled environment.
-- In a fresh-DB scenario, db-migrate without pgcrypto would stall here.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS managed_service;

-- =====================================================================
-- Table 1: tenants
-- =====================================================================
CREATE TABLE IF NOT EXISTS managed_service.tenants (
    -- Primary key (UUID v4, not BIGSERIAL: more robust for cross-node / cross-database migration)
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The tenant's DID (B2B customer entity identity; UNIQUE prevents duplicate registration)
    tenant_did      TEXT NOT NULL UNIQUE,

    -- Billing tier
    -- FREE: anonymous / IP rate-limit 100 req/min
    -- PRO : API key rate-limit 10000 req/min/key
    tier            TEXT NOT NULL,

    -- Display name (for the admin console)
    display_name    TEXT NOT NULL,

    -- Contact email (account alerts / usage-overage notifications; nullable, not required in the alpha phase)
    contact_email   TEXT,

    -- Creation time (DB server-side time, to avoid app clock drift)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Tri-state state machine
    -- ACTIVE : serving normally
    -- SUSPENDED : usage overage / unpaid balance / policy-violation suspension (fail-closed: all requests during throttling -> 429)
    -- DELETED : soft delete (retains historical usage audit; hard delete goes through the GDPR process)
    status          TEXT NOT NULL DEFAULT 'ACTIVE',

    CONSTRAINT ck_tenants_tier CHECK (tier IN ('FREE', 'PRO')),
    CONSTRAINT ck_tenants_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DELETED'))
);

CREATE INDEX IF NOT EXISTS ix_tenants_tenant_did
    ON managed_service.tenants (tenant_did);

CREATE INDEX IF NOT EXISTS ix_tenants_status
    ON managed_service.tenants (status);

COMMENT ON TABLE managed_service.tenants IS
    'Managed-service tenant entity table (B2B customer identity and billing tier).';

-- =====================================================================
-- Table 2: api_keys (pro-tier credentials)
-- =====================================================================
CREATE TABLE IF NOT EXISTS managed_service.api_keys (
    -- Primary key
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Owning tenant (CASCADE: on tenant hard delete, the credential is deleted too; on soft delete, status->REVOKED)
    tenant_id       UUID NOT NULL REFERENCES managed_service.tenants(id)
                       ON DELETE CASCADE,

    -- SHA-256 hex of the API key (lowercase, 64 characters)
    -- The raw key is returned only once at issuance; only the hash is stored (fail-closed)
    key_hash        TEXT NOT NULL UNIQUE,

    -- API key prefix (first 8 characters, for identification / admin log display)
    -- Of the form "ap_live_" or "ap_test_"; one-to-one with key_hash
    key_prefix      TEXT NOT NULL,

    -- Description (user note for this key's purpose)
    description     TEXT,

    -- Creation time
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Expiry time (nullable = never expires; recommended to set in the alpha phase)
    expires_at      TIMESTAMPTZ,

    -- Last-used time (updated after each successful auth; used for auto-revoke of idle keys)
    last_used_at    TIMESTAMPTZ,

    -- State machine
    -- ACTIVE : in effect normally
    -- REVOKED : user-initiated revocation / detected leak
    -- EXPIRED : expires_at has passed (passive expire, batch-updated by a scheduled job)
    status          TEXT NOT NULL DEFAULT 'ACTIVE',

    CONSTRAINT ck_api_keys_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_api_keys_key_prefix_length CHECK (char_length(key_prefix) >= 4)
);

CREATE INDEX IF NOT EXISTS ix_api_keys_tenant_id
    ON managed_service.api_keys (tenant_id);

CREATE INDEX IF NOT EXISTS ix_api_keys_status
    ON managed_service.api_keys (status);

-- Expiry-scan index (scheduled job batch-updates ACTIVE -> EXPIRED)
CREATE INDEX IF NOT EXISTS ix_api_keys_expires_at
    ON managed_service.api_keys (expires_at)
    WHERE status = 'ACTIVE' AND expires_at IS NOT NULL;

COMMENT ON TABLE managed_service.api_keys IS
    'Pro-tier API key credential table (stores only SHA-256 hash + prefix; the raw key is not persisted).';

-- =====================================================================
-- Table 3: usage_log (per-day aggregate)
-- =====================================================================
-- Design: exactly one row per (tenant_id, api_key_id, endpoint, bucket_day)
-- At request completion, INSERT...ON CONFLICT...DO UPDATE...request_count = request_count + 1
-- An errored request also does error_count += 1.

-- Per-request detail is not recorded: aggregating tens-of-thousands-per-second requests by day yields a 100k:1 data-volume reduction
-- Per-request audit goes through ActionRecord (policy layer), not stored redundantly.

-- tenant_id NULL means FREE tier anonymous access (rate-limited by IP; the IP is not persisted).
-- api_key_id NULL means FREE tier (no key) or the key has been deleted.
CREATE TABLE IF NOT EXISTS managed_service.usage_log (
    -- Primary key
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant ID (NULL = FREE tier anonymous access)
    tenant_id       UUID REFERENCES managed_service.tenants(id) ON DELETE SET NULL,

    -- API key ID (NULL = FREE tier or the key has been deleted)
    api_key_id      UUID REFERENCES managed_service.api_keys(id) ON DELETE SET NULL,

    -- Endpoint
    -- resolver : DID resolution endpoint (GET /v1/resolve/:did)
    -- revocation : revocation-check endpoint (GET /v1/revocation/:credentialId)
    endpoint        TEXT NOT NULL,

    -- Per-day aggregate (DATE type, auto-truncated to the day; time zone per DB default UTC)
    bucket_day      DATE NOT NULL,

    -- Total request count (INCR by INSERT...ON CONFLICT...DO UPDATE)
    request_count   BIGINT NOT NULL DEFAULT 0,

    -- Errored request count (4xx/5xx; used for SLO error-budget calculation)
    error_count     BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT ck_usage_log_endpoint CHECK (endpoint IN ('resolver', 'revocation')),
    CONSTRAINT ck_usage_log_request_count CHECK (request_count >= 0),
    CONSTRAINT ck_usage_log_error_count CHECK (error_count >= 0),

    -- Unique constraint = ON CONFLICT target
    -- Note: tenant_id / api_key_id may be NULL, requiring a COALESCE-friendly partial index
    -- PostgreSQL UNIQUE treats NULL != NULL by default; handled instead with partial unique indexes.
    CONSTRAINT uniq_usage_per_tenant_endpoint_day
        UNIQUE (tenant_id, api_key_id, endpoint, bucket_day)
);

-- Note: UNIQUE (tenant_id, api_key_id, endpoint, bucket_day) is an ordinary unique constraint when both columns are NOT NULL;
-- when NULL columns are present, PostgreSQL treats NULLs as distinct by default.
-- The partial unique indexes below cover only "originally anonymous" rows (FREE tier, no tenant, no key)
-- and do **not** cover historical rows after ON DELETE SET NULL (multiple NULL rows are allowed to coexist, preserving each history record).

-- The original uniq_usage_tenant_no_key_per_endpoint_day index would conflict after
-- ON DELETE SET NULL -- after deleting multiple keys for the same tenant,
-- row1 SET NULL = (T, NULL, e, d), row2 SET NULL = (T, NULL, e, d), and the second SET NULL triggers a unique violation.
-- This partial index is now removed; multiple NULL rows coexist, aligning with the "history retention" semantics.

-- Unique only over "fully anonymous" rows (FREE tier); historical rows after a deleted key do not enter this index (because tenant_id IS NOT NULL)
CREATE UNIQUE INDEX IF NOT EXISTS uniq_usage_anon_per_endpoint_day
    ON managed_service.usage_log (endpoint, bucket_day)
    WHERE tenant_id IS NULL AND api_key_id IS NULL;

-- (Removed: uniq_usage_tenant_no_key_per_endpoint_day, see the note above)

-- Query index: by day range + per-tenant aggregation
CREATE INDEX IF NOT EXISTS ix_usage_log_bucket_day
    ON managed_service.usage_log (bucket_day DESC);

CREATE INDEX IF NOT EXISTS ix_usage_log_tenant_id
    ON managed_service.usage_log (tenant_id, bucket_day DESC)
    WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE managed_service.usage_log IS
    'Per-day aggregate usage log (INSERT...ON CONFLICT...DO UPDATE INCR pattern).';
