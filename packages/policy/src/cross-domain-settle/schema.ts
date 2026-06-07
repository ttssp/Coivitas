/**
 * Cross-trust-domain settle schema initialization
 *
 * Does not use versioned SQL migrations (no pre-allocated sequence numbers).
 * The table structure is created by initDomainSchema() at runtime or during test setup (IF NOT EXISTS idempotent),
 * with schemas isolated per trust domain.
 *
 * The schema name is validated before being string-concatenated,
 * disallowing special characters (only lowercase letters, digits, and underscores allowed) to prevent SQL injection.
 */

import type { DatabasePool } from '@coivitas/shared';

/**
 * Validate schema name safety (only [a-z0-9_] allowed, must be non-empty)
 * The production implementation does not depend on the pg-format package; it uses input validation to prevent injection instead
 */
function assertSafeSchemaName(name: string): void {
    if (!/^[a-z][a-z0-9_]*$/.test(name)) {
        throw new Error(
            `SETTLE_SCHEMA_INVALID: schema name must match [a-z][a-z0-9_]*, got: ${JSON.stringify(name)}`,
        );
    }
}

/**
 * Initialize the settle tables for one trust domain (idempotent, IF NOT EXISTS).
 *
 * Table structure:
 * - settle_records: settle records written by the recipient side (PENDING → SETTLED | RELEASED)
 * - reconciliation_cursors: reconciliation cursors maintained by the sender side (composite key)
 *
 * @param pool PG connection pool
 * @param schemaName trust-domain schema name (only [a-z][a-z0-9_]* allowed)
 */
export async function initDomainSchema(
    pool: DatabasePool,
    schemaName: string,
): Promise<void> {
    assertSafeSchemaName(schemaName);

    // the schema must be created first
    await pool.query(`CREATE SCHEMA IF NOT EXISTS ${schemaName}`);

    // settle records table (written by the recipient side)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${schemaName}.settle_records (
            settle_id                   TEXT PRIMARY KEY,
            sender_domain               TEXT NOT NULL,
            recipient_domain            TEXT NOT NULL,
            agent_did                   TEXT NOT NULL,
            metric                      TEXT NOT NULL,
            amount                      NUMERIC NOT NULL,
            "window"                    TEXT NOT NULL,
            window_start                TIMESTAMPTZ NOT NULL,
            sender_ledger_signature     TEXT NOT NULL,
            recipient_ledger_signature  TEXT NOT NULL,
            state                       TEXT NOT NULL DEFAULT 'PENDING',
            created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            settled_at                  TIMESTAMPTZ,
            expires_at                  TIMESTAMPTZ NOT NULL,
            CONSTRAINT valid_state CHECK (state IN ('PENDING', 'SETTLED', 'RELEASED'))
        )
    `);

    // reconciliation cursor table (maintained by the sender side, composite cursor last_created_at + last_settle_id)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${schemaName}.reconciliation_cursors (
            sender_domain           TEXT NOT NULL,
            recipient_domain        TEXT NOT NULL,
            agent_did               TEXT NOT NULL,
            metric                  TEXT NOT NULL,
            last_created_at         TIMESTAMPTZ,
            last_settle_id          TEXT,
            last_reconciled_at      TIMESTAMPTZ,
            PRIMARY KEY (sender_domain, recipient_domain, agent_did, metric)
        )
    `);

    // index: efficient scanning for the TTL reaping job (state=PENDING + expires_at filter)
    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_settle_pending_expires
        ON ${schemaName}.settle_records (state, expires_at)
        WHERE state = 'PENDING'
    `);

    // index: reconciliation pull (composite cursor scan)
    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_settle_for_reconcile
        ON ${schemaName}.settle_records (sender_domain, agent_did, metric, created_at, settle_id)
    `);
}

/**
 * Drop a trust-domain schema (test-only, must not be called in production code)
 */
export async function dropDomainSchema(
    pool: DatabasePool,
    schemaName: string,
): Promise<void> {
    assertSafeSchemaName(schemaName);
    await pool.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
}
