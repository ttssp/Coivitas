/**
 * sql-migration-shape — atp v0.1 026 + 027 SQL migration shape verify
 *
 * Static shape verify (no DB connection); verification anchors:
 *   - 026 audit_events table 12 fields (atp align)
 *   - 026 CHECK constraints (audit_class enum + atp_version semver + hash hex + actor_did did: + action len)
 *   - 026 composite index (tenant_id, audit_class, created_at DESC)
 *   - 027 FK REFERENCES tenants(id) ON DELETE RESTRICT (anti cascade erasure)
 *   - 027 ROW LEVEL SECURITY policy (multi-tenant DB-layer backstop)
 *
 * Anti-phantom guard: frozen fields must appear literally in the SQL (regex match);
 * any missing field → test fail.
 */

import { describe, expect, it, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SQL_DIR = resolve(__dirname, '../../../sql');

function readSql(filename: string): string {
    return readFileSync(resolve(SQL_DIR, filename), 'utf8');
}

describe('026_atp_audit_events.sql — shape verify', () => {
    let sql: string;
    beforeAll(() => {
        sql = readSql('026_atp_audit_events.sql');
    });

    it('should declare CREATE TABLE audit_events when shape verify passes', () => {
        expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS managed_service\.audit_events/);
    });

    it('should declare atp_version TEXT NOT NULL when 12 fields align', () => {
        expect(sql).toMatch(/atp_version\s+TEXT NOT NULL/);
    });

    it('should declare event_id UUID PRIMARY KEY', () => {
        expect(sql).toMatch(/event_id\s+UUID PRIMARY KEY/);
    });

    it('should declare tenant_id UUID NOT NULL for multi-tenant isolation', () => {
        expect(sql).toMatch(/tenant_id\s+UUID NOT NULL/);
    });

    it('should declare audit_class TEXT NOT NULL for per-class chain', () => {
        expect(sql).toMatch(/audit_class\s+TEXT NOT NULL/);
    });

    it('should declare actor_did TEXT NOT NULL when DID brand literal', () => {
        expect(sql).toMatch(/actor_did\s+TEXT NOT NULL/);
    });

    it('should declare action TEXT NOT NULL when AuditAction brand literal', () => {
        expect(sql).toMatch(/^\s+action\s+TEXT NOT NULL/m);
    });

    it('should declare target TEXT NOT NULL DEFAULT empty when field is mandatory', () => {
        expect(sql).toMatch(/target\s+TEXT NOT NULL DEFAULT ''/);
    });

    it('should declare canonical_payload TEXT NOT NULL', () => {
        expect(sql).toMatch(/canonical_payload TEXT NOT NULL/);
    });

    it('should declare tamper_proof_hash CHAR(64) NOT NULL when SHA-256 hex literal', () => {
        expect(sql).toMatch(/tamper_proof_hash\s+CHAR\(64\) NOT NULL/);
    });

    it('should declare previous_hash CHAR(64) (nullable;GENESIS support)', () => {
        expect(sql).toMatch(/previous_hash\s+CHAR\(64\)/);
    });

    it('should declare created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()', () => {
        expect(sql).toMatch(/created_at\s+TIMESTAMPTZ NOT NULL DEFAULT NOW\(\)/);
    });

    it('should declare signature TEXT (optional) when v0.1 optional signature', () => {
        expect(sql).toMatch(/signature\s+TEXT/);
    });

    it('should declare audit_class CHECK IN L1/L2/L3 when per-class enum freeze', () => {
        expect(sql).toMatch(/audit_class IN \('L1', 'L2', 'L3'\)/);
    });

    it('should declare atp_version CHECK semver when version invariant enforced', () => {
        expect(sql).toMatch(/atp_version ~ '\^\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\$'/);
    });

    it('should declare tamper_proof_hash CHECK 64 hex chars', () => {
        expect(sql).toMatch(/tamper_proof_hash ~ '\^\[0-9a-f\]\{64\}\$'/);
    });

    it('should declare previous_hash CHECK null OR hex', () => {
        expect(sql).toMatch(/previous_hash IS NULL OR previous_hash ~ '\^\[0-9a-f\]\{64\}\$'/);
    });

    it('should declare actor_did CHECK LIKE did:% when DID prefix invariant', () => {
        expect(sql).toMatch(/actor_did LIKE 'did:%'/);
    });

    it('should declare action CHECK length [1, 256]', () => {
        expect(sql).toMatch(/length\(action\) > 0 AND length\(action\) <= 256/);
    });

    it('should declare composite index (tenant_id, audit_class, created_at DESC)', () => {
        expect(sql).toMatch(
            /CREATE INDEX[^;]+ix_audit_events_tenant_class_created[^;]+ON managed_service\.audit_events \(tenant_id, audit_class, created_at DESC\)/,
        );
    });

    it('should declare auxiliary index actor_did when audit-share downstream query', () => {
        expect(sql).toMatch(
            /CREATE INDEX[^;]+ix_audit_events_actor_did_created[^;]+actor_did, created_at DESC/,
        );
    });

    it('should register schema_migrations 026_atp_audit_events for migration tracking', () => {
        expect(sql).toContain("'026_atp_audit_events'");
    });

    it('should reference soft-delete only design (no tenant hard-delete)', () => {
        expect(sql).toContain('soft-delete');
    });
});

describe('027_atp_audit_events_fk_and_rls.sql — FK + RLS shape verify', () => {
    let sql: string;
    beforeAll(() => {
        sql = readSql('027_atp_audit_events_fk_and_rls.sql');
    });

    it('should declare FK fk_audit_events_tenant_id REFERENCES tenants(id) ON DELETE RESTRICT', () => {
        expect(sql).toMatch(/ADD CONSTRAINT fk_audit_events_tenant_id/);
        expect(sql).toMatch(/REFERENCES managed_service\.tenants\(id\)/);
        expect(sql).toMatch(/ON DELETE RESTRICT/);
    });

    it('should NOT declare ON DELETE CASCADE (anti cascade erasure of audit history)', () => {
        expect(sql).not.toMatch(/ON DELETE CASCADE/);
    });

    it('should enable ROW LEVEL SECURITY on audit_events (multi-tenant DB-layer backstop)', () => {
        expect(sql).toMatch(/ALTER TABLE managed_service\.audit_events ENABLE ROW LEVEL SECURITY/);
    });

    it('should create policy audit_events_tenant_isolation (per tenant_id strict)', () => {
        expect(sql).toMatch(/CREATE POLICY audit_events_tenant_isolation/);
        expect(sql).toMatch(/USING \(tenant_id = current_setting\('app\.current_tenant_id'/);
    });

    it('should document audit_writer_l1 / audit_writer_l2 DB role separation', () => {
        expect(sql).toContain('audit_writer_l1');
        expect(sql).toContain('audit_writer_l2');
    });

    it('should NOT grant DELETE / UPDATE to any role (audit immutability)', () => {
        // Global GRANT negative case: there must be no GRANT DELETE / GRANT UPDATE outside of reference comments
        // Reference-phase notes (commented-out reference example) do not count as violations — match \nGRANT via regex (non commented-out)
        const grantStatements = sql
            .split('\n')
            .filter((l) => /^\s*GRANT\s/i.test(l));
        for (const stmt of grantStatements) {
            expect(stmt).not.toMatch(/\bDELETE\b/i);
            expect(stmt).not.toMatch(/\bUPDATE\b/i);
        }
    });

    it('should register schema_migrations 027_atp_audit_events_fk_and_rls', () => {
        expect(sql).toContain("'027_atp_audit_events_fk_and_rls'");
    });
});

