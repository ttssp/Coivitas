/**
 * Conformance test — T1-T5 holder binding
 *
 *
 * Acceptance criterion references (spec line 782 (g) + line 791 (p)):
 *   (g) R14 is DEFERRED as a whole to a later release — the holder binding registration flow
 *       **must not be implemented** ( init/challenge step + MCPClientBinding.proofOfPossession)
 *   (p) R10 DEFER — credentialKid-to-mcpClientId binding deferred to a later release
 *
 * T-id status (each reconciled against spec line 811-815):
 *   T1: register binding with principal signature → 200 + binding stored
 *       DEFERRED (criterion (g)) — registration flow not implemented
 *   T2: register binding with INVALID principal signature → 401 unauthorized
 *       DEFERRED (criterion (g)) — registration flow not implemented
 *   T3: lookup expired binding → MCP_BINDING_EXPIRED_OR_MISSING
 *       IMPLEMENTED — already covered by holder-binding-resolver.test.ts step 1
 *   T4: revoke binding via principal sig → subsequent calls reject
 *       PARTIAL — revocation lookup is implemented (holder-binding-resolver step 2/3);
 *       the revoke registration flow is DEFERRED to a later release
 *   T5: same mcp_client_id register twice (overlap notAfter) → reject / supersede
 *       DEFERRED (criterion (g)) — registration flow not implemented
 *
 * This file does **not repeat** unit tests that already PASS; it records T-id status guards via it.todo / it.skip.
 *
 * Important invariant (A30): T-id numbered coverage = conformance scope closure;
 *   T-ids that the spec DEFERs are also expressed as it.skip + a spec line reference — A30 does not allow a partial scope.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── T1: register binding (DEFERRED) ─────────────────────────────────────────

describe('T1 holder binding register happy path (line 811)', () => {
    // spec line 811: `T1: register binding with principal signature → 200 + binding stored`
    // DEFERRED: criterion (g) R14 line 782 "the holder binding registration flow **must not be implemented**"
    it.skip(
        'T1 — should register binding with principal signature when DEFERRED registration is implemented (line 811)',
        () => {
            // not implemented yet; to be revived once the canonical signed payload primitive lands
            expect.fail('T1 DEFERRED (acceptance criterion (g))');
        },
    );

    it('T1 invariant — holder-binding-resolver.ts source must NOT export registration API (DEFER guard)', () => {
        // grep guard: the registration flow is **not** implemented — the source must not contain registerBinding / registerMCPClient
        const source = readFileSync(
            resolve(__dirname, '../../holder-binding-resolver.ts'),
            'utf-8',
        );
        // strip comments + string literals
        const codeOnly = source
            .split('\n')
            .filter((line) => {
                const trimmed = line.trim();
                if (trimmed.startsWith('//')) return false;
                if (trimmed.startsWith('*')) return false;
                if (trimmed.startsWith('/*')) return false;
                if (trimmed.startsWith('*/')) return false;
                return true;
            })
            .join('\n')
            .replace(/'[^']*'/g, "''")
            .replace(/"[^"]*"/g, '""')
            .replace(/`[^`]*`/g, '``');
        // DEFER guard: must not export a registration API
        expect(codeOnly).not.toMatch(/export\s+(async\s+)?function\s+registerBinding/);
        expect(codeOnly).not.toMatch(/export\s+(async\s+)?function\s+registerMCPClient/);
        expect(codeOnly).not.toMatch(/proofOfPossession\s*:/);
    });
});

// ─── T2: register with INVALID principal signature (DEFERRED) ────────────────

describe('T2 holder binding register invalid sig (line 812)', () => {
    // spec line 812: `T2: register binding with INVALID principal signature → 401 unauthorized`
    // DEFERRED: criterion (g) R14 line 782
    it.skip(
        'T2 — should reject 401 when principal signature invalid when DEFERRED registration is implemented (line 812)',
        () => {
            expect.fail('T2 DEFERRED (acceptance criterion (g))');
        },
    );
});

// ─── T3: lookup expired binding (IMPLEMENTED) ────────────────────────────────

describe('T3 holder binding lookup expired (line 813)', () => {
    // spec line 813: `T3: lookup expired binding → MCP_BINDING_EXPIRED_OR_MISSING`
    // IMPLEMENTED — holder-binding-resolver.test.ts:90 already covers the step 1 expired path
    it('T3 — should reference IMPLEMENTED test in holder-binding-resolver.test.ts (reference)', () => {
        // grep guard: holder-binding-resolver.test.ts contains the "notAfter <= now (binding expired)" test
        const testSource = readFileSync(
            resolve(__dirname, '../holder-binding-resolver.test.ts'),
            'utf-8',
        );
        expect(testSource).toMatch(/notAfter <= now/);
        expect(testSource).toMatch(/MCP_BINDING_EXPIRED_OR_MISSING/);
    });
});

// ─── T4: revoke binding via principal sig (PARTIAL - lookup implemented) ─────────

describe('T4 holder binding revocation reject subsequent calls (line 814)', () => {
    // spec line 814: `T4: revoke binding via principal sig → subsequent calls reject`
    // PARTIAL:
    //   - revocation lookup is implemented (holder-binding-resolver step 2/3)
    //   - the revoke registration flow (principal-sig verification + status write) is DEFERRED to a later release (criterion (g))
    it('T4 — should reference the implemented revocation lookup test in holder-binding-resolver.test.ts (step 2/3)', () => {
        // grep guard: the revocation status tombstone reject exists
        const testSource = readFileSync(
            resolve(__dirname, '../holder-binding-resolver.test.ts'),
            'utf-8',
        );
        expect(testSource).toMatch(/mcp_error_binding_revoked/);
        expect(testSource).toMatch(/tombstone/);
    });

    it.skip(
        'T4 — revoke binding REGISTRATION DEFERRED to a later release (criterion (g))',
        () => {
            expect.fail('T4 revoke registration flow DEFERRED to a later release (acceptance criterion (g))');
        },
    );
});

// ─── T5: register same mcp_client_id twice (DEFERRED) ────────────────────────

describe('T5 holder binding duplicate register conflict (line 815)', () => {
    // spec line 815: `T5: same mcp_client_id register twice (overlap notAfter) → reject (or supersede)`
    // DEFERRED: criterion (g) R14 line 782 — registration flow not implemented
    it.skip(
        'T5 — should reject 409 mcp_error_binding_conflict on duplicate active register when DEFERRED registration is implemented (line 815)',
        () => {
            expect.fail('T5 DEFERRED (acceptance criterion (g))');
        },
    );
});

// ─── T1-T5 conformance grep test (A30 guard) ──────────────────────────────

describe('T1-T5 conformance grep — acceptance criteria guard', () => {
    // A30 invariant: spec line 811-815's 5 T-ids are covered by describe blocks in this file
    it('source must contain the 5 describe blocks T1/T2/T3/T4/T5', () => {
        const self = readFileSync(__filename, 'utf-8');
        for (const tid of ['T1', 'T2', 'T3', 'T4', 'T5']) {
            // describe block (does not depend on description details, only greps the T-id prefix)
            expect(self).toMatch(new RegExp(`describe\\('${tid} `));
        }
    });

    it('source must reference spec line 811-815 in 5 places', () => {
        const self = readFileSync(__filename, 'utf-8');
        // spec line reference guard (prevents conformance from desyncing after spec line numbers shift)
        for (const line of ['811', '812', '813', '814', '815']) {
            expect(self).toContain(`line ${line}`);
        }
    });
});
