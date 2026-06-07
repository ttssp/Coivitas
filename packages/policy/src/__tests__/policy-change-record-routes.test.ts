/**
 * policy-change-record-routes.test.ts
 *
 * Test goal: the registerPolicyChangeRecordRoutes standalone read-path middleware
 * (packages/policy/src/middleware/policy-change-record-routes.ts)
 *
 * Coverage strategy:
 * - no dependency on a real database; DatabasePool.query is mocked with vi.fn()
 * - drive Express directly with MockSocket + IncomingMessage, no port to listen on
 * - full coverage of the 5 scenario classes the user specified:
 *   1. filter by action (POLICY_CREATED)
 *   2. filter by agentDid
 *   3. pagination (cursor generation / cursor passed in)
 *   4. bad parameter → 400 POLICY_QUERY_MALFORMED
 *   5. empty result (records:[], no nextCursor)
 * Additional authorization scenarios:
 *   6. no checker → 403 AUDIT_FORBIDDEN (deny-all fail-safe)
 *   7. checker denies → 403 + DB not called
 *   8. checker allows → DB query executes normally
 */

import { Duplex } from 'node:stream';
import { IncomingMessage, ServerResponse } from 'node:http';

import express from 'express';
import { describe, expect, it, vi, type Mock } from 'vitest';

import type { AuditAccessChecker } from '@coivitas/types';

import {
    registerPolicyChangeRecordRoutes,
    type RegisterPolicyChangeRecordRoutesOptions,
} from '../middleware/policy-change-record-routes.js';

// ═══════════════════════════════════════════════════════════════════════════
// MockSocket + inject (same pattern as audit-access-routes.test.ts, no external module dependency)
// ═══════════════════════════════════════════════════════════════════════════

class MockSocket extends Duplex {
    _chunks: Buffer[] = [];
    private _mockDestroyed = false;

    _read() {}
    _write(chunk: Buffer | string, enc: BufferEncoding, cb: () => void) {
        this._chunks.push(
            Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, enc),
        );
        cb();
    }
    cork() {}
    uncork() {}
    setTimeout() { return this as unknown as this; }
    ref() { return this as unknown as this; }
    unref() { return this as unknown as this; }
    destroy(_err?: Error) {
        if (!this._mockDestroyed) {
            this._mockDestroyed = true;
            this.emit('close');
        }
        return this;
    }
    get destroyed() { return this._mockDestroyed; }
    get remoteAddress() { return '127.0.0.1'; }
    get remotePort() { return 12345; }
    get writable() { return !this._mockDestroyed; }
    /** Pin readable=false so that on-finished.isFinished(req) becomes true*/
    get readable() { return false; }
}

interface InjectResponse {
    status: number;
    body: string;
    json: Record<string, unknown>;
}

function inject(
    app: ReturnType<typeof express>,
    method: string,
    path: string,
    headers: Record<string, string> = {},
): Promise<InjectResponse> {
    return new Promise((resolve) => {
        const sock = new MockSocket();
        const req = new IncomingMessage(
            sock as unknown as import('net').Socket,
        );
        req.method = method.toUpperCase();
        req.url = path;
        req.headers = headers;

        const res = new ServerResponse(req);
        res.assignSocket(sock as unknown as import('net').Socket);

        const collect = () => {
            const raw = Buffer.concat(sock._chunks).toString('utf8');
            const headerEnd = raw.indexOf('\r\n\r\n');
            const bodyStr = headerEnd >= 0 ? raw.slice(headerEnd + 4) : raw;
            const statusLine =
                headerEnd >= 0 ? raw.slice(0, headerEnd).split('\r\n')[0] : '';
            const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)/);
            const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
            let json: Record<string, unknown> = {};
            try {
                json = JSON.parse(bodyStr) as Record<string, unknown>;
            } catch { /* not JSON*/ }
            resolve({ status, body: bodyStr, json });
        };

        let resolved = false;
        const once = () => {
            if (!resolved) {
                resolved = true;
                collect();
            }
        };
        res.on('finish', once);
        sock.on('close', once);

        (
            app as unknown as {
                handle: (req: IncomingMessage, res: ServerResponse) => void;
            }
        ).handle(req, res);
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Test data factories
// ═══════════════════════════════════════════════════════════════════════════

/** Standard structure of a policy_change_records DB row*/
function makeDbRow(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
    return {
        id: '1',
        record_id: '550e8400-e29b-41d4-a716-446655440000',
        agent_did: 'did:agent:aabbccddeeff001122334455667788',
        principal_did: 'did:key:zTest123',
        action_type: 'POLICY_CREATED',
        params: { policyId: 'pol-001', policyVersion: 1, changeType: 'CREATED' },
        row_hash: 'abc123hash',
        prev_row_hash: '',
        actor_signature: 'actor-sig',
        ledger_signature: 'ledger-sig',
        created_at: '2026-04-18T12:34:56.789Z',
        ...overrides,
    };
}

/**
 * Build a mock DatabasePool.
 * queryMock holds a separate reference to avoid triggering the
 * @typescript-eslint/unbound-method rule via pool.query property access.
 */
function makeMockPool(rows: Record<string, unknown>[] = []): {
    pool: import('@coivitas/shared').DatabasePool;
    queryMock: Mock;
} {
    const queryMock = vi.fn().mockResolvedValue({ rows });
    const pool = { query: queryMock } as unknown as import('@coivitas/shared').DatabasePool;
    return { pool, queryMock };
}

/**
 * allow-all AuditAccessChecker (for test use).
 * Production must use a real checker with subject-scope constraints.
 */
const ALLOW_ALL_CHECKER: AuditAccessChecker = {
    check: (_request) => Promise.resolve({ allowed: true }),
};

/**
 * deny-with-custom-code AuditAccessChecker (for testing the checker-denies scenario).
 */
function makeDenyChecker(reason = 'test denied'): AuditAccessChecker {
    return {
        check: (_request) =>
            Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason,
            }),
    };
}

/**
 * Register the routes and return the Express app.
 * Injects ALLOW_ALL_CHECKER by default (keeping existing test scenarios unchanged);
 * the authorization-specific tests must explicitly override the auditAccessChecker field.
 */
function makeApp(options: RegisterPolicyChangeRecordRoutesOptions) {
    const app = express();
    // Inject an allow-all checker by default so existing functional tests pass straight through the auth layer
    const optionsWithChecker: RegisterPolicyChangeRecordRoutesOptions = {
        auditAccessChecker: ALLOW_ALL_CHECKER,
        ...options,
    };
    registerPolicyChangeRecordRoutes(app, optionsWithChecker);
    return app;
}

// ═══════════════════════════════════════════════════════════════════════════
// Test suite
// ═══════════════════════════════════════════════════════════════════════════

describe('registerPolicyChangeRecordRoutes', () => {

    // -----------------------------------------------------------------------
    // Scenario 1: filter by action → 200, records array, SQL contains the matching condition
    // -----------------------------------------------------------------------
    it('should return 200 with records when filtered by action=POLICY_CREATED', async () => {
        const row = makeDbRow({ action_type: 'POLICY_CREATED' });
        const { pool, queryMock } = makeMockPool([row]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?action=POLICY_CREATED',
        );

        expect(resp.status).toBe(200);
        expect(Array.isArray(resp.json['records'])).toBe(true);
        const records = resp.json['records'] as Record<string, unknown>[];
        expect(records).toHaveLength(1);
        expect(records[0]['actionType']).toBe('POLICY_CREATED');
        expect(records[0]['recordId']).toBe(row['record_id']);
        // The DB query should be called once, and the SQL should contain the action_type filter
        expect(queryMock).toHaveBeenCalledOnce();
        const [queryText] = queryMock.mock.calls[0] as [string, unknown[]];
        expect(queryText).toContain('action_type =');
    });

    // -----------------------------------------------------------------------
    // Scenario 1b: action=POLICY_UPDATED also passes the whitelist
    // -----------------------------------------------------------------------
    it('should accept action=POLICY_UPDATED through whitelist', async () => {
        const row = makeDbRow({ action_type: 'POLICY_UPDATED' });
        const { pool } = makeMockPool([row]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?action=POLICY_UPDATED',
        );

        expect(resp.status).toBe(200);
        const records = resp.json['records'] as Record<string, unknown>[];
        expect(records[0]['actionType']).toBe('POLICY_UPDATED');
    });

    // -----------------------------------------------------------------------
    // Scenario 2: filter by agentDid → 200, SQL contains the agent_did condition
    // -----------------------------------------------------------------------
    it('should return 200 with records when filtered by agentDid', async () => {
        const agentDid = 'did:agent:aabbccddeeff001122334455667788';
        const row = makeDbRow({ agent_did: agentDid });
        const { pool, queryMock } = makeMockPool([row]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            `/policy-change-records?agentDid=${encodeURIComponent(agentDid)}`,
        );

        expect(resp.status).toBe(200);
        const records = resp.json['records'] as Record<string, unknown>[];
        expect(records).toHaveLength(1);
        expect(records[0]['agentDid']).toBe(agentDid);
        // The DB query values should contain agentDid
        const [, queryValues] = queryMock.mock.calls[0] as [string, unknown[]];
        expect(queryValues).toContain(agentDid);
    });

    // -----------------------------------------------------------------------
    // Scenario 3a: pagination — when the DB returns limit+1 rows, a nextCursor should be produced
    // -----------------------------------------------------------------------
    it('should return nextCursor when DB returns limit+1 rows (hasMore=true)', async () => {
        // Default limit=50; returning 51 rows triggers hasMore
        const rows = Array.from({ length: 51 }, (_, i) =>
            makeDbRow({
                id: String(i + 1),
                created_at: `2026-04-18T12:34:5${String(i % 10).padStart(1, '0')}.000Z`,
            }),
        );
        const { pool } = makeMockPool(rows);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(200);
        const records = resp.json['records'] as unknown[];
        // Only the first 50 are returned; the 51st is truncated
        expect(records).toHaveLength(50);
        expect(typeof resp.json['nextCursor']).toBe('string');
        // The cursor should be valid Base64URL
        const cursor = resp.json['nextCursor'] as string;
        expect(/^[A-Za-z0-9_-]+$/.test(cursor)).toBe(true);
    });

    // -----------------------------------------------------------------------
    // Scenario 3b: pagination — when a valid cursor (single-key id format) is passed in, the SQL should contain the id > condition
    // -----------------------------------------------------------------------
    it('should include cursor condition in SQL when cursor param is provided', async () => {
        // The cursor format changed to a single-key id (Base64URL(id)), no longer ts|id
        const cursor = Buffer.from('42', 'utf8').toString('base64url');
        const { pool, queryMock } = makeMockPool([]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            `/policy-change-records?cursor=${cursor}`,
        );

        expect(resp.status).toBe(200);
        // The SQL should contain the cursor condition (id >)
        const [queryText] = queryMock.mock.calls[0] as [string, unknown[]];
        expect(queryText).toContain('id >');
    });

    // -----------------------------------------------------------------------
    // Scenario 3c: ORDER BY id ASC (matching the writer hash chain sequence)
    // -----------------------------------------------------------------------
    it('should use ORDER BY id ASC to match writer hash chain sequence', async () => {
        const { pool, queryMock } = makeMockPool([]);
        const app = makeApp({ dbPool: pool });

        await inject(app, 'GET', '/policy-change-records');

        const [queryText] = queryMock.mock.calls[0] as [string, unknown[]];
        // ORDER BY id (matching the writer's ORDER BY id DESC), not sorted by created_at
        expect(queryText).toContain('ORDER BY id ASC');
        // Should not contain ORDER BY created_at
        expect(queryText).not.toMatch(/ORDER BY created_at/);
    });

    // -----------------------------------------------------------------------
    // Scenario 3d: old-format cursor (ts|id) → 400 POLICY_QUERY_MALFORMED (fail-closed)
    // -----------------------------------------------------------------------
    it('should return 400 POLICY_QUERY_MALFORMED when cursor is old composite format (ts|id)', async () => {
        // Old-format cursor: Base64URL(timestamp|id), where the id segment is not purely numeric
        const oldFormatCursor = Buffer.from(
            '2026-04-18T12:34:56.789Z|42',
            'utf8',
        ).toString('base64url');
        const { pool, queryMock } = makeMockPool([]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            `/policy-change-records?cursor=${oldFormatCursor}`,
        );

        // After decoding, the old format contains '2026-...|42', not purely numeric → fail-closed 400
        expect(resp.status).toBe(400);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('POLICY_QUERY_MALFORMED');
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 3e: cursor decodes to a non-numeric string → 400 POLICY_QUERY_MALFORMED
    // -----------------------------------------------------------------------
    it('should return 400 POLICY_QUERY_MALFORMED when cursor decodes to non-numeric string', async () => {
        // Valid Base64URL, but not purely numeric after decoding
        const malformedCursor = Buffer.from('not-a-number', 'utf8').toString('base64url');
        const { pool, queryMock } = makeMockPool([]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            `/policy-change-records?cursor=${malformedCursor}`,
        );

        expect(resp.status).toBe(400);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('POLICY_QUERY_MALFORMED');
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 3f: non-Base64URL cursor → 400 (at the parseQueryParams stage)
    // -----------------------------------------------------------------------
    it('should return 400 POLICY_QUERY_MALFORMED when cursor contains non-Base64URL chars', async () => {
        const { pool, queryMock } = makeMockPool([]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?cursor=not+valid+base64url!!',
        );

        expect(resp.status).toBe(400);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('POLICY_QUERY_MALFORMED');
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 4a: unknown query parameter → 400 POLICY_QUERY_MALFORMED
    // -----------------------------------------------------------------------
    it('should return 400 POLICY_QUERY_MALFORMED when unknown query param is provided', async () => {
        const { pool, queryMock } = makeMockPool();
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?unknownField=bad',
        );

        expect(resp.status).toBe(400);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('POLICY_QUERY_MALFORMED');
        // The DB should not be called
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 4b: action not in the whitelist → 400 POLICY_QUERY_MALFORMED
    // -----------------------------------------------------------------------
    it('should return 400 POLICY_QUERY_MALFORMED when action is not a POLICY_* type', async () => {
        const { pool, queryMock } = makeMockPool();
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?action=INQUIRY',
        );

        expect(resp.status).toBe(400);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('POLICY_QUERY_MALFORMED');
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 4c: agentDid has the wrong prefix → 400
    // -----------------------------------------------------------------------
    it('should return 400 when agentDid does not start with did:agent:', async () => {
        const { pool } = makeMockPool();
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?agentDid=did:key:wrong',
        );

        expect(resp.status).toBe(400);
        expect(
            (resp.json['error'] as Record<string, unknown>)['code'],
        ).toBe('POLICY_QUERY_MALFORMED');
    });

    // -----------------------------------------------------------------------
    // Scenario 4d: limit out of range → 400
    // -----------------------------------------------------------------------
    it('should return 400 when limit is out of range (>500)', async () => {
        const { pool, queryMock } = makeMockPool();
        const app = makeApp({ dbPool: pool });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?limit=501',
        );

        expect(resp.status).toBe(400);
        expect(
            (resp.json['error'] as Record<string, unknown>)['code'],
        ).toBe('POLICY_QUERY_MALFORMED');
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 5: empty result → 200, records:[], no nextCursor
    // -----------------------------------------------------------------------
    it('should return 200 with empty records array and no nextCursor when DB returns nothing', async () => {
        const { pool } = makeMockPool([]); // empty result set
        const app = makeApp({ dbPool: pool });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(200);
        const records = resp.json['records'] as unknown[];
        expect(records).toHaveLength(0);
        expect(resp.json['nextCursor']).toBeUndefined();
    });

    // -----------------------------------------------------------------------
    // Scenario 6: DB query fails → 500 INTERNAL_ERROR (fail-closed)
    // -----------------------------------------------------------------------
    it('should return 500 INTERNAL_ERROR when DB query throws', async () => {
        const queryMock = vi.fn().mockRejectedValue(new Error('DB connection refused'));
        const pool = { query: queryMock } as unknown as import('@coivitas/shared').DatabasePool;
        const app = makeApp({ dbPool: pool });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(500);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('INTERNAL_ERROR');
        expect(typeof error['detail']).toBe('string');
    });

    // -----------------------------------------------------------------------
    // Scenario 6: no checker → 403 AUDIT_FORBIDDEN (deny-all fail-safe)
    // -----------------------------------------------------------------------
    it('should return 403 AUDIT_FORBIDDEN when no auditAccessChecker is provided (deny-all fail-safe)', async () => {
        const { pool, queryMock } = makeMockPool([makeDbRow()]);
        // Note: call registerPolicyChangeRecordRoutes directly, not via makeApp (which injects allow-all by default)
        const app = express();
        registerPolicyChangeRecordRoutes(app, {
            dbPool: pool,
            // Intentionally omit auditAccessChecker to trigger the deny-all default
        });

        const resp = await inject(app, 'GET', '/policy-change-records');

        // deny-all fail-safe: 403 AUDIT_FORBIDDEN
        expect(resp.status).toBe(403);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('AUDIT_FORBIDDEN');
        // The DB should not be called (auth runs before the DB query)
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 7: checker.check() denies → 403, DB not called
    // -----------------------------------------------------------------------
    it('should return 403 and not query DB when auditAccessChecker denies', async () => {
        const { pool, queryMock } = makeMockPool([makeDbRow()]);
        const app = express();
        registerPolicyChangeRecordRoutes(app, {
            dbPool: pool,
            auditAccessChecker: makeDenyChecker('subject scope mismatch'),
        });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(403);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('AUDIT_FORBIDDEN');
        expect(error['detail']).toBe('subject scope mismatch');
        // The DB should not be called (auth fails before the DB)
        expect(queryMock).not.toHaveBeenCalled();
    });

    // -----------------------------------------------------------------------
    // Scenario 8: checker.check() allows → DB query executes normally
    // -----------------------------------------------------------------------
    it('should execute DB query when auditAccessChecker allows', async () => {
        const { pool, queryMock } = makeMockPool([makeDbRow()]);
        const app = express();
        registerPolicyChangeRecordRoutes(app, {
            dbPool: pool,
            auditAccessChecker: ALLOW_ALL_CHECKER,
        });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(200);
        // The DB should be called once
        expect(queryMock).toHaveBeenCalledOnce();
    });

    // -----------------------------------------------------------------------
    // Scenario 9: custom routePrefix takes effect (renumbered from the original scenario 7)
    // -----------------------------------------------------------------------
    it('should respond on custom routePrefix instead of default path', async () => {
        const { pool } = makeMockPool([]);
        const app = makeApp({ dbPool: pool, routePrefix: '/audit/policy-changes' });

        // The default path should not respond (Express returns 404)
        const defaultResp = await inject(app, 'GET', '/policy-change-records');
        expect(defaultResp.status).not.toBe(200);

        // The custom path should respond
        const customResp = await inject(app, 'GET', '/audit/policy-changes');
        expect(customResp.status).toBe(200);
    });

    // -----------------------------------------------------------------------
    // Scenario 8: response body field mapping is correct (snake_case → camelCase, Date object serialization)
    // -----------------------------------------------------------------------
    it('should map DB row fields from snake_case to camelCase in response', async () => {
        const row = makeDbRow({
            record_id: 'rec-uuid-001',
            agent_did: 'did:agent:deadbeef',
            principal_did: 'did:key:zTest999',
            action_type: 'POLICY_REVOKED',
            row_hash: 'hash-001',
            prev_row_hash: 'hash-000',
            actor_signature: 'actor-sig-001',
            ledger_signature: 'ledger-sig-001',
            created_at: new Date('2026-04-18T12:34:56.789Z'), // Date object should be serialized to an ISO string
        });
        const { pool } = makeMockPool([row]);
        const app = makeApp({ dbPool: pool });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(200);
        const record = (resp.json['records'] as Record<string, unknown>[])[0]!;
        expect(record['recordId']).toBe('rec-uuid-001');
        expect(record['agentDid']).toBe('did:agent:deadbeef');
        expect(record['principalDid']).toBe('did:key:zTest999');
        expect(record['actionType']).toBe('POLICY_REVOKED');
        expect(record['rowHash']).toBe('hash-001');
        expect(record['prevRowHash']).toBe('hash-000');
        expect(record['actorSignature']).toBe('actor-sig-001');
        expect(record['ledgerSignature']).toBe('ledger-sig-001');
        // Date object should be serialized to an ISO string
        expect(typeof record['createdAt']).toBe('string');
        expect(record['createdAt']).toBe('2026-04-18T12:34:56.789Z');
    });

    // -----------------------------------------------------------------------
    // Scenario 10: the real checker receives non-null query/resolvedIdentity
    // -----------------------------------------------------------------------
    it('should pass non-null query and resolvedIdentity to real checker when identityResolver is provided', async () => {
        // PrincipalAuditAccessChecker-style mock: inspects query.queryParams / resolvedIdentity.principalDid
        const capturedRequests: import('@coivitas/types').VerifiedAuditRequest[] = [];
        const realLikeChecker: AuditAccessChecker = {
            check: (request) => {
                capturedRequests.push(request);
                // Simulate PrincipalAuditAccessChecker behavior: dereference query/resolvedIdentity
                if (request.lane !== 'business') {
                    return Promise.resolve({ allowed: false, code: 'AUDIT_FORBIDDEN', reason: 'wrong lane' });
                }
                // These two lines would TypeError in the earlier implementation (null.principalDid); after the fix they no longer crash
                const principalDid = request.resolvedIdentity.principalDid;
                const requesterDid = request.query.requesterDid;
                void principalDid;
                void requesterDid;
                return Promise.resolve({ allowed: true });
            },
        };

        const mockIdentity: import('@coivitas/types').AgentIdentityDocument = {
            id: 'did:agent:aabb1122334455' as import('@coivitas/types').DID,
            specVersion: '0.1.0',
            principalDid: 'did:key:zPrincipal001' as import('@coivitas/types').DID,
            publicKey: 'ed25519-pub-key',
            bindingProof: {
                type: 'Ed25519Signature2020',
                created: '2026-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
                proofPurpose: 'assertionMethod',
                verificationMethod: 'did:agent:aabb1122334455#key-1',
                jws: 'mock-jws',
            },
            createdAt: '2026-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
            updatedAt: '2026-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
        };

        const identityResolver = vi.fn().mockResolvedValue(mockIdentity);
        const { pool, queryMock } = makeMockPool([makeDbRow()]);
        const app = express();
        registerPolicyChangeRecordRoutes(app, {
            dbPool: pool,
            auditAccessChecker: realLikeChecker,
            identityResolver,
        });

        const resp = await inject(
            app,
            'GET',
            '/policy-change-records?agentDid=did:agent:aabb1122334455',
            {
                'x-audit-requester-did': 'did:key:zPrincipal001',
                'x-audit-target-agent-did': 'did:agent:aabb1122334455',
            },
        );

        // The request passes (checker returns allowed=true)
        expect(resp.status).toBe(200);
        // The DB is called once (after the checker passes)
        expect(queryMock).toHaveBeenCalledOnce();
        // The checker is called once and receives non-null arguments
        expect(capturedRequests).toHaveLength(1);
        const captured = capturedRequests[0]!;
        expect(captured.lane).toBe('business');
        if (captured.lane === 'business') {
            // resolvedIdentity must be a real object (not null) — the core acceptance point
            expect(captured.resolvedIdentity).not.toBeNull();
            expect(captured.resolvedIdentity.principalDid).toBe('did:key:zPrincipal001');
            // query.queryParams must be a real object (containing agentDid), not null
            expect(captured.query).not.toBeNull();
            expect(captured.query.queryParams.agentDid).toBe('did:agent:aabb1122334455');
            // query.requesterDid is extracted from the request header
            expect(captured.query.requesterDid).toBe('did:key:zPrincipal001');
        }
        // identityResolver is called once
        expect(identityResolver).toHaveBeenCalledOnce();
    });

    // -----------------------------------------------------------------------
    // Scenario 11: identityResolver returns null → 403 fail-closed
    // -----------------------------------------------------------------------
    it('should return 403 AUDIT_FORBIDDEN when identityResolver returns null (fail-closed)', async () => {
        const checkerSpy = vi.fn().mockResolvedValue({ allowed: true });
        const realLikeChecker: AuditAccessChecker = { check: checkerSpy };
        const { pool, queryMock } = makeMockPool([makeDbRow()]);
        const app = express();
        registerPolicyChangeRecordRoutes(app, {
            dbPool: pool,
            auditAccessChecker: realLikeChecker,
            // identityResolver returns null → fail-closed
            identityResolver: vi.fn().mockResolvedValue(null),
        });

        const resp = await inject(app, 'GET', '/policy-change-records');

        expect(resp.status).toBe(403);
        const error = resp.json['error'] as Record<string, unknown>;
        expect(error['code']).toBe('AUDIT_FORBIDDEN');
        // Identity resolution failed; neither the checker nor the DB should be called
        expect(checkerSpy).not.toHaveBeenCalled();
        expect(queryMock).not.toHaveBeenCalled();
    });
});
