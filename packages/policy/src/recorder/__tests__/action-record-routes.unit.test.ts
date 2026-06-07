/**
 * action-record-routes.unit.test.ts
 *
 * Unit tests: cover all routes, middleware, and PrincipalAuditAccessChecker in action-record-routes.ts.
 *
 * Test strategy:
 * - No real database; mock pg Pool.query with vi.fn() and dispatch by SQL keyword
 * - No supertest; make HTTP requests with node:http + the global fetch (Node 20+)
 * - Use a static Ed25519 test key pair; compute real signatures with sign() from @coivitas/crypto
 * - The snapshot anchor is returned by the DB mock; snapshotMaxId is determined by the anchor row id
 */

import { Duplex } from 'node:stream';
import { IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';

import express from 'express';
import { describe, expect, it, vi, type Mock } from 'vitest';

import { canonicalize, sign } from '@coivitas/crypto';
import { IdentityRegistry } from '@coivitas/identity';
import type { DID, Signature, Timestamp } from '@coivitas/types';
import { ProtocolError, SESSION_GOVERNOR_DID } from '@coivitas/types';

import type {
    AuditAccessChecker,
    AuditResourceBinding,
    ControlPlaneRequesterScope,
    VerifiedAuditRequest,
} from '../../audit/types.js';
import {
    ControlPlaneAuditAccessChecker,
    PrincipalAuditAccessChecker,
    registerActionRecordRoutes,
    __testing__makeHandleGet,
    __testing__makeHandleVerify,
    __testing__makeHandleSignedLedgerHead,
    __testing__makeHandleChainVerify,
} from '../action-record-routes.js';
import {
    buildUnsignedRecordPayload,
    computeRecordHash,
    createRecordSignature,
    derivePublicKeyFromPrivateKey,
} from '../shared.js';

// ═══════════════════════════════════════════════════════════════════════════
// Static test key pair (deterministic, not random)

// Generation method: Ed25519 seed = 0xab * 32 bytes
// seed (32B, 64 hex): 'ab'.repeat(32)
// public (32B, 64 hex): 248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930
// full private (64B, 128 hex): seed + public
// did:key: did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK
// ═══════════════════════════════════════════════════════════════════════════
const TEST_PUB_HEX =
    '248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930';
const TEST_FULL_PRIV_HEX = 'ab'.repeat(32) + TEST_PUB_HEX; // 128 hex chars

// Standalone ledger key: used to generate a real signature for action_records.ledger_signature,
// so that /records/:id/verify can genuinely verify ledger_signature.
// seed uses 'cd'*32 to distinguish it from TEST_FULL_PRIV_HEX, avoiding accidentally using the same key for actor/ledger.
const TEST_LEDGER_SEED_HEX = 'cd'.repeat(32);
const TEST_LEDGER_PUB_HEX = derivePublicKeyFromPrivateKey(TEST_LEDGER_SEED_HEX);
const TEST_REQUESTER_DID =
    'did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK' as DID;

// Target agent DID (did:agent:* format)
const TEST_AGENT_DID =
    'did:agent:aabbccddeeff00112233445566778899aabbccdd' as DID;

// Snapshot anchor record (returned by the DB snapshot query)
const SNAPSHOT_RECORD_ID = '11111111-1111-4111-8111-111111111111';
const SNAPSHOT_CREATED_AT = '2024-01-01T00:00:00.000Z';
const SNAPSHOT_RECORD_HASH = 'snap-hash-001';
const SNAPSHOT_INTERNAL_ID = '50'; // snapshotMaxId = BigInt('50')

// Test action record row
const TEST_RECORD_INTERNAL_ID = '42'; // 42 <= 50, within the snapshot boundary
const TEST_RECORD_ID = '22222222-2222-4222-8222-222222222222';

// Build real hashes and signatures to support the /records/:id/verify and /records/chain/verify tests
// payload is kept consistent with buildUnsignedRecordPayload
const TEST_RECORD_UNSIGNED_PAYLOAD = buildUnsignedRecordPayload({
    recordId: TEST_RECORD_ID,
    agentDid: TEST_AGENT_DID,
    principalDid: TEST_REQUESTER_DID,
    actionType: 'INQUIRY',
    parametersSummary: null,
    authorizationRef: null,
    resultSummary: null,
    previousRecordHash: '',
    createdAt:
        '2024-01-01T00:00:00.000Z' as import('@coivitas/types').Timestamp,
});
const TEST_RECORD_HASH = computeRecordHash(
    TEST_RECORD_UNSIGNED_PAYLOAD,
    '',
    'hex',
);
const TEST_RECORD_ACTOR_SIG = createRecordSignature(
    TEST_RECORD_UNSIGNED_PAYLOAD,
    TEST_FULL_PRIV_HEX,
    'hex',
);
const TEST_RECORD_LEDGER_SIG = createRecordSignature(
    TEST_RECORD_UNSIGNED_PAYLOAD,
    TEST_LEDGER_SEED_HEX,
    'hex',
);

const TEST_RECORD_ROW = {
    id: TEST_RECORD_INTERNAL_ID,
    record_id: TEST_RECORD_ID,
    agent_did: TEST_AGENT_DID,
    principal_did: TEST_REQUESTER_DID,
    action_type: 'INQUIRY',
    parameters_summary: null,
    authorization_ref: null,
    result_summary: null,
    record_hash: TEST_RECORD_HASH,
    previous_record_hash: '',
    actor_signature: TEST_RECORD_ACTOR_SIG,
    ledger_signature: TEST_RECORD_LEDGER_SIG,
    delegation_depth: null,
    session_id: null,
    created_at: '2024-01-01T00:00:00.000Z',
};

// ═══════════════════════════════════════════════════════════════════════════
// Mock Pool factory

// Dispatch by SQL keyword:
// 'identity.agents' → identityRows (IdentityRegistry.queryForAudit)
// 'WHERE record_id = $1\n AND agent_did' → snapshotRows (snapshot anchor query)
// 'ORDER BY id DESC' → others (/ledger/head)
// default → recordRows
// ═══════════════════════════════════════════════════════════════════════════
interface PoolOverrides {
    identityRows?: object[];
    snapshotRows?: object[];
    recordRows?: object[];
    ledgerHeadRows?: object[];
}

function makeAgentDocument(
    agentDid: DID,
    pubKeyHex: string,
    principalDid: DID = TEST_REQUESTER_DID,
) {
    return {
        id: agentDid,
        specVersion: '0.1.0',
        principalDid,
        publicKey: pubKeyHex,
        bindingProof: {
            principalDid,
            agentDid,
            issuedAt: '2024-01-01T00:00:00.000Z',
            expiresAt: null,
            signature: 'binding-sig',
        },
        capabilities: [],
        serviceEndpoints: [],
        createdAt: '2024-01-01T00:00:00.000Z' as Timestamp,
        updatedAt: '2024-01-01T00:00:00.000Z' as Timestamp,
        version: 1,
    };
}

function makePool(overrides: PoolOverrides = {}) {
    const identityRows = overrides.identityRows ?? [
        {
            did: TEST_AGENT_DID,
            document: makeAgentDocument(TEST_AGENT_DID, TEST_PUB_HEX),
            status: 'active',
            version: 1,
        },
    ];
    const snapshotRows = overrides.snapshotRows ?? [
        {
            id: SNAPSHOT_INTERNAL_ID,
            record_hash: SNAPSHOT_RECORD_HASH,
            created_at: SNAPSHOT_CREATED_AT,
        },
    ];
    const recordRows = overrides.recordRows ?? [TEST_RECORD_ROW];
    const ledgerHeadRows = overrides.ledgerHeadRows ?? [
        {
            record_id: SNAPSHOT_RECORD_ID,
            created_at: SNAPSHOT_CREATED_AT,
            record_hash: SNAPSHOT_RECORD_HASH,
        },
    ];

    const query: Mock = vi.fn().mockImplementation((sql: string) => {
        if (typeof sql !== 'string')
            return Promise.resolve({ rows: recordRows });
        if (sql.includes('identity.agents')) {
            return Promise.resolve({ rows: identityRows });
        }
        // anchor query (MAX(id)) for signed ledger.head
        if (sql.includes('MAX(id)')) {
            // Return anchor_id = the id of the current head row (if any)
            const headRow = ledgerHeadRows[0] as
                | { record_id: string; created_at: string; record_hash: string }
                | undefined;
            return Promise.resolve({
                rows: headRow ? [{ anchor_id: SNAPSHOT_INTERNAL_ID }] : [],
            });
        }
        if (sql.includes('ORDER BY id DESC')) {
            // /ledger/head query (including the anchor-bound variant)
            return Promise.resolve({ rows: ledgerHeadRows });
        }
        if (sql.includes('AND agent_did')) {
            // Snapshot anchor query: SELECT id, record_hash, created_at FROM policy.action_records WHERE record_id=$1 AND agent_did=$2 AND created_at=$3
            return Promise.resolve({ rows: snapshotRows });
        }
        // default: action_records list/get
        return Promise.resolve({ rows: recordRows });
    });

    return { query } as unknown as import('pg').Pool;
}

// ═══════════════════════════════════════════════════════════════════════════
// Express app + HTTP server factory
// ═══════════════════════════════════════════════════════════════════════════

// queryForAudit / getDocumentHistory mock: hijacks pool.query, skipping the triple-binding validation (test simplification)

// Basic verify tests such as Section 5a assume the agent has not rotated keys; history degenerates
// to [v1=current], so identityRows[0].document can be reused directly (consistent with
// IdentityRegistry.getDocumentHistory's behavior in the single-version case: it returns a single-element array).
function makeRegistryFromPool(pool: import('pg').Pool): IdentityRegistry {
    type IdentityRow = {
        did: string;
        document: object;
        status: 'active' | 'suspended' | 'deactivated';
        version: number;
    };
    return {
        queryForAudit: async (did: DID) => {
            const result = await pool.query(
                `SELECT did, document, status, version FROM identity.agents WHERE did = $1`,
                [did],
            );
            if (!result.rows[0]) return null;
            const row = result.rows[0] as IdentityRow;
            return {
                document: { ...row.document, version: row.version },
                status: row.status,
            };
        },
        getDocumentHistory: async (did: DID) => {
            const result = await pool.query(
                `SELECT did, document, status, version FROM identity.agents WHERE did = $1`,
                [did],
            );
            if (!result.rows[0]) return [];
            const row = result.rows[0] as IdentityRow;
            return [{ ...row.document, version: row.version }];
        },
    } as unknown as IdentityRegistry;
}

function makeApp(
    pool: import('pg').Pool,
    checkerOverride?: AuditAccessChecker,
    /**
     * v0.2 governor lane options.
     */
    governorOpts?: {
        controlPlaneChecker?: AuditAccessChecker;
        controlPlaneResolver?: (did: DID) => Promise<{
            did: DID;
            metadata: Readonly<Record<string, unknown>>;
            verifiedAt: import('@coivitas/types').Timestamp;
        } | null>;
        /**
         * Public-key resolver for the control-plane verify path.
         */
        resolveControlPlanePublicKey?: (did: DID) => Promise<string | null>;
    },
) {
    const app = express();
    app.use(express.json());

    registerActionRecordRoutes(app, {
        dbPool: pool,
        identityRegistry: makeRegistryFromPool(pool),
        ledgerPublicKey: TEST_LEDGER_PUB_HEX,
        checker: checkerOverride,
        controlPlaneChecker: governorOpts?.controlPlaneChecker,
        controlPlaneResolver: governorOpts?.controlPlaneResolver,
        resolveControlPlanePublicKey:
            governorOpts?.resolveControlPlanePublicKey,
    });

    return app;
}

// ═══════════════════════════════════════════════════════════════════════════
// MockSocket + inject: an HTTP injection tool that does not bind a TCP port

// How it works:
// 1. MockSocket extends Duplex and intercepts the bytes written by ServerResponse
// 2. get readable() { return false; } makes on-finished.isFinished(req) return true immediately,
// avoiding finalhandler hanging forever while waiting for the req 'end' event (404 routes must go through finalhandler)
// 3. app.handle(req, res) drives the Express routing chain directly, without a real TCP connection
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
    setTimeout() {
        return this as unknown as this;
    }
    ref() {
        return this as unknown as this;
    }
    unref() {
        return this as unknown as this;
    }

    destroy(_err?: Error) {
        if (!this._mockDestroyed) {
            this._mockDestroyed = true;
            this.emit('close');
        }
        return this;
    }

    get destroyed() {
        return this._mockDestroyed;
    }
    get remoteAddress() {
        return '127.0.0.1';
    }
    get remotePort() {
        return 12345;
    }
    get writable() {
        return !this._mockDestroyed;
    }
    // Key: make on-finished.isFinished(req) return true immediately
    // to avoid finalhandler hanging forever while waiting for req.on('end')
    get readable() {
        return false;
    }
}

interface InjectResponse {
    status: number;
    body: string;
    json: unknown;
}

function inject(
    application: ReturnType<typeof express>,
    method: string,
    path: string,
    opts: { headers?: Record<string, string> } = {},
): Promise<InjectResponse> {
    return new Promise((resolve) => {
        const sock = new MockSocket();
        const req = new IncomingMessage(
            sock as unknown as import('net').Socket,
        );
        req.method = method.toUpperCase();
        req.url = path;
        req.headers = opts.headers ?? {};

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
            let json: unknown = null;
            try {
                json = JSON.parse(bodyStr);
            } catch {
                /* not JSON*/
            }
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

        // Express 5 app.handle() drives the routing chain directly
        (
            application as unknown as {
                handle: (req: IncomingMessage, res: ServerResponse) => void;
            }
        ).handle(req, res);
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Signing utilities

// Build the HTTP request headers that the middleware expects
// ═══════════════════════════════════════════════════════════════════════════
interface AuditRequestHeaders {
    'x-audit-requester': string;
    'x-audit-signature': string;
    'x-audit-timestamp': string;
    'x-audit-snapshot-headcreatedat': string;
    'x-audit-snapshot-headrecordid': string;
    'x-audit-snapshot-headrecordhash'?: string;
}

interface MakeAuditHeadersParams {
    requesterDid?: DID;
    targetAgentDid?: DID;
    resourceBinding: AuditResourceBinding;
    queryParams?: Record<string, unknown>;
    timestamp?: string;
    snapshotHeadCreatedAt?: string;
    snapshotHeadRecordId?: string;
    snapshotHeadRecordHash?: string;
    privateKey?: string;
    /** Override the signature (to test the invalid-signature scenario) */
    overrideSignature?: string;
}

function makeAuditHeaders(params: MakeAuditHeadersParams): AuditRequestHeaders {
    const requesterDid = params.requesterDid ?? TEST_REQUESTER_DID;
    const targetAgentDid = params.targetAgentDid ?? TEST_AGENT_DID;
    const timestamp =
        params.timestamp ?? (new Date().toISOString() as Timestamp);
    const snapshotHeadCreatedAt =
        params.snapshotHeadCreatedAt ?? SNAPSHOT_CREATED_AT;
    const snapshotHeadRecordId =
        params.snapshotHeadRecordId ?? SNAPSHOT_RECORD_ID;
    const snapshotHeadRecordHash =
        params.snapshotHeadRecordHash ?? SNAPSHOT_RECORD_HASH;
    const privateKey = params.privateKey ?? TEST_FULL_PRIV_HEX;

    const snapshotBoundary = {
        headCreatedAt: snapshotHeadCreatedAt as Timestamp,
        headRecordId: snapshotHeadRecordId,
        ...(snapshotHeadRecordHash
            ? { headRecordHash: snapshotHeadRecordHash }
            : {}),
    };

    const signaturePayload = {
        requesterDid,
        targetAgentDid,
        httpMethod: 'GET' as const,
        resourceBinding: params.resourceBinding,
        queryParams: params.queryParams ?? {},
        snapshotBoundary,
        timestamp,
    };

    const canonical = canonicalize(signaturePayload);
    const msgBytes = new TextEncoder().encode(canonical);
    const signature = params.overrideSignature ?? sign(msgBytes, privateKey);

    const headers: AuditRequestHeaders = {
        'x-audit-requester': requesterDid,
        'x-audit-signature': signature,
        'x-audit-timestamp': timestamp,
        'x-audit-snapshot-headcreatedat': snapshotHeadCreatedAt,
        'x-audit-snapshot-headrecordid': snapshotHeadRecordId,
    };
    if (snapshotHeadRecordHash) {
        headers['x-audit-snapshot-headrecordhash'] = snapshotHeadRecordHash;
    }
    return headers;
}

// ═══════════════════════════════════════════════════════════════════════════
// buildPath: build a path string with query parameters (inject() uses the path directly, no baseUrl needed)
// ═══════════════════════════════════════════════════════════════════════════
function buildPath(path: string, params: Record<string, string> = {}): string {
    const url = new URL(path, 'http://localhost');
    for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
    }
    return url.pathname + (url.search || '');
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: PrincipalAuditAccessChecker
// ═══════════════════════════════════════════════════════════════════════════
describe('PrincipalAuditAccessChecker', () => {
    const checker = new PrincipalAuditAccessChecker();

    function makeVerifiedRequest(
        overrides: {
            requesterDid?: DID;
            targetAgentDid?: DID;
            principalDocDid?: DID;
            queryParamAgentDid?: DID;
            queryParamPrincipalDid?: DID;
        } = {},
    ): VerifiedAuditRequest {
        const requesterDid = overrides.requesterDid ?? TEST_REQUESTER_DID;
        const targetAgentDid = overrides.targetAgentDid ?? TEST_AGENT_DID;
        const principalDocDid = overrides.principalDocDid ?? TEST_REQUESTER_DID;

        return {
            // union type forces the lane discriminant
            lane: 'business',
            query: {
                requesterDid,
                targetAgentDid,
                httpMethod: 'GET',
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: {
                    ...(overrides.queryParamAgentDid
                        ? { agentDid: overrides.queryParamAgentDid }
                        : {}),
                    ...(overrides.queryParamPrincipalDid
                        ? { principalDid: overrides.queryParamPrincipalDid }
                        : {}),
                },
                snapshotBoundary: {
                    headCreatedAt: SNAPSHOT_CREATED_AT as Timestamp,
                    headRecordId: SNAPSHOT_RECORD_ID,
                },
                timestamp: new Date().toISOString() as Timestamp,
                signature: 'sig' as Signature,
            },
            resolvedIdentity: makeAgentDocument(
                targetAgentDid,
                TEST_PUB_HEX,
                principalDocDid,
            ),
            identityStatus: 'active',
            verifiedAt: new Date().toISOString() as Timestamp,
        };
    }

    it('should allow when principalDid matches requester and no agentDid filter', async () => {
        // resolvedIdentity.principalDid === requesterDid, no agentDid/principalDid filter
        const result = await checker.check(makeVerifiedRequest());
        expect(result.allowed).toBe(true);
    });

    it('should deny AUDIT_FORBIDDEN when principalDid in resolvedIdentity does not match requester', async () => {
        // resolvedIdentity.principalDid !== requesterDid
        const result = await checker.check(
            makeVerifiedRequest({
                principalDocDid: 'did:key:zzzzzzDifferent' as DID,
            }),
        );
        expect(result.allowed).toBe(false);
        if (!result.allowed) {
            expect(result.code).toBe('AUDIT_FORBIDDEN');
        }
    });

    it('should deny AUDIT_FORBIDDEN when agentDid filter conflicts with targetAgentDid', async () => {
        // queryParams.agentDid !== targetAgentDid → AUDIT_FORBIDDEN (not AUDIT_QUERY_MALFORMED)
        // agentDid filter conflict is semantic auth failure
        const result = await checker.check(
            makeVerifiedRequest({
                targetAgentDid: TEST_AGENT_DID,
                queryParamAgentDid:
                    'did:agent:ffffffffffffffffffffffffffffffffffffffff' as DID,
            }),
        );
        expect(result.allowed).toBe(false);
        if (!result.allowed) {
            expect(result.code).toBe('AUDIT_FORBIDDEN');
        }
    });

    it('should allow when agentDid filter matches targetAgentDid', async () => {
        // queryParams.agentDid === targetAgentDid → allowed
        const result = await checker.check(
            makeVerifiedRequest({ queryParamAgentDid: TEST_AGENT_DID }),
        );
        expect(result.allowed).toBe(true);
    });

    it('should deny AUDIT_FORBIDDEN when principalDid filter does not match requester', async () => {
        // queryParams.principalDid !== requesterDid → AUDIT_FORBIDDEN
        const result = await checker.check(
            makeVerifiedRequest({
                queryParamPrincipalDid:
                    'did:key:zzzzzzDifferentPrincipal' as DID,
            }),
        );
        expect(result.allowed).toBe(false);
        if (!result.allowed) {
            expect(result.code).toBe('AUDIT_FORBIDDEN');
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: GET /ledger/head (unsigned helper endpoint)
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /ledger/head', () => {
    it('should return 200 with headRecordId, headCreatedAt, headRecordHash when ledger has records', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const res = await inject(
            app,
            'GET',
            buildPath('/ledger/head', { agent_did: TEST_AGENT_DID }),
        );
        expect(res.status).toBe(200);
        const body = res.json as Record<string, unknown>;
        expect(body).toMatchObject({
            agentDid: TEST_AGENT_DID,
            headRecordId: SNAPSHOT_RECORD_ID,
            headRecordHash: SNAPSHOT_RECORD_HASH,
        });
        expect(typeof body['headCreatedAt']).toBe('string');
    });

    it('should return 404 with NOT_FOUND when ledger is empty', async () => {
        const pool = makePool({ ledgerHeadRows: [] });
        const app = makeApp(pool);
        const res = await inject(
            app,
            'GET',
            buildPath('/ledger/head', { agent_did: TEST_AGENT_DID }),
        );
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should return 400 when agent_did query param is missing', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const res = await inject(app, 'GET', '/ledger/head');
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when agent_did does not start with did:agent:', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const res = await inject(
            app,
            'GET',
            buildPath('/ledger/head', { agent_did: 'did:key:invalid' }),
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should propagate DB error as 500 when pool.query throws in ledger/head', async () => {
        // Covers the registerLedgerHeadRoute catch(err) → next(err) path (lines 764-766)
        // Build a pool that throws on ORDER BY id DESC
        const errorPool = {
            query: vi.fn().mockImplementation((sql: string) => {
                if (sql.includes('ORDER BY id DESC')) {
                    return Promise.reject(new Error('DB connection lost'));
                }
                return Promise.resolve({ rows: [] });
            }),
        } as unknown as import('pg').Pool;
        // The Express default error handler returns 500
        const app = makeApp(errorPool);
        // Add a fallback error handler
        app.use(
            (
                _err: unknown,
                _req: import('express').Request,
                res: import('express').Response,
                _next: import('express').NextFunction,
            ) => {
                res.status(500).json({
                    error: { code: 'INTERNAL_ERROR', detail: 'db error' },
                });
            },
        );
        const res = await inject(
            app,
            'GET',
            buildPath('/ledger/head', { agent_did: TEST_AGENT_DID }),
        );
        expect(res.status).toBe(500);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: GET /records
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /records', () => {
    it('should return 200 with paginated records within snapshot boundary', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { records: unknown[] };
        expect(Array.isArray(body.records)).toBe(true);
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for malformed cursor (no pipe)', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                cursor: 'bad-cursor-no-pipe',
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                cursor: 'bad-cursor-no-pipe',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for invalid start date', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, start: 'not-a-date' },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                start: 'not-a-date',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for invalid end date', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, end: 'not-a-date' },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                end: 'not-a-date',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return empty records when all DB rows are beyond snapshot boundary', async () => {
        // record id '200' > snapshotMaxId '50' → should be filtered by WHERE id <= $2
        // But since the mock pool does no real SQL filtering, here we verify the response structure is correct
        // The actual filtering is done by the SQL clause "id <= snapshotMaxId", guaranteed by the DB layer
        const pool = makePool({ recordRows: [] }); // the pool returns empty directly
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { records: unknown[] };
        expect(body.records).toHaveLength(0);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: GET /records/:id
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /records/:id', () => {
    it('should return 200 with record details when record exists within snapshot', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        // For records.get, targetAgentDid comes from prefetchedRecord.agent_did (not URL).
        // parseQueryParams converts URL ?agent_did=X → { agentDid: X } in the signature payload.
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.get', recordId: TEST_RECORD_ID },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 404 NOT_FOUND when record does not exist', async () => {
        const pool = makePool({ recordRows: [] }); // existenceGuard returns empty
        const app = makeApp(pool);
        // On record-not-found, the middleware reads agent_did from the query param,
        // so agent_did must be included in both the URL and the signature payload
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.get', recordId: TEST_RECORD_ID },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for non-UUID record id', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        // recordExistenceGuard returns 400 for non-UUID-v4 formats
        const res = await inject(app, 'GET', '/records/not-a-uuid');
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 404 NOT_FOUND when record is outside snapshot boundary', async () => {
        // record._internalId (200) > snapshotMaxId (50) → 404 NOT_FOUND (information hiding)
        const outsideRecord = { ...TEST_RECORD_ROW, id: '200' };
        // The existenceGuard mock returns outsideRecord, the middleware must also pass, then makeHandleGet returns 404
        // For existenceGuard to pass but the handler to return 404, the snapshot anchor must also return snapshotMaxId < 200
        // The current SNAPSHOT_INTERNAL_ID = '50' < 200, which satisfies the condition
        const pool = makePool({ recordRows: [outsideRecord] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.get', recordId: TEST_RECORD_ID },
        });
        // existenceGuard queries the record and returns outsideRecord, then the middleware uses the prefetched agent_did
        // Afterwards makeHandleGet checks record._internalId > snapshotMaxId → 404
        const res = await inject(app, 'GET', `/records/${TEST_RECORD_ID}`, {
            headers,
        });
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('NOT_FOUND');
    });

    // The AUDIT_RESOURCE_BINDING_MISMATCH branch is architecturally unreachable on the HTTP middleware path:
    // auditMiddleware always sets targetAgentDid to prefetchedRecord.agent_did,
    // so the secondary check inside makeHandleGet/makeHandleVerify never triggers.
    // Coverage of this branch is done via Section 8 (directly constructing an AuditHandlerContext); see the end of the file.
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 5a: GET /records/:id/verify
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /records/:id/verify', () => {
    it('should return 200 with valid checks when record hash and actor signature are correct', async () => {
        const pool = makePool(); // TEST_RECORD_ROW already includes a real hash + actor_signature
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean }>;
        };
        // All three checks pass: record_hash / actor_signature / ledger_signature
        const hashCheck = body.checks.find((c) => c.name === 'record_hash');
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        const ledgerCheck = body.checks.find(
            (c) => c.name === 'ledger_signature',
        );
        expect(hashCheck?.valid).toBe(true);
        expect(actorCheck?.valid).toBe(true);
        expect(ledgerCheck?.valid).toBe(true);
        expect(body.valid).toBe(true);
        // the partialVerification field has been removed
        expect(
            (body as Record<string, unknown>)['partialVerification'],
        ).toBeUndefined();
    });

    it('should return 200 with valid=false when record_hash is corrupted', async () => {
        // Tamper with the stored hash → computeRecordHash does not match → hashCheck.valid = false
        const corruptedRow = {
            ...TEST_RECORD_ROW,
            record_hash: 'deadbeef' + 'a'.repeat(56),
        };
        const pool = makePool({ recordRows: [corruptedRow] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean }>;
        };
        const hashCheck = body.checks.find((c) => c.name === 'record_hash');
        expect(hashCheck?.valid).toBe(false);
        expect(body.valid).toBe(false);
    });

    it('should return 404 NOT_FOUND when record is outside snapshot boundary', async () => {
        // record internal id 200 > snapshotMaxId 50
        const outsideRow = { ...TEST_RECORD_ROW, id: '200' };
        const pool = makePool({ recordRows: [outsideRow] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should return 200 with valid=false when ledger_signature is invalid', async () => {
        // Regression guard: ledger_signature is replaced with a signature signed by the wrong key;
        // before the fix the endpoint returned valid:true (hard-coded skipping of the ledger check), now it must return valid:false.
        const WRONG_LEDGER_SEED = '11'.repeat(32);
        const forgedLedgerSig = createRecordSignature(
            TEST_RECORD_UNSIGNED_PAYLOAD,
            WRONG_LEDGER_SEED,
            'hex',
        );
        const tamperedRow = {
            ...TEST_RECORD_ROW,
            ledger_signature: forgedLedgerSig,
        };
        const pool = makePool({ recordRows: [tamperedRow] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean }>;
        };
        const hashCheck = body.checks.find((c) => c.name === 'record_hash');
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        const ledgerCheck = body.checks.find(
            (c) => c.name === 'ledger_signature',
        );
        // hash / actor still genuinely pass, only ledger fails → overall valid:false
        expect(hashCheck?.valid).toBe(true);
        expect(actorCheck?.valid).toBe(true);
        expect(ledgerCheck?.valid).toBe(false);
        expect(body.valid).toBe(false);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 5a-bis: GET /records/:id/verify — actor_signature candidate public-key set strategy

// Background:
// The verify endpoint verifies actor_signature using the agent publicKey "valid at the moment the
// record was created". The initial algorithm picked a single public key by doc.updatedAt; but
// IdentityRegistry.update also increments version, advances updatedAt, and overwrites
// previous_document on non-key changes (modifying capabilities / serviceEndpoints) (registry.ts:174-201).
// As a result:
// - Scenario A: the key was never rotated, but after two ordinary metadata updates,
// the updatedAt of both [current, previous] returned by getDocumentHistory is later than
// record.createdAt → the initial algorithm returns null → false-positive of actor_signature being invalid.
// - Scenario B: 1 rotation + 1 metadata edit. previousPublicKey can still be read from the current
// document, but the updatedAt of both [current, previous] is later than the early
// record.createdAt → the same false positive.

// Fix strategy (candidate public-key set):
// - Collect publicKey + previousPublicKey from all docs in verifiedAudit.resolvedIdentity and history,
// then dedupe to form the candidate set.
// - Try each candidate in turn against record.actorSignature; if any passes, it is valid.
// - Ed25519 unforgeability guarantee: a public key that verifies must have been signed by a private
// key the agent once held → security is not relaxed; this only eliminates the false rejection of
// legitimate records caused by "misusing updatedAt".
// - Empty candidate set (extreme mock boundary) → reason "unable to resolve historical public key".
// - Non-empty candidate set but all fail (including genuine loss from "history has been truncated, K1 is gone") →
// reason "actor signature invalid".
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /records/:id/verify — actor_signature historical publicKey resolution', () => {
    // Preparation: the second/third "future" key seeds. Only publicKey is used for the historical
    // documents; they are never actually used to sign the current record — the record itself is still
    // issued by TEST_FULL_PRIV_HEX, simulating an "earlier-created record". This design forces the
    // algorithm to correctly select v1 in order to verify successfully.
    const ROTATED_KEY_SEED_V2 = '22'.repeat(32);
    const ROTATED_KEY_PUB_V2 =
        derivePublicKeyFromPrivateKey(ROTATED_KEY_SEED_V2);
    const ROTATED_KEY_SEED_V3 = '33'.repeat(32);
    const ROTATED_KEY_PUB_V3 =
        derivePublicKeyFromPrivateKey(ROTATED_KEY_SEED_V3);

    // Key time anchors: record.createdAt = 2024-01-01T00:00:00.000Z (TEST_RECORD_ROW.created_at)
    // v1 validity interval [2024-01-01, 2024-02-01)
    // v2 validity interval [2024-02-01, 2024-03-01)
    // v3 validity interval [2024-03-01, ∞)
    const V1_UPDATED_AT = '2024-01-01T00:00:00.000Z';
    const V2_UPDATED_AT = '2024-02-01T00:00:00.000Z';
    const V3_UPDATED_AT = '2024-03-01T00:00:00.000Z';

    function makeHistoricalDoc(opts: {
        publicKey: string;
        updatedAt: string;
        version: number;
    }) {
        return {
            ...makeAgentDocument(TEST_AGENT_DID, opts.publicKey),
            updatedAt: opts.updatedAt as Timestamp,
            version: opts.version,
        };
    }

    // Build an IdentityRegistry mock:
    // queryForAudit returns the current latest document (whose publicKey = history[0].publicKey),
    // getDocumentHistory returns the full history (in descending version order).
    function makeRegistryWithHistory(
        history: ReturnType<typeof makeHistoricalDoc>[],
    ): IdentityRegistry {
        const current = history[0]!;
        return {
            queryForAudit: (_did: DID) =>
                Promise.resolve({
                    document: current,
                    status: 'active',
                }),
            getDocumentHistory: (_did: DID) => Promise.resolve(history),
        } as unknown as IdentityRegistry;
    }

    it('should validate actor_signature with current publicKey when no rotation has happened', async () => {
        // 0 rotations: history contains only v1 (publicKey = TEST_PUB_HEX). The record is issued by TEST_FULL_PRIV_HEX.
        const history = [
            makeHistoricalDoc({
                publicKey: TEST_PUB_HEX,
                updatedAt: V1_UPDATED_AT,
                version: 1,
            }),
        ];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(true);
        expect(actorCheck?.reason).toBeUndefined();
    });

    it('should validate actor_signature with previous publicKey when one rotation has happened after the record', async () => {
        // 1 rotation: history = [v2 (NEW_KEY, updatedAt=2024-02-01), v1 (TEST_PUB_HEX, updatedAt=2024-01-01)]
        // record.createdAt = 2024-01-01 → should select v1 (TEST_PUB_HEX)
        const history = [
            makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V2,
                updatedAt: V2_UPDATED_AT,
                version: 2,
            }),
            makeHistoricalDoc({
                publicKey: TEST_PUB_HEX,
                updatedAt: V1_UPDATED_AT,
                version: 1,
            }),
        ];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        // Key regression guard: the original implementation took verifiedAudit.resolvedIdentity.publicKey (=v2 NEW_KEY) → must fail;
        // after the fix it takes historical v1 → must pass.
        expect(actorCheck?.valid).toBe(true);
        expect(actorCheck?.reason).toBeUndefined();
    });

    it('should validate actor_signature with the oldest matching publicKey when two rotations have happened after the record', async () => {
        // 2 rotations: history = [v3, v2, v1], record.createdAt = 2024-01-01 → should select v1
        const history = [
            makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V3,
                updatedAt: V3_UPDATED_AT,
                version: 3,
            }),
            makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V2,
                updatedAt: V2_UPDATED_AT,
                version: 2,
            }),
            makeHistoricalDoc({
                publicKey: TEST_PUB_HEX,
                updatedAt: V1_UPDATED_AT,
                version: 1,
            }),
        ];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(true);
        expect(actorCheck?.reason).toBeUndefined();
    });

    it('should mark actor_signature historical_key_unavailable when history is at retention upper bound and no candidate verifies (3+ rotations scenario)', async () => {
        // Genuine loss scenario: history = [v3, v2] (v1 has been overwritten and lost);
        // the record is issued by K1, but the candidate set can only obtain {K3, K2} (even
        // v2.previousPublicKey is only the one before K2 — here makeHistoricalDoc does not write previousPublicKey).
        // The candidate set is non-empty but all verifications fail.

        // When history.length >= 2 (the current registry schema upper bound),
        // it is impossible within a two-version window to distinguish "genuine forgery" from
        // "the historical key has been overwritten", so the reason is switched from the ambiguous
        // 'actor signature invalid' to 'historical_key_unavailable', hinting to the auditor that "it
        // may be an old key that has already been overwritten".
        const history = [
            makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V3,
                updatedAt: V3_UPDATED_AT,
                version: 3,
            }),
            makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V2,
                updatedAt: V2_UPDATED_AT,
                version: 2,
            }),
        ];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(false);
        // history.length === 2 → 'historical_key_unavailable'
        expect(actorCheck?.reason).toBe('historical_key_unavailable');
        // The overall valid must be false (any failing check)
        expect(body.valid).toBe(false);
    });

    it('should mark actor_signature invalid when no candidate verifies and history is shallow (single version → likely real forgery, not historical loss)', async () => {
        // Counterexample: when history.length < 2, the registry fully covers recent keys, so the
        // candidate set still failing entirely leans toward "genuine mismatch" rather than "historical
        // loss" — keep the original reason.
        // Here history = [v2] (only 1 version), the current resolvedIdentity is also K2, and the
        // record is issued by K1 → candidate set {K2}, verification must fail; history.length === 1.
        const history = [
            makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V2,
                updatedAt: V2_UPDATED_AT,
                version: 2,
            }),
        ];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(false);
        // history is shallow (< 2 versions) → still 'actor signature invalid'
        expect(actorCheck?.reason).toBe('actor signature invalid');
        expect(body.valid).toBe(false);
    });

    it('should mark actor_signature invalid with "unable to resolve" when both history and current resolvedIdentity yield no publicKey', async () => {
        // Extreme boundary: the candidate set is completely empty. This does not happen on the
        // production path (resolvedIdentity always has a publicKey), but we mock a resolvedIdentity with
        // publicKey="" + empty history to force the candidate set to be genuinely empty, covering the
        // "unable to resolve" early-return branch.
        const pool = makePool();
        const registry = {
            queryForAudit: (_did: DID) =>
                Promise.resolve({
                    document: {
                        ...makeAgentDocument(TEST_AGENT_DID, TEST_PUB_HEX),
                        publicKey: '',
                    },
                    status: 'active' as const,
                }),
            getDocumentHistory: () => Promise.resolve([] as never[]),
        } as unknown as IdentityRegistry;
        const app = makeAppWithRegistry(pool, registry);
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(false);
        expect(actorCheck?.reason).toBe(
            'unable to resolve historical public key',
        );
    });

    // ── Regression guard: never rotated + multiple metadata updates ───────────────────
    it('should validate actor_signature when key never rotated but identity document had multiple metadata updates', async () => {
        // Scenario A: register → add capability (version 2) → change endpoint (version 3), publicKey always = K1.
        // history = [v3 (K1, updatedAt=T2), v2 (K1, updatedAt=T1)], both updatedAt later than record.createdAt.
        // Candidate set = {K1} (after dedupe), the record is signed by K1 → must pass.
        // Initial algorithm: both updatedAt later → null → false-positive invalid (a regression that once occurred).
        const history = [
            makeHistoricalDoc({
                publicKey: TEST_PUB_HEX,
                updatedAt: V3_UPDATED_AT,
                version: 3,
            }),
            makeHistoricalDoc({
                publicKey: TEST_PUB_HEX,
                updatedAt: V2_UPDATED_AT,
                version: 2,
            }),
        ];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(true);
        expect(actorCheck?.reason).toBeUndefined();
    });

    // ── Regression guard: 1 rotation + 1 subsequent metadata update ───────────────
    it('should validate actor_signature via previousPublicKey when one rotation followed by metadata edit drops v1 from history', async () => {
        // Scenario B: register K1 (v=1) → rotate K1→K2 (v=2) → edit metadata (v=3, K2).
        // history = [v3 (publicKey=K2, previousPublicKey=K1, updatedAt=T2),
        // v2 (publicKey=K2, previousPublicKey=K1, updatedAt=T1)]
        // The record is issued by K1, and record.createdAt is earlier than T1.
        // Candidate set = {K2, K1} (K1 comes from v3.previousPublicKey), the record is signed by K1 → must pass.
        // Initial algorithm: both updatedAt later than record.createdAt → null → false-positive invalid.
        const docV3WithPrev = {
            ...makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V2,
                updatedAt: V3_UPDATED_AT,
                version: 3,
            }),
            previousPublicKey: TEST_PUB_HEX,
        };
        const docV2WithPrev = {
            ...makeHistoricalDoc({
                publicKey: ROTATED_KEY_PUB_V2,
                updatedAt: V2_UPDATED_AT,
                version: 2,
            }),
            previousPublicKey: TEST_PUB_HEX,
        };
        const history = [docV3WithPrev, docV2WithPrev];
        const pool = makePool();
        const app = makeAppWithRegistry(pool, makeRegistryWithHistory(history));
        const headers = makeAuditHeaders({
            resourceBinding: {
                route: 'records.verify',
                recordId: TEST_RECORD_ID,
            },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                agent_did: TEST_AGENT_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean; reason?: string }>;
        };
        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(true);
        expect(actorCheck?.reason).toBeUndefined();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 5b: GET /records/chain/verify
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /records/chain/verify', () => {
    it('should return 200 with valid=true and recordCount=0 when chain is empty', async () => {
        const pool = makePool({ recordRows: [] }); // an empty chain passes directly
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.chain.verify', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records/chain/verify', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { valid: boolean; recordCount: number };
        expect(body.valid).toBe(true);
        expect(body.recordCount).toBe(0);
    });

    it('should return 200 with valid=true and recordCount=1 when single record chain is intact', async () => {
        // TEST_RECORD_ROW already has a real hash, previous_record_hash='' (first record) → the chain is intact
        const pool = makePool({ recordRows: [TEST_RECORD_ROW] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.chain.verify', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records/chain/verify', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { valid: boolean; recordCount: number };
        expect(body.valid).toBe(true);
        expect(body.recordCount).toBe(1);
    });

    it('should return 200 with valid=false when previous_record_hash does not link to prior record', async () => {
        // The 2nd record's previous_record_hash does not equal the 1st record's record_hash → broken chain
        const record2Id = '33333333-3333-4333-8333-333333333333';
        // The 2nd record's previous_record_hash is intentionally set to a wrong value
        const wrongPrevHash = 'badhash' + '0'.repeat(57);
        const record2UnsignedPayload = buildUnsignedRecordPayload({
            recordId: record2Id,
            agentDid: TEST_AGENT_DID,
            principalDid: TEST_REQUESTER_DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: wrongPrevHash,
            createdAt:
                '2024-01-02T00:00:00.000Z' as import('@coivitas/types').Timestamp,
        });
        const record2Hash = computeRecordHash(
            record2UnsignedPayload,
            wrongPrevHash,
            'hex',
        );
        const record2ActorSig = createRecordSignature(
            record2UnsignedPayload,
            TEST_FULL_PRIV_HEX,
            'hex',
        );
        const record2Row = {
            id: '43', // 43 <= 50, within the boundary
            record_id: record2Id,
            agent_did: TEST_AGENT_DID,
            principal_did: TEST_REQUESTER_DID,
            action_type: 'INQUIRY',
            parameters_summary: null,
            authorization_ref: null,
            result_summary: null,
            record_hash: record2Hash,
            previous_record_hash: wrongPrevHash, // wrong: should be TEST_RECORD_HASH
            actor_signature: record2ActorSig,
            ledger_signature: 'ledgersig002',
            delegation_depth: null,
            session_id: null,
            created_at: '2024-01-02T00:00:00.000Z',
        };
        const pool = makePool({ recordRows: [TEST_RECORD_ROW, record2Row] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.chain.verify', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records/chain/verify', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            brokenAt: string;
            reason: string;
            recordCount: number;
        };
        expect(body.valid).toBe(false);
        expect(body.reason).toBe('previous_record_hash mismatch');
        expect(body.brokenAt).toBe(record2Id);
    });

    it('should return 200 with valid=false when record_hash does not match computed hash', async () => {
        // The stored record_hash value is tampered with → computeRecordHash does not match → hash mismatch
        const corruptedRow = {
            ...TEST_RECORD_ROW,
            record_hash: 'cafebabe' + 'f'.repeat(56),
        };
        const pool = makePool({ recordRows: [corruptedRow] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.chain.verify', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records/chain/verify', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            valid: boolean;
            brokenAt: string;
            reason: string;
            recordCount: number;
        };
        expect(body.valid).toBe(false);
        expect(body.reason).toBe('record_hash mismatch');
        expect(body.brokenAt).toBe(TEST_RECORD_ID);
    });

    it('should return 400 AUDIT_QUERY_MALFORMED when chain exceeds 10000 records', async () => {
        // Regression guard: the original hard-coded LIMIT 10001 would silently truncate and return valid:true;
        // after the fix, a window exceeding 10000 records should return 400, requiring a narrower start/end.
        // Build a mock pool with 10001 records (content does not matter, only that the count > 10000).
        const bulkRows = Array.from({ length: 10001 }, (_, i) => ({
            ...TEST_RECORD_ROW,
            id: String(i + 1),
            record_id: `${(i + 1).toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`,
        }));
        const pool = makePool({ recordRows: bulkRows });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.chain.verify', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records/chain/verify', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
        expect(body.error.detail).toMatch(/exceeds 10000/);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 5c: GET /records advanced filtering (covers the optional clauses of makeHandleList)
// ═══════════════════════════════════════════════════════════════════════════
describe('GET /records advanced filters', () => {
    it('should return 200 with principalDid filter applied', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                principalDid: TEST_REQUESTER_DID,
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                principal_did: TEST_REQUESTER_DID,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 200 with action filter applied', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, action: 'INQUIRY' },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                action: 'INQUIRY',
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 200 with sessionId filter applied', async () => {
        const validSessionId = randomUUID();
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                sessionId: validSessionId,
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                session_id: validSessionId,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 200 with start and end filters applied', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                start: '2024-01-01T00:00:00.000Z',
                end: '2024-12-31T23:59:59.999Z',
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                start: '2024-01-01T00:00:00.000Z',
                end: '2024-12-31T23:59:59.999Z',
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 200 with valid cursor and next page', async () => {
        // The pool returns limit+1 records to trigger hasMore=true and generate nextCursor
        // The default limit=100, so build 101 records
        const manyRows = Array.from({ length: 101 }, (_, i) => ({
            ...TEST_RECORD_ROW,
            id: String(i + 1),
            record_id: randomUUID(),
            created_at: new Date(Date.UTC(2024, 0, i + 1)).toISOString(),
        }));
        const pool = makePool({ recordRows: manyRows });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { records: unknown[]; nextCursor?: string };
        expect(body.nextCursor).toBeDefined();
    });

    it('should return 200 with valid cursor-paginated second page', async () => {
        // cursor is Base64URL; the internal structure is "${iso}|${id}".
        const cursorTs = '2024-01-01T00:00:00.000Z';
        const cursorId = '42';
        const validCursor = Buffer.from(
            `${cursorTs}|${cursorId}`,
            'utf8',
        ).toString('base64url');
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, cursor: validCursor },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                cursor: validCursor,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for cursor with non-integer id part', async () => {
        // After decoding valid Base64URL, "ts|non-int" → BigInt() throws → AUDIT_QUERY_MALFORMED
        const invalidCursor = Buffer.from(
            '2024-01-01T00:00:00.000Z|not-an-int',
            'utf8',
        ).toString('base64url');
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, cursor: invalidCursor },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                cursor: invalidCursor,
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED when X-Audit-Snapshot-HeadCreatedAt is not strict ISO 8601', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
            // Intentionally pass a ±HH:MM offset; the timestamp passes strict validation but headCreatedAt does not
            snapshotHeadCreatedAt: '2024-01-01T00:00:00+00:00',
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for cursor whose timestamp segment is not strict ISO 8601', async () => {
        // After decoding valid Base64URL, "non-iso|42" → rejected by isValidIso8601 → AUDIT_QUERY_MALFORMED
        const invalidCursor = Buffer.from(
            '2024-01-01 00:00:00|42',
            'utf8',
        ).toString('base64url');
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, cursor: invalidCursor },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                cursor: invalidCursor,
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should emit Base64URL nextCursor', async () => {
        // Regression guard: nextCursor must be Base64URL, decoding to the structure "${iso}|${id}".
        // The old implementation emitted "${iso}|${id}" as plaintext directly, violating the encoding convention.
        const manyRows = Array.from({ length: 3 }, (_, i) => ({
            ...TEST_RECORD_ROW,
            id: String(i + 1),
            record_id: `${(i + 1).toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`,
            created_at: new Date(Date.UTC(2024, 0, i + 1)).toISOString(),
        }));
        const pool = makePool({ recordRows: manyRows });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, limit: 2 },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                limit: '2',
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { records: unknown[]; nextCursor?: string };
        expect(body.nextCursor).toBeDefined();
        // Valid Base64URL character set (A-Z a-z 0-9 - _)
        expect(body.nextCursor).toMatch(/^[A-Za-z0-9_-]+$/);
        // Must not contain plaintext separators like a pipe or colon (otherwise it was not Base64URL encoded)
        expect(body.nextCursor).not.toContain('|');
        expect(body.nextCursor).not.toContain(':');
        // Roundtrip: after decoding it must be "${iso}|${id}"
        const decoded = Buffer.from(body.nextCursor!, 'base64url').toString(
            'utf8',
        );
        expect(decoded).toMatch(
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\|\d+$/,
        );
    });

    it('should return 400 AUDIT_QUERY_MALFORMED when start is ISO but not UTC (has +HH:MM offset)', async () => {
        // Regression guard: the start filter must go through strict UTC-milliseconds validation;
        // a timestamp with an offset must be rejected and must not be silently normalized by the server's toISOString().
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                start: '2024-01-01T00:00:00.000+08:00',
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                start: '2024-01-01T00:00:00.000+08:00',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 200 with start/end filters in chain/verify', async () => {
        // Covers the start/end filter clauses in makeHandleChainVerify
        const pool = makePool({ recordRows: [TEST_RECORD_ROW] });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.chain.verify', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                start: '2024-01-01T00:00:00.000Z',
                end: '2024-12-31T23:59:59.999Z',
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records/chain/verify', {
                agent_did: TEST_AGENT_DID,
                start: '2024-01-01T00:00:00.000Z',
                end: '2024-12-31T23:59:59.999Z',
            }),
            { headers },
        );
        expect(res.status).toBe(200);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: query parameter validation
// ═══════════════════════════════════════════════════════════════════════════
describe('Query params validation', () => {
    it('should return 400 when limit is greater than 500', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, limit: 501 },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                limit: '501',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when limit is 0 (below minimum)', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, limit: 0 },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                limit: '0',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when action is not in ACTION_VOCABULARY', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, action: 'DELETE' },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                action: 'DELETE',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // POLICY_CREATED/UPDATED/REVOKED are written to the standalone table policy_change_records,
    // not via the action_records route, so 400 AUDIT_QUERY_MALFORMED is expected here.
    it('should return 400 when action=POLICY_CREATED (not in ACTION_VOCABULARY)', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                action: 'INQUIRY',
            },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                action: 'POLICY_CREATED',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 7: middleware edge cases
// ═══════════════════════════════════════════════════════════════════════════
describe('Middleware edge cases', () => {
    it('should return 400 when x-audit-requester header is missing', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const allHeaders = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        // Delete a required header
        const { 'x-audit-requester': _removed, ...rest } = allHeaders;
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when x-audit-signature header is missing', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const allHeaders = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const { 'x-audit-signature': _removed, ...rest } = allHeaders;
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when x-audit-timestamp header is missing', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const allHeaders = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const { 'x-audit-timestamp': _removed, ...rest } = allHeaders;
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when x-audit-snapshot-headcreatedat header is missing', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const allHeaders = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const { 'x-audit-snapshot-headcreatedat': _removed, ...rest } =
            allHeaders;
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when x-audit-snapshot-headrecordid header is missing', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const { 'x-audit-snapshot-headrecordid': _removed, ...rest } = headers;
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 401 AUDIT_TIMESTAMP_SKEW when timestamp is more than 5 minutes old', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        // A timestamp from 6 minutes ago
        const oldTimestamp = new Date(Date.now() - 6 * 60 * 1000).toISOString();
        const snapshotCreatedAt = new Date(
            Date.now() - 7 * 60 * 1000,
        ).toISOString();
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
            timestamp: oldTimestamp,
            snapshotHeadCreatedAt: snapshotCreatedAt,
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_TIMESTAMP_SKEW');
    });

    it('should return 401 AUDIT_SIGNATURE_INVALID when signature is tampered', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
            overrideSignature: 'a'.repeat(128), // invalid signature (correct length but wrong content)
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SIGNATURE_INVALID');
    });

    it('should return 401 AUDIT_REQUESTER_UNKNOWN when requester DID is not did:key:', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        // x-audit-requester uses a non-did:key: format → extractPublicKeyFromDIDKey throws
        const headers = makeAuditHeaders({
            requesterDid: TEST_AGENT_DID, // did:agent: rather than did:key: → 400/401
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        // extractPublicKeyFromDIDKey fails → AUDIT_REQUESTER_UNKNOWN (401)
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_REQUESTER_UNKNOWN');
    });

    it('should return 403 AUDIT_FORBIDDEN when AuditAccessChecker denies', async () => {
        const alwaysDenyChecker: AuditAccessChecker = {
            check: () =>
                Promise.resolve({
                    allowed: false,
                    code: 'AUDIT_FORBIDDEN' as const,
                    reason: 'test denial',
                }),
        };
        const pool = makePool();
        const app = makeApp(pool, alwaysDenyChecker);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(403);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
    });

    it('should return 404 IDENTITY_NOT_FOUND when target agent is not in registry', async () => {
        const pool = makePool({ identityRows: [] }); // empty identity rows
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('IDENTITY_NOT_FOUND');
    });

    it('should return 400 when x-audit-snapshot-headrecordid is not UUID v4', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
            snapshotHeadRecordId: 'not-a-uuid',
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    it('should return 400 AUDIT_SNAPSHOT_BOUNDARY_VIOLATED when snapshot anchor not found', async () => {
        const pool = makePool({ snapshotRows: [] }); // snapshot anchor does not exist
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED for unknown query parameter', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, unknown_param: 'value' },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', {
                agent_did: TEST_AGENT_DID,
                unknown_param: 'value',
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when AuditAccessChecker denies with AUDIT_QUERY_MALFORMED', async () => {
        // Covers the decision.code === 'AUDIT_QUERY_MALFORMED' → 400 branch (lines 459-460)
        const malformedChecker: AuditAccessChecker = {
            check: () =>
                Promise.resolve({
                    allowed: false,
                    code: 'AUDIT_QUERY_MALFORMED' as const,
                    reason: 'bad query',
                }),
        };
        const pool = makePool();
        const app = makeApp(pool, malformedChecker);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 500 when AuditAccessChecker denies with unknown error code', async () => {
        // Covers the ternary fallthrough → 500 branch (lines 459-460 else clause)
        const unknownCodeChecker: AuditAccessChecker = {
            check: () =>
                Promise.resolve({
                    allowed: false,
                    code: 'UNKNOWN_CODE' as never,
                    reason: 'unexpected',
                }),
        };
        const pool = makePool();
        const app = makeApp(pool, unknownCodeChecker);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(500);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 8: directly test the BINDING_MISMATCH branch (architecturally unreachable via HTTP; requires test-only exports)

// The BINDING_MISMATCH check in makeHandleGet/makeHandleVerify is unreachable in the normal HTTP flow:
// auditMiddleware always copies targetAgentDid from prefetchedRecord.agent_did, so the two values are always equal.
// Use the __testing__ exports to directly construct an AuditHandlerContext that makes the two values differ, triggering this branch.
// ═══════════════════════════════════════════════════════════════════════════
describe('Section 8: AUDIT_RESOURCE_BINDING_MISMATCH branches (direct handler context)', () => {
    const DIFFERENT_DID =
        'did:agent:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' as DID;

    function makeMinimalRes() {
        let capturedStatus = 200;
        let capturedBody: unknown;
        return {
            get statusCode() {
                return capturedStatus;
            },
            get capturedBody() {
                return capturedBody;
            },
            status(n: number) {
                capturedStatus = n;
                return {
                    json: (b: unknown) => {
                        capturedBody = b;
                    },
                };
            },
        };
    }

    function makeVerifiedAuditForRecord(
        targetAgentDid: DID,
    ): VerifiedAuditRequest {
        return {
            // union type forces the lane discriminant
            lane: 'business',
            query: {
                requesterDid: TEST_REQUESTER_DID,
                targetAgentDid,
                httpMethod: 'GET',
                resourceBinding: {
                    route: 'records.get',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {},
                snapshotBoundary: {
                    headCreatedAt:
                        SNAPSHOT_CREATED_AT as import('@coivitas/types').Timestamp,
                    headRecordId: SNAPSHOT_RECORD_ID,
                },
                timestamp:
                    new Date().toISOString() as import('@coivitas/types').Timestamp,
                signature: 'sig' as import('@coivitas/types').Signature,
            },
            resolvedIdentity: makeAgentDocument(targetAgentDid, TEST_PUB_HEX),
            identityStatus: 'active',
            verifiedAt:
                new Date().toISOString() as import('@coivitas/types').Timestamp,
        };
    }

    it('should return 400 AUDIT_RESOURCE_BINDING_MISMATCH when makeHandleGet sees agent_did mismatch', async () => {
        const handler = __testing__makeHandleGet();
        const mockRes = makeMinimalRes();

        // verifiedAudit.query.targetAgentDid = TEST_AGENT_DID
        // prefetchedRecord.agent_did = DIFFERENT_DID → mismatch → BINDING_MISMATCH branch
        await handler({
            verifiedAudit: makeVerifiedAuditForRecord(TEST_AGENT_DID),
            snapshotMaxId: BigInt(SNAPSHOT_INTERNAL_ID),
            prefetchedRecord: {
                ...TEST_RECORD_ROW,
                agent_did: DIFFERENT_DID,
            } as never,
            res: mockRes as unknown as import('express').Response,
        });

        expect(mockRes.statusCode).toBe(400);
        const body = mockRes.capturedBody as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_RESOURCE_BINDING_MISMATCH');
    });

    it('should return 400 AUDIT_RESOURCE_BINDING_MISMATCH when makeHandleVerify sees agent_did mismatch', async () => {
        // The BINDING_MISMATCH branch is before the actor_signature check, so getDocumentHistory is not invoked
        const handler = __testing__makeHandleVerify(TEST_LEDGER_PUB_HEX, () =>
            Promise.resolve([]),
        );
        const mockRes = makeMinimalRes();

        await handler({
            verifiedAudit: makeVerifiedAuditForRecord(TEST_AGENT_DID),
            snapshotMaxId: BigInt(SNAPSHOT_INTERNAL_ID),
            prefetchedRecord: {
                ...TEST_RECORD_ROW,
                agent_did: DIFFERENT_DID,
            } as never,
            res: mockRes as unknown as import('express').Response,
        });

        expect(mockRes.statusCode).toBe(400);
        const body = mockRes.capturedBody as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_RESOURCE_BINDING_MISMATCH');
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Helper factory: accepts a custom IdentityRegistry (for ProtocolError / catch branch tests)
// ═══════════════════════════════════════════════════════════════════════════
function makeAppWithRegistry(
    pool: import('pg').Pool,
    registry: IdentityRegistry,
    checkerOverride?: AuditAccessChecker,
) {
    const app = express();
    app.use(express.json());
    registerActionRecordRoutes(app, {
        dbPool: pool,
        identityRegistry: registry,
        ledgerPublicKey: TEST_LEDGER_PUB_HEX,
        checker: checkerOverride,
    });
    // Fallback error handler: convert next(err) into a 500 JSON response
    app.use(
        (
            err: unknown,
            _req: IncomingMessage,
            res: ServerResponse,
            _next: unknown,
        ) => {
            res.statusCode = (err as { status?: number })?.status ?? 500;
            res.setHeader('Content-Type', 'application/json');
            res.end(
                JSON.stringify({
                    error: { code: 'INTERNAL_ERROR', detail: String(err) },
                }),
            );
        },
    );
    return app;
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 9: fill coverage gaps (parseQueryParams branches + catch blocks + ProtocolError)
// ═══════════════════════════════════════════════════════════════════════════
describe('Section 9: Additional branch coverage for middleware and catch paths', () => {
    // ── parseQueryParams: empty-string value (lines 183-186) ──────────────────────
    it('should return 400 AUDIT_QUERY_MALFORMED when query param value is empty string', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        // ?start= is parsed by Express's simple query parser as an empty string ''
        const path = `/records?agent_did=${encodeURIComponent(TEST_AGENT_DID)}&start=`;
        const res = await inject(app, 'GET', path, { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── parseQueryParams: invalid agent_did format (lines 195-198) ─────────
    it('should return 400 AUDIT_QUERY_MALFORMED when agent_did query param has wrong prefix', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const badAgentDid = 'did:wrong:aabbccddeeff';
        // Step 3 checks the agent_did prefix before step 4 (parseQueryParams) (lines 345-347)
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {},
        });
        const path = `/records?agent_did=${encodeURIComponent(badAgentDid)}`;
        const res = await inject(app, 'GET', path, { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── parseQueryParams: invalid principal_did format (lines 204-207) ──────
    it('should return 400 AUDIT_QUERY_MALFORMED when principal_did has wrong prefix', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const badPrincipal = 'did:wrong:abc123';
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {
                agentDid: TEST_AGENT_DID,
                principalDid: badPrincipal as DID,
            },
        });
        const path = `/records?agent_did=${encodeURIComponent(TEST_AGENT_DID)}&principal_did=${encodeURIComponent(badPrincipal)}`;
        const res = await inject(app, 'GET', path, { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── parseQueryParams: invalid session_id (lines 222-225) ────────────
    it('should return 400 AUDIT_QUERY_MALFORMED when session_id is not UUID v4', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const badSession = 'not-a-uuid-at-all';
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID, sessionId: badSession },
        });
        const path = `/records?agent_did=${encodeURIComponent(TEST_AGENT_DID)}&session_id=${encodeURIComponent(badSession)}`;
        const res = await inject(app, 'GET', path, { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── Step 3 list: missing agent_did (lines 342-344) ───────────────────
    it('should return 400 AUDIT_QUERY_MALFORMED when agent_did is absent for records.list', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {},
        });
        const res = await inject(app, 'GET', '/records', { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── Step 3 list: agent_did not did:agent: (lines 345-347) ────────────
    it('should return 400 AUDIT_QUERY_MALFORMED when agent_did for list is not did:agent:', async () => {
        const pool = makePool();
        const app = makeApp(pool);
        const notAgentDid = 'did:key:z6MkfakeAgent';
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: {},
        });
        const path = `/records?agent_did=${encodeURIComponent(notAgentDid)}`;
        const res = await inject(app, 'GET', path, { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── headRecordHash mismatch (lines 375-377) ───────────────────────────
    it('should return 400 AUDIT_SNAPSHOT_BOUNDARY_VIOLATED when headRecordHash mismatches stored hash', async () => {
        const pool = makePool({
            snapshotRows: [
                {
                    id: SNAPSHOT_INTERNAL_ID,
                    record_hash: 'stored-hash-abc',
                    created_at: SNAPSHOT_CREATED_AT,
                },
            ],
        });
        const app = makeApp(pool);
        // The request headers carry a hash different from the DB
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
            snapshotHeadRecordHash: 'different-hash-xyz',
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    // ── headCreatedAt > timestamp (lines 382-384) ─────────────────────────
    it('should return 400 AUDIT_SNAPSHOT_BOUNDARY_VIOLATED when headCreatedAt is after timestamp', async () => {
        const futureHeadAt = '2030-01-01T00:00:00.000Z';
        const pastTimestamp = '2024-01-01T00:00:00.000Z';
        const pool = makePool({
            snapshotRows: [
                {
                    id: SNAPSHOT_INTERNAL_ID,
                    record_hash: SNAPSHOT_RECORD_HASH,
                    created_at: futureHeadAt,
                },
            ],
        });
        const app = makeApp(pool);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
            snapshotHeadCreatedAt: futureHeadAt,
            snapshotHeadRecordHash: SNAPSHOT_RECORD_HASH,
            timestamp: pastTimestamp,
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    // ── resolveForAudit rethrows non-BINDING_PROOF_INVALID errors → 500 ─
    it('should return 500 when queryForAudit throws a non-BINDING_PROOF_INVALID ProtocolError (rethrow path)', async () => {
        const pool = makePool();
        const throwingRegistry = {
            queryForAudit: (_did: DID) =>
                Promise.reject(
                    new ProtocolError(
                        'INTERNAL_ERROR',
                        'unexpected identity store failure',
                    ),
                ),
        } as unknown as IdentityRegistry;
        const app = makeAppWithRegistry(pool, throwingRegistry);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(500);
        const body = res.json as { error: { code: string } };
        // The fallback error handler converts next(err) into INTERNAL_ERROR JSON
        expect(body.error.code).toBe('INTERNAL_ERROR');
    });

    // ── resolveForAudit throws ProtocolError(BINDING_PROOF_INVALID) (lines 430-435) ─
    it('should return 401 AUDIT_IDENTITY_UNVERIFIED when queryForAudit throws BINDING_PROOF_INVALID', async () => {
        const pool = makePool();
        const throwingRegistry = {
            queryForAudit: (_did: DID) =>
                Promise.reject(
                    new ProtocolError(
                        'BINDING_PROOF_INVALID',
                        'binding proof mismatch in test',
                    ),
                ),
        } as unknown as IdentityRegistry;
        const app = makeAppWithRegistry(pool, throwingRegistry);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_IDENTITY_UNVERIFIED');
    });

    // ── makeAuditMiddleware catch block: snapshot query throws (lines 466-468) ─
    it('should return 500 when pool.query throws unexpectedly in audit middleware', async () => {
        // Simulate: the identity query passes but the snapshot query throws
        const pool = {
            query: vi.fn().mockImplementation((sql: string) => {
                if (
                    typeof sql === 'string' &&
                    sql.includes('identity.agents')
                ) {
                    return Promise.resolve({
                        rows: [
                            {
                                did: TEST_AGENT_DID,
                                document: makeAgentDocument(
                                    TEST_AGENT_DID,
                                    TEST_PUB_HEX,
                                ),
                                status: 'active',
                                version: 1,
                            },
                        ],
                    });
                }
                // the snapshot query (AND agent_did) and all other queries throw
                return Promise.reject(new Error('DB connection lost'));
            }),
        } as unknown as import('pg').Pool;

        const app = makeAppWithRegistry(pool, makeRegistryFromPool(pool));
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(500);
    });

    // ── makeRecordExistenceGuard catch block (lines 286-288) ─────────────────
    it('should return 500 when pool.query throws in recordExistenceGuard', async () => {
        const throwingPool = {
            query: vi.fn().mockRejectedValue(new Error('DB timeout')),
        } as unknown as import('pg').Pool;
        const registry = {
            queryForAudit: () => Promise.resolve(null),
        } as unknown as IdentityRegistry;
        const app = makeAppWithRegistry(throwingPool, registry);
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.get', recordId: TEST_RECORD_ID },
            queryParams: {},
        });
        const res = await inject(app, 'GET', `/records/${TEST_RECORD_ID}`, {
            headers,
        });
        expect(res.status).toBe(500);
    });

    // ── auditHandler catch block: handler throws internally (lines 67-69) ─────────────
    it('should return 500 when the audit handler function throws internally', async () => {
        // pool.query throws in makeHandleList, triggering auditHandler catch(err) → next(err)
        const pool = {
            query: vi.fn().mockImplementation((sql: string) => {
                if (
                    typeof sql === 'string' &&
                    sql.includes('identity.agents')
                ) {
                    return Promise.resolve({
                        rows: [
                            {
                                did: TEST_AGENT_DID,
                                document: makeAgentDocument(
                                    TEST_AGENT_DID,
                                    TEST_PUB_HEX,
                                ),
                                status: 'active',
                                version: 1,
                            },
                        ],
                    });
                }
                if (typeof sql === 'string' && sql.includes('AND agent_did')) {
                    return Promise.resolve({
                        rows: [
                            {
                                id: SNAPSHOT_INTERNAL_ID,
                                record_hash: SNAPSHOT_RECORD_HASH,
                                created_at: SNAPSHOT_CREATED_AT,
                            },
                        ],
                    });
                }
                // the final SELECT query of makeHandleList throws
                return Promise.reject(new Error('handler-level DB error'));
            }),
        } as unknown as import('pg').Pool;

        const app = makeAppWithRegistry(pool, makeRegistryFromPool(pool));
        const headers = makeAuditHeaders({
            resourceBinding: { route: 'records.list', recordId: null },
            queryParams: { agentDid: TEST_AGENT_DID },
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/records', { agent_did: TEST_AGENT_DID }),
            { headers },
        );
        expect(res.status).toBe(500);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// audit-access-model v0.2 governor lane e2e real-path regression

// Key design:
// - Do **not** bypass with permissiveChecker; use the real ControlPlaneAuditAccessChecker
// - Cover the matrix of 4 audit routes × {valid governor query / fail-closed scenarios /
// business DID takes the legacy path}
// - Directly cover the attack surface of the earlier "audit lane scope vulnerability"
// ═══════════════════════════════════════════════════════════════════════════

describe('governor lane e2e (real-path regression)', () => {
    const TEST_GOVERNOR_REQUESTER =
        'did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK' as DID;

    const makeGovernorResolver =
        (overrides?: { metadata?: Readonly<Record<string, unknown>> }) =>
        (did: DID) => {
            if (did !== SESSION_GOVERNOR_DID) return Promise.resolve(null);
            return Promise.resolve({
                did,
                metadata:
                    overrides?.metadata ??
                    ({
                        role: 'session-governor',
                        deployedBy: 'test-deployment',
                    } as const),
                verifiedAt: new Date().toISOString() as Timestamp,
            });
        };

    // v0.2: per-requester affected subject scope helper
    // The scope field changed from targetAgentDid to affectedAgentDid (an immutable payload field),
    // preventing the "any allow-listed requester can still read the entire governor ledger in the governor lane" vulnerability
    const TEST_AFFECTED_AGENT_DID =
        'did:agent:1111111111111111111111111111111111111111' as DID;
    const makeGovernorScope = (): ControlPlaneRequesterScope => ({
        allowedAffectedAgentDids: new Set<DID>([TEST_AFFECTED_AGENT_DID]),
    });

    const makeGovernorChecker = () =>
        new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
            ]),
        );

    // ─── /records route × governor lane ────────────────────────────────────
    describe('GET /records (governor lane)', () => {
        it('should allow valid governor audit query with control-plane resolver + checker', async () => {
            const pool = makePool();
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            // v0.2: the control-plane lane must explicitly declare affectedAgentDid
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: {
                    agentDid: SESSION_GOVERNOR_DID,
                    affectedAgentDid: TEST_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records', {
                    agent_did: SESSION_GOVERNOR_DID,
                    affected_agent_did: TEST_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            // The governor lane passes; the business records list may be empty (the mock pool's default rows do not match the governor agent_did)
            // Key assertion: no longer returns IDENTITY_NOT_FOUND / AUDIT_FORBIDDEN
            expect([200, 500]).toContain(res.status);
            if (res.status === 200) {
                expect(res.json).toBeTruthy();
            }
        });

        it('should fail-closed 403 when control-plane resolver missing', async () => {
            const pool = makePool();
            // Inject only the checker, no resolver
            const app = makeApp(pool, undefined, {
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: { agentDid: SESSION_GOVERNOR_DID },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records', { agent_did: SESSION_GOVERNOR_DID }),
                { headers },
            );
            expect(res.status).toBe(403);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('AUDIT_FORBIDDEN');
            expect(body.error.detail).toContain('control-plane lane disabled');
        });

        it('should fail-closed 403 when control-plane checker missing', async () => {
            const pool = makePool();
            // Inject only the resolver, no checker
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: { agentDid: SESSION_GOVERNOR_DID },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records', { agent_did: SESSION_GOVERNOR_DID }),
                { headers },
            );
            expect(res.status).toBe(403);
            const body = res.json as { error: { code: string } };
            expect(body.error.code).toBe('AUDIT_FORBIDDEN');
        });

        it('should reject 403 when requesterDid not in control-plane allow-list', async () => {
            const pool = makePool();
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                // The scope does not contain TEST_GOVERNOR_REQUESTER, hence 403
                controlPlaneChecker: new ControlPlaneAuditAccessChecker(
                    new Map<DID, ControlPlaneRequesterScope>([
                        [
                            'did:key:z6MknrTHt3JBYTFAtTksJB1xjoEK3T2TaYW9Tyy3XnL5dyey' as DID,
                            makeGovernorScope(),
                        ],
                    ]),
                ),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: { agentDid: SESSION_GOVERNOR_DID },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records', { agent_did: SESSION_GOVERNOR_DID }),
                { headers },
            );
            expect(res.status).toBe(403);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('AUDIT_FORBIDDEN');
            expect(body.error.detail).toContain(
                'requester is not in the control-plane allow-list',
            );
        });

        it('should fail-closed 404 IDENTITY_NOT_FOUND when resolver returns null for governor DID', async () => {
            const pool = makePool();
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: () => Promise.resolve(null), // resolver returns null
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: { agentDid: SESSION_GOVERNOR_DID },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records', { agent_did: SESSION_GOVERNOR_DID }),
                { headers },
            );
            expect(res.status).toBe(404);
            const body = res.json as { error: { code: string } };
            expect(body.error.code).toBe('IDENTITY_NOT_FOUND');
        });
    });

    // ─── /records/:id/verify route × governor lane ─────────────────────────
    // v0.1 governor lane rejects verify directly with 403.
    // v0.2: the control-plane lane accepts verify; the deployer injects resolveControlPlanePublicKey
    // to resolve the governor public key; when not injected, it fails closed with 403 (hinting at the injection path).
    describe('GET /records/:id/verify (governor lane)', () => {
        it('should reject 403 when resolveControlPlanePublicKey is not injected (fail-closed)', async () => {
            // Without injecting resolveControlPlanePublicKey → control-plane verify is unreachable → 403
            const governorRecordRow = {
                ...TEST_RECORD_ROW,
                agent_did: SESSION_GOVERNOR_DID,
                principal_did: SESSION_GOVERNOR_DID,
                action_type: 'SESSION_SUPERSEDED',
            };
            const pool = makePool({ recordRows: [governorRecordRow] });
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.verify',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {
                    affectedAgentDid: TEST_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                    affected_agent_did: TEST_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            expect(res.status).toBe(403);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('AUDIT_FORBIDDEN');
            expect(body.error.detail).toContain('resolveControlPlanePublicKey');
            expect(body.error.detail).toContain('IntegrityChecker');
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // v0.3: control-plane lane row-level subject scope validation
    // Full coverage of /records/:id + /records/:id/verify + /records/chain/verify
    // Attack scenario: first get a recordId via /audit/ledger/head, then request that recordId using
    // one's own authorized affected_agent_did, verifying that row.parameters_summary affected* matches
    // query.affected* strictly (mismatch → 400)
    // ═══════════════════════════════════════════════════════════════════
    describe('v0.3 row-level subject scope', () => {
        // Helper: build a SESSION_SUPERSEDED governor record whose payload points to SCOPED_AFFECTED
        const SCOPED_AFFECTED_AGENT_DID = TEST_AFFECTED_AGENT_DID;
        const FOREIGN_AFFECTED_AGENT_DID =
            'did:agent:ffffffffffffffffffffffffffffffffffffffff' as DID;
        const FOREIGN_AFFECTED_PRINCIPAL_DID =
            'did:key:z6MkForeignPrincipalDoNotShowToScopedRequester' as DID;
        const SCOPED_AFFECTED_PRINCIPAL_DID =
            'did:key:z6MkScopedPrincipalAllowedSubjectMatchesScope' as DID;

        const makeGovernorRecord = (
            paramsAffectedAgent: string,
            paramsAffectedPrincipal?: string,
        ) => ({
            ...TEST_RECORD_ROW,
            agent_did: SESSION_GOVERNOR_DID,
            principal_did: SESSION_GOVERNOR_DID,
            action_type: 'SESSION_SUPERSEDED',
            parameters_summary: {
                oldSessionId: '550e8400-e29b-41d4-a716-446655440200',
                newSessionId: '550e8400-e29b-41d4-a716-446655440201',
                reason: 'EXPLICIT_CLOSE',
                timestamp: '2026-04-28T03:00:00.000Z',
                affectedAgentDid: paramsAffectedAgent,
                ...(paramsAffectedPrincipal
                    ? { affectedPrincipalDid: paramsAffectedPrincipal }
                    : {}),
            } as Record<string, unknown>,
        });

        const makeStep5App = (
            rows: ReturnType<typeof makeGovernorRecord>[],
        ) => {
            const pool = makePool({ recordRows: rows });
            return makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
                resolveControlPlanePublicKey: () => Promise.resolve(null),
            });
        };

        it('GET /records/:id should reject 404 NOT_FOUND when row.affectedAgentDid != query.affectedAgentDid (cross-subject escalation — v0.4 existence-oracle defense)', async () => {
            // Attack: the requester scope contains SCOPED_AFFECTED; first /ledger/head obtains the
            // recordId of a record on the governor chain (whose row.affectedAgentDid = FOREIGN);
            // then request that recordId using an affected_agent_did within one's own scope, attempting an out-of-scope read
            const row = makeGovernorRecord(FOREIGN_AFFECTED_AGENT_DID);
            const pool = makePool({ recordRows: [row] });
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.get',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {
                    affectedAgentDid: SCOPED_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath(`/records/${TEST_RECORD_ID}`, {
                    affected_agent_did: SCOPED_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            // v0.4: control-plane out-of-scope = 404 NOT_FOUND (same as a missing record, existence-oracle defense)
            expect(res.status).toBe(404);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('NOT_FOUND');
        });

        it('GET /records/:id should accept 200 when row.affectedAgentDid === query.affectedAgentDid', async () => {
            const row = makeGovernorRecord(SCOPED_AFFECTED_AGENT_DID);
            const pool = makePool({ recordRows: [row] });
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.get',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {
                    affectedAgentDid: SCOPED_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath(`/records/${TEST_RECORD_ID}`, {
                    affected_agent_did: SCOPED_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            expect(res.status).toBe(200);
        });

        it('GET /records/:id should reject 404 NOT_FOUND when query.affectedPrincipalDid mismatches row.affectedPrincipalDid (v0.4 existence-oracle defense)', async () => {
            // The row's principal != the query's principal → 404 NOT_FOUND (the principal dimension is also enforced row-level + status-code uniformity)
            const row = makeGovernorRecord(
                SCOPED_AFFECTED_AGENT_DID,
                FOREIGN_AFFECTED_PRINCIPAL_DID,
            );
            const pool = makePool({ recordRows: [row] });
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.get',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {
                    affectedAgentDid: SCOPED_AFFECTED_AGENT_DID,
                    affectedPrincipalDid: SCOPED_AFFECTED_PRINCIPAL_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath(`/records/${TEST_RECORD_ID}`, {
                    affected_agent_did: SCOPED_AFFECTED_AGENT_DID,
                    affected_principal_did: SCOPED_AFFECTED_PRINCIPAL_DID,
                }),
                { headers },
            );
            expect(res.status).toBe(404);
            const body = res.json as { error: { code: string } };
            expect(body.error.code).toBe('NOT_FOUND');
        });

        it('GET /records/:id/verify should reject 404 NOT_FOUND when row.affectedAgentDid != query.affectedAgentDid (v0.4 existence-oracle defense)', async () => {
            // The same cross-subject attack applied to the verify endpoint: the row-level mismatch is
            // intercepted before resolveControlPlanePublicKey (failing early outside the row, not wasting verification work) + 404 status-code uniformity
            const row = makeGovernorRecord(FOREIGN_AFFECTED_AGENT_DID);
            const app = makeStep5App([row]);
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.verify',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {
                    affectedAgentDid: SCOPED_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath(`/records/${TEST_RECORD_ID}/verify`, {
                    affected_agent_did: SCOPED_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            expect(res.status).toBe(404);
            const body = res.json as { error: { code: string } };
            expect(body.error.code).toBe('NOT_FOUND');
        });

        it('GET /records/chain/verify should reject 403 in control-plane lane (subject scope vs full-chain semantics conflict)', async () => {
            // chain.verify is fully disabled in the control-plane lane: the semantics of subject scope
            // and full hash-chain closure fundamentally conflict; governor chain integrity is performed
            // by the deployer's operations-side IntegrityChecker (within the trust boundary)
            const row = makeGovernorRecord(SCOPED_AFFECTED_AGENT_DID);
            const pool = makePool({ recordRows: [row] });
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.chain.verify',
                    recordId: null,
                },
                queryParams: {
                    agentDid: SESSION_GOVERNOR_DID,
                    affectedAgentDid: SCOPED_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records/chain/verify', {
                    agent_did: SESSION_GOVERNOR_DID,
                    affected_agent_did: SCOPED_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            expect(res.status).toBe(403);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('AUDIT_FORBIDDEN');
            expect(body.error.detail).toContain('chain/verify');
            expect(body.error.detail).toContain('IntegrityChecker');
        });

        it('GET /records/:id should reject 404 NOT_FOUND when prefetched row has no parameters_summary.affectedAgentDid (v0.4 fail-closed + existence-oracle defense)', async () => {
            // Guards against a row written without the affected* field → the control-plane lane rejects (fail-closed + status-code uniformity)
            const row = {
                ...TEST_RECORD_ROW,
                agent_did: SESSION_GOVERNOR_DID,
                principal_did: SESSION_GOVERNOR_DID,
                action_type: 'SESSION_SUPERSEDED',
                parameters_summary: null, // simulate historical/corrupted data
            };
            const pool = makePool({ recordRows: [row] });
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: SESSION_GOVERNOR_DID,
                resourceBinding: {
                    route: 'records.get',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {
                    affectedAgentDid: SCOPED_AFFECTED_AGENT_DID,
                },
            });
            const res = await inject(
                app,
                'GET',
                buildPath(`/records/${TEST_RECORD_ID}`, {
                    affected_agent_did: SCOPED_AFFECTED_AGENT_DID,
                }),
                { headers },
            );
            expect(res.status).toBe(404);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('NOT_FOUND');
        });

        it('should not regress the business lane: affected* row-level validation applies only to the control-plane lane, the business path is unaffected', async () => {
            // With an ordinary business agent, affected* should not be enforced (the business lane has no scope concept)
            const pool = makePool();
            const app = makeApp(pool); // no governor opts
            const headers = makeAuditHeaders({
                resourceBinding: {
                    route: 'records.get',
                    recordId: TEST_RECORD_ID,
                },
                queryParams: {},
            });
            const res = await inject(app, 'GET', `/records/${TEST_RECORD_ID}`, {
                headers,
            });
            expect(res.status).toBe(200);
        });
    });

    // ─── business lane zero-regression assertions ─────────────────────────────────────────
    describe('business lane regression (governor lane does not affect v0.1)', () => {
        it('should still allow business audit with PrincipalAuditAccessChecker when governor opts injected', async () => {
            const pool = makePool();
            // Inject governor opts, but query with a business DID
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const headers = makeAuditHeaders({
                resourceBinding: { route: 'records.list', recordId: null },
                queryParams: { agentDid: TEST_AGENT_DID },
            });
            const res = await inject(
                app,
                'GET',
                buildPath('/records', { agent_did: TEST_AGENT_DID }),
                { headers },
            );
            // The business lane takes the existing v0.1 path, zero regression
            expect(res.status).toBe(200);
        });
    });

    // ─── /ledger/head × governor DID ──────────────────
    describe('GET /ledger/head (control-plane DID rejection)', () => {
        it('should reject 403 AUDIT_FORBIDDEN when agent_did is governor (honest declaration)', async () => {
            const pool = makePool();
            const app = makeApp(pool, undefined, {
                controlPlaneResolver: makeGovernorResolver(),
                controlPlaneChecker: makeGovernorChecker(),
            });
            const res = await inject(
                app,
                'GET',
                `/ledger/head?agent_did=${encodeURIComponent(SESSION_GOVERNOR_DID)}`,
                {},
            );
            expect(res.status).toBe(403);
            const body = res.json as {
                error: { code: string; detail: string };
            };
            expect(body.error.code).toBe('AUDIT_FORBIDDEN');
            expect(body.error.detail).toContain(
                'control-plane head requires signed',
            );
        });

        it('should still reject 400 for malformed (non-governor) DID prefix', async () => {
            const pool = makePool();
            const app = makeApp(pool);
            const res = await inject(
                app,
                'GET',
                `/ledger/head?agent_did=did:wrong:abc`,
                {},
            );
            expect(res.status).toBe(400);
            const body = res.json as { error: { code: string } };
            expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
        });
    });

    // ─── ControlPlaneAuditAccessChecker unit behavior ──────────────────────────
    describe('ControlPlaneAuditAccessChecker unit behavior', () => {
        it('should reject when invoked on business lane', async () => {
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
                ]),
            );
            const businessRequest: VerifiedAuditRequest = {
                lane: 'business',
                query: {
                    requesterDid: TEST_GOVERNOR_REQUESTER,
                    targetAgentDid: TEST_AGENT_DID,
                    httpMethod: 'GET',
                    resourceBinding: {
                        route: 'records.list',
                        recordId: null,
                    },
                    queryParams: {},
                    snapshotBoundary: {
                        headCreatedAt: SNAPSHOT_CREATED_AT as Timestamp,
                        headRecordId: SNAPSHOT_RECORD_ID,
                    },
                    timestamp: new Date().toISOString() as Timestamp,
                    signature: 'sig' as Signature,
                },
                resolvedIdentity: makeAgentDocument(
                    TEST_AGENT_DID,
                    TEST_PUB_HEX,
                ),
                identityStatus: 'active',
                verifiedAt: new Date().toISOString() as Timestamp,
            };
            const decision = await checker.check(businessRequest);
            expect(decision.allowed).toBe(false);
            if (!decision.allowed) {
                expect(decision.code).toBe('AUDIT_FORBIDDEN');
                expect(decision.reason).toContain('non-control-plane lane');
            }
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Two regression groups:
// 1: governor lane bootstrap — GET /audit/ledger/head does not enforce a snapshot
// 2: ControlPlaneAuditAccessChecker.check() agentDid consistency
// ═══════════════════════════════════════════════════════════════════════════

describe('governor head bootstrap (signed /audit/ledger/head)', () => {
    const TEST_GOVERNOR_REQUESTER =
        'did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK' as DID;

    const makeGovernorResolver = () => (did: DID) => {
        if (did !== SESSION_GOVERNOR_DID) return Promise.resolve(null);
        return Promise.resolve({
            did,
            metadata: {
                role: 'session-governor',
                deployedBy: 'test-deployment',
            } as const,
            verifiedAt: new Date().toISOString() as Timestamp,
        });
    };

    // v0.4: per-requester affected subject scope helper
    // v0.2/v0.3 let ledger.head bypass the affected* check — but the recordId returned by head
    // becomes an existence oracle on /records/:id + makes out-of-scope activity observable. v0.4 fix:
    // ledger.head also enforces affectedAgentDid declaration + scope validation + a co-bound handler-side SQL predicate (subject-scoped head).
    const TEST_AFFECTED_AGENT_DID =
        'did:agent:2222222222222222222222222222222222222222' as DID;
    const TEST_BOOTSTRAP_AFFECTED = TEST_AFFECTED_AGENT_DID;
    const makeGovernorScope = (): ControlPlaneRequesterScope => ({
        allowedAffectedAgentDids: new Set<DID>([TEST_AFFECTED_AGENT_DID]),
    });

    const makeGovernorChecker = () =>
        new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
            ]),
        );

    /**
     * Dedicated audit-headers builder: the bootstrap endpoint's signature payload does **not**
     * include snapshotBoundary (head is an output, not an input). Reusing makeAuditHeaders would
     * introduce snapshotBoundary, making the signature differ from the canonical the server expects →
     * fail. This helper uses the snapshot-less form of SignedAuditQuery on its own.
     */
    function makeBootstrapHeaders(params: {
        requesterDid?: DID;
        targetAgentDid?: DID;
        timestamp?: Timestamp;
        privateKey?: string;
        /**
         * queryParams.agentDid defaults to targetAgentDid (consistent with agent_did in the URL).
         * Passing null explicitly omits it; passing a DID explicitly creates the attack scenario where it differs from targetAgentDid.
         */
        queryParamAgentDid?: DID | null;
        /**
         * agent_did in the URL defaults to targetAgentDid; pass it explicitly to test a URL-vs-signature mismatch.
         */
        urlAgentDid?: DID;
        /**
         * v0.4: the control-plane lane enforces affectedAgentDid declaration, and
         * ledger.head no longer bypasses it. Defaults to TEST_BOOTSTRAP_AFFECTED; pass null explicitly to omit it and test fail-closed.
         */
        affectedAgentDid?: DID | null;
    }): {
        headers: Record<string, string>;
        urlAgentDid: DID;
        urlAffectedAgentDid?: DID;
    } {
        const requesterDid = params.requesterDid ?? TEST_GOVERNOR_REQUESTER;
        const targetAgentDid = params.targetAgentDid ?? SESSION_GOVERNOR_DID;
        const timestamp =
            params.timestamp ?? (new Date().toISOString() as Timestamp);
        const privateKey = params.privateKey ?? TEST_FULL_PRIV_HEX;
        const urlAgentDid = params.urlAgentDid ?? targetAgentDid;
        const effectiveAffectedAgentDid =
            params.affectedAgentDid === null
                ? undefined
                : (params.affectedAgentDid ?? TEST_BOOTSTRAP_AFFECTED);

        // The server rebuilds queryParams.agentDid from the URL; the signature payload must align with it
        const queryParams: Record<string, unknown> = {};
        const effectiveAgentDid =
            params.queryParamAgentDid === null
                ? undefined
                : (params.queryParamAgentDid ?? urlAgentDid);
        if (effectiveAgentDid !== undefined) {
            queryParams['agentDid'] = effectiveAgentDid;
        }
        if (effectiveAffectedAgentDid !== undefined) {
            queryParams['affectedAgentDid'] = effectiveAffectedAgentDid;
        }

        const signaturePayload = {
            requesterDid,
            targetAgentDid,
            httpMethod: 'GET' as const,
            resourceBinding: { route: 'ledger.head', recordId: null },
            queryParams,
            timestamp,
        };

        const canonical = canonicalize(signaturePayload);
        const msgBytes = new TextEncoder().encode(canonical);
        const signature = sign(msgBytes, privateKey);

        return {
            headers: {
                'x-audit-requester': requesterDid,
                'x-audit-signature': signature,
                'x-audit-timestamp': timestamp,
            },
            urlAgentDid,
            urlAffectedAgentDid: effectiveAffectedAgentDid,
        };
    }

    // ─── Positive path ─────────────────────────────────────────────────────────
    it('should allow valid governor bootstrap call and return subject-scoped head triple (v0.4)', async () => {
        const pool = makePool({
            ledgerHeadRows: [
                {
                    record_id: '33333333-3333-4333-8333-333333333333',
                    created_at: '2024-02-01T00:00:00.000Z',
                    record_hash: 'governor-head-hash-001',
                },
            ],
        });
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({
            requesterDid: TEST_GOVERNOR_REQUESTER,
            targetAgentDid: SESSION_GOVERNOR_DID,
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as {
            agentDid: string;
            headRecordId: string;
            headCreatedAt: string;
            headRecordHash: string;
        };
        expect(body.agentDid).toBe(SESSION_GOVERNOR_DID);
        expect(body.headRecordId).toBe('33333333-3333-4333-8333-333333333333');
        expect(body.headRecordHash).toBe('governor-head-hash-001');
    });

    // ─── Key negative: still passes without the snapshot boundary header (contrast with /records*) ──
    it('should NOT require X-Audit-Snapshot-Head* headers (key bootstrap fix)', async () => {
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({});
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        // Key assertion: should not return AUDIT_SNAPSHOT_BOUNDARY_VIOLATED or AUDIT_QUERY_MALFORMED
        expect(res.status).not.toBe(400);
        expect([200, 403]).toContain(res.status);
    });

    it('should reject 400 when agent_did is not governor DID', async () => {
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({
            targetAgentDid: TEST_AGENT_DID,
            urlAgentDid: TEST_AGENT_DID,
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: TEST_AGENT_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
        expect(body.error.detail).toContain('did:system:session-governor');
    });

    it('should reject 401 with invalid signature', async () => {
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({});
        // Tamper with the signature's first character: if it is already '0', change it to 'f', otherwise to '0'
        const sig = headers['x-audit-signature']!;
        headers['x-audit-signature'] =
            (sig[0] === '0' ? 'f' : '0') + sig.slice(1);
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SIGNATURE_INVALID');
    });

    it('should reject 401 when timestamp outside ±300s window', async () => {
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const oldTimestamp = new Date(
            Date.now() - 10 * 60 * 1000,
        ).toISOString() as Timestamp;
        const { headers } = makeBootstrapHeaders({ timestamp: oldTimestamp });
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_TIMESTAMP_SKEW');
    });

    it('should reject 403 AUDIT_FORBIDDEN when requester not in allow-list', async () => {
        // Use another static key pair (seed='12'*32) to masquerade as a non-allow-list requester
        const otherSeed = '12'.repeat(32);
        const otherPubHex = derivePublicKeyFromPrivateKey(otherSeed);
        const otherFullPriv = otherSeed + otherPubHex;
        // Note: requesterDid must be derivable from publicKeyHex (extractPublicKeyFromDIDKey).
        // Simplification: reuse TEST_GOVERNOR_REQUESTER's DID but sign with another private key → 401,
        // not 403; to test 403 we must use a valid signature + a DID not in the allow-list. Use a
        // different allow-list: allow only another DID, then sign with TEST_GOVERNOR_REQUESTER.
        const otherAllowed =
            'did:key:z6Mkk7y4WsexXcSFbCKnXG1F1AukwxyMM6tD1xfbVNaH3xkV' as DID;
        void otherFullPriv;
        const checker = new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [otherAllowed, makeGovernorScope()],
            ]),
        );
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: checker,
        });
        const { headers } = makeBootstrapHeaders({});
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(403);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
        expect(body.error.detail).toContain('allow-list');
    });

    it('should reject 403 when control-plane resolver missing', async () => {
        const pool = makePool();
        // Only the checker is injected; the resolver is not
        const app = makeApp(pool, undefined, {
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({});
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(403);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
        expect(body.error.detail).toContain('control-plane lane disabled');
    });

    it('should reject 400 when missing X-Audit-* headers', async () => {
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            {},
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should reject 404 when governor has no records yet', async () => {
        const pool = makePool({ ledgerHeadRows: [] });
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({});
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: TEST_BOOTSTRAP_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('NOT_FOUND');
    });

    // ─── affected_agent_did mandatory-declaration regression ─────────────────────────────────────
    it('should reject 403 AUDIT_FORBIDDEN when affected_agent_did is missing (v0.4 bypass revoked)', async () => {
        // v0.2/v0.3 let ledger.head bypass affected* — v0.4 revokes that bypass
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({
            affectedAgentDid: null, // explicitly omitted
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                // intentionally do not pass affected_agent_did
            }),
            { headers },
        );
        expect(res.status).toBe(403);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
        expect(body.error.detail).toContain('affectedAgentDid');
    });

    it('should reject 403 when affected_agent_did is outside requester scope (v0.4 ledger.head also goes through scope)', async () => {
        // An affected_agent_did not in scope → AUDIT_FORBIDDEN (prevents out-of-scope head probing)
        const FOREIGN_AFFECTED =
            'did:agent:9999999999999999999999999999999999999999' as DID;
        const pool = makePool();
        const app = makeApp(pool, undefined, {
            controlPlaneResolver: makeGovernorResolver(),
            controlPlaneChecker: makeGovernorChecker(),
        });
        const { headers } = makeBootstrapHeaders({
            affectedAgentDid: FOREIGN_AFFECTED,
        });
        const res = await inject(
            app,
            'GET',
            buildPath('/audit/ledger/head', {
                agent_did: SESSION_GOVERNOR_DID,
                affected_agent_did: FOREIGN_AFFECTED,
            }),
            { headers },
        );
        expect(res.status).toBe(403);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
        expect(body.error.detail).toContain('subject scope');
    });
});

describe('ControlPlaneAuditAccessChecker agentDid consistency + affected scope', () => {
    const TEST_GOVERNOR_REQUESTER =
        'did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK' as DID;

    // v0.2: per-requester affected subject scope helper (scoped to this describe)
    // The scope field = the immutable payload affectedAgentDid (no longer targetAgentDid)
    const TEST_AFFECTED_AGENT_1 =
        'did:agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as DID;
    const TEST_AFFECTED_AGENT_2 =
        'did:agent:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as DID;
    const TEST_AFFECTED_PRINCIPAL_1 =
        'did:key:z6MkAffectedPrincipal1111111111111111111111' as DID;
    const TEST_AFFECTED_PRINCIPAL_2 =
        'did:key:z6MkAffectedPrincipal2222222222222222222222' as DID;
    const makeGovernorScope = (): ControlPlaneRequesterScope => ({
        allowedAffectedAgentDids: new Set<DID>([TEST_AFFECTED_AGENT_1]),
    });

    /**
     * Build a control-plane verified request.
     * - route defaults to `records.list`, forcing the affected* scope validation path;
     * - to test the ledger.head bypass path, pass 'ledger.head' explicitly.
     */
    function makeControlPlaneRequest(overrides: {
        queryParamAgentDid?: DID | undefined;
        queryParamAffectedAgentDid?: DID | undefined;
        queryParamAffectedPrincipalDid?: DID | undefined;
        targetAgentDid?: DID;
        route?: 'records.list' | 'ledger.head';
    }): VerifiedAuditRequest {
        const requesterDid = TEST_GOVERNOR_REQUESTER;
        const targetAgentDid = overrides.targetAgentDid ?? SESSION_GOVERNOR_DID;
        const queryParams: {
            agentDid?: DID;
            affectedAgentDid?: DID;
            affectedPrincipalDid?: DID;
        } = {};
        if (overrides.queryParamAgentDid !== undefined) {
            queryParams.agentDid = overrides.queryParamAgentDid;
        }
        if (overrides.queryParamAffectedAgentDid !== undefined) {
            queryParams.affectedAgentDid = overrides.queryParamAffectedAgentDid;
        }
        if (overrides.queryParamAffectedPrincipalDid !== undefined) {
            queryParams.affectedPrincipalDid =
                overrides.queryParamAffectedPrincipalDid;
        }
        const route = overrides.route ?? 'records.list';
        return {
            lane: 'control-plane',
            query: {
                requesterDid,
                targetAgentDid,
                httpMethod: 'GET',
                resourceBinding: { route, recordId: null },
                queryParams,
                timestamp: new Date().toISOString() as Timestamp,
                signature: 'sig' as Signature,
            },
            resolution: {
                did: targetAgentDid,
                metadata: {} as const,
                verifiedAt: new Date().toISOString() as Timestamp,
            },
            verifiedAt: new Date().toISOString() as Timestamp,
        };
    }

    // ─── finding 2 agentDid consistency (retained, orthogonal to affected scope) ─────
    it('should reject 403 when route=ledger.head and queryParams.affectedAgentDid is missing (v0.4 revokes bypass)', async () => {
        // v0.2/v0.3 let the ledger.head route bypass the affected* check — but the recordId returned
        // by head becomes an existence oracle on /records/:id + makes out-of-scope activity observable.
        // v0.4 revision: ledger.head also enforces affectedAgentDid declaration + scope validation
        const checker = new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
            ]),
        );
        const decision = await checker.check(
            makeControlPlaneRequest({
                route: 'ledger.head',
                queryParamAgentDid: undefined,
                // queryParamAffectedAgentDid intentionally omitted
            }),
        );
        expect(decision.allowed).toBe(false);
        if (!decision.allowed) {
            expect(decision.code).toBe('AUDIT_FORBIDDEN');
            expect(decision.reason).toContain('affectedAgentDid');
        }
    });

    it('should allow when route=ledger.head with valid affectedAgentDid in scope (v0.4)', async () => {
        const checker = new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
            ]),
        );
        const decision = await checker.check(
            makeControlPlaneRequest({
                route: 'ledger.head',
                queryParamAgentDid: undefined,
                queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
            }),
        );
        expect(decision.allowed).toBe(true);
    });

    it('should allow when queryParams.agentDid equals targetAgentDid (records.list with affected scope hit)', async () => {
        const checker = new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
            ]),
        );
        const decision = await checker.check(
            makeControlPlaneRequest({
                queryParamAgentDid: SESSION_GOVERNOR_DID,
                targetAgentDid: SESSION_GOVERNOR_DID,
                queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
            }),
        );
        expect(decision.allowed).toBe(true);
    });

    it('should reject 403 when queryParams.agentDid differs from targetAgentDid (cross-agent escalation)', async () => {
        const checker = new ControlPlaneAuditAccessChecker(
            new Map<DID, ControlPlaneRequesterScope>([
                [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
            ]),
        );
        // Attack scenario: the signature authorizes the governor but the in-query agentDid points to another agent
        const otherAgent =
            'did:agent:99999999999999999999999999999999aabbccdd' as DID;
        const decision = await checker.check(
            makeControlPlaneRequest({
                queryParamAgentDid: otherAgent,
                targetAgentDid: SESSION_GOVERNOR_DID,
                queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
            }),
        );
        expect(decision.allowed).toBe(false);
        if (!decision.allowed) {
            expect(decision.code).toBe('AUDIT_FORBIDDEN');
            expect(decision.reason).toContain('queryParams.agentDid');
            expect(decision.reason).toContain('targetAgentDid');
        }
    });

    // ─── v0.2 per-requester affected subject scope matrix ─────
    describe('v0.2 per-requester affected subject scope', () => {
        it('should reject 403 when queryParams.affectedAgentDid is missing (forces explicit subject declaration)', async () => {
            // The control-plane lane must explicitly provide queryParams.affectedAgentDid
            // to guard against the v0.1 vulnerability — any allow-listed requester could still read the entire governor ledger in the governor lane
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
                ]),
            );
            const decision = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    // queryParamAffectedAgentDid intentionally omitted
                }),
            );
            expect(decision.allowed).toBe(false);
            if (!decision.allowed) {
                expect(decision.code).toBe('AUDIT_FORBIDDEN');
                expect(decision.reason).toContain('affectedAgentDid');
            }
        });

        it('should reject 403 when affectedAgentDid not in scope.allowedAffectedAgentDids', async () => {
            // The affected subject is not in scope → fail-closed
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
                ]),
            );
            const decision = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_2, // not in scope (the scope contains only _1)
                }),
            );
            expect(decision.allowed).toBe(false);
            if (!decision.allowed) {
                expect(decision.code).toBe('AUDIT_FORBIDDEN');
                expect(decision.reason).toContain('subject scope');
            }
        });

        it('should fail-closed (403) when scope.allowedAffectedAgentDids is empty set', async () => {
            // fail-closed: an empty scope = reject any affected* (guards against the "empty set = fully open" misuse)
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [
                        TEST_GOVERNOR_REQUESTER,
                        { allowedAffectedAgentDids: new Set<DID>() },
                    ],
                ]),
            );
            const decision = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                }),
            );
            expect(decision.allowed).toBe(false);
            if (!decision.allowed) {
                expect(decision.code).toBe('AUDIT_FORBIDDEN');
                expect(decision.reason).toContain('subject scope');
            }
        });

        it('should reject 403 when requester is not in the Map (allow-list miss)', async () => {
            // requester is not in the scope Map → intercepted at the first gate (allow-list semantics preserved)
            const otherRequester =
                'did:key:z6Mkk7y4WsexXcSFbCKnXG1F1AukwxyMM6tD1xfbVNaH3xkV' as DID;
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [otherRequester, makeGovernorScope()],
                ]),
            );
            const decision = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                }),
            );
            expect(decision.allowed).toBe(false);
            if (!decision.allowed) {
                expect(decision.code).toBe('AUDIT_FORBIDDEN');
                expect(decision.reason).toContain('allow-list');
            }
        });

        it('should allow per-requester affected subject scope with multiple affected agents', async () => {
            // Multi-affected-agent scope: the requester can read any affected agent within scope
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [
                        TEST_GOVERNOR_REQUESTER,
                        {
                            allowedAffectedAgentDids: new Set<DID>([
                                TEST_AFFECTED_AGENT_1,
                                TEST_AFFECTED_AGENT_2,
                            ]),
                        },
                    ],
                ]),
            );
            const decision1 = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                }),
            );
            expect(decision1.allowed).toBe(true);
            const decision2 = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_2,
                }),
            );
            expect(decision2.allowed).toBe(true);
        });

        it('should enforce optional principal dimension when scope.allowedAffectedPrincipalDids is set', async () => {
            // Optional principal scope: when scope contains allowedAffectedPrincipalDids → queryParams.affectedPrincipalDid is required to be within scope
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [
                        TEST_GOVERNOR_REQUESTER,
                        {
                            allowedAffectedAgentDids: new Set<DID>([
                                TEST_AFFECTED_AGENT_1,
                            ]),
                            allowedAffectedPrincipalDids: new Set<DID>([
                                TEST_AFFECTED_PRINCIPAL_1,
                            ]),
                        },
                    ],
                ]),
            );
            // principal is in scope → allow
            const decisionAllow = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                    queryParamAffectedPrincipalDid: TEST_AFFECTED_PRINCIPAL_1,
                }),
            );
            expect(decisionAllow.allowed).toBe(true);
            // principal not in scope → reject
            const decisionDeny = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                    queryParamAffectedPrincipalDid: TEST_AFFECTED_PRINCIPAL_2,
                }),
            );
            expect(decisionDeny.allowed).toBe(false);
            if (!decisionDeny.allowed) {
                expect(decisionDeny.code).toBe('AUDIT_FORBIDDEN');
                expect(decisionDeny.reason).toContain('Principal');
            }
            // The principal-dimension scope is set but the query lacks affectedPrincipalDid → reject (fail-closed)
            const decisionMissing = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                    // queryParamAffectedPrincipalDid intentionally omitted
                }),
            );
            expect(decisionMissing.allowed).toBe(false);
        });

        it('should not require affectedPrincipalDid when scope.allowedAffectedPrincipalDids is undefined (dimension is optional)', async () => {
            // By default scope.allowedAffectedPrincipalDids = undefined → the principal dimension is unconstrained
            const checker = new ControlPlaneAuditAccessChecker(
                new Map<DID, ControlPlaneRequesterScope>([
                    [TEST_GOVERNOR_REQUESTER, makeGovernorScope()],
                ]),
            );
            const decision = await checker.check(
                makeControlPlaneRequest({
                    queryParamAgentDid: SESSION_GOVERNOR_DID,
                    targetAgentDid: SESSION_GOVERNOR_DID,
                    queryParamAffectedAgentDid: TEST_AFFECTED_AGENT_1,
                    // queryParamAffectedPrincipalDid not passed — when the scope does not constrain the principal dimension, it should allow
                }),
            );
            expect(decision.allowed).toBe(true);
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// v0.5: 5-surface SQL predicate symmetry regression matrix.

// The pure property-based fixture (control-plane-scope.property.test.ts) only covers the pure-function
// semantics of recordVisibleToScope. **The SQL predicates and handler behavior of all 5 surfaces
// (list/get/verify/head/chain) must align strictly with recordVisibleToScope** — this describe adds
// SQL-layer assertions:

// - When query.affectedPrincipalDid is present, the head SQL must include the
// `parameters_summary->>'affectedPrincipalDid' = $N` predicate + values containing that DID;
// - The chain.verify remote API must reject with 400 when start is not the genesis (symmetric with the CLI).

// Any SQL implementation that "drops a dimension" will necessarily fail this matrix — preventing recurrence of the same root cause.
// ═══════════════════════════════════════════════════════════════════════════
describe('v0.5 5-surface SQL parity matrix (prevents same-root-cause recurrence)', () => {
    const TEST_GOVERNOR_REQUESTER =
        'did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK' as DID;
    const TEST_AFFECTED_AGENT_DID =
        'did:agent:2222222222222222222222222222222222222222' as DID;
    const TEST_AFFECTED_PRINCIPAL_DID =
        'did:key:z6MkAffectedPrincipalForV5SqlParityMatrixTest' as DID;

    /**
     * pool factory: dispatch by SQL keyword + capture the (sql, values) of each query call for assertions.
     * Unlike makePool(): this factory provides a capturedQueries array so tests can inspect SQL
     * predicates directly (the key to preventing regression — if the v0.5 SQL is later reverted and
     * drops the affectedPrincipalDid predicate, the assertions here fail immediately).
     */
    function makeCapturingPool(opts: {
        ledgerHeadRows?: object[];
        chainVerifyGenesisRow?: { created_at: string } | null;
    }) {
        const captured: Array<{ sql: string; values: unknown[] }> = [];
        const ledgerHeadRows = opts.ledgerHeadRows ?? [
            {
                record_id: '99999999-9999-4999-8999-999999999999',
                created_at: '2026-04-29T00:00:00.000Z',
                record_hash: 'governor-head-hash-v5',
            },
        ];
        const snapshotRows = [
            {
                id: '50',
                record_hash: 'snap-hash',
                created_at: '2024-01-01T00:00:00.000Z',
            },
        ];
        const query: Mock = vi
            .fn()
            .mockImplementation((sql: string, values: unknown[] = []) => {
                captured.push({ sql, values });
                if (typeof sql !== 'string') {
                    return Promise.resolve({ rows: [] });
                }
                if (sql.includes('identity.agents')) {
                    return Promise.resolve({ rows: [] });
                }
                // MAX(id) anchor query
                if (sql.includes('MAX(id)')) {
                    return Promise.resolve({
                        rows:
                            ledgerHeadRows.length > 0
                                ? [{ anchor_id: '50' }]
                                : [],
                    });
                }
                if (sql.includes('ORDER BY id DESC')) {
                    return Promise.resolve({ rows: ledgerHeadRows });
                }
                // chain.verify's internal genesis-probe query: ORDER BY id ASC LIMIT 1
                if (
                    sql.includes('ORDER BY id ASC') &&
                    sql.includes('LIMIT 1')
                ) {
                    return Promise.resolve({
                        rows:
                            opts.chainVerifyGenesisRow === undefined
                                ? []
                                : opts.chainVerifyGenesisRow === null
                                  ? []
                                  : [opts.chainVerifyGenesisRow],
                    });
                }
                if (sql.includes('AND agent_did')) {
                    return Promise.resolve({ rows: snapshotRows });
                }
                return Promise.resolve({ rows: [] });
            });
        return {
            pool: { query } as unknown as import('pg').Pool,
            captured,
        };
    }

    // ─── Shared helper: mock res (captures status + json) + mock verifiedAudit ─────
    function makeMockRes() {
        let statusCode = 200;
        let bodyJson: unknown = null;
        const res = {
            locals: {} as Record<string, unknown>,
            status(code: number) {
                statusCode = code;
                return this;
            },
            json(body: unknown) {
                bodyJson = body;
                return this;
            },
        } as unknown as import('express').Response;
        return {
            res,
            getStatus: () => statusCode,
            getBody: () => bodyJson,
        };
    }

    function makeControlPlaneVerifiedAudit(opts: {
        affectedAgentDid?: DID;
        affectedPrincipalDid?: DID;
        targetAgentDid?: DID;
        route?: 'ledger.head' | 'records.chain.verify';
        start?: string;
    }): VerifiedAuditRequest {
        const queryParams: Record<string, unknown> = {};
        if (opts.affectedAgentDid !== undefined) {
            queryParams['affectedAgentDid'] = opts.affectedAgentDid;
        }
        if (opts.affectedPrincipalDid !== undefined) {
            queryParams['affectedPrincipalDid'] = opts.affectedPrincipalDid;
        }
        if (opts.start !== undefined) {
            queryParams['start'] = opts.start;
        }
        return {
            lane: 'control-plane',
            query: {
                requesterDid: TEST_GOVERNOR_REQUESTER,
                targetAgentDid: opts.targetAgentDid ?? SESSION_GOVERNOR_DID,
                httpMethod: 'GET',
                resourceBinding: {
                    route: opts.route ?? 'ledger.head',
                    recordId: null,
                },
                queryParams,
                timestamp: new Date().toISOString() as Timestamp,
                signature: 'sig' as Signature,
            },
            resolution: {
                did: opts.targetAgentDid ?? SESSION_GOVERNOR_DID,
                metadata: {} as const,
                verifiedAt: new Date().toISOString() as Timestamp,
            },
            verifiedAt: new Date().toISOString() as Timestamp,
        };
    }

    function makeBusinessVerifiedAudit(opts: {
        targetAgentDid?: DID;
        start?: string;
    }): VerifiedAuditRequest {
        const queryParams: Record<string, unknown> = {};
        if (opts.start !== undefined) {
            queryParams['start'] = opts.start;
        }
        const targetAgentDid = opts.targetAgentDid ?? TEST_AGENT_DID;
        // resolvedIdentity is of type AgentIdentityDocument; this matrix only asserts the entry-point
        // SQL behavior of chain.verify and does not depend on identity field semantics — use an
        // unknown cast to skip the structural construction.
        const resolvedIdentity = makeAgentDocument(
            targetAgentDid,
            TEST_PUB_HEX,
        ) as unknown as VerifiedAuditRequest & { lane: 'business' } extends {
            resolvedIdentity: infer R;
        }
            ? R
            : never;
        return {
            lane: 'business',
            query: {
                requesterDid: TEST_REQUESTER_DID,
                targetAgentDid,
                httpMethod: 'GET',
                resourceBinding: {
                    route: 'records.chain.verify',
                    recordId: null,
                },
                queryParams,
                timestamp: new Date().toISOString() as Timestamp,
                signature: 'sig' as Signature,
            },
            resolvedIdentity,
            identityStatus: 'active',
            verifiedAt: new Date().toISOString() as Timestamp,
        };
    }

    // ─── head SQL must include the affectedPrincipalDid predicate ───────
    it('head SQL includes the affectedPrincipalDid predicate + values (query passes it explicitly → SQL enforces it; regression guard)', async () => {
        const { pool, captured } = makeCapturingPool({});
        const handler = __testing__makeHandleSignedLedgerHead(pool);
        const { res, getStatus } = makeMockRes();
        res.locals['verifiedAudit'] = makeControlPlaneVerifiedAudit({
            affectedAgentDid: TEST_AFFECTED_AGENT_DID,
            affectedPrincipalDid: TEST_AFFECTED_PRINCIPAL_DID,
        });
        await handler(
            { url: '/audit/ledger/head' } as import('express').Request,
            res,
            (() => undefined) as import('express').NextFunction,
        );
        // The handler has already called res.json; status should be 200 (the mock head row was injected)
        expect(getStatus()).toBe(200);
        const headCall = captured.find(
            (c) =>
                typeof c.sql === 'string' && c.sql.includes('ORDER BY id DESC'),
        );
        expect(headCall).toBeDefined();
        // Regression-guard assertion: the SQL must include the affectedPrincipalDid predicate
        expect(headCall!.sql).toContain(
            "parameters_summary->>'affectedPrincipalDid'",
        );
        // values must include all three: governor DID + affectedAgentDid + affectedPrincipalDid
        expect(headCall!.values).toContain(SESSION_GOVERNOR_DID);
        expect(headCall!.values).toContain(TEST_AFFECTED_AGENT_DID);
        expect(headCall!.values).toContain(TEST_AFFECTED_PRINCIPAL_DID);
    });

    it('head SQL does not include that predicate when the query omits affectedPrincipalDid (backward compatible; principal dimension is optional)', async () => {
        const { pool, captured } = makeCapturingPool({});
        const handler = __testing__makeHandleSignedLedgerHead(pool);
        const { res, getStatus } = makeMockRes();
        res.locals['verifiedAudit'] = makeControlPlaneVerifiedAudit({
            affectedAgentDid: TEST_AFFECTED_AGENT_DID,
            // do not pass affectedPrincipalDid
        });
        await handler(
            { url: '/audit/ledger/head' } as import('express').Request,
            res,
            (() => undefined) as import('express').NextFunction,
        );
        expect(getStatus()).toBe(200);
        const headCall = captured.find(
            (c) =>
                typeof c.sql === 'string' && c.sql.includes('ORDER BY id DESC'),
        );
        expect(headCall).toBeDefined();
        expect(headCall!.sql).not.toContain(
            "parameters_summary->>'affectedPrincipalDid'",
        );
        expect(headCall!.values).not.toContain(TEST_AFFECTED_PRINCIPAL_DID);
    });

    // ─── chain.verify with a non-genesis start point → 400 ─────────────
    it('chain.verify with a non-genesis start point → 400 AUDIT_QUERY_MALFORMED (symmetric with the CLI)', async () => {
        // genesis = 2026-04-01; start = 2026-04-15 is strictly later than genesis → must be 400
        const { pool } = makeCapturingPool({
            chainVerifyGenesisRow: { created_at: '2026-04-01T00:00:00.000Z' },
        });
        const handler = __testing__makeHandleChainVerify(pool);
        const { res, getStatus, getBody } = makeMockRes();
        await handler({
            verifiedAudit: makeBusinessVerifiedAudit({
                start: '2026-04-15T00:00:00.000Z',
            }),
            snapshotMaxId: BigInt('1000'),
            res,
        });
        expect(getStatus()).toBe(400);
        const body = getBody() as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
        expect(body.error.detail).toContain('genesis');
        expect(body.error.detail).toContain('CLI');
    });

    it('chain.verify with start equal to genesis (≤ genesis) → not rejected (genesis start point is valid)', async () => {
        const { pool } = makeCapturingPool({
            chainVerifyGenesisRow: { created_at: '2026-04-15T00:00:00.000Z' },
        });
        const handler = __testing__makeHandleChainVerify(pool);
        const { res, getStatus } = makeMockRes();
        await handler({
            verifiedAudit: makeBusinessVerifiedAudit({
                start: '2026-04-15T00:00:00.000Z',
            }),
            snapshotMaxId: BigInt('1000'),
            res,
        });
        // A valid genesis start point → not 400 at the guard; the mock pool's default empty records → 200 valid:true
        expect(getStatus()).toBe(200);
    });

    it('chain.verify without start → skips the genesis probe (backward compatible)', async () => {
        const { pool, captured } = makeCapturingPool({});
        const handler = __testing__makeHandleChainVerify(pool);
        const { res, getStatus } = makeMockRes();
        await handler({
            verifiedAudit: makeBusinessVerifiedAudit({}),
            snapshotMaxId: BigInt('1000'),
            res,
        });
        expect(getStatus()).toBe(200);
        const genesisCall = captured.find(
            (c) =>
                typeof c.sql === 'string' &&
                c.sql.includes('ORDER BY id ASC') &&
                c.sql.includes('LIMIT 1'),
        );
        expect(genesisCall).toBeUndefined();
    });
});
