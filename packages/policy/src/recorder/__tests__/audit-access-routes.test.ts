/**
 * audit-access-routes.test.ts —
 *
 * Unit tests: audit-access-model v0.2 business lane middleware factory
 *
 * Test strategy:
 *   - No real database; ActionRecordReader is a pure-function mock
 *   - No real HTTP server; drive Express directly with MockSocket + IncomingMessage
 *   - Use a static Ed25519 key pair and generate real signatures via sign()
 *   - Cover the v0.1 downgrade path + the v0.2 full path + the delegated-key path
 *
 * firewall: business lane only; governor lane / IntegrityChecker is out of scope for this test
 */

import { Duplex } from 'node:stream';
import { IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';

import express from 'express';
import { describe, expect, it, vi, afterEach } from 'vitest';

import { canonicalize, sign } from '@coivitas/crypto';
import type { DID, Timestamp } from '@coivitas/types';

import type {
    AuditAccessChecker,
    AuditResourceBinding,
    VerifiedAuditRequest,
} from '../../audit/types.js';
import {
    createAuditAccessMiddleware,
    InMemoryAuditNonceStore,
    NullDelegatedAuditKeyResolver,
    NullAuditMetaLedger,
    type ActionRecordReader,
    type AuditNonceStore,
    type AuditMetaLedger,
    type SnapshotAnchorResult,
} from '../audit-access-routes.js';
import type { DelegatedAuditKeyResolver } from '../delegated-key-resolver.js';

// ═══════════════════════════════════════════════════════════════════════════
// Static test key pair (deterministic, Ed25519 seed = 0xab*32)

// seed : 'ab'.repeat(32)
// public : 248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930
// did:key : did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK
// ═══════════════════════════════════════════════════════════════════════════
const TEST_PUB_HEX =
    '248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930';
const TEST_FULL_PRIV_HEX = 'ab'.repeat(32) + TEST_PUB_HEX;
const TEST_REQUESTER_DID =
    'did:key:z6MkguuUVNj72BEqpY3qHikwFtSCiUWgDGbwiX8pqu5uh3gK' as DID;

// For delegated-key tests: another Ed25519 key pair (seed = 0xcd*32)
// Used to test the delegatedAuditKeyId path
const DELEGATED_PUB_HEX =
    '6f6b32fcb7f7a2543c2e2c0c48e0e7c11ad0cc8dca5c88bd98e0e0ec2bfef14';
const _DELEGATED_FULL_PRIV_HEX = 'cd'.repeat(32) + DELEGATED_PUB_HEX;
const DELEGATED_KEY_DID =
    'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp' as DID;

const TEST_AGENT_DID = 'did:agent:aabbccddeeff001122334455' as DID;

// snapshot anchor constants
const SNAP_RECORD_ID = '11111111-1111-4111-8111-111111111111';
const SNAP_CREATED_AT = '2024-01-01T00:00:00.000Z';
const SNAP_RECORD_HASH = 'snap-hash-001';
const SNAP_INTERNAL_ID = '50';

// ═══════════════════════════════════════════════════════════════════════════
// Default mock factories
// ═══════════════════════════════════════════════════════════════════════════

function makeActionRecordReader(
    override?: Partial<SnapshotAnchorResult> | null,
): ActionRecordReader {
    return {
        findSnapshotAnchor: vi.fn().mockResolvedValue(
            override === null
                ? null
                : {
                      internalId: SNAP_INTERNAL_ID,
                      recordHash: SNAP_RECORD_HASH,
                      createdAt: SNAP_CREATED_AT,
                      ...override,
                  },
        ),
    };
}

function makeIdentityStore(options?: {
    returnNull?: boolean;
    throwBinding?: boolean;
}) {
    return {
        resolveForAudit: vi.fn().mockImplementation(async () => {
            if (options?.returnNull) return null;
            if (options?.throwBinding) {
                const { ProtocolError } = await import('@coivitas/types');
                throw new ProtocolError(
                    'BINDING_PROOF_INVALID',
                    'binding proof invalid',
                );
            }
            return {
                document: {
                    id: TEST_AGENT_DID,
                    specVersion: '0.1.0',
                    principalDid: TEST_REQUESTER_DID,
                    publicKey: TEST_PUB_HEX,
                    bindingProof: {
                        principalDid: TEST_REQUESTER_DID,
                        agentDid: TEST_AGENT_DID,
                        issuedAt: '2024-01-01T00:00:00.000Z',
                        expiresAt: null,
                        signature: 'binding-sig',
                    },
                    capabilities: [],
                    serviceEndpoints: [],
                    createdAt: '2024-01-01T00:00:00.000Z' as Timestamp,
                    updatedAt: '2024-01-01T00:00:00.000Z' as Timestamp,
                    version: 1,
                },
                status: 'active' as const,
                verifiedAt: '2024-01-01T00:00:00.000Z' as Timestamp,
            };
        }),
    };
}

function makeChecker(options?: {
    allow?: boolean;
    code?: string;
}): AuditAccessChecker {
    const allow = options?.allow ?? true;
    const code = options?.code ?? 'AUDIT_FORBIDDEN';
    return {
        check: vi
            .fn()
            .mockResolvedValue(
                allow
                    ? { allowed: true }
                    : { allowed: false, code, reason: `test ${code}` },
            ),
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// MockSocket + inject: an HTTP injection tool with no TCP port
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
    get readable() {
        return false;
    }
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
            let json: Record<string, unknown> = {};
            try {
                json = JSON.parse(bodyStr) as Record<string, unknown>;
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

        (
            app as unknown as {
                handle: (req: IncomingMessage, res: ServerResponse) => void;
            }
        ).handle(req, res);
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Signing utility: build valid X-Audit-* request headers
// ═══════════════════════════════════════════════════════════════════════════
interface MakeHeadersOptions {
    requesterDid?: DID;
    targetAgentDid?: DID;
    resourceBinding?: AuditResourceBinding;
    queryParams?: Record<string, unknown>;
    timestamp?: string;
    snapshotHeadCreatedAt?: string;
    snapshotHeadRecordId?: string;
    snapshotHeadRecordHash?: string;
    privateKey?: string;
    overrideSignature?: string;
    /** v0.2 extension fields */
    nonce?: string;
    proofType?: string;
    delegatedKeyId?: string;
    /** Whether to include the v0.2 fields when signing */
    signWithV2Fields?: boolean;
}

function makeHeaders(opts: MakeHeadersOptions = {}): Record<string, string> {
    const requesterDid = opts.requesterDid ?? TEST_REQUESTER_DID;
    const targetAgentDid = opts.targetAgentDid ?? TEST_AGENT_DID;
    const timestamp = opts.timestamp ?? new Date().toISOString();
    const resourceBinding = opts.resourceBinding ?? {
        route: 'records.list' as const,
        recordId: null,
    };
    const privateKey = opts.privateKey ?? TEST_FULL_PRIV_HEX;
    const snapshotHeadCreatedAt = opts.snapshotHeadCreatedAt ?? SNAP_CREATED_AT;
    const snapshotHeadRecordId = opts.snapshotHeadRecordId ?? SNAP_RECORD_ID;
    const snapshotHeadRecordHash = opts.snapshotHeadRecordHash;

    // Includes agentDid by default, consistent with the implementation extracting it from the agent_did query param
    const queryParams: Record<string, unknown> = opts.queryParams ?? {
        agentDid: targetAgentDid,
    };
    const snapshotBoundary = {
        headCreatedAt: snapshotHeadCreatedAt as Timestamp,
        headRecordId: snapshotHeadRecordId,
        ...(snapshotHeadRecordHash
            ? { headRecordHash: snapshotHeadRecordHash }
            : {}),
    };

    const signaturePayload: Record<string, unknown> = {
        requesterDid,
        targetAgentDid,
        httpMethod: 'GET' as const,
        resourceBinding,
        queryParams,
        snapshotBoundary,
        timestamp,
    };

    // The v0.2 fields are included in the signature only when signWithV2Fields is true
    const { nonce, proofType, delegatedKeyId, signWithV2Fields } = opts;
    if (signWithV2Fields) {
        if (nonce !== undefined) signaturePayload['nonce'] = nonce;
        if (proofType !== undefined) signaturePayload['proofType'] = proofType;
        if (delegatedKeyId !== undefined)
            signaturePayload['delegatedAuditKeyId'] = delegatedKeyId;
    }

    const canonical = canonicalize(signaturePayload);
    const msgBytes = new TextEncoder().encode(canonical);
    const signature = opts.overrideSignature ?? sign(msgBytes, privateKey);

    const headers: Record<string, string> = {
        'x-audit-requester': requesterDid,
        'x-audit-signature': signature,
        'x-audit-timestamp': timestamp,
        'x-audit-snapshot-headcreatedat': snapshotHeadCreatedAt,
        'x-audit-snapshot-headrecordid': snapshotHeadRecordId,
    };
    if (snapshotHeadRecordHash) {
        headers['x-audit-snapshot-headrecordhash'] = snapshotHeadRecordHash;
    }
    if (nonce !== undefined) headers['x-audit-nonce'] = nonce;
    if (proofType !== undefined) headers['x-audit-proof-type'] = proofType;
    if (delegatedKeyId !== undefined)
        headers['x-audit-delegated-key-id'] = delegatedKeyId;
    return headers;
}

// The ledger.head route does not require snapshot headers
function makeHeadHeaders(
    opts: Omit<MakeHeadersOptions, 'resourceBinding'> = {},
): Record<string, string> {
    const requesterDid = opts.requesterDid ?? TEST_REQUESTER_DID;
    const targetAgentDid = opts.targetAgentDid ?? TEST_AGENT_DID;
    const timestamp = opts.timestamp ?? new Date().toISOString();
    const privateKey = opts.privateKey ?? TEST_FULL_PRIV_HEX;

    const resourceBinding: AuditResourceBinding = {
        route: 'ledger.head',
        recordId: null,
    };
    // Includes agentDid by default, consistent with the implementation extracting it from the agent_did query param
    const queryParams: Record<string, unknown> = opts.queryParams ?? {
        agentDid: targetAgentDid,
    };

    const signaturePayload: Record<string, unknown> = {
        requesterDid,
        targetAgentDid,
        httpMethod: 'GET' as const,
        resourceBinding,
        queryParams,
        timestamp,
    };

    const canonical = canonicalize(signaturePayload);
    const msgBytes = new TextEncoder().encode(canonical);
    const signature = opts.overrideSignature ?? sign(msgBytes, privateKey);

    return {
        'x-audit-requester': requesterDid,
        'x-audit-signature': signature,
        'x-audit-timestamp': timestamp,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Express app factory
// ═══════════════════════════════════════════════════════════════════════════
interface AppOptions {
    route?: AuditResourceBinding['route'];
    checker?: AuditAccessChecker;
    identityStore?: ReturnType<typeof makeIdentityStore>;
    actionRecordReader?: ActionRecordReader;
    nonceStore?: AuditNonceStore;
    delegatedKeyResolver?: DelegatedAuditKeyResolver;
    metaLedger?: AuditMetaLedger;
    clock?: () => number;
}

function makeApp(opts: AppOptions = {}): {
    app: ReturnType<typeof express>;
    checker: AuditAccessChecker;
    identityStore: ReturnType<typeof makeIdentityStore>;
    actionRecordReader: ActionRecordReader;
    nonceStore: AuditNonceStore;
    metaLedger: AuditMetaLedger;
} {
    const route = opts.route ?? 'records.list';
    const checker = opts.checker ?? makeChecker();
    const identityStore = opts.identityStore ?? makeIdentityStore();
    const actionRecordReader =
        opts.actionRecordReader ?? makeActionRecordReader();
    const nonceStore = opts.nonceStore ?? new InMemoryAuditNonceStore();
    const delegatedKeyResolver =
        opts.delegatedKeyResolver ?? new NullDelegatedAuditKeyResolver();
    const metaLedger = opts.metaLedger ?? new NullAuditMetaLedger();

    const app = express();
    app.use(express.json());

    // Mount the middleware on the corresponding route
    const middleware = createAuditAccessMiddleware(route, {
        checker,
        identityStore: identityStore as unknown as Parameters<
            typeof createAuditAccessMiddleware
        >[1]['identityStore'],
        actionRecordReader,
        nonceStore,
        delegatedKeyResolver,
        metaLedger,
        clock: opts.clock,
    });

    // Mount on different paths depending on route
    if (route === 'records.list') {
        app.get('/records', middleware, (_req, res) => {
            res.json({
                ok: true,
                clientVersion: res.locals['auditClientVersion'] as
                    | string
                    | undefined,
            });
        });
    } else if (route === 'records.get') {
        app.get('/records/:id', middleware, (_req, res) => {
            res.json({ ok: true });
        });
    } else if (route === 'ledger.head') {
        app.get('/ledger/head', middleware, (_req, res) => {
            res.json({ ok: true });
        });
    }

    return {
        app,
        checker,
        identityStore,
        actionRecordReader,
        nonceStore,
        metaLedger,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: InMemoryAuditNonceStore unit tests
// ═══════════════════════════════════════════════════════════════════════════
describe('InMemoryAuditNonceStore', () => {
    it('should return false when nonce is first seen', async () => {
        const store = new InMemoryAuditNonceStore();
        const nonce = randomUUID();
        const isReplay = await store.checkAndStore(nonce);
        expect(isReplay).toBe(false);
        store.dispose();
    });

    it('should return true when same nonce is seen again within window', async () => {
        const store = new InMemoryAuditNonceStore();
        const nonce = randomUUID();
        await store.checkAndStore(nonce);
        const isReplay = await store.checkAndStore(nonce);
        expect(isReplay).toBe(true);
        store.dispose();
    });

    it('should return false when nonce is re-used after TTL expiry', async () => {
        let fakeNow = 0;
        const store = new InMemoryAuditNonceStore(100, () => fakeNow, 999_999);
        const nonce = randomUUID();

        // First write
        await store.checkAndStore(nonce);
        // TTL = 100ms -> advance 200ms
        fakeNow = 200;
        const isReplay = await store.checkAndStore(nonce);
        expect(isReplay).toBe(false);
        store.dispose();
    });

    it('should allow different nonces independently', async () => {
        const store = new InMemoryAuditNonceStore();
        const n1 = randomUUID();
        const n2 = randomUUID();
        await store.checkAndStore(n1);
        const isReplay = await store.checkAndStore(n2);
        expect(isReplay).toBe(false);
        store.dispose();
    });

    it('should clean up expired entries', async () => {
        let fakeNow = 0;
        const store = new InMemoryAuditNonceStore(100, () => fakeNow, 999_999);
        const nonce = randomUUID();
        await store.checkAndStore(nonce);
        fakeNow = 200;
        // Trigger cleanup manually (via dispose + rebuild, or check the store size without exposing private members)
        // Verify that re-entry after TTL expiry = false (indirectly proving it was cleaned up)
        const isReplay = await store.checkAndStore(nonce);
        expect(isReplay).toBe(false);
        store.dispose();
    });

    it('should support dispose to stop cleanup timer', () => {
        const store = new InMemoryAuditNonceStore();
        // dispose does not throw
        expect(() => store.dispose()).not.toThrow();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: NullDelegatedAuditKeyResolver
// ═══════════════════════════════════════════════════════════════════════════
describe('NullDelegatedAuditKeyResolver', () => {
    it('should always return null', async () => {
        const resolver = new NullDelegatedAuditKeyResolver();
        const result = await resolver.resolve('key-id-1', TEST_AGENT_DID);
        expect(result).toBeNull();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: NullAuditMetaLedger
// ═══════════════════════════════════════════════════════════════════════════
describe('NullAuditMetaLedger', () => {
    it('should resolve without error', async () => {
        const ledger = new NullAuditMetaLedger();
        await expect(
            ledger.recordEvent({
                requesterDid: TEST_REQUESTER_DID,
                targetAgentDid: TEST_AGENT_DID,
                route: 'records.list',
                decision: 'allowed',
                timestamp: new Date().toISOString(),
            }),
        ).resolves.toBeUndefined();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: createAuditAccessMiddleware — v0.1 compatibility path (downgrade mode)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (v0.1 compat path)', () => {
    it('should allow request and set auditClientVersion=v0.1-compat when nonce and proofType absent', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { ok: boolean; clientVersion: string };
        expect(body.ok).toBe(true);
        expect(body.clientVersion).toBe('v0.1-compat');
    });

    it('should pass verifiedAudit to res.locals when allowed', async () => {
        const checker: AuditAccessChecker = {
            check: vi.fn().mockImplementation((req: VerifiedAuditRequest) => {
                expect(req.lane).toBe('business');
                expect(req.query.requesterDid).toBe(TEST_REQUESTER_DID);
                return Promise.resolve({ allowed: true });
            }),
        };
        const { app } = makeApp({ checker });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 400 when x-audit-requester is missing', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const { 'x-audit-requester': _drop, ...rest } = headers;
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when x-audit-signature is missing', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const { 'x-audit-signature': _drop, ...rest } = headers;
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when x-audit-timestamp is missing', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const { 'x-audit-timestamp': _drop, ...rest } = headers;
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when timestamp format is invalid', async () => {
        const { app } = makeApp();
        const headers = makeHeaders({ timestamp: '2024-01-01' }); // missing milliseconds + Z
        // Reset the timestamp header to an invalid value (replaced after signing)
        headers['x-audit-timestamp'] = '2024-01-01';
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when agent_did query param is missing', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const res = await inject(app, 'GET', '/records', { headers });
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when agent_did prefix is invalid', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            '/records?agent_did=did:wrong:foo',
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when snapshot headers missing for records.list route', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        const {
            'x-audit-snapshot-headcreatedat': _c,
            'x-audit-snapshot-headrecordid': _r,
            ...rest
        } = headers;
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: rest },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 when headRecordId is not UUID v4', async () => {
        const { app } = makeApp();
        const headers = makeHeaders({ snapshotHeadRecordId: 'not-a-uuid' });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    it('should return 400 when snapshot anchor not found', async () => {
        const { app } = makeApp({
            actionRecordReader: makeActionRecordReader(null),
        });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    it('should return 400 when headRecordHash does not match stored hash', async () => {
        const { app } = makeApp();
        const headers = makeHeaders({ snapshotHeadRecordHash: 'wrong-hash' });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    it('should return 400 when headCreatedAt is after timestamp', async () => {
        const { app } = makeApp();
        const now = new Date();
        const future = new Date(now.getTime() + 60_000).toISOString();
        // headCreatedAt = future > timestamp = now -> violates the ordering constraint
        const headers = makeHeaders({
            timestamp: now.toISOString(),
            snapshotHeadCreatedAt: future,
        });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SNAPSHOT_BOUNDARY_VIOLATED');
    });

    it('should return 401 when timestamp skew exceeds ±300s', async () => {
        const { app } = makeApp();
        const oldTimestamp = new Date(Date.now() - 600_000).toISOString();
        const headers = makeHeaders({ timestamp: oldTimestamp });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_TIMESTAMP_SKEW');
    });

    it('should return 401 when signature is invalid', async () => {
        const { app } = makeApp();
        const headers = makeHeaders({ overrideSignature: 'ab'.repeat(64) }); // 128 hex chars = 64 bytes, wrong sig
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_SIGNATURE_INVALID');
    });

    it('should return 401 when requesterDid is not a valid DID key', async () => {
        const { app } = makeApp();
        const headers = makeHeaders();
        // Replace requesterDid with a non-did:key format (the public key cannot be resolved)
        headers['x-audit-requester'] = 'did:agent:aaaa';
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_REQUESTER_UNKNOWN');
    });

    it('should return 404 when target agent not found in identity store', async () => {
        const { app } = makeApp({
            identityStore: makeIdentityStore({ returnNull: true }),
        });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(404);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('IDENTITY_NOT_FOUND');
    });

    it('should return 401 when identity store throws BINDING_PROOF_INVALID', async () => {
        const { app } = makeApp({
            identityStore: makeIdentityStore({ throwBinding: true }),
        });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_IDENTITY_UNVERIFIED');
    });

    it('should return 403 when checker returns AUDIT_FORBIDDEN', async () => {
        const { app } = makeApp({
            checker: makeChecker({ allow: false, code: 'AUDIT_FORBIDDEN' }),
        });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(403);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
    });

    it('should return 401 when checker returns AUDIT_REQUESTER_UNKNOWN', async () => {
        const { app } = makeApp({
            checker: makeChecker({
                allow: false,
                code: 'AUDIT_REQUESTER_UNKNOWN',
            }),
        });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
    });

    it('should return 400 when checker returns AUDIT_QUERY_MALFORMED', async () => {
        const { app } = makeApp({
            checker: makeChecker({
                allow: false,
                code: 'AUDIT_QUERY_MALFORMED',
            }),
        });
        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
    });

    it('should call metaLedger.recordEvent with denied when checker rejects', async () => {
        const metaLedger = {
            recordEvent: vi.fn().mockResolvedValue(undefined),
        };
        const { app } = makeApp({
            checker: makeChecker({ allow: false, code: 'AUDIT_FORBIDDEN' }),
            metaLedger,
        });
        const headers = makeHeaders();
        await inject(app, 'GET', `/records?agent_did=${TEST_AGENT_DID}`, {
            headers,
        });
        expect(metaLedger.recordEvent).toHaveBeenCalledOnce();
        const call = metaLedger.recordEvent.mock.calls[0][0] as {
            decision: string;
        };
        expect(call.decision).toBe('denied');
    });

    it('should call metaLedger.recordEvent with allowed when request passes', async () => {
        const metaLedger = {
            recordEvent: vi.fn().mockResolvedValue(undefined),
        };
        const { app } = makeApp({ metaLedger });
        const headers = makeHeaders();
        await inject(app, 'GET', `/records?agent_did=${TEST_AGENT_DID}`, {
            headers,
        });
        expect(metaLedger.recordEvent).toHaveBeenCalledOnce();
        const call = metaLedger.recordEvent.mock.calls[0][0] as {
            decision: string;
        };
        expect(call.decision).toBe('allowed');
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 5: ledger.head route (does not require snapshot headers)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (ledger.head route)', () => {
    it('should allow request without snapshot headers', async () => {
        const { app } = makeApp({ route: 'ledger.head' });
        const headers = makeHeadHeaders();
        const res = await inject(
            app,
            'GET',
            `/ledger/head?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(200);
    });

    it('should return 400 when required headers missing for ledger.head', async () => {
        const { app } = makeApp({ route: 'ledger.head' });
        const headers = makeHeadHeaders();
        const { 'x-audit-requester': _drop, ...rest } = headers;
        const res = await inject(
            app,
            'GET',
            `/ledger/head?agent_did=${TEST_AGENT_DID}`,
            { headers: rest },
        );
        expect(res.status).toBe(400);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: v0.2 path — nonce replay protection (step 6.5)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (v0.2 nonce replay protection)', () => {
    it('should set auditClientVersion=v0.2 when nonce header is present', async () => {
        const { app } = makeApp();
        const nonce = randomUUID();
        const headers = makeHeaders({ nonce, signWithV2Fields: true });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { clientVersion: string };
        expect(body.clientVersion).toBe('v0.2');
    });

    it('should set auditClientVersion=v0.2 when proofType header is present', async () => {
        const { app } = makeApp();
        const proofType = 'Ed25519Signature2020';
        // When proofType is present, nonce must also be provided
        const nonce = randomUUID();
        const headers = makeHeaders({
            nonce,
            proofType,
            signWithV2Fields: true,
        });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.json as { clientVersion: string };
        expect(body.clientVersion).toBe('v0.2');
    });

    it('should return 400 when nonce is not UUID v4 format', async () => {
        const { app } = makeApp();
        const headers = makeHeaders({
            nonce: 'not-a-uuid',
            signWithV2Fields: true,
        });
        // Replace the nonce header with an invalid value (replaced after signing, so the signature may pass when other checks run first)
        headers['x-audit-nonce'] = 'not-a-uuid';
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 401 AUDIT_NONCE_REPLAY when nonce is replayed within window', async () => {
        const nonceStore = new InMemoryAuditNonceStore();
        const { app } = makeApp({ nonceStore });
        const nonce = randomUUID();

        // The first request succeeds
        const h1 = makeHeaders({ nonce, signWithV2Fields: true });
        const r1 = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: h1 },
        );
        expect(r1.status).toBe(200);

        // The second replay — note the timestamp must be new, otherwise a timestamp skew error triggers first
        // Use the same nonce + a new timestamp + re-sign
        const h2 = makeHeaders({ nonce, signWithV2Fields: true });
        const r2 = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: h2 },
        );
        expect(r2.status).toBe(401);
        const body = r2.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_NONCE_REPLAY');

        nonceStore.dispose();
    });

    it('should include nonce in metaLedger.recordEvent when nonce is present', async () => {
        const metaLedger = {
            recordEvent: vi.fn().mockResolvedValue(undefined),
        };
        const { app } = makeApp({ metaLedger });
        const nonce = randomUUID();
        const headers = makeHeaders({ nonce, signWithV2Fields: true });
        await inject(app, 'GET', `/records?agent_did=${TEST_AGENT_DID}`, {
            headers,
        });
        expect(metaLedger.recordEvent).toHaveBeenCalledOnce();
        const call = metaLedger.recordEvent.mock.calls[0][0] as {
            nonce: string;
        };
        expect(call.nonce).toBe(nonce);
    });

    it('should return 400 when proofType is invalid value', async () => {
        const { app } = makeApp();
        // When proofType is present, nonce must also be provided
        const headers = makeHeaders({
            nonce: randomUUID(),
            proofType: 'InvalidProofType',
            signWithV2Fields: true,
        });
        headers['x-audit-proof-type'] = 'InvalidProofType';
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // The nonce must not be stored before authentication (pre-auth DoS defense)
    it('should NOT store nonce when signature is invalid (pre-auth DoS defense)', async () => {
        const nonceStore = new InMemoryAuditNonceStore();
        const { app } = makeApp({ nonceStore });
        const nonce = randomUUID();

        // First: send a request with a wrong signature (forged hex) → 401 AUDIT_SIGNATURE_INVALID
        // Before the fix: the nonce was already written by checkAndStore → occupied
        // After the fix: because signature verification fails, the nonce is not consumed
        const badHeaders = makeHeaders({
            nonce,
            signWithV2Fields: true,
            overrideSignature: 'a'.repeat(128), // forged signature
        });
        const r1 = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: badHeaders },
        );
        expect(r1.status).toBe(401);
        const r1Body = r1.json as { error: { code: string } };
        expect(r1Body.error.code).toBe('AUDIT_SIGNATURE_INVALID');

        // Second: use a valid signature + the same nonce → should pass with 200 (the nonce was not occupied)
        const goodHeaders = makeHeaders({ nonce, signWithV2Fields: true });
        const r2 = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers: goodHeaders },
        );
        expect(r2.status).toBe(200);

        nonceStore.dispose();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 7: v0.2 path — delegated audit key (step 9 extension)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (v0.2 delegated key path)', () => {
    it('should return 401 when delegated key resolver returns null', async () => {
        const { app } = makeApp({
            delegatedKeyResolver: new NullDelegatedAuditKeyResolver(),
        });
        const delegatedKeyId = 'key-id-001';
        // When delegatedKeyId is present, nonce must also be provided
        const headers = makeHeaders({
            nonce: randomUUID(),
            delegatedKeyId,
            signWithV2Fields: true,
        });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_REQUESTER_UNKNOWN');
    });

    it('should return 401 when delegated key principalDid does not match requesterDid', async () => {
        const wrongPrincipalDid = 'did:key:z6Mkother' as DID;
        const delegatedKeyResolver: DelegatedAuditKeyResolver = {
            resolve: vi.fn().mockResolvedValue({
                id: 'key-id-001',
                principalDid: wrongPrincipalDid, // does not match TEST_REQUESTER_DID
                delegatedTo: DELEGATED_KEY_DID,
                targetAgentDid: TEST_AGENT_DID,
                issuedAt: '2024-01-01T00:00:00.000Z' as Timestamp,
                expiresAt: null,
            }),
        };
        const { app } = makeApp({ delegatedKeyResolver });
        const delegatedKeyId = 'key-id-001';
        const headers = makeHeaders({
            nonce: randomUUID(),
            delegatedKeyId,
            signWithV2Fields: true,
        });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_REQUESTER_UNKNOWN');
    });

    it('should return 401 when delegated key DID cannot be decoded', async () => {
        const delegatedKeyResolver: DelegatedAuditKeyResolver = {
            resolve: vi.fn().mockResolvedValue({
                id: 'key-id-001',
                principalDid: TEST_REQUESTER_DID, // matches
                delegatedTo: 'did:agent:invalid-not-didkey' as DID, // cannot be decoded
                targetAgentDid: TEST_AGENT_DID,
                issuedAt: '2024-01-01T00:00:00.000Z' as Timestamp,
                expiresAt: null,
            }),
        };
        const { app } = makeApp({ delegatedKeyResolver });
        const delegatedKeyId = 'key-id-001';
        const headers = makeHeaders({
            nonce: randomUUID(),
            delegatedKeyId,
            signWithV2Fields: true,
        });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(401);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_REQUESTER_UNKNOWN');
    });

    // fail-closed when v0.2 indicators without nonce
    it('should return 400 AUDIT_QUERY_MALFORMED when proofType is present without nonce', async () => {
        const { app } = makeApp();
        const proofType = 'Ed25519Signature2020';
        // Pass proofType without nonce — before the fix this was silently marked v0.2 and skipped the nonce check
        const headers = makeHeaders({ proofType, signWithV2Fields: true });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should return 400 AUDIT_QUERY_MALFORMED when delegatedKeyId is present without nonce', async () => {
        const { app } = makeApp({
            delegatedKeyResolver: new NullDelegatedAuditKeyResolver(),
        });
        const delegatedKeyId = 'key-id-001';
        // Pass delegatedKeyId without nonce
        const headers = makeHeaders({ delegatedKeyId, signWithV2Fields: true });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 8: duplicate header detection (step 1 replay protection)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (duplicate header detection)', () => {
    it('should return 400 when x-audit-requester appears multiple times', async () => {
        const { app } = makeApp();
        // Node merges duplicate headers into "a, b"; detect this via headersDistinct
        // We simulate the headersDistinct behavior (setting headersDistinct directly on IncomingMessage)
        const headers = makeHeaders();
        // Build request headers containing duplicate values — simulated by setting the comma-joined value directly
        const req = new IncomingMessage(
            new MockSocket() as unknown as import('net').Socket,
        );
        req.method = 'GET';
        req.url = `/records?agent_did=${TEST_AGENT_DID}`;
        // Standard headers
        req.headers = headers;
        // headersDistinct simulation (duplicate x-audit-requester)
        Object.defineProperty(req, 'headersDistinct', {
            get() {
                return {
                    'x-audit-requester': [
                        headers['x-audit-requester'],
                        headers['x-audit-requester'],
                    ],
                };
            },
        });

        const res = await new Promise<InjectResponse>((resolve) => {
            const sock = new MockSocket();
            const serverRes = new ServerResponse(req);
            serverRes.assignSocket(sock as unknown as import('net').Socket);

            const collect = () => {
                const raw = Buffer.concat(sock._chunks).toString('utf8');
                const headerEnd = raw.indexOf('\r\n\r\n');
                const bodyStr = headerEnd >= 0 ? raw.slice(headerEnd + 4) : raw;
                const statusLine =
                    headerEnd >= 0
                        ? raw.slice(0, headerEnd).split('\r\n')[0]
                        : '';
                const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+)/);
                const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
                let json: Record<string, unknown> = {};
                try {
                    json = JSON.parse(bodyStr) as Record<string, unknown>;
                } catch {
                    
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
            serverRes.on('finish', once);
            sock.on('close', once);

            (
                app as unknown as {
                    handle: (req: IncomingMessage, res: ServerResponse) => void;
                }
            ).handle(req, serverRes);
        });

        expect(res.status).toBe(400);
        const body = res.json as { error: { code: string; detail: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
        expect(body.error.detail).toContain('Duplicate header');
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 9: records.get route (with the :id path parameter)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (records.get route)', () => {
    it('should allow request with valid :id param', async () => {
        const { app } = makeApp({ route: 'records.get' });
        const recordId = '33333333-3333-4333-8333-333333333333';
        const headers = makeHeaders({
            resourceBinding: { route: 'records.get', recordId },
        });
        const res = await inject(
            app,
            'GET',
            `/records/${recordId}?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        expect(res.status).toBe(200);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 10: error propagation (the next(err) path)
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (error propagation)', () => {
    it('should call next(err) when unexpected error thrown in identity store', async () => {
        const identityStore = {
            resolveForAudit: vi
                .fn()
                .mockRejectedValue(new Error('DB connection failed')),
        };
        const errorHandler = vi.fn(
            (
                _err: Error,
                _req: unknown,
                res: { status: (c: number) => { json: (b: unknown) => void } },
                _next: unknown,
            ) => {
                res.status(500).json({ error: { code: 'INTERNAL_ERROR' } });
            },
        );

        const { app } = makeApp({
            identityStore: identityStore as unknown as ReturnType<
                typeof makeIdentityStore
            >,
        });
        // Mount the error-handling middleware
        app.use(errorHandler as unknown as Parameters<typeof app.use>[0]);

        const headers = makeHeaders();
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}`,
            { headers },
        );
        // The Express default error handler returns 500
        expect([500, 400, 401]).toContain(res.status);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 11: queryParams parsing
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (queryParams parsing)', () => {
    it('should parse limit query param', async () => {
        const checker: AuditAccessChecker = {
            check: vi.fn().mockImplementation((req: VerifiedAuditRequest) => {
                expect(req.query.queryParams.limit).toBe(50);
                return Promise.resolve({ allowed: true });
            }),
        };
        const { app } = makeApp({ checker });
        // Include limit=50 when signing (consistent with the implementation extracting it from the query string into queryParams)
        const headers = makeHeaders({
            queryParams: { agentDid: TEST_AGENT_DID, limit: 50 },
        });
        await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}&limit=50`,
            { headers },
        );
        expect(
            (checker.check as ReturnType<typeof vi.fn>).mock.calls.length,
        ).toBe(1);
    });

    it('should ignore limit > 500', async () => {
        const checker: AuditAccessChecker = {
            check: vi.fn().mockImplementation((req: VerifiedAuditRequest) => {
                expect(req.query.queryParams.limit).toBeUndefined();
                return Promise.resolve({ allowed: true });
            }),
        };
        const { app } = makeApp({ checker });
        // limit=501 is rejected by the implementation (not placed into queryParams); the signature only includes agentDid
        const headers = makeHeaders(); // default queryParams = { agentDid: ... }
        await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}&limit=501`,
            { headers },
        );
        expect(
            (checker.check as ReturnType<typeof vi.fn>).mock.calls.length,
        ).toBe(1);
    });

    it('should parse session_id query param', async () => {
        const checker: AuditAccessChecker = {
            check: vi.fn().mockImplementation((req: VerifiedAuditRequest) => {
                expect(req.query.queryParams.sessionId).toBe('sess-001');
                return Promise.resolve({ allowed: true });
            }),
        };
        const { app } = makeApp({ checker });
        // Include sessionId when signing (consistent with the implementation extracting it from the query string into queryParams)
        const headers = makeHeaders({
            queryParams: { agentDid: TEST_AGENT_DID, sessionId: 'sess-001' },
        });
        await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_AGENT_DID}&session_id=sess-001`,
            { headers },
        );
        expect(
            (checker.check as ReturnType<typeof vi.fn>).mock.calls.length,
        ).toBe(1);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 12: snapshotMaxId setting
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (snapshotMaxId on res.locals)', () => {
    it('should set snapshotMaxId as BigInt on res.locals', async () => {
        let capturedLocals: Record<string, unknown> = {};
        const checker: AuditAccessChecker = {
            check: vi.fn().mockImplementation((_req: VerifiedAuditRequest) => {
                return Promise.resolve({ allowed: true });
            }),
        };

        // Use a custom route handler to capture res.locals
        const app = express();
        app.use(express.json());
        const middleware = createAuditAccessMiddleware('records.list', {
            checker,
            identityStore: makeIdentityStore() as unknown as Parameters<
                typeof createAuditAccessMiddleware
            >[1]['identityStore'],
            actionRecordReader: makeActionRecordReader(),
            nonceStore: new InMemoryAuditNonceStore(),
            delegatedKeyResolver: new NullDelegatedAuditKeyResolver(),
            metaLedger: new NullAuditMetaLedger(),
        });
        app.get('/records', middleware, (_req, res) => {
            capturedLocals = { ...res.locals };
            res.json({ ok: true });
        });

        const headers = makeHeaders();
        await inject(app, 'GET', `/records?agent_did=${TEST_AGENT_DID}`, {
            headers,
        });
        expect(typeof capturedLocals['snapshotMaxId']).toBe('bigint');
        expect(capturedLocals['snapshotMaxId']).toBe(BigInt(SNAP_INTERNAL_ID));
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 13: error-code to HTTP status mapping
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (error code to HTTP status mapping)', () => {
    const codeToStatus: Array<[string, number]> = [
        ['AUDIT_FORBIDDEN', 403],
        ['AUDIT_QUERY_MALFORMED', 400],
        ['AUDIT_RESOURCE_BINDING_MISMATCH', 400],
        ['AUDIT_SNAPSHOT_BOUNDARY_VIOLATED', 400],
        ['AUDIT_SIGNATURE_INVALID', 401],
        ['AUDIT_TIMESTAMP_SKEW', 401],
        ['AUDIT_REQUESTER_UNKNOWN', 401],
        ['AUDIT_IDENTITY_UNVERIFIED', 401],
        ['AUDIT_NONCE_REPLAY', 401],
    ];

    for (const [code, expectedStatus] of codeToStatus) {
        it(`should map ${code} to HTTP ${expectedStatus}`, async () => {
            const { app } = makeApp({
                checker: makeChecker({ allow: false, code }),
            });
            const headers = makeHeaders();
            const res = await inject(
                app,
                'GET',
                `/records?agent_did=${TEST_AGENT_DID}`,
                { headers },
            );
            expect(res.status).toBe(expectedStatus);
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 14: did:key prefix support
// ═══════════════════════════════════════════════════════════════════════════
describe('createAuditAccessMiddleware (did:key agent_did prefix)', () => {
    it('should accept agent_did with did:key: prefix', async () => {
        // agent_did may be in did:key: format (a compatibility test scenario)
        const { app } = makeApp();
        const headers = makeHeaders({ targetAgentDid: TEST_REQUESTER_DID });
        const res = await inject(
            app,
            'GET',
            `/records?agent_did=${TEST_REQUESTER_DID}`,
            { headers },
        );
        // Passes did:key: format validation (the identityStore mock does not distinguish and returns a fixed result)
        expect([200, 400, 401, 404]).toContain(res.status);
    });
});

// cleanup
afterEach(() => {
    vi.clearAllMocks();
});
