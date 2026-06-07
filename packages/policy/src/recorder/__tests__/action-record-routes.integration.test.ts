/**
 * action-record-routes integration test
 *
 * Coverage:
 *   1. GET /ledger/head — unauthenticated helper endpoint
 *   2. GET /records — list query (including limit pagination)
 *   3. GET /records/:id — single record fetch
 *   4. GET /records/:id/verify — single record signature verification
 *   5. GET /records/chain/verify — hash chain verification
 *   Security assertions:
 *   6. Snapshot boundary: records added after the snapshot are not visible
 *   7. Cross-agent access → 403 AUDIT_FORBIDDEN
 *   8. Unknown query parameter → 400 AUDIT_QUERY_MALFORMED
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import express from 'express';

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '@coivitas/identity';
import { createTestDatabase, createTestServer } from '@coivitas/shared';
import type { DID } from '@coivitas/types';

import { ActionRecorder, registerActionRecordRoutes } from '../../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

// ── fetch helper (supports custom headers) ────────────────────────────────────────
interface FetchOptions {
    headers?: Record<string, string>;
    queryString?: string;
}

async function httpGet(
    baseUrl: string,
    path: string,
    options: FetchOptions = {},
): Promise<{ status: number; body: unknown }> {
    const url = `${baseUrl}${path}${options.queryString ? `?${options.queryString}` : ''}`;
    const res = await fetch(url, {
        method: 'GET',
        headers: options.headers,
    });
    const contentType = res.headers.get('content-type') ?? '';
    const body = contentType.includes('application/json')
        ? await res.json()
        : await res.text();
    return { status: res.status, body };
}

describeIfDatabase('action-record-routes integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let pool: Awaited<ReturnType<typeof createTestDatabase>>['pool'];
    let recorder: ActionRecorder;
    let registry: IdentityRegistry;
    let agentDid: DID;
    let agentPrivateKey: string;
    let requesterDid: DID;
    let requesterPrivateKey: string;
    let serverUrl: string;
    let serverClose: () => Promise<void>;
    let firstRecordId: string;
    let headRecordId: string;
    let headCreatedAt: string;
    let headRecordHash: string;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        pool = database.pool;

        registry = new IdentityRegistry(pool);

        // Create the requester (principal) key pair
        const principal = generateKeyPair();
        requesterDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        requesterPrivateKey = principal.privateKey;

        // Create the agent identity
        const agent = createAgentIdentity({
            principalDid: requesterDid,
            principalPrivateKey: principal.privateKey,
        });
        agentDid = agent.document.id; // did:agent:... format
        agentPrivateKey = agent.privateKey;
        await registry.register(agent.document);

        // Create the ledger key and construct the ActionRecorder
        // slice(0, 64): take the first 32 bytes (64 hex chars) as the seed key
        const ledger = generateKeyPair();
        recorder = new ActionRecorder(pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });

        // Write 3 records; save the first and last IDs for use by the individual tests
        for (let i = 0; i < 3; i++) {
            const result = await recorder.record({
                agentDid,
                principalDid: requesterDid,
                actionType: 'INQUIRY',
                parametersSummary: { index: i },
                authorizationRef: null,
                resultSummary: { status: 'SUCCESS' },
                actorPrivateKey: agentPrivateKey,
            });
            if (i === 0) {
                firstRecordId = result.recordId;
            }
            if (i === 2) {
                // Read the exact timestamp from the DB (timestamptz → ISO string)
                const row = await pool.query<{
                    record_id: string;
                    created_at: string;
                    record_hash: string;
                }>(
                    'SELECT record_id, created_at, record_hash FROM policy.action_records WHERE record_id = $1',
                    [result.recordId],
                );
                headRecordId = row.rows[0]!.record_id;
                // After the pg driver converts the timestamptz back, ISO-ize it again to stay consistent with the route side
                headCreatedAt = new Date(row.rows[0]!.created_at).toISOString();
                headRecordHash = row.rows[0]!.record_hash;
            }
        }

        // Start the HTTP test server (the createTestServer callback is not async; express is imported at the top level)
        const server = await createTestServer((app) => {
            app.use(express.json());
            registerActionRecordRoutes(app, {
                dbPool: pool,
                identityRegistry: registry,
                ledgerPublicKey: recorder.ledgerPublicKey,
            });
        });
        serverUrl = server.url;
        serverClose = server.close;
    });

    afterAll(async () => {
        await serverClose?.();
        await cleanup?.();
    });

    // ── Helper that builds the signed request headers ────────────────────────────────────────────
    // Bottom line: the signature payload uses the parsed camelCase queryParams (consistent with the parseQueryParams output)
    function makeHeaders(
        route:
            | 'records.list'
            | 'records.get'
            | 'records.verify'
            | 'records.chain.verify',
        recordId: string | null,
        rawQueryParams: Record<string, unknown> = {},
        overrides: {
            snapshotBoundary?: {
                headCreatedAt: string;
                headRecordId: string;
                headRecordHash?: string;
            };
            targetAgentDid?: string;
        } = {},
    ): Record<string, string> {
        const timestamp = new Date().toISOString();

        // snake_case URL parameters → camelCase AuditQueryParams (reproduces the parseQueryParams logic)
        const queryParams: Record<string, unknown> = {};
        if (rawQueryParams['agent_did'] !== undefined)
            queryParams['agentDid'] = rawQueryParams['agent_did'];
        if (rawQueryParams['principal_did'] !== undefined)
            queryParams['principalDid'] = rawQueryParams['principal_did'];
        if (rawQueryParams['action'] !== undefined)
            queryParams['action'] = rawQueryParams['action'];
        if (rawQueryParams['session_id'] !== undefined)
            queryParams['sessionId'] = rawQueryParams['session_id'];
        if (rawQueryParams['start'] !== undefined)
            queryParams['start'] = rawQueryParams['start'];
        if (rawQueryParams['end'] !== undefined)
            queryParams['end'] = rawQueryParams['end'];
        if (rawQueryParams['limit'] !== undefined)
            queryParams['limit'] = rawQueryParams['limit'];
        if (rawQueryParams['cursor'] !== undefined)
            queryParams['cursor'] = rawQueryParams['cursor'];

        const resourceBinding = { route, recordId };

        const snap = overrides.snapshotBoundary ?? {
            headCreatedAt,
            headRecordId,
            headRecordHash,
        };

        const signaturePayload = {
            requesterDid,
            targetAgentDid: overrides.targetAgentDid ?? agentDid,
            httpMethod: 'GET' as const,
            resourceBinding,
            queryParams,
            snapshotBoundary: snap,
            timestamp,
        };

        const msgBytes = new TextEncoder().encode(
            canonicalize(signaturePayload),
        );
        const signature = sign(msgBytes, requesterPrivateKey);

        const headers: Record<string, string> = {
            'x-audit-requester': requesterDid,
            'x-audit-signature': signature,
            'x-audit-timestamp': timestamp,
            'x-audit-snapshot-headcreatedat': snap.headCreatedAt,
            'x-audit-snapshot-headrecordid': snap.headRecordId,
        };
        if (snap.headRecordHash) {
            headers['x-audit-snapshot-headrecordhash'] = snap.headRecordHash;
        }
        return headers;
    }

    // ── GET /ledger/head ─────────────────────────────────────────────────────

    it('should return head record info when GET /ledger/head with valid agent_did', async () => {
        const res = await httpGet(serverUrl, '/ledger/head', {
            queryString: `agent_did=${agentDid}`,
        });
        expect(res.status).toBe(200);
        const body = res.body as Record<string, unknown>;
        expect(body['agentDid']).toBe(agentDid);
        expect(body['headRecordId']).toBe(headRecordId);
        expect(body['headCreatedAt']).toBe(headCreatedAt);
        expect(body['headRecordHash']).toBe(headRecordHash);
    });

    it('should return 404 from /ledger/head when agent does not exist', async () => {
        const res = await httpGet(serverUrl, '/ledger/head', {
            queryString:
                'agent_did=did:agent:0000000000000000000000000000000000000000',
        });
        expect(res.status).toBe(404);
    });

    // ── GET /records ─────────────────────────────────────────────────────────

    it('should list all 3 records when GET /records with valid signature', async () => {
        const headers = makeHeaders('records.list', null, {
            agent_did: agentDid,
        });
        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });
        expect(res.status).toBe(200);
        const body = res.body as {
            records: Array<Record<string, unknown>>;
            nextCursor?: string;
        };
        expect(body.records).toHaveLength(3);
        expect(body.records[0]).toHaveProperty('recordId');
        expect(body.records[0]).toHaveProperty('agentDid', agentDid);
        // _internalId is not exposed externally
        expect(body.records[0]).not.toHaveProperty('_internalId');
    });

    it('should respect limit parameter when GET /records with limit=2', async () => {
        const headers = makeHeaders('records.list', null, {
            agent_did: agentDid,
            limit: 2,
        });
        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}&limit=2`,
            headers,
        });
        expect(res.status).toBe(200);
        const body = res.body as { records: unknown[]; nextCursor?: string };
        expect(body.records).toHaveLength(2);
        expect(body.nextCursor).toBeDefined();
    });

    // ── GET /records/:id ─────────────────────────────────────────────────────

    it('should fetch single record when GET /records/:id with valid signature', async () => {
        const headers = makeHeaders('records.get', firstRecordId);
        const res = await httpGet(serverUrl, `/records/${firstRecordId}`, {
            headers,
        });
        expect(res.status).toBe(200);
        const body = res.body as Record<string, unknown>;
        expect(body['recordId']).toBe(firstRecordId);
        expect(body['agentDid']).toBe(agentDid);
    });

    // ── GET /records/:id/verify ───────────────────────────────────────────────

    it('should verify single record signature when GET /records/:id/verify', async () => {
        // The route returns `{ valid, checks: [...] }`, without the partialVerification field (removed).
        // This route was injected with recorder.ledgerPublicKey;
        // all three checks pass on the happy path, so the overall valid=true.
        const headers = makeHeaders('records.verify', firstRecordId);
        const res = await httpGet(
            serverUrl,
            `/records/${firstRecordId}/verify`,
            { headers },
        );
        expect(res.status).toBe(200);
        const body = res.body as {
            valid: boolean;
            checks: Array<{ name: string; valid: boolean }>;
        };
        expect(body.valid).toBe(true);
        expect(
            (body as Record<string, unknown>)['partialVerification'],
        ).toBeUndefined();

        const hashCheck = body.checks.find((c) => c.name === 'record_hash');
        expect(hashCheck?.valid).toBe(true);

        const actorCheck = body.checks.find(
            (c) => c.name === 'actor_signature',
        );
        expect(actorCheck?.valid).toBe(true);

        const ledgerCheck = body.checks.find(
            (c) => c.name === 'ledger_signature',
        );
        expect(ledgerCheck?.valid).toBe(true);
    });

    // ── GET /records/chain/verify ─────────────────────────────────────────────

    it('should verify chain integrity when GET /records/chain/verify', async () => {
        const headers = makeHeaders('records.chain.verify', null, {
            agent_did: agentDid,
        });
        const res = await httpGet(serverUrl, '/records/chain/verify', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });
        expect(res.status).toBe(200);
        const body = res.body as { valid: boolean; recordCount: number };
        expect(body.valid).toBe(true);
        expect(body.recordCount).toBe(3);
    });

    // ── Security assertion 1: snapshot boundary ─────────────────────────────────────────────────

    it('should not see post-snapshot records when snapshot boundary is applied', async () => {
        // Write a 4th record after the snapshot capture point
        await recorder.record({
            agentDid,
            principalDid: requesterDid,
            actionType: 'CONFIRM',
            parametersSummary: { post: true },
            authorizationRef: null,
            resultSummary: null,
            actorPrivateKey: agentPrivateKey,
        });

        // Request with the original snapshot boundary — should still see only 3 records
        const headers = makeHeaders('records.list', null, {
            agent_did: agentDid,
        });
        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });
        expect(res.status).toBe(200);
        const body = res.body as { records: unknown[] };
        expect(body.records).toHaveLength(3); // the 4th record is not visible
    });

    // ── Security assertion 2: cross-agent access → 403 ─────────────────────────────────────

    it('should deny access to other agent records with AUDIT_FORBIDDEN', async () => {
        // Create a second agent (a different principal)
        const other = generateKeyPair();
        const otherPrincipalDid = didKeyFromPublicKey(
            Buffer.from(other.publicKey, 'hex'),
        );
        const otherAgent = createAgentIdentity({
            principalDid: otherPrincipalDid,
            principalPrivateKey: other.privateKey,
        });
        await registry.register(otherAgent.document);
        const otherAgentDid = otherAgent.document.id;

        // Write a record for the other agent
        await recorder.record({
            agentDid: otherAgentDid,
            principalDid: otherPrincipalDid,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            actorPrivateKey: otherAgent.privateKey,
        });

        // Get the otherAgent's snapshot anchor from /ledger/head
        const headRes = await httpGet(serverUrl, '/ledger/head', {
            queryString: `agent_did=${otherAgentDid}`,
        });
        const headBody = headRes.body as {
            headRecordId: string;
            headCreatedAt: string;
            headRecordHash: string;
        };
        const otherHead = {
            headRecordId: headBody.headRecordId,
            headCreatedAt: headBody.headCreatedAt,
            headRecordHash: headBody.headRecordHash,
        };

        // Attempt to access agentB's records using agentA's principal (requesterDid)
        const headers = makeHeaders(
            'records.list',
            null,
            { agent_did: otherAgentDid },
            { targetAgentDid: otherAgentDid, snapshotBoundary: otherHead },
        );

        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${otherAgentDid}`,
            headers,
        });

        expect(res.status).toBe(403);
        const body = res.body as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_FORBIDDEN');
    });

    // ── Security assertion 3: same-signature replay within the 300s window (known limitation) ──────────────────────────

    // Known limitation: the audit middleware only validates the ±300s time window and has no nonce
    // table, so the same signature can be successfully replayed within the window. This is an
    // explicit v0.1 convention, and this test serves to lock in the contract — if nonce protection
    // is introduced in the future, this case must be updated accordingly.
    it('should accept replay of same signature within 300s window when no nonce store', async () => {
        const headers = makeHeaders('records.list', null, {
            agent_did: agentDid,
        });

        const first = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });
        expect(first.status).toBe(200);

        // Submit the exact same headers again (same timestamp, same signature, same snapshotBoundary)
        const replay = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });
        expect(replay.status).toBe(200); // known limitation: the current implementation accepts replays
    });

    // ── Security assertion 4: unknown query parameter → 400 ──────────────────────────────────────

    it('should reject unknown query params with AUDIT_QUERY_MALFORMED', async () => {
        // parseQueryParams runs before signature verification,
        // so an unknown parameter returns 400 directly before signature checking (the signature content does not include the inject parameter)
        // inject is not an allowed query parameter
        const headers = makeHeaders('records.list', null, {});

        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}&inject=extra`,
            headers,
        });

        expect(res.status).toBe(400);
        const body = res.body as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    // ── Security assertion 5: ISO 8601 regex contract (UTC milliseconds) ──────────────────────────

    // Requires the timestamp to be byte-equivalent to toISOString().
    // Any deviation (missing milliseconds, ±HH:MM offset, lowercase z) should be blocked as 400 at
    // Step 1.5, before signature checking (Step 10), preventing NaN from bypassing the ±300s
    // replay-protection / ordering checks.

    // Note: the signature itself will not pass (we tampered with the header), but the 400 is returned
    // before the 401, so asserting code=AUDIT_QUERY_MALFORMED proves the regex is in effect.
    it('should reject AUDIT_QUERY_MALFORMED when X-Audit-Timestamp lacks milliseconds', async () => {
        const headers = makeHeaders('records.list', null, {
            agent_did: agentDid,
        });
        headers['x-audit-timestamp'] = '2026-04-18T12:34:56Z'; // missing .sss

        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });

        expect(res.status).toBe(400);
        const body = res.body as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });

    it('should reject AUDIT_QUERY_MALFORMED when X-Audit-Timestamp uses non-UTC offset', async () => {
        const headers = makeHeaders('records.list', null, {
            agent_did: agentDid,
        });
        headers['x-audit-timestamp'] = '2026-04-18T12:34:56.789+08:00'; // not Z

        const res = await httpGet(serverUrl, '/records', {
            queryString: `agent_did=${agentDid}`,
            headers,
        });

        expect(res.status).toBe(400);
        const body = res.body as { error: { code: string } };
        expect(body.error.code).toBe('AUDIT_QUERY_MALFORMED');
    });
});
