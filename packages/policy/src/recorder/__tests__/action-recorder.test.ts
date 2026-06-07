import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '@coivitas/identity';
import { createTestDatabase } from '@coivitas/shared';
import type { DID, Signature, Timestamp } from '@coivitas/types';

import { ActionRecorder } from '../../index.js';
import {
    buildUnsignedRecordPayload,
    computeRecordHash,
    createRecordSignature,
    derivePublicKeyFromPrivateKey,
    normalizeSigningPrivateKey,
    toPersistedRecord,
    verifyRecordSignature,
} from '../shared.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

function makeTestPayload(recordId: string): Record<string, unknown> {
    return buildUnsignedRecordPayload({
        recordId,
        agentDid: 'did:key:agent' as DID,
        principalDid: 'did:key:principal' as DID,
        actionType: 'INQUIRY',
        parametersSummary: null,
        authorizationRef: null,
        resultSummary: null,
        previousRecordHash: '',
        createdAt: '2024-01-01T00:00:00Z' as Timestamp,
    });
}

describeIfDatabase('ActionRecorder', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let recorder: ActionRecorder;
    let agentDid: DID;
    let agentPrivateKey: string;
    let principalDid: DID;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;

        const registry = new IdentityRegistry(database.pool);
        const principal = generateKeyPair();
        principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const agent = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        agentDid = agent.document.id;
        agentPrivateKey = agent.privateKey;
        await registry.register(agent.document);

        const ledger = generateKeyPair();
        recorder = new ActionRecorder(database.pool, {
            kind: 'standard',
            ledgerPrivateKey: ledger.privateKey.slice(0, 64),
        });
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('writes records and returns record id plus hash', async () => {
        const result = await recorder.record({
            agentDid: agentDid as never,
            principalDid: principalDid as never,
            actionType: 'INQUIRY',
            parametersSummary: { product: 'laptop' },
            resultSummary: { status: 'SUCCESS' },
            actorPrivateKey: agentPrivateKey,
        });

        expect(result.recordId).toBeTruthy();
        // LEDGER_ENCODING defaults to base64url → 43 char;
        // the historical 64-char expectation was based on the earlier hex default.
        expect(result.hash).toHaveLength(43);
    });

    it('supports filtered queries ordered by created_at', async () => {
        await recorder.record({
            agentDid: agentDid as never,
            principalDid: principalDid as never,
            actionType: 'QUOTE',
            parametersSummary: { amount: 100 },
            authorizationRef: { tokenId: 'token-1' },
            resultSummary: { ok: true },
            actorPrivateKey: agentPrivateKey,
        });

        const { records } = await recorder.query({
            agentDid: agentDid as never,
            actionType: 'QUOTE',
            limit: 10,
        });

        expect(records.length).toBeGreaterThanOrEqual(1);
        expect(records.every((record) => record.actionType === 'QUOTE')).toBe(
            true,
        );
    });
});

describe('normalizeSigningPrivateKey and derivePublicKeyFromPrivateKey', () => {
    it('should expand 64-char seed to 128-char expanded key', () => {
        const keyPair = generateKeyPair();
        // generateKeyPair already returns a 128-char expanded key; take the first 64 chars as the seed
        const seed = keyPair.privateKey.slice(0, 64);
        const normalized = normalizeSigningPrivateKey(seed);
        expect(normalized).toHaveLength(128);
        // The last 64 chars after expansion are the public key, which should match keyPair.publicKey
        expect(normalized.slice(64)).toBe(keyPair.publicKey);
    });

    it('should return 128-char key unchanged when already expanded', () => {
        const keyPair = generateKeyPair();
        const normalized = normalizeSigningPrivateKey(keyPair.privateKey);
        expect(normalized).toBe(keyPair.privateKey);
    });

    it('should derive public key from 128-char expanded private key', () => {
        const keyPair = generateKeyPair();
        const derived = derivePublicKeyFromPrivateKey(keyPair.privateKey);
        expect(derived).toBe(keyPair.publicKey);
    });

    it('should derive public key from 64-char seed', () => {
        const keyPair = generateKeyPair();
        const seed = keyPair.privateKey.slice(0, 64);
        const derived = derivePublicKeyFromPrivateKey(seed);
        expect(derived).toBe(keyPair.publicKey);
    });
});

describe('dual-signature verification', () => {
    it('should produce actor signature verifiable with actor public key', () => {
        const actorKeyPair = generateKeyPair();
        const payload = makeTestPayload('rec-1');
        const sig = createRecordSignature(payload, actorKeyPair.privateKey);
        expect(
            verifyRecordSignature(payload, sig, actorKeyPair.publicKey),
        ).toBe(true);
    });

    it('should produce different signatures for actor and ledger keys', () => {
        const actorKeyPair = generateKeyPair();
        const ledgerKeyPair = generateKeyPair();
        const payload = makeTestPayload('rec-2');
        const actorSig = createRecordSignature(
            payload,
            actorKeyPair.privateKey,
        );
        const ledgerSig = createRecordSignature(
            payload,
            ledgerKeyPair.privateKey,
        );
        expect(actorSig).not.toBe(ledgerSig);
    });

    it('should reject tampered payload', () => {
        const actorKeyPair = generateKeyPair();
        const payload = makeTestPayload('rec-3');
        const sig = createRecordSignature(payload, actorKeyPair.privateKey);
        const tampered = { ...payload, actionType: 'QUOTE' };
        expect(
            verifyRecordSignature(tampered, sig, actorKeyPair.publicKey),
        ).toBe(false);
    });
});

describe('delegationDepth and sessionId fields', () => {
    it('should preserve delegationDepth when provided', () => {
        const actorSig = 'a'.repeat(128) as Signature;
        const ledgerSig = 'b'.repeat(128) as Signature;

        const record = toPersistedRecord({
            recordId: 'rec-ds-1',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            recordHash: 'hash123',
            actorSignature: actorSig,
            ledgerSignature: ledgerSig,
            delegationDepth: 2,
            sessionId: 'session-abc',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });

        expect(record.delegationDepth).toBe(2);
    });

    it('should preserve sessionId when provided', () => {
        const actorSig = 'a'.repeat(128) as Signature;
        const ledgerSig = 'b'.repeat(128) as Signature;

        const record = toPersistedRecord({
            recordId: 'rec-ds-1b',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            recordHash: 'hash123b',
            actorSignature: actorSig,
            ledgerSignature: ledgerSig,
            delegationDepth: 2,
            sessionId: 'session-abc',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });

        expect(record.sessionId).toBe('session-abc');
    });

    it('should have delegationDepth as undefined when not provided', () => {
        const actorSig = 'a'.repeat(128) as Signature;
        const ledgerSig = 'b'.repeat(128) as Signature;

        const record = toPersistedRecord({
            recordId: 'rec-ds-2',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            recordHash: 'hash456',
            actorSignature: actorSig,
            ledgerSignature: ledgerSig,
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });

        expect(record.delegationDepth).toBeUndefined();
    });

    it('should have sessionId as undefined when not provided', () => {
        const actorSig = 'a'.repeat(128) as Signature;
        const ledgerSig = 'b'.repeat(128) as Signature;

        const record = toPersistedRecord({
            recordId: 'rec-ds-2b',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            recordHash: 'hash456b',
            actorSignature: actorSig,
            ledgerSignature: ledgerSig,
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });

        expect(record.sessionId).toBeUndefined();
    });
});

describe('delegationDepth/sessionId included in the signing payload', () => {
    it('should include delegationDepth in unsigned payload when provided', () => {
        const base = buildUnsignedRecordPayload({
            recordId: 'rec-p1-1',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });
        const withDepth = buildUnsignedRecordPayload({
            recordId: 'rec-p1-1',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
            delegationDepth: 2,
        });
        expect(withDepth['delegationDepth']).toBe(2);
        expect(base['delegationDepth']).toBeUndefined();
        // The two payloads differ, so the signatures differ
        const kp = generateKeyPair();
        const sigBase = createRecordSignature(base, kp.privateKey);
        const sigDepth = createRecordSignature(withDepth, kp.privateKey);
        expect(sigBase).not.toBe(sigDepth);
    });

    it('should include sessionId in unsigned payload when provided', () => {
        const base = buildUnsignedRecordPayload({
            recordId: 'rec-p1-2',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });
        const withSession = buildUnsignedRecordPayload({
            recordId: 'rec-p1-2',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
            sessionId: 'sess-xyz',
        });
        expect(withSession['sessionId']).toBe('sess-xyz');
        expect(base['sessionId']).toBeUndefined();
        const kp = generateKeyPair();
        const sigBase = createRecordSignature(base, kp.privateKey);
        const sigSession = createRecordSignature(withSession, kp.privateKey);
        expect(sigBase).not.toBe(sigSession);
    });

    it('should not include delegationDepth key when undefined', () => {
        const payload = buildUnsignedRecordPayload({
            recordId: 'rec-p1-3',
            agentDid: 'did:key:agent' as DID,
            principalDid: 'did:key:principal' as DID,
            actionType: 'INQUIRY',
            parametersSummary: null,
            authorizationRef: null,
            resultSummary: null,
            previousRecordHash: '',
            createdAt: '2024-01-01T00:00:00Z' as Timestamp,
        });
        expect(
            Object.prototype.hasOwnProperty.call(payload, 'delegationDepth'),
        ).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(payload, 'sessionId')).toBe(
            false,
        );
    });
});

describe('base64url encoding output', () => {
    it('should produce 128-char hex signature by default', () => {
        const keyPair = generateKeyPair();
        const payload = makeTestPayload('rec-enc-1');
        const sig = createRecordSignature(payload, keyPair.privateKey);
        expect(sig).toHaveLength(128);
        expect(sig).toMatch(/^[0-9a-f]+$/);
    });

    it('should produce base64url signature when outputEncoding is base64url', () => {
        const keyPair = generateKeyPair();
        const payload = makeTestPayload('rec-enc-2');
        const sig = createRecordSignature(
            payload,
            keyPair.privateKey,
            'base64url',
        );
        // Ed25519 signature is 64 bytes; base64url without padding = 86 characters
        expect(sig).toHaveLength(86);
        expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce 64-char hex record hash by default', () => {
        const payload = makeTestPayload('rec-enc-3');
        const h = computeRecordHash(payload, '');
        expect(h).toHaveLength(64);
        expect(h).toMatch(/^[0-9a-f]+$/);
    });

    it('should produce base64url record hash when outputEncoding is base64url', () => {
        const payload = makeTestPayload('rec-enc-4');
        const h = computeRecordHash(payload, '', 'base64url');
        // SHA-256 = 32 bytes; base64url without padding = 43 characters
        expect(h).toHaveLength(43);
        expect(h).toMatch(/^[A-Za-z0-9_-]+$/);
    });
});
