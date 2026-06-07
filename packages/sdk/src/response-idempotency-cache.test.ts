import { describe, expect, it } from 'vitest';

import type { DID } from '@coivitas/types';
import { generateKeyPair } from '@coivitas/crypto';

import {
    InMemoryResponseIdempotencyCache,
    rebuildEnvelopeFromSpec,
    type CachedResponseSpec,
    type IdempotencyKey,
} from './orchestrator.js';

// Unit tests for the InMemoryResponseIdempotencyCache +
// rebuildEnvelopeFromSpec reference implementations. Covers check/record
// idempotency, TTL expiry cleanup, sessionId=null normalization, the four
// key dimensions (recipientDid / senderDid / sessionId / envelopeId), and
// that the rebuild helper produces the correct envelope for each of the 5
// kinds (SUCCESS / AUTHORIZATION_INSUFFICIENT / IDENTITY_VERIFICATION_FAILED /
// INVALID_ENVELOPE / INTERNAL_ERROR).

function makeSuccessSpec(marker: string): CachedResponseSpec {
    return {
        kind: 'SUCCESS',
        agentDid: 'did:agent:recipient-stub' as DID,
        originalSenderDid: 'did:agent:sender-stub' as DID,
        sessionId: null,
        requestId: `req-${marker}`,
        action: 'PING',
        data: { marker },
        recordId: `record-${marker}`,
    };
}

const recipientA = 'did:agent:recipient-aaa' as DID;
const senderA = 'did:agent:sender-aaa' as DID;

describe('InMemoryResponseIdempotencyCache', () => {
    it('returns null on miss and cached spec on hit', async () => {
        const cache = new InMemoryResponseIdempotencyCache();
        const key: IdempotencyKey = {
            recipientDid: recipientA,
            senderDid: senderA,
            sessionId: 'sess-1',
            envelopeId: 'env-1',
        };

        expect(await cache.check(key)).toBeNull();

        const spec = makeSuccessSpec('resp-1');
        await cache.record(key, spec);

        const hit = await cache.check(key);
        expect(hit).toBe(spec);
    });

    it('treats sessionId null and empty-string as collapsed keys (consistent normalization)', async () => {
        const cache = new InMemoryResponseIdempotencyCache();
        const nullKey: IdempotencyKey = {
            recipientDid: recipientA,
            senderDid: senderA,
            sessionId: null,
            envelopeId: 'env-same',
        };
        const emptyKey: IdempotencyKey = {
            recipientDid: recipientA,
            senderDid: senderA,
            sessionId: '',
            envelopeId: 'env-same',
        };

        const specNull = makeSuccessSpec('null');
        const specEmpty = makeSuccessSpec('empty');
        await cache.record(nullKey, specNull);
        await cache.record(emptyKey, specEmpty);

        // buildKey uses `sessionId ?? ''`: null and '' land on the same key, so the later write overwrites the earlier one.
        expect(await cache.check(nullKey)).toBe(specEmpty);
        expect(await cache.check(emptyKey)).toBe(specEmpty);
    });

    it('expires entries after TTL', async () => {
        const cache = new InMemoryResponseIdempotencyCache({ ttlMs: 1 });
        const key: IdempotencyKey = {
            recipientDid: recipientA,
            senderDid: senderA,
            sessionId: 'sess-1',
            envelopeId: 'env-1',
        };
        await cache.record(key, makeSuccessSpec('resp-1'));

        // Wait for the TTL to expire
        await new Promise((r) => setTimeout(r, 10));

        expect(await cache.check(key)).toBeNull();
    });

    it('differentiates keys by recipientDid / senderDid / sessionId / envelopeId', async () => {
        const cache = new InMemoryResponseIdempotencyCache();
        const base: IdempotencyKey = {
            recipientDid: recipientA,
            senderDid: senderA,
            sessionId: 'sess-1',
            envelopeId: 'env-1',
        };
        await cache.record(base, makeSuccessSpec('base'));

        // Baseline assertion: the same key must HIT
        expect(await cache.check(base)).not.toBeNull();

        // Key assertion: a recipientDid difference must cause a MISS (the strong-isolation dimension for a shared backend)
        expect(
            await cache.check({
                ...base,
                recipientDid: 'did:agent:recipient-bbb' as DID,
            }),
        ).toBeNull();

        // The remaining dimension differences still hold
        expect(
            await cache.check({
                ...base,
                senderDid: 'did:agent:sender-bbb' as DID,
            }),
        ).toBeNull();
        expect(
            await cache.check({ ...base, sessionId: 'sess-2' }),
        ).toBeNull();
        expect(
            await cache.check({ ...base, envelopeId: 'env-2' }),
        ).toBeNull();
    });
});

describe('rebuildEnvelopeFromSpec', () => {
    // buildEnvelope / buildErrorEnvelope need a valid Ed25519 private key to sign.
    const keyPair = generateKeyPair() as {
        publicKey: string;
        privateKey: string;
    };
    const agentDid = 'did:agent:recipient-rebuild' as DID;
    const originalSenderDid = 'did:agent:sender-rebuild' as DID;

    it('rebuilds SUCCESS envelope with fresh timestamp + signature', () => {
        const spec: CachedResponseSpec = {
            kind: 'SUCCESS',
            agentDid,
            originalSenderDid,
            sessionId: 'sess-rebuild',
            requestId: 'req-1',
            action: 'PING',
            data: { hello: 'world' },
            recordId: 'record-1',
            sequenceNumber: 42,
        };
        const env1 = rebuildEnvelopeFromSpec(spec, keyPair.privateKey);
        const env2 = rebuildEnvelopeFromSpec(spec, keyPair.privateKey);

        expect(env1.messageType).toBe('NEGOTIATION_RESPONSE');
        expect(env1.header.senderDid).toBe(agentDid);
        expect(env1.header.recipientDid).toBe(originalSenderDid);
        expect(env1.header.sessionId).toBe('sess-rebuild');
        expect(env1.body).toMatchObject({
            requestId: 'req-1',
            action: 'PING',
            status: 'SUCCESS',
            data: { hello: 'world' },
            recordId: 'record-1',
        });
        // Each rebuild's signature + timestamp is "fresh" — not a byte-level replay.
        // Signatures may occasionally match when called within the same millisecond, but the id is newly generated each time.
        expect(env1.id).not.toBe(env2.id);
    });

    it('rebuilds AUTHORIZATION_INSUFFICIENT envelope', () => {
        const spec: CachedResponseSpec = {
            kind: 'AUTHORIZATION_INSUFFICIENT',
            agentDid,
            originalSenderDid,
            sessionId: null,
            relatedEnvelopeId: 'original-env-id',
            message: 'scope denied',
        };
        const env = rebuildEnvelopeFromSpec(spec, keyPair.privateKey);
        expect(env.messageType).toBe('ERROR');
        expect((env.body as { code: string }).code).toBe(
            'AUTHORIZATION_INSUFFICIENT',
        );
        expect((env.body as { message: string }).message).toBe('scope denied');
    });

    it('rebuilds IDENTITY_VERIFICATION_FAILED envelope', () => {
        const spec: CachedResponseSpec = {
            kind: 'IDENTITY_VERIFICATION_FAILED',
            agentDid,
            originalSenderDid,
            sessionId: null,
            relatedEnvelopeId: 'original-env-id',
            message: 'signature invalid',
        };
        const env = rebuildEnvelopeFromSpec(spec, keyPair.privateKey);
        expect((env.body as { code: string }).code).toBe(
            'IDENTITY_VERIFICATION_FAILED',
        );
    });

    it('rebuilds INVALID_ENVELOPE envelope', () => {
        const spec: CachedResponseSpec = {
            kind: 'INVALID_ENVELOPE',
            agentDid,
            originalSenderDid,
            sessionId: null,
            message: 'unparsable',
        };
        const env = rebuildEnvelopeFromSpec(spec, keyPair.privateKey);
        expect((env.body as { code: string }).code).toBe('INVALID_ENVELOPE');
    });

    it('rebuilds INTERNAL_ERROR envelope', () => {
        const spec: CachedResponseSpec = {
            kind: 'INTERNAL_ERROR',
            agentDid,
            originalSenderDid,
            sessionId: null,
            relatedEnvelopeId: 'original-env-id',
            message: 'audit write failed',
        };
        const env = rebuildEnvelopeFromSpec(spec, keyPair.privateKey);
        expect((env.body as { code: string }).code).toBe('INTERNAL_ERROR');
    });
});
