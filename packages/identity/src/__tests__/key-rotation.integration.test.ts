/**
 * Key rotation Registry integration test
 *
 * Full flow:
 *   1. createAgentIdentity -> register()
 *   2. initiateKeyRotation -> completeKeyRotation -> update() (version 1->2)
 *   3. query() returns the new-key document (version=2)
 *   4. resolvePublicKeys(ROTATING) -> the old key is valid within the Grace Period
 *   5. Simulate expiry: rotationStartedAt set to 25h ago -> resolvePublicKeys does not return previous
 *   6. After expiry, verifying the token with the old key -> SIGNATURE_INVALID
 *   7. Concurrent write: a second update with the same expectedVersion=1 -> VERSION_CONFLICT
 *   8. getDocumentHistory() returns the two versions [v2, v1]
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestDatabase } from '@coivitas/shared';
import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import type { DID, Signature, Timestamp } from '@coivitas/types';

import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    issueCapabilityToken,
    resolvePublicKeys,
    verifyCapabilityToken,
} from '../index.js';
import {
    completeKeyRotation,
    initiateKeyRotation,
} from '../key-rotation.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

function signRotationPayload(
    payload: { agentDid: string; newPublicKey: string; oldPublicKey: string; rotatedAt: string },
    privateKey: string,
): Signature {
    const bytes = new TextEncoder().encode(
        canonicalize({
            agentDid: payload.agentDid,
            newPublicKey: payload.newPublicKey,
            oldPublicKey: payload.oldPublicKey,
            rotatedAt: payload.rotatedAt,
        }),
    );
    return sign(bytes, privateKey) as Signature;
}

describeIfDatabase('key-rotation registry integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let registry: IdentityRegistry;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        registry = new IdentityRegistry(database.pool);
    });

    afterAll(async () => {
        await cleanup?.();
    });

    it('should complete full key rotation lifecycle with grace period enforcement', async () => {
        // Step 1: create the identity and register it
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY'],
        });
        const v1Doc = identity.document;
        const oldPrivateKey = identity.privateKey;
        const oldPublicKey = v1Doc.publicKey;

        await registry.register(v1Doc);

        // Step 2: initiate the rotation
        const newKeyPair = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = signRotationPayload(
            { agentDid: v1Doc.id, newPublicKey: newKeyPair.publicKey, oldPublicKey, rotatedAt },
            principal.privateKey,
        );
        const rotatingDoc = initiateKeyRotation({
            currentDoc: v1Doc,
            currentPrivateKey: oldPrivateKey,
            newKeyPair,
            principalApproval,
            rotatedAt,
        });
        const v2Doc = completeKeyRotation(rotatingDoc);

        // Step 3: persist the v2 document (optimistic lock version 1->2)
        await registry.update(v2Doc, 1);

        // Step 4: query() should return the new-key document, with version injected from the SQL column
        const queried = await registry.query(v1Doc.id);
        expect(queried).not.toBeNull();
        expect(queried!.publicKey).toBe(newKeyPair.publicKey);
        expect(queried!.version).toBe(2);

        // Step 5a: the old key is valid within the Grace Period
        // rotatedAt was just generated, less than 24h ago, so the old key should be within the Grace Period
        const resolvedKeys = resolvePublicKeys(
            { document: queried!, rotationState: 'ROTATING', rotationStartedAt: rotatedAt },
            { gracePeriodMs: 24 * 60 * 60 * 1000 },
        );
        expect(resolvedKeys.previous).toBe(oldPublicKey);
        expect(resolvedKeys.current).toBe(newKeyPair.publicKey);

        // Issue a capability token with the old key (did:key format)
        const issuerDid = didKeyFromPublicKey(Buffer.from(oldPublicKey, 'hex'));
        const issuedAt = new Date(Date.now() - 1000).toISOString() as Timestamp;
        const tokenWithOldKey = issueCapabilityToken({
            issuerDid,
            issuedTo: 'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
            capabilities: [{
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'recipient', values: ['supplier-a'] },
            }],
            expiresAt: '2099-12-31T23:59:59.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: oldPrivateKey,
            issuedAt,
        });

        // A token signed with the old key within the Grace Period should verify successfully
        const verifyGracePeriod = verifyCapabilityToken(tokenWithOldKey, issuedAt, {
            ...resolvedKeys,
            previousValidBefore: rotatedAt,
        });
        expect(verifyGracePeriod.valid).toBe(true);

        // Step 5b: simulate Grace Period expiry (rotationStartedAt set to 25h ago)
        const expiredStartedAt = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString() as Timestamp;
        const expiredKeys = resolvePublicKeys(
            { document: queried!, rotationState: 'ROTATING', rotationStartedAt: expiredStartedAt },
        );
        expect(expiredKeys.previous).toBeUndefined();

        // Step 6: after the Grace Period expires, verifying the old-key token fails
        // ACTIVE -> STABLE (v0.3.0 state mapping); the version field has been removed from ResolvedPublicKeys
        const verifyExpired = verifyCapabilityToken(tokenWithOldKey, issuedAt, {
            current: newKeyPair.publicKey,
            rotationState: 'STABLE',
        });
        expect(verifyExpired.valid).toBe(false);
        expect(verifyExpired.code).toBe('SIGNATURE_INVALID');
    });

    it('should return version history [v2, v1] after one rotation', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });
        const v1Doc = identity.document;

        await registry.register(v1Doc);

        const newKeyPair = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = signRotationPayload(
            { agentDid: v1Doc.id, newPublicKey: newKeyPair.publicKey, oldPublicKey: v1Doc.publicKey, rotatedAt },
            principal.privateKey,
        );
        const v2Doc = completeKeyRotation(initiateKeyRotation({
            currentDoc: v1Doc,
            currentPrivateKey: identity.privateKey,
            newKeyPair,
            principalApproval,
            rotatedAt,
        }));
        await registry.update(v2Doc, 1);

        const history = await registry.getDocumentHistory(v1Doc.id);
        expect(history).toHaveLength(2);
        expect(history[0]!.version).toBe(2);
        expect(history[1]!.version).toBe(1);
    });

    it('should reject concurrent update with stale expectedVersion', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        const v2Doc = { ...identity.document, version: 2 };
        // First update succeeds (expectedVersion=1)
        await registry.update(v2Doc, 1);

        // Concurrent write: another update with expectedVersion=1 (now stale) -> VERSION_CONFLICT
        await expect(registry.update(v2Doc, 1)).rejects.toMatchObject({
            code: 'VERSION_CONFLICT',
        });
    });
});
