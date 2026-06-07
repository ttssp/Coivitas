import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTestDatabase } from '@coivitas/shared';
import { generateKeyPair } from '@coivitas/crypto';
import type { AgentIdentityDocument, DID } from '@coivitas/types';

import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
} from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('IdentityRegistry', () => {
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

    it('registers and queries an active identity', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        await registry.register(identity.document);

        // query() injects version from SQL column; original document has no version field
        await expect(registry.query(identity.document.id)).resolves.toEqual(
            expect.objectContaining({ ...identity.document, version: 1 }),
        );
    });

    it('rejects duplicate identities', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        await registry.register(identity.document);

        await expect(
            registry.register(identity.document),
        ).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'IDENTITY_ALREADY_EXISTS',
        });
    });

    it('deactivates identities and hides them from query results', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        await registry.register(identity.document);
        await registry.deactivate(identity.document.id);
        await registry.deactivate(identity.document.id);

        await expect(registry.query(identity.document.id)).resolves.toBeNull();
    });

    it('should update document with version increment when using optimistic lock', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        // version=2 document (only tests optimistic-lock logic, no real rotation signature)
        const updatedDoc = { ...identity.document, version: 2 };
        await expect(registry.update(updatedDoc, 1)).resolves.toBeUndefined();

        // query should return the new document, with version injected from the SQL column
        const queried = await registry.query(identity.document.id);
        expect(queried?.version).toBe(2);
    });

    it('should reject update when expected version does not match DB version', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        const updatedDoc = { ...identity.document, version: 2 };
        // Pass the wrong expectedVersion=99 (DB has 1) -> VERSION_CONFLICT
        await expect(registry.update(updatedDoc, 99)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'VERSION_CONFLICT',
        });
    });

    it('should reject update when document.version is not expectedVersion + 1', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        // expectedVersion=1 (matches DB), but document.version=5 (not 2)
        const wrongVersionDoc = { ...identity.document, version: 5 };
        await expect(registry.update(wrongVersionDoc, 1)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'VERSION_CONFLICT',
        });
    });

    it('should throw IDENTITY_NOT_FOUND when updating non-existent DID', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });
        const updatedDoc = { ...identity.document, version: 2 };
        await expect(registry.update(updatedDoc, 1)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'IDENTITY_NOT_FOUND',
        });
    });

    it('should reject key rotation when rotationProof.oldPublicKey does not match stored publicKey', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        const newKeyPair = generateKeyPair();
        // Construct a document whose publicKey changed but whose rotationProof.oldPublicKey disagrees with the DB
        const tampered = {
            ...identity.document,
            version: 2,
            publicKey: newKeyPair.publicKey,
            rotationProof: {
                agentDid: identity.document.id,
                oldPublicKey: newKeyPair.publicKey, // intentionally wrong: inconsistent with the oldPublicKey currently stored in the DB
                newPublicKey: newKeyPair.publicKey,
                rotatedAt: new Date().toISOString(),
                oldKeySignature: 'deadbeef',
                newKeySignature: 'deadbeef',
                principalSignature: 'deadbeef',
            },
        };
        await expect(registry.update(tampered as AgentIdentityDocument, 1)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'BINDING_PROOF_INVALID',
        });
    });

    it('should throw IDENTITY_DEACTIVATED when updating deactivated identity', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);
        await registry.deactivate(identity.document.id);

        const updatedDoc = { ...identity.document, version: 2 };
        await expect(registry.update(updatedDoc, 1)).rejects.toMatchObject({
            name: 'ProtocolError',
            code: 'IDENTITY_DEACTIVATED',
        });
    });

    it('should return document history ordered by version descending when multiple rotations occurred', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        // First update: version 1 -> 2
        const v2Doc = { ...identity.document, version: 2 };
        await registry.update(v2Doc, 1);

        // Second update: version 2 -> 3 (the v1 snapshot is lost; the schema keeps only the most recent layer)
        const v3Doc = { ...identity.document, version: 3 };
        await registry.update(v3Doc, 2);

        const history = await registry.getDocumentHistory(identity.document.id);
        // Schema constraint: keep only the current document (v3) + the previous-version snapshot (v2), 2 entries total
        expect(history).toHaveLength(2);
        expect(history[0]!.version).toBe(3);
        expect(history[1]!.version).toBe(2);
    });

    it('should return single document when no rotation has occurred', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(Buffer.from(principal.publicKey, 'hex'));
        const identity = createAgentIdentity({ principalDid, principalPrivateKey: principal.privateKey });

        await registry.register(identity.document);

        const history = await registry.getDocumentHistory(identity.document.id);
        expect(history).toHaveLength(1);
        expect(history[0]!.version).toBe(1);
    });

    it('should return empty array for non-existent DID in getDocumentHistory', async () => {
        const history = await registry.getDocumentHistory(
            'did:agent:0000000000000000000000000000000000000000' as DID,
        );
        expect(history).toEqual([]);
    });
});
