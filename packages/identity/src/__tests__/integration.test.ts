import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    createApp,
    createTestDatabase,
    createTestServer,
} from '@coivitas/shared';
import { generateKeyPair } from '@coivitas/crypto';

import {
    createAgentIdentity,
    didKeyFromPublicKey,
    IdentityRegistry,
    registerIdentityRoutes,
    resolveAgentDID,
    verifyBinding,
} from '../index.js';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('identity integration', () => {
    let cleanup: (() => Promise<void>) | undefined;
    let closeServer: (() => Promise<void>) | undefined;
    let registryUrl = '';
    let registry: IdentityRegistry;

    beforeAll(async () => {
        const database = await createTestDatabase();
        cleanup = database.cleanup;
        registry = new IdentityRegistry(database.pool);
        const app = createApp();
        registerIdentityRoutes(app, registry);
        const server = await createTestServer((testApp) => {
            registerIdentityRoutes(testApp, registry);
        });
        registryUrl = server.url;
        closeServer = server.close;
    });

    afterAll(async () => {
        await closeServer?.();
        await cleanup?.();
    });

    it('covers the principal-agent identity lifecycle with a real PostgreSQL registry', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
            capabilities: ['INQUIRY', 'QUOTE'],
        });

        expect(identity.document.principalDid).toBe(principalDid);
        expect(verifyBinding(identity.document.bindingProof)).toBe(true);

        await registry.register(identity.document);

        const resolved = await resolveAgentDID(
            identity.document.id,
            registryUrl,
        );
        expect(resolved).toEqual(identity.document);
        expect(verifyBinding(resolved!.bindingProof)).toBe(true);

        await registry.deactivate(identity.document.id);

        await expect(
            resolveAgentDID(identity.document.id, registryUrl),
        ).resolves.toBeNull();
    });
});
