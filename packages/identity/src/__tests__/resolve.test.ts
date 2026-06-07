import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    createAgentIdentity,
    didKeyFromPublicKey,
    resolveAgentDID,
} from '../index.js';
import { generateKeyPair } from '@coivitas/crypto';

describe('resolveAgentDID', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    it('returns null for 404 responses', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(
                () =>
                    new Response(
                        JSON.stringify({
                            error: { code: 'IDENTITY_NOT_FOUND' },
                        }),
                        {
                            status: 404,
                            headers: { 'content-type': 'application/json' },
                        },
                    ),
            ),
        );

        const result = await resolveAgentDID(
            'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as never,
            'https://resolver.example.com',
        );
        expect(result).toBeNull();
    });

    it('loads the identity document over HTTP', async () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const identity = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        vi.stubGlobal(
            'fetch',
            vi.fn(
                () =>
                    new Response(JSON.stringify(identity.document), {
                        status: 200,
                        headers: { 'content-type': 'application/json' },
                    }),
            ),
        );

        const result = await resolveAgentDID(
            identity.document.id,
            'https://resolver.example.com',
        );
        expect(result).toEqual(identity.document);
    });

    it('wraps resolver failures in a ProtocolError with the URL', async () => {
        await expect(
            resolveAgentDID(
                'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as never,
                'http://127.0.0.1:1',
                50,
            ),
        ).rejects.toEqual(
            expect.objectContaining({
                name: 'ProtocolError',
                code: 'INTERNAL_ERROR',
            }),
        );
    });
});
