import { generateKeyPair } from '@coivitas/crypto';
import {
    extractPublicKeyFromDIDKey,
    resolveAgentDID,
} from '@coivitas/identity';
import { createApp, createPool } from '@coivitas/shared';
import type { DatabasePool } from '@coivitas/shared';
import type { DID } from '@coivitas/types';
import {
    IdentityRegistry,
    registerIdentityRoutes,
    registerRevocationRoutes,
    RevocationList,
} from '@coivitas/identity';

export async function resolveDemoPublicKey(
    did: DID,
    identityRegistryUrl: string,
): Promise<string | null> {
    if (did.startsWith('did:key:')) {
        return extractPublicKeyFromDIDKey(did);
    }

    const document = await resolveAgentDID(did, identityRegistryUrl);
    return document?.publicKey ?? null;
}

export function ensureLedgerPrivateKey(ledgerPrivateKey?: string): string {
    return ledgerPrivateKey ?? generateKeyPair().privateKey.slice(0, 64);
}

export function ensurePool(pool?: DatabasePool): {
    pool: DatabasePool;
    ownPool: boolean;
} {
    if (pool) {
        return { pool, ownPool: false };
    }

    return {
        pool: createPool(),
        ownPool: true,
    };
}

export async function startLocalIdentityService(
    pool: DatabasePool,
): Promise<{ url: string; close: () => Promise<void> }> {
    const app = createApp();
    const registry = new IdentityRegistry(pool);
    const revocations = new RevocationList(pool);

    registerIdentityRoutes(app, registry);
    registerRevocationRoutes(app, revocations);

    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve, reject) => {
        server.once('listening', () => resolve());
        server.once('error', (error) => reject(error));
    });

    const address = server.address();
    if (!address || typeof address === 'string') {
        throw new Error('Identity service failed to bind to a local port.');
    }

    return {
        url: `http://127.0.0.1:${address.port}`,
        close: async () => {
            server.closeAllConnections?.();
            await new Promise<void>((resolve, reject) => {
                server.close((error) => {
                    if (error) {
                        reject(error);
                        return;
                    }
                    resolve();
                });
            });
        },
    };
}
