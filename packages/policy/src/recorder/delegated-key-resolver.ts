/**
 * NullDelegatedAuditKeyResolver — default implementation of the delegated audit key resolver
 *
 * It always returns null (fail-closed), making the delegatedAuditKeyId path
 * unavailable by default. It can be replaced by PostgresDelegatedAuditKeyResolver.
 *
 * Note: the DelegatedAuditKeyResolver interface is defined in @coivitas/types,
 * imported directly here to avoid a dual source of truth.
 */

import type { DelegatedAuditKeyResolver } from '@coivitas/types';

export type { DelegatedAuditKeyResolver };

/**
 * No-op implementation of the delegated audit key resolver.
 *
 * Always returns null — the delegated audit key path is not implemented by default.
 * Deployers may inject a custom implementation (such as PostgresDelegatedAuditKeyResolver).
 *
 */
export class NullDelegatedAuditKeyResolver implements DelegatedAuditKeyResolver {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public resolve(_keyId: string, _targetAgentDid: string): Promise<null> {
        return Promise.resolve(null);
    }
}
