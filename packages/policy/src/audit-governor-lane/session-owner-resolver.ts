/**
 * session-owner-resolver.ts -- sessionId -> owner DID reverse lookup.
 *
 * Background: the affected DID is caller-supplied data. Without a reverse session-binding
 * check, a caller can mismatch the DID so that the wrong requester sees the wrong data.
 *
 * This module provides the SessionOwnerResolver runtime implementation, which calls
 * resolveOwner and asserts a match before the control-plane recorder INSERT, throwing
 * fail-closed on a mismatch.
 *
 */

import { ProtocolError, type DID } from '@coivitas/types';

import type { SessionOwnerResolver } from './types.js';

// ---------------------------------------------------------------------------
// InMemorySessionOwnerResolver -- single-process in-memory implementation (tests + minimal viable deployment)
// ---------------------------------------------------------------------------

/**
 * In-memory SessionOwnerResolver.
 *
 * Production deployments should replace it with a PostgreSQL / SessionRegistry query implementation.
 * Provides a register() method for the SessionRegistry / handshake flow to register
 * session -> owner mappings.
 */
export class InMemorySessionOwnerResolver implements SessionOwnerResolver {
    private readonly store = new Map<
        string,
        { agentDid: DID; principalDid: DID }
    >();

    /**
     * Register a single sessionId -> owner mapping.
     * Idempotent: re-registering the same sessionId overwrites it.
     */
    public register(
        sessionId: string,
        owner: { agentDid: DID; principalDid: DID },
    ): void {
        this.store.set(sessionId, owner);
    }

    /**
     * Look up the session owner.
     * Returns null = sessionId does not exist.
     */
    public resolveOwner(
        sessionId: string,
    ): Promise<{ agentDid: DID; principalDid: DID } | null> {
        return Promise.resolve(this.store.get(sessionId) ?? null);
    }

    /** Internal: get the current number of stored entries (for tests). */
    public get size(): number {
        return this.store.size;
    }

    /** Internal: clear the store (for tests). */
    public clear(): void {
        this.store.clear();
    }
}

// ---------------------------------------------------------------------------
// assertSessionBinding -- assert affected DID matches the session owner before INSERT
// ---------------------------------------------------------------------------

/**
 * Before the control-plane recorder INSERT, asserts that the caller-supplied affected DID
 * matches the session's real owner.
 *
 * Mandatory match rules:
 * 1. resolveOwner(sessionId) -> { agentDid, principalDid }
 * 2. Assert params.affectedAgentDid === owner.agentDid
 *    && params.affectedPrincipalDid === owner.principalDid
 * 3. Mismatch -> throw ProtocolError('INTERNAL_ERROR') fail-closed
 *    (uses INTERNAL_ERROR + detail for disambiguation, error code reuse)
 * 4. resolveOwner returns null -> throw fail-closed
 *
 * @param resolver SessionOwnerResolver instance
 * @param sessionId ID of the old session being superseded
 * @param affectedAgentDid the affected agent DID supplied by the caller
 * @param affectedPrincipalDid the affected principal DID supplied by the caller
 * @throws ProtocolError('INTERNAL_ERROR') on a match failure or a nonexistent session
 */
export async function assertSessionBinding(
    resolver: SessionOwnerResolver,
    sessionId: string,
    affectedAgentDid: DID,
    affectedPrincipalDid: DID,
): Promise<void> {
    const owner = await resolver.resolveOwner(sessionId);

    if (owner === null) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `SESSION_BINDING_MISMATCH: sessionId '${sessionId}' not found in session registry. ` +
                `Cannot verify affected DID binding (fail-closed). ` +
                `(session binding contract).`,
        );
    }

    if ((affectedAgentDid as string) !== (owner.agentDid as string)) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `SESSION_BINDING_MISMATCH: affectedAgentDid='${affectedAgentDid}' ` +
                `does not match session owner agentDid='${owner.agentDid}' ` +
                `for sessionId='${sessionId}' (fail-closed). ` +
                `(session binding contract).`,
        );
    }

    if ((affectedPrincipalDid as string) !== (owner.principalDid as string)) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `SESSION_BINDING_MISMATCH: affectedPrincipalDid='${affectedPrincipalDid}' ` +
                `does not match session owner principalDid='${owner.principalDid}' ` +
                `for sessionId='${sessionId}' (fail-closed). ` +
                `(session binding contract).`,
        );
    }
}
