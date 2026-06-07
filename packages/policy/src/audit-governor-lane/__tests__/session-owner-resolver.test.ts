/**
 * SessionOwnerResolver + assertSessionBinding unit tests.
 *
 * Coverage:
 * - InMemorySessionOwnerResolver register / look up / overwrite / clear
 * - assertSessionBinding happy path
 * - assertSessionBinding session not found -> fail-closed
 * - assertSessionBinding agentDid mismatch -> fail-closed
 * - assertSessionBinding principalDid mismatch -> fail-closed
 *
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { DID } from '@coivitas/types';

import {
    InMemorySessionOwnerResolver,
    assertSessionBinding,
} from '../session-owner-resolver.js';

const AGENT_DID = 'did:agent:test-agent-001' as DID;
const PRINCIPAL_DID = 'did:key:z6MkpTHR8VNs5xA...' as DID;
const OTHER_AGENT_DID = 'did:agent:other-agent' as DID;
const OTHER_PRINCIPAL_DID = 'did:key:z6MkOtherKey...' as DID;
const SESSION_ID = 'session-abc-123';

describe('InMemorySessionOwnerResolver', () => {
    let resolver: InMemorySessionOwnerResolver;

    beforeEach(() => {
        resolver = new InMemorySessionOwnerResolver();
    });

    it('should return null when sessionId is not registered', async () => {
        const result = await resolver.resolveOwner('non-existent');
        expect(result).toBeNull();
    });

    it('should resolve registered session owner', async () => {
        resolver.register(SESSION_ID, {
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });

        const result = await resolver.resolveOwner(SESSION_ID);
        expect(result).toEqual({
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });
    });

    it('should overwrite on duplicate register (idempotent)', async () => {
        resolver.register(SESSION_ID, {
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });
        resolver.register(SESSION_ID, {
            agentDid: OTHER_AGENT_DID,
            principalDid: OTHER_PRINCIPAL_DID,
        });

        const result = await resolver.resolveOwner(SESSION_ID);
        expect(result).toEqual({
            agentDid: OTHER_AGENT_DID,
            principalDid: OTHER_PRINCIPAL_DID,
        });
    });

    it('should report correct size', () => {
        expect(resolver.size).toBe(0);
        resolver.register('s1', {
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });
        expect(resolver.size).toBe(1);
        resolver.register('s2', {
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });
        expect(resolver.size).toBe(2);
    });

    it('should clear all entries', () => {
        resolver.register('s1', {
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });
        resolver.clear();
        expect(resolver.size).toBe(0);
    });
});

describe('assertSessionBinding', () => {
    let resolver: InMemorySessionOwnerResolver;

    beforeEach(() => {
        resolver = new InMemorySessionOwnerResolver();
        resolver.register(SESSION_ID, {
            agentDid: AGENT_DID,
            principalDid: PRINCIPAL_DID,
        });
    });

    it('should pass when affected DIDs match session owner', async () => {
        // happy path -- no throw
        await assertSessionBinding(
            resolver,
            SESSION_ID,
            AGENT_DID,
            PRINCIPAL_DID,
        );
    });

    it('should throw fail-closed when session not found', async () => {
        await expect(
            assertSessionBinding(
                resolver,
                'non-existent-session',
                AGENT_DID,
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('SESSION_BINDING_MISMATCH');

        await expect(
            assertSessionBinding(
                resolver,
                'non-existent-session',
                AGENT_DID,
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('not found in session registry');
    });

    it('should throw fail-closed when agentDid does not match', async () => {
        await expect(
            assertSessionBinding(
                resolver,
                SESSION_ID,
                OTHER_AGENT_DID,
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('SESSION_BINDING_MISMATCH');

        await expect(
            assertSessionBinding(
                resolver,
                SESSION_ID,
                OTHER_AGENT_DID,
                PRINCIPAL_DID,
            ),
        ).rejects.toThrow('affectedAgentDid');
    });

    it('should throw fail-closed when principalDid does not match', async () => {
        await expect(
            assertSessionBinding(
                resolver,
                SESSION_ID,
                AGENT_DID,
                OTHER_PRINCIPAL_DID,
            ),
        ).rejects.toThrow('SESSION_BINDING_MISMATCH');

        await expect(
            assertSessionBinding(
                resolver,
                SESSION_ID,
                AGENT_DID,
                OTHER_PRINCIPAL_DID,
            ),
        ).rejects.toThrow('affectedPrincipalDid');
    });

    it('should throw ProtocolError with code INTERNAL_ERROR', async () => {
        try {
            await assertSessionBinding(
                resolver,
                'missing',
                AGENT_DID,
                PRINCIPAL_DID,
            );
            expect.fail('should have thrown');
        } catch (err: unknown) {
            expect((err as { code: string }).code).toBe('INTERNAL_ERROR');
        }
    });

});
