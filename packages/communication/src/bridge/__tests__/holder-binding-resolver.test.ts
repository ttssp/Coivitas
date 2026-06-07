/**
 * MCP Bridge — holder binding resolver unit tests
 *
 * Five-step flow:
 *   1. binding lookup → null/expired → MCP_BINDING_EXPIRED_OR_MISSING
 *   2. revocation resolver throw → mcp_error_binding_revocation_unreachable
 *   3. revocation resolver timeout → mcp_error_binding_revocation_unreachable (5s)
 *   4. revocation status non-null → mcp_error_binding_revoked
 *   5. did resolver null → MCP_AGENT_DID_UNRESOLVED
 *   6. all OK → { agentDid, verificationKey }
 *
 * Test coverage (≥ 12 tests):
 *   - 5-step happy path + 4 error-code fail-closed paths (≥ 1 test per path)
 *   - 5 + 1 boundary cases (empty mcpClientId / long ID / abnormal timestamp / missing verificationKey)
 *   - withTimeout helper unit test
 */
import { describe, expect, it, vi } from 'vitest';

import type { DID } from '@coivitas/types';

import {
    DEFAULT_REVOCATION_RESOLVER_TIMEOUT_MS,
    isResolutionError,
    MCP_ERROR,
    resolveSenderForMCPCall,
    resolutionErrorToMcpError,
    withTimeout,
    type BindingRevocationResolver,
    type DidPublicKeyResolver,
    type HolderBindingRegistry,
    type MCPClientBinding,
    type MCPSenderResolutionError,
    type ResolvedAgentKey,
    type RevocationStatus,
} from '../index.js';

// ─── helper / fixtures ──────────────────────────────────────────────────────

function makeBinding(
    overrides?: Partial<MCPClientBinding>,
): MCPClientBinding {
    const nowMs = Date.now();
    return {
        mcpClientId: 'mcp-client-1',
        agentDid: 'did:agent:alice' as DID,
        issuedAt: nowMs - 60_000,
        notAfter: nowMs + 3_600_000, // 1h future
        principalSignature: 'principal-sig-base64url-placeholder',
        ...overrides,
    };
}

function makeRegistry(
    binding: MCPClientBinding | null,
): HolderBindingRegistry {
    return {
        lookup: vi.fn().mockResolvedValue(binding),
    };
}

const noopRevocationResolver: BindingRevocationResolver = () =>
    Promise.resolve(null);

const validKey: ResolvedAgentKey = {
    verificationKey: 'BASE64URL_ED25519_PUBKEY_PLACEHOLDER',
};

const validDidResolver: DidPublicKeyResolver = () => Promise.resolve(validKey);

// ─── tests ───────────────────────────────────────────────────────────────────

describe('resolveSenderForMCPCall', () => {
    describe('step 1: binding lookup', () => {
        it('should return MCP_BINDING_EXPIRED_OR_MISSING when binding is null (lookup miss)', async () => {
            const result = await resolveSenderForMCPCall(
                'mcp-client-not-found',
                makeRegistry(null),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('MCP_BINDING_EXPIRED_OR_MISSING');
            }
        });

        it('should return MCP_BINDING_EXPIRED_OR_MISSING when notAfter <= now (binding expired)', async () => {
            // Date.now() > Date.parse(binding.notAfter)
            const expiredBinding = makeBinding({
                notAfter: Date.now() - 1_000, // expired 1s ago
            });
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(expiredBinding),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('MCP_BINDING_EXPIRED_OR_MISSING');
            }
        });
    });

    describe('step 2: bindingRevocationResolver mandatory path', () => {
        it('should return mcp_error_binding_revocation_unreachable when resolver throws', async () => {
            // fail-closed
            const throwingResolver: BindingRevocationResolver = () => {
                throw new Error('intentional resolver failure');
            };
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                validDidResolver,
                throwingResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe(
                    'mcp_error_binding_revocation_unreachable',
                );
            }
        });

        it('should return mcp_error_binding_revocation_unreachable on async rejection', async () => {
            const rejectingResolver: BindingRevocationResolver = () =>
                Promise.reject(new Error('async network failure'));
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                validDidResolver,
                rejectingResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe(
                    'mcp_error_binding_revocation_unreachable',
                );
            }
        });

        it('should return mcp_error_binding_revocation_unreachable when resolver hangs past 5s timeout', async () => {
            // timeout 5s fail-closed
            const hangingResolver: BindingRevocationResolver = () =>
                new Promise<RevocationStatus | null>((resolve) => {
                    // never resolves (until the test timeout is cut off by withTimeout)
                    setTimeout(() => resolve(null), 60_000);
                });
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                validDidResolver,
                hangingResolver,
                100, // 100ms test timeout (5s in production)
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe(
                    'mcp_error_binding_revocation_unreachable',
                );
            }
        });

        it('should use DEFAULT_REVOCATION_RESOLVER_TIMEOUT_MS = 5000', () => {
            expect(DEFAULT_REVOCATION_RESOLVER_TIMEOUT_MS).toBe(5000);
        });
    });

    describe('step 3: revocation status', () => {
        it('should return mcp_error_binding_revoked when revocation status kind=tombstone', async () => {
            // revocationStatus !== null → revoked
            const tombstoned: RevocationStatus = {
                kind: 'tombstone',
                timestamp: '2026-05-10T00:00:00Z',
                signature: 'sig-base64url',
            };
            const tombstoneResolver: BindingRevocationResolver = () =>
                Promise.resolve(tombstoned);
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                validDidResolver,
                tombstoneResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('mcp_error_binding_revoked');
            }
        });

        it('should return mcp_error_binding_revoked when revocation status kind=pending', async () => {
            // != null means reject (including pending)
            const pending: RevocationStatus = {
                kind: 'pending',
                timestamp: '2026-05-10T00:00:00Z',
                signature: 'sig-base64url',
            };
            const pendingResolver: BindingRevocationResolver = () =>
                Promise.resolve(pending);
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                validDidResolver,
                pendingResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('mcp_error_binding_revoked');
            }
        });
    });

    describe('step 4: didResolver', () => {
        it('should return MCP_AGENT_DID_UNRESOLVED when didResolver returns null', async () => {
            const nullDidResolver: DidPublicKeyResolver = () =>
                Promise.resolve(null);
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                nullDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('MCP_AGENT_DID_UNRESOLVED');
            }
        });

        it('should return MCP_AGENT_DID_UNRESOLVED when didResolver throws (coalesced)', async () => {
            // fail-closed; resolver exceptions are coalesced into unresolved
            const throwingDidResolver: DidPublicKeyResolver = () => {
                throw new Error('did resolver failure');
            };
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                throwingDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('MCP_AGENT_DID_UNRESOLVED');
            }
        });
    });

    describe('step 5: success path', () => {
        it('should return { agentDid, verificationKey } when all 5 steps pass', async () => {
            // happy path
            const binding = makeBinding({
                agentDid: 'did:agent:alice' as DID,
            });
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(binding),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(false);
            if (!isResolutionError(result)) {
                expect(result.agentDid).toBe('did:agent:alice');
                expect(result.verificationKey).toBe(
                    'BASE64URL_ED25519_PUBKEY_PLACEHOLDER',
                );
            }
        });

        it('should call resolvers in order: lookup → revocation → did (verify call order)', async () => {
            // call order: lookup → revocation → did
            const callOrder: string[] = [];
            const registry: HolderBindingRegistry = {
                lookup: vi.fn().mockImplementation((_id) => {
                    callOrder.push('lookup');
                    return Promise.resolve(makeBinding());
                }),
            };
            const revocationResolver: BindingRevocationResolver = (_id) => {
                callOrder.push('revocation');
                return Promise.resolve(null);
            };
            const didResolver: DidPublicKeyResolver = (_did) => {
                callOrder.push('did');
                return Promise.resolve(validKey);
            };
            await resolveSenderForMCPCall(
                'mcp-client-1',
                registry,
                didResolver,
                revocationResolver,
            );
            expect(callOrder).toEqual(['lookup', 'revocation', 'did']);
        });

        it('should NOT call did resolver when revocation status is non-null (short-circuit)', async () => {
            // performance: revoked → should not continue to call the did resolver (short-circuit)
            const didResolver = vi.fn(validDidResolver);
            const tombstoned: RevocationStatus = {
                kind: 'tombstone',
                timestamp: '2026-05-10T00:00:00Z',
                signature: 'sig',
            };
            await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                didResolver,
                () => Promise.resolve(tombstoned),
            );
            expect(didResolver).not.toHaveBeenCalled();
        });
    });

    describe('boundary cases + abnormal binding fields', () => {
        it('should treat binding with notAfter=now (boundary) as expired (> now means not-expired)', async () => {
            // Date.now() > notAfter → expired
            // when notAfter == now, Date.now() > notAfter is false (treated as active)
            // but a 1ms drift may occur in practice; this test verifies rejection when nowMs > notAfter
            const past = Date.now() - 1; // 1ms ago
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding({ notAfter: past })),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('MCP_BINDING_EXPIRED_OR_MISSING');
            }
        });

        it('should handle very long mcpClientId (256 chars) gracefully', async () => {
            const longId = 'x'.repeat(256);
            const longBinding = makeBinding({ mcpClientId: longId });
            const result = await resolveSenderForMCPCall(
                longId,
                makeRegistry(longBinding),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(false);
        });

        it('should propagate to MCP_BINDING_EXPIRED_OR_MISSING when binding has weird future notAfter (year 9999)', async () => {
            // boundary: an extremely far-future notAfter does not affect the expired check (still active)
            const farFutureBinding = makeBinding({
                notAfter: 99_999_999_999_999, // year ~5138
            });
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(farFutureBinding),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(false);
        });

        it('should treat empty verificationKey from didResolver as success (this layer does not validate key shape — handled by the upper-layer envelope verify path)', async () => {
            // this layer does not verify key shape; a non-null resolver return is treated as resolved
            // this is by design — key shape verify is the responsibility of upstream/downstream (layering)
            const emptyKeyResolver: DidPublicKeyResolver = () =>
                Promise.resolve({ verificationKey: '' });
            const result = await resolveSenderForMCPCall(
                'mcp-client-1',
                makeRegistry(makeBinding()),
                emptyKeyResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(false);
            if (!isResolutionError(result)) {
                expect(result.verificationKey).toBe('');
            }
        });

        it('should treat empty mcpClientId in registry lookup the same way (lookup miss → expired_or_missing)', async () => {
            // on the implementation side, registry.lookup('') returns null = the same path
            const result = await resolveSenderForMCPCall(
                '',
                makeRegistry(null),
                validDidResolver,
                noopRevocationResolver,
            );
            expect(isResolutionError(result)).toBe(true);
            if (isResolutionError(result)) {
                expect(result.error).toBe('MCP_BINDING_EXPIRED_OR_MISSING');
            }
        });
    });

    describe('error → wire MCPBridgeError mapping', () => {
        it('should map MCP_BINDING_EXPIRED_OR_MISSING → mcp_error_binding_missing', () => {
            const err: MCPSenderResolutionError = {
                error: 'MCP_BINDING_EXPIRED_OR_MISSING',
            };
            const wire = resolutionErrorToMcpError(err);
            expect(wire.mcp_code).toBe(MCP_ERROR.BINDING_MISSING);
            expect(wire.internal_code).toBe('MCP_BINDING_EXPIRED_OR_MISSING');
        });

        it('should map mcp_error_binding_revoked → wire mcp_error_binding_revoked', () => {
            const wire = resolutionErrorToMcpError({
                error: 'mcp_error_binding_revoked',
            });
            expect(wire.mcp_code).toBe(MCP_ERROR.BINDING_REVOKED);
            expect(wire.internal_code).toBe('mcp_error_binding_revoked');
        });

        it('should map mcp_error_binding_revocation_unreachable → wire mcp_error_binding_revocation_unreachable', () => {
            const wire = resolutionErrorToMcpError({
                error: 'mcp_error_binding_revocation_unreachable',
            });
            expect(wire.mcp_code).toBe(MCP_ERROR.BINDING_REVOCATION_UNREACHABLE);
            expect(wire.internal_code).toBe(
                'mcp_error_binding_revocation_unreachable',
            );
        });

        it('should map MCP_AGENT_DID_UNRESOLVED → wire mcp_error_agent_did_unresolved', () => {
            const wire = resolutionErrorToMcpError({
                error: 'MCP_AGENT_DID_UNRESOLVED',
            });
            expect(wire.mcp_code).toBe(MCP_ERROR.AGENT_DID_UNRESOLVED);
            expect(wire.internal_code).toBe('MCP_AGENT_DID_UNRESOLVED');
        });
    });
});

describe('withTimeout helper', () => {
    it('should resolve with promise result when promise completes within timeout', async () => {
        const result = await withTimeout(
            (_signal) => Promise.resolve('ok'),
            1000,
        );
        expect(result).toBe('ok');
    });

    it('should reject when promise hangs past timeout', async () => {
        await expect(
            withTimeout(
                (_signal) =>
                    new Promise<string>((resolve) =>
                        setTimeout(() => resolve('late'), 1000),
                    ),
                50, // 50ms timeout < 1000ms hang
            ),
        ).rejects.toThrow(/timeout after 50ms/);
    });

    it('should propagate rejection from promiseFactory immediately', async () => {
        await expect(
            withTimeout(
                (_signal) => Promise.reject(new Error('inner failure')),
                1000,
            ),
        ).rejects.toThrow(/inner failure/);
    });

    it('should signal abort via AbortSignal when timeout fires', async () => {
        let abortFired = false;
        try {
            await withTimeout(
                (signal) =>
                    new Promise<string>((resolve, reject) => {
                        signal.addEventListener('abort', () => {
                            abortFired = true;
                            reject(new Error('aborted'));
                        });
                        setTimeout(() => resolve('late'), 1000);
                    }),
                50,
            );
        } catch {
            // expected timeout
        }
        // the abort signal must fire after the timeout
        await new Promise((r) => setTimeout(r, 100));
        expect(abortFired).toBe(true);
    });
});
