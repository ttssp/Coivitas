/**
 * MCP Bridge — cross-hop fail-closed guard unit tests
 *
 * Acceptance behavior:
 * - cross-hop authority transition is deferred to a later phase
 * - cross-hop fail-closed
 *
 * Test sections:
 * - T28 (cross-hop fail-closed)
 * - T29 (cross-hop fail-closed)
 * - T41 (cross-hop fail-closed)
 * - T42 (same-hop forward — envelope forward to be added in a later phase)
 *
 * This file only tests the fail-closed behavior of the guard helpers;
 * the full processMCPMultiHopCall + envelope forward T41/T42 e2e tests will be added in a later phase.
 */
import { describe, expect, it } from 'vitest';

import {
    assertSameHop,
    checkSameHop,
    MCPCrossHopDeferredError,
} from '../cross-hop-guard.js';
import * as guardModule from '../cross-hop-guard.js';
import { MCP_ERROR } from '../types.js';

describe('cross-hop guard', () => {
    describe('assertSameHop', () => {
        it('should throw MCPCrossHopDeferredError when nextHopMcpServer differs from thisServerId', () => {
            // cross-hop fail-closed
            expect(() => assertSameHop('srv-A', 'srv-B')).toThrow(
                MCPCrossHopDeferredError,
            );
        });

        it('should not throw when nextHopMcpServer equals thisServerId (same-hop local routing)', () => {
            // same-hop forward incomingEnvelope
            expect(() => assertSameHop('srv-A', 'srv-A')).not.toThrow();
        });

        it('should attach mcp_code=mcp_error_cross_hop_deferred when error is thrown', () => {
            // error code
            try {
                assertSameHop('srv-A', 'srv-B');
                throw new Error('expected throw not raised');
            } catch (err) {
                expect(err).toBeInstanceOf(MCPCrossHopDeferredError);
                if (err instanceof MCPCrossHopDeferredError) {
                    expect(err.mcp_code).toBe(MCP_ERROR.CROSS_HOP_DEFERRED);
                    expect(err.internal_code).toBe('CROSS_HOP_DEFERRED_PHASE6');
                    const bridgeErr = err.toBridgeError();
                    expect(bridgeErr.mcp_code).toBe(
                        'mcp_error_cross_hop_deferred',
                    );
                    expect(bridgeErr.internal_code).toBe(
                        'CROSS_HOP_DEFERRED_PHASE6',
                    );
                }
            }
        });
    });

    describe('checkSameHop', () => {
        it('should return ok=false with CROSS_HOP_DEFERRED error when next hop differs (T41 literal)', () => {
            // T41: cross-hop call → fail-closed `mcp_error_cross_hop_deferred`
            const r = checkSameHop('srv-A', 'srv-B');
            expect(r.ok).toBe(false);
            if (!r.ok) {
                expect(r.error.mcp_code).toBe('mcp_error_cross_hop_deferred');
                expect(r.error.internal_code).toBe('CROSS_HOP_DEFERRED_PHASE6');
            }
        });

        it('should return ok=true when next hop equals current server (T42 literal same-hop OK)', () => {
            // T42: same-hop local routing → forward (to be implemented later; this file only checks guard ok)
            const r = checkSameHop('srv-A', 'srv-A');
            expect(r.ok).toBe(true);
        });
    });

    describe('OUT-OF-SCOPE guard', () => {
        it('should never expose any cross-hop sub-token mint or holderProof signing API when consuming public exports', () => {
            // guard: the cross-hop guard module does **not** export any sub-token mint / holderProof signing API
            // the entire cross-hop branch dead code has been deleted
            // this test inspects the module export surface via an ESM namespace import (import-time invariant)
            const exposed = Object.keys(guardModule);
            // allowed exports: assertSameHop / checkSameHop / MCPCrossHopDeferredError
            expect(exposed).toEqual(
                expect.arrayContaining([
                    'assertSameHop',
                    'checkSameHop',
                    'MCPCrossHopDeferredError',
                ]),
            );
            // forbidden exports: any function related to the mint / sign / forward keywords
            const forbidden = exposed.filter((k) =>
                /mint|sign.*holder|forward.*envelope|crossHopForward/i.test(k),
            );
            expect(forbidden).toEqual([]);
        });
    });
});
