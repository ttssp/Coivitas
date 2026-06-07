/**
 * MCP Bridge — cross-hop fail-closed guard
 *
 * Conclusion: cross-hop forwarding is OUT-OF-SCOPE in the current version and is
 * uniformly fail-closed; any `nextHopMcpServer !== thisServerId()` path no longer
 * mints a sub-token / signs a holderProof / returns an outgoing envelope, but
 * instead directly returns a `CROSS_HOP_DEFERRED_PHASE6` error.
 * cross-hop authority transition is deferred to a later version (enabled after the
 * canonical signed payload primitive + recipient-delegation flow primitive are
 * jointly redesigned).
 *
 * This file provides guard helpers:
 * - `assertSameHop(thisServerId, nextHopMcpServer)` — differing server → throws a CROSS_HOP_DEFERRED_PHASE6 error
 * - `MCPCrossHopDeferredError` — error class (used by try/catch to capture the fail-closed case)
 *
 * Any cross-hop sub-token mint / holderProof signing / forward envelope code is
 * strictly forbidden in this file — the entire cross-hop branch has been deleted
 * (fail-closed: no partial-acceptance of auth primitives).
 */

import {
    MCP_ERROR,
    makeMcpError,
    type MCPBridgeError,
    type MCPServerId,
} from './types.js';

/**
 * MCP cross-hop fail-closed error
 *
 * Any `nextHopMcpServer !== thisServerId()` path throws this error;
 * the upper layer captures it and converts it to the MCP wire response `mcp_error_cross_hop_deferred`.
 */
export class MCPCrossHopDeferredError extends Error {
    public readonly mcp_code = MCP_ERROR.CROSS_HOP_DEFERRED;
    public readonly internal_code = 'CROSS_HOP_DEFERRED_PHASE6';

    constructor(thisServerId: MCPServerId, nextHopMcpServer: MCPServerId) {
        super(
            `cross-hop forwarding is not implemented: this=${thisServerId} next=${nextHopMcpServer}`,
        );
        this.name = 'MCPCrossHopDeferredError';
    }

    toBridgeError(): MCPBridgeError {
        return makeMcpError(this.mcp_code, this.internal_code, this.message);
    }
}

/**
 * fail-closed guard
 *
 * MUST be called first after receiving an incoming envelope;
 * any cross-hop path directly throws `MCPCrossHopDeferredError`.
 *
 * This function does **not** perform:
 * - sub-token mint
 * - holderProof signing
 * - outgoing envelope construction
 *
 * (fail-closed: no partial-acceptance of auth primitives)
 */
export function assertSameHop(
    thisServerId: MCPServerId,
    nextHopMcpServer: MCPServerId,
): void {
    if (nextHopMcpServer !== thisServerId) {
        throw new MCPCrossHopDeferredError(thisServerId, nextHopMcpServer);
    }
}

/**
 * Non-throwing version (consumed directly by the caller):
 * - same-hop → `{ ok: true }`
 * - cross-hop → `{ ok: false, error: MCPBridgeError(CROSS_HOP_DEFERRED) }`
 */
export function checkSameHop(
    thisServerId: MCPServerId,
    nextHopMcpServer: MCPServerId,
): { ok: true } | { ok: false; error: MCPBridgeError } {
    if (nextHopMcpServer !== thisServerId) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.CROSS_HOP_DEFERRED,
                'CROSS_HOP_DEFERRED_PHASE6',
                `cross-hop forwarding is not implemented: this=${thisServerId} next=${nextHopMcpServer}`,
            ),
        };
    }
    return { ok: true };
}
