/**
 * MCP Bridge — envelope adapter (same-hop only)
 *
 * Processing flow:
 *   1. verify incoming envelope (Mode B per SD-Token) — currently performs only a
 *      structural forward; the full verifyCapabilityToken call is handled by the
 *      scope validator + outbox upstream/downstream
 *   2. fail-closed: nextHopMcpServer !== thisServerId() → CROSS_HOP_DEFERRED_PHASE6
 *   3. same-hop local routing: forward incomingEnvelope (no MCP server boundary crossed)
 *
 * This file **implements**:
 *   - incomingMCPCallToEnvelope: MCP CallToolRequest → AP NegotiationEnvelope (Mode B
 *     framework; body wraps mcpMessage + capabilityClaim placeholder field;
 *     signing/verification handled upstream/downstream)
 *   - outgoingEnvelopeToMCPResponse: AP NegotiationEnvelope → MCP CallToolResult
 *   - processSingleHopMCPCall: cross-hop fail-closed guard + same-hop forward
 *   - does **not** contain sub-token mint / sign holderProof / forward-envelope (fail-closed)
 *
 * This file does **not** implement:
 *   - cross-hop sub-token mint+sign (fail-closed; deferred to a later version)
 *   - PoP credential resolver (DEFERRED as a whole to a later version)
 *   - outbox / scope validator (separate modules)
 *   - SD-CapabilityToken delegation chain depth verify (that companion spec does not yet exist — placeholder only)
 *
 * Single-hop constraints:
 *   - assertSameHop / checkSameHop are mandatory-path (same as cross-hop-guard)
 *   - any cross-hop path is fail-closed `mcp_error_cross_hop_deferred`
 *   - the `processSingleHopMCPCall` name reflects single-hop semantics; it is **not** called multi-hop
 */

import type {
    DID,
    NegotiationEnvelope,
    MessageType,
    Signature,
    Timestamp,
} from '@coivitas/types';

import { assertSameHop, MCPCrossHopDeferredError } from './cross-hop-guard.js';
import {
    MCP_ERROR,
    makeMcpError,
    type MCPBridgeError,
    type MCPCallParams,
    type MCPClientId,
    type MCPMessage,
    type MCPServerId,
} from './types.js';

// ─── envelope body sub-structure (capabilityClaim field) ─

/**
 * MCPCallEnvelopeBody — MCP `tools/call` → NegotiationEnvelope.body schema
 *
 * Field mapping:
 *   - mcpMessage: raw MCP wire payload (passed through to the downstream settler / validator)
 *   - capabilityClaim: the incoming envelope's SD-CapabilityToken claim (Mode B per SD-Token)
 *
 * The capabilityClaim field is currently a `unknown` placeholder — the full SD-Token
 * type is defined by the corresponding companion spec (that spec is not yet published;
 * the body field is kept ahead of time so it can be aligned once drafted).
 *
 * messageType is set to 'NEGOTIATION_REQUEST' (consistent with the base envelope
 * protocol; MCP wire distinguishes via the body sub-structure; no new messageType is
 * introduced — the wire-format is frozen and the messageType union is not extended).
 */
export interface MCPCallEnvelopeBody {
    /** raw MCP wire payload (JSON-RPC style) */
    mcpMessage: MCPMessage;
    /**
     * The SD-CapabilityToken claim carried by the incoming envelope (Mode B per SD-Token).
     *
     * Typed as `unknown` — the full SD-Token shape is specified by the SD-CapabilityToken spec;
     * because that spec is deferred and does not yet exist, the capabilityClaim field is a
     * placeholder so upstream/downstream can reference it.
     */
    capabilityClaim?: unknown;
    /** MCP client identifier (corresponds to the holder binding registry) */
    mcpClientId: MCPClientId;
}

// ─── incoming MCP call → AP envelope ─────────────────────────────

/**
 * incomingMCPCallToEnvelope input
 *
 * This interface accepts single-hop only (not called multi-hop):
 *   incomingMCPCall + resolved sender (agentDid + verificationKey) + context envelope (Mode B claim)
 */
export interface IncomingMCPCallContext {
    /** raw MCP `tools/call` wire payload */
    mcpMessage: MCPMessage;
    /** context envelope (includes capabilityClaim Mode B) */
    incomingEnvelope?: NegotiationEnvelope;
    /** sender agent DID resolved via holder-binding-resolver */
    senderAgentDid: DID;
    /** used for envelope signature verification (outer Mode B flow check) */
    senderVerificationKey: string;
    /** MCP client identifier (corresponds to the binding registry) */
    mcpClientId: MCPClientId;
    /** envelope recipient (usually = thisServer.serverDid) */
    recipientDid: DID;
    /** envelope id generator (default randomUUID) */
    envelopeId: string;
    /** envelope timestamp (default ISO-8601 now) */
    timestamp: Timestamp;
    /** envelope signature (signed by the Mode B caller; currently a placeholder) */
    signature: Signature;
    /**
     * envelope specVersion (capabilityClaim verify Mode B);
     * must be ∈ SUPPORTED_SPEC_VERSIONS; supplied by the caller.
     */
    specVersion: string;
}

/**
 * incomingMCPCallToEnvelope — MCP message → NegotiationEnvelope (Mode B framework)
 *
 * Does **not** perform sub-token mint / signing / chain forward (fail-closed).
 * Only does field mapping + body sub-structure wrapping; envelope signing is done by
 * the upper-layer envelope.ts createEnvelope path (this function only handles the
 * wire shape conversion).
 *
 * fail-closed semantics: a missing key mcpMessage field → return error (no partial envelope).
 */
export function incomingMCPCallToEnvelope(
    ctx: IncomingMCPCallContext,
):
    | { ok: true; envelope: NegotiationEnvelope }
    | { ok: false; error: MCPBridgeError } {
    // fail-closed: mcpMessage must include method + jsonrpc 2.0
    if (!ctx.mcpMessage || ctx.mcpMessage.jsonrpc !== '2.0') {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'MCP_MESSAGE_INVALID_JSONRPC',
                'incoming MCP message missing or jsonrpc != 2.0',
            ),
        };
    }
    if (!ctx.mcpMessage.method || typeof ctx.mcpMessage.method !== 'string') {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'MCP_MESSAGE_INVALID_METHOD',
                'incoming MCP message missing method',
            ),
        };
    }
    // mcpClientId must be non-empty (aligned with the binding registry primary key)
    if (!ctx.mcpClientId || ctx.mcpClientId.length === 0) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.BINDING_MISSING,
                'MCP_CLIENT_ID_EMPTY',
                'mcpClientId required for envelope construction',
            ),
        };
    }
    if (!ctx.senderAgentDid || ctx.senderAgentDid.length === 0) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.AGENT_DID_UNRESOLVED,
                'SENDER_AGENT_DID_EMPTY',
                'sender agentDid required for envelope construction',
            ),
        };
    }
    if (!ctx.recipientDid || ctx.recipientDid.length === 0) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'RECIPIENT_DID_EMPTY',
                'recipientDid required for envelope construction',
            ),
        };
    }

    const body: MCPCallEnvelopeBody = {
        mcpMessage: ctx.mcpMessage,
        mcpClientId: ctx.mcpClientId,
    };
    // capabilityClaim in the context envelope is passed through (Mode B)
    if (ctx.incomingEnvelope) {
        const capClaim = (ctx.incomingEnvelope.body as { capabilityClaim?: unknown })
            .capabilityClaim;
        if (capClaim !== undefined) {
            body.capabilityClaim = capClaim;
        }
    }

    // messageType is set to 'NEGOTIATION_REQUEST' (compatible with the union subset of
    // the frozen wire-format; MCP wire business semantics are distinguished by
    // body.mcpMessage.method, without extending the MessageType union)
    const messageType: MessageType = 'NEGOTIATION_REQUEST';

    const envelope: NegotiationEnvelope = {
        id: ctx.envelopeId,
        specVersion: ctx.specVersion,
        header: {
            senderDid: ctx.senderAgentDid,
            recipientDid: ctx.recipientDid,
            sessionId: null,
        },
        messageType,
        body: body as unknown as Record<string, unknown>,
        signature: ctx.signature,
        timestamp: ctx.timestamp,
    };

    return { ok: true, envelope };
}

// ─── outgoing envelope → MCP response ─────────────────────────────

/**
 * outgoingEnvelopeToMCPResponse — AP envelope → MCP CallToolResult mapping
 *
 * Corresponds to same-hop forward incomingEnvelope + outbox sync flow:
 *   - sync flow: SettlementReceipt immediate
 *   - currently does not populate the settlement receipt body field (handled by the
 *     outbox module); only performs wire shape conversion — envelope.body → MCP response payload
 *
 * mcpClientId check: the response's mcpClientId must match envelope.body.mcpClientId;
 * on mismatch → return error (a mismatch is a binding misconfiguration / routing error).
 */
export function outgoingEnvelopeToMCPResponse(
    envelope: NegotiationEnvelope,
    expectedMcpClientId: MCPClientId,
):
    | { ok: true; mcpResponse: { jsonrpc: '2.0'; id: string | number; result: unknown } }
    | { ok: false; error: MCPBridgeError } {
    if (!envelope || typeof envelope !== 'object') {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'ENVELOPE_MISSING',
                'outgoing envelope missing',
            ),
        };
    }
    const body = envelope.body as unknown as MCPCallEnvelopeBody | undefined;
    if (!body || !body.mcpMessage) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'ENVELOPE_BODY_MISSING_MCP_MESSAGE',
                'outgoing envelope body missing mcpMessage',
            ),
        };
    }
    if (body.mcpClientId !== expectedMcpClientId) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.BINDING_MISSING,
                'MCP_CLIENT_ID_MISMATCH',
                `envelope mcpClientId='${body.mcpClientId}' != expected='${expectedMcpClientId}'`,
            ),
        };
    }

    return {
        ok: true,
        mcpResponse: {
            jsonrpc: '2.0' as const,
            id: body.mcpMessage.id,
            // result = the envelope body's (mcpMessage.params + outgoing payload);
            // currently just passed through — the full settlement receipt is populated by the outbox module
            result: {
                method: body.mcpMessage.method,
                params: body.mcpMessage.params ?? null,
            },
        },
    };
}

// ─── single-hop call processor (same-hop only) ──────────

/**
 * processSingleHopMCPCall — same-hop only path
 *
 * Processing steps:
 *   1. verify incoming envelope (Mode B) — verified ahead of time by the caller;
 *      a placeholder here (assumes the incoming envelope has already been verified by
 *      the caller via verifyCapabilityToken; the full verify path is supplied
 *      upstream/downstream, this function only does a structural forward)
 *   2. fail-closed: nextHopMcpServer !== thisServerId() → fail-closed
 *   3. same-hop local routing: outgoingEnvelope = incomingEnvelope
 *
 * Does **not**:
 *   - sub-token mint
 *   - holderProof signing
 *   - reconstruct the outgoing envelope (forwards incomingEnvelope directly)
 *
 * fail-closed semantics:
 *   - cross-hop (thisServer !== nextHop) → throw MCPCrossHopDeferredError → caller converts to wire error
 *   - the upper layer catches MCPCrossHopDeferredError via try/catch and converts to an MCP wire response (see cross-hop-guard)
 *
 * Named single-hop (not multi-hop) — reflects the same-hop only scope.
 *
 * @returns same-hop OK = `{ ok: true, outgoingEnvelope }`;
 *          cross-hop = `{ ok: false, error: cross_hop_deferred }`;
 *          other errors (missing envelope fields, etc.) = `{ ok: false, error }`
 */
export function processSingleHopMCPCall(args: {
    /** current server identifier (the return value of thisServerId()) */
    thisServerId: MCPServerId;
    /** next-hop server identifier (must == thisServerId) */
    nextHopMcpServer: MCPServerId;
    /** context envelope (assumed already verified; only does a structural forward) */
    incomingEnvelope: NegotiationEnvelope;
    /** expected mcpClientId (aligned with the binding) */
    expectedMcpClientId: MCPClientId;
}):
    | { ok: true; outgoingEnvelope: NegotiationEnvelope }
    | { ok: false; error: MCPBridgeError } {
    // fail-closed: key incoming envelope fields are required
    if (!args.incomingEnvelope || !args.incomingEnvelope.body) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'INCOMING_ENVELOPE_MISSING',
                'incomingEnvelope missing or body empty',
            ),
        };
    }
    const body = args.incomingEnvelope.body as unknown as MCPCallEnvelopeBody;
    if (!body.mcpMessage) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.SETTLEMENT_FAILED,
                'INCOMING_ENVELOPE_BODY_MISSING_MCP_MESSAGE',
                'incoming envelope body missing mcpMessage',
            ),
        };
    }
    if (body.mcpClientId !== args.expectedMcpClientId) {
        return {
            ok: false,
            error: makeMcpError(
                MCP_ERROR.BINDING_MISSING,
                'MCP_CLIENT_ID_MISMATCH',
                `envelope mcpClientId='${body.mcpClientId}' != expected='${args.expectedMcpClientId}'`,
            ),
        };
    }

    // fail-closed: nextHopMcpServer !== thisServerId() → CROSS_HOP_DEFERRED_PHASE6
    // uses assertSameHop (see cross-hop-guard.ts); throws MCPCrossHopDeferredError
    try {
        assertSameHop(args.thisServerId, args.nextHopMcpServer);
    } catch (err) {
        if (err instanceof MCPCrossHopDeferredError) {
            return {
                ok: false,
                error: err.toBridgeError(),
            };
        }
        throw err; // not a cross-hop error (infrastructure exception) → propagate
    }

    // same-hop local routing: forward incomingEnvelope
    // does not construct a new envelope; does not mint a new token; does not sign
    return { ok: true, outgoingEnvelope: args.incomingEnvelope };
}

// ─── envelope adapter integration interface (implements types.ts MCPEnvelopeAdapter) ──────────

/**
 * MCPEnvelopeAdapterImpl — implements the MCPEnvelopeAdapter interface from types.ts
 *
 * Currently adaptIncoming only does same-hop validation + body sub-structure extraction;
 * full envelope construction is done by the caller via `incomingMCPCallToEnvelope` (decoupled).
 */
export class MCPEnvelopeAdapterImpl {
    constructor(public readonly thisServerId: MCPServerId) {}

    /**
     * Same-hop only adapter — the incoming envelope must forward to thisServer.
     *
     * cross-hop triggers fail-closed `mcp_error_cross_hop_deferred`.
     */
    async adaptIncoming(
        mcpMessage: MCPMessage,
        incomingEnvelope: NegotiationEnvelope,
    ): Promise<
        | { ok: true; envelope: NegotiationEnvelope }
        | { ok: false; error: MCPBridgeError }
    > {
        // verify that mcpMessage is consistent with the envelope body
        if (!incomingEnvelope.body) {
            return {
                ok: false,
                error: makeMcpError(
                    MCP_ERROR.SETTLEMENT_FAILED,
                    'INCOMING_ENVELOPE_BODY_MISSING',
                    'incoming envelope body missing',
                ),
            };
        }
        const body = incomingEnvelope.body as unknown as MCPCallEnvelopeBody;
        if (
            !body.mcpMessage ||
            body.mcpMessage.id !== mcpMessage.id ||
            body.mcpMessage.method !== mcpMessage.method
        ) {
            return {
                ok: false,
                error: makeMcpError(
                    MCP_ERROR.SETTLEMENT_FAILED,
                    'MCP_MESSAGE_ENVELOPE_BODY_MISMATCH',
                    'envelope body.mcpMessage does not match the provided mcpMessage',
                ),
            };
        }
        return Promise.resolve({ ok: true, envelope: incomingEnvelope });
    }
}

// ─── helper: extract MCP call params (ScopeValidator field reference) ──────

/**
 * Extracts MCPCallParams from the envelope body (a precursor to the scope validator call).
 *
 * Fields read by ScopeValidator:
 *   - mcpMessage.params.tool / arguments / numeric_limit / value / currency
 *
 * This helper only extracts; full validation is implemented in the scope validator.
 */
export function extractMCPCallParams(
    envelope: NegotiationEnvelope,
): MCPCallParams | null {
    if (!envelope.body) return null;
    const body = envelope.body as unknown as MCPCallEnvelopeBody;
    if (!body.mcpMessage || !body.mcpMessage.params) return null;
    return body.mcpMessage.params;
}
