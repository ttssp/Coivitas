/**
 * MCP Bridge — envelope adapter unit tests
 *
 * Tests correspond to:
 *   - T41: cross-hop call → fail-closed `mcp_error_cross_hop_deferred`
 *   - T42: same-hop forward incomingEnvelope (no mint, no sign)
 *   - key invariant: envelope-adapter.ts contains no mint / sign-holder / forward-envelope keyword
 *
 * Test coverage (≥ 8 tests):
 *   - incoming MCP message → envelope field mapping
 *   - outgoing envelope → MCP response field mapping
 *   - single-hop pass / cross-hop reject (T41/T42)
 *   - missing envelope fields → reject
 *   - mcpClientId mismatch → reject
 *   - envelope adapter contains no mint / sign-holder keyword (grep verify in source)
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type {
    DID,
    NegotiationEnvelope,
    Signature,
    Timestamp,
} from '@coivitas/types';

import {
    extractMCPCallParams,
    incomingMCPCallToEnvelope,
    MCP_ERROR,
    MCPCrossHopDeferredError,
    MCPEnvelopeAdapterImpl,
    outgoingEnvelopeToMCPResponse,
    processSingleHopMCPCall,
    type IncomingMCPCallContext,
    type MCPCallEnvelopeBody,
    type MCPMessage,
} from '../index.js';

// ─── helper / fixtures ──────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

function makeMcpMessage(overrides?: Partial<MCPMessage>): MCPMessage {
    return {
        jsonrpc: '2.0',
        id: 'req-1',
        method: 'tools/call',
        params: {
            tool: 'echo',
            arguments: {
                value: 100,
                currency: 'USD',
                numeric_limit: 5,
            },
        },
        ...overrides,
    };
}

function makeIncomingCtx(
    overrides?: Partial<IncomingMCPCallContext>,
): IncomingMCPCallContext {
    return {
        mcpMessage: makeMcpMessage(),
        senderAgentDid: 'did:agent:alice' as DID,
        senderVerificationKey: 'BASE64URL_PUBKEY_PLACEHOLDER',
        mcpClientId: 'mcp-client-1',
        recipientDid: 'did:agent:server' as DID,
        envelopeId: 'env-uuid-v4',
        timestamp: '2026-05-10T12:00:00Z' as Timestamp,
        signature: 'sig-base64url-placeholder' as Signature,
        specVersion: '0.3.0',
        ...overrides,
    };
}

function makeEnvelopeWithMcpBody(overrides?: {
    mcpClientId?: string;
    mcpMessage?: MCPMessage;
    capabilityClaim?: unknown;
}): NegotiationEnvelope {
    const body: MCPCallEnvelopeBody = {
        mcpMessage: overrides?.mcpMessage ?? makeMcpMessage(),
        mcpClientId: overrides?.mcpClientId ?? 'mcp-client-1',
        capabilityClaim: overrides?.capabilityClaim,
    };
    return {
        id: 'env-uuid-v4',
        specVersion: '0.3.0',
        header: {
            senderDid: 'did:agent:alice' as DID,
            recipientDid: 'did:agent:server' as DID,
            sessionId: null,
        },
        messageType: 'NEGOTIATION_REQUEST',
        body: body as unknown as Record<string, unknown>,
        signature: 'sig-base64url-placeholder' as Signature,
        timestamp: '2026-05-10T12:00:00Z' as Timestamp,
    };
}

// ─── tests ───────────────────────────────────────────────────────────────────

describe('incomingMCPCallToEnvelope (MCP message → AP envelope)', () => {
    it('should map MCP call to envelope with correct senderDid + recipientDid + body', () => {
        const result = incomingMCPCallToEnvelope(makeIncomingCtx());
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.envelope.header.senderDid).toBe('did:agent:alice');
            expect(result.envelope.header.recipientDid).toBe('did:agent:server');
            expect(result.envelope.specVersion).toBe('0.3.0');
            expect(result.envelope.id).toBe('env-uuid-v4');
            expect(result.envelope.messageType).toBe('NEGOTIATION_REQUEST');
            // the body sub-structure contains mcpMessage + mcpClientId
            const body = result.envelope.body as MCPCallEnvelopeBody;
            expect(body.mcpClientId).toBe('mcp-client-1');
            expect(body.mcpMessage.method).toBe('tools/call');
            expect(body.mcpMessage.id).toBe('req-1');
        }
    });

    it('should propagate capabilityClaim from incomingEnvelope.body when provided', () => {
        // the incoming envelope carries capabilityClaim (Mode B)
        const claim = { tokenId: 'urn:cap:test', scope: 'read' };
        const incomingEnv = makeEnvelopeWithMcpBody({ capabilityClaim: claim });
        const ctx = makeIncomingCtx({ incomingEnvelope: incomingEnv });
        const result = incomingMCPCallToEnvelope(ctx);
        expect(result.ok).toBe(true);
        if (result.ok) {
            const body = result.envelope.body as MCPCallEnvelopeBody;
            expect(body.capabilityClaim).toEqual(claim);
        }
    });

    it('should reject when mcpMessage.jsonrpc !== "2.0"', () => {
        const ctx = makeIncomingCtx({
            mcpMessage: {
                ...makeMcpMessage(),
                jsonrpc: '1.0' as unknown as '2.0',
            },
        });
        const result = incomingMCPCallToEnvelope(ctx);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe(
                'MCP_MESSAGE_INVALID_JSONRPC',
            );
        }
    });

    it('should reject when mcpClientId is empty', () => {
        const ctx = makeIncomingCtx({ mcpClientId: '' });
        const result = incomingMCPCallToEnvelope(ctx);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.mcp_code).toBe(MCP_ERROR.BINDING_MISSING);
            expect(result.error.internal_code).toBe('MCP_CLIENT_ID_EMPTY');
        }
    });

    it('should reject when senderAgentDid is empty', () => {
        const ctx = makeIncomingCtx({ senderAgentDid: '' as DID });
        const result = incomingMCPCallToEnvelope(ctx);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.mcp_code).toBe(MCP_ERROR.AGENT_DID_UNRESOLVED);
        }
    });

    it('should reject when recipientDid is empty', () => {
        const ctx = makeIncomingCtx({ recipientDid: '' as DID });
        const result = incomingMCPCallToEnvelope(ctx);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe('RECIPIENT_DID_EMPTY');
        }
    });

    it('should reject when method is missing', () => {
        const ctx = makeIncomingCtx({
            mcpMessage: {
                ...makeMcpMessage(),
                method: '' as string,
            },
        });
        const result = incomingMCPCallToEnvelope(ctx);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe('MCP_MESSAGE_INVALID_METHOD');
        }
    });
});

describe('outgoingEnvelopeToMCPResponse (envelope → MCP response)', () => {
    it('should map envelope to MCP CallToolResult-like wire response', () => {
        const env = makeEnvelopeWithMcpBody();
        const result = outgoingEnvelopeToMCPResponse(env, 'mcp-client-1');
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.mcpResponse.jsonrpc).toBe('2.0');
            expect(result.mcpResponse.id).toBe('req-1');
            expect(result.mcpResponse.result).toMatchObject({
                method: 'tools/call',
            });
        }
    });

    it('should reject when expectedMcpClientId mismatches body.mcpClientId', () => {
        const env = makeEnvelopeWithMcpBody({ mcpClientId: 'mcp-client-1' });
        const result = outgoingEnvelopeToMCPResponse(env, 'mcp-client-OTHER');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe('MCP_CLIENT_ID_MISMATCH');
            expect(result.error.mcp_code).toBe(MCP_ERROR.BINDING_MISSING);
        }
    });

    it('should reject when envelope body missing mcpMessage', () => {
        const broken: NegotiationEnvelope = {
            ...makeEnvelopeWithMcpBody(),
            body: {} as Record<string, unknown>,
        };
        const result = outgoingEnvelopeToMCPResponse(broken, 'mcp-client-1');
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe(
                'ENVELOPE_BODY_MISSING_MCP_MESSAGE',
            );
        }
    });
});

describe('processSingleHopMCPCall (T41/T42)', () => {
    it('T42: should forward incomingEnvelope when same-hop (thisServer === nextHop)', () => {
        // T42: same-hop local routing → forward incomingEnvelope
        const env = makeEnvelopeWithMcpBody({ mcpClientId: 'mcp-client-1' });
        const result = processSingleHopMCPCall({
            thisServerId: 'srv-A',
            nextHopMcpServer: 'srv-A',
            incomingEnvelope: env,
            expectedMcpClientId: 'mcp-client-1',
        });
        expect(result.ok).toBe(true);
        if (result.ok) {
            // forward incomingEnvelope; does not construct a new envelope
            expect(result.outgoingEnvelope).toBe(env);
        }
    });

    it('T41: should fail-closed mcp_error_cross_hop_deferred when cross-hop (thisServer !== nextHop)', () => {
        // T41: cross-hop forward → fail-closed `mcp_error_cross_hop_deferred`
        const env = makeEnvelopeWithMcpBody({ mcpClientId: 'mcp-client-1' });
        const result = processSingleHopMCPCall({
            thisServerId: 'srv-A',
            nextHopMcpServer: 'srv-B',
            incomingEnvelope: env,
            expectedMcpClientId: 'mcp-client-1',
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.mcp_code).toBe(MCP_ERROR.CROSS_HOP_DEFERRED);
            expect(result.error.internal_code).toBe('CROSS_HOP_DEFERRED_PHASE6');
        }
    });

    it('should reject when mcpClientId mismatches (binding misalignment)', () => {
        const env = makeEnvelopeWithMcpBody({ mcpClientId: 'mcp-client-1' });
        const result = processSingleHopMCPCall({
            thisServerId: 'srv-A',
            nextHopMcpServer: 'srv-A',
            incomingEnvelope: env,
            expectedMcpClientId: 'mcp-client-OTHER',
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe('MCP_CLIENT_ID_MISMATCH');
        }
    });

    it('should reject when incomingEnvelope.body is missing', () => {
        const broken: NegotiationEnvelope = {
            ...makeEnvelopeWithMcpBody(),
            body: undefined as unknown as Record<string, unknown>,
        };
        const result = processSingleHopMCPCall({
            thisServerId: 'srv-A',
            nextHopMcpServer: 'srv-A',
            incomingEnvelope: broken,
            expectedMcpClientId: 'mcp-client-1',
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe('INCOMING_ENVELOPE_MISSING');
        }
    });

    it('should reject when envelope body missing mcpMessage', () => {
        const env: NegotiationEnvelope = {
            ...makeEnvelopeWithMcpBody(),
            body: { mcpClientId: 'mcp-client-1' } as unknown as Record<
                string,
                unknown
            >,
        };
        const result = processSingleHopMCPCall({
            thisServerId: 'srv-A',
            nextHopMcpServer: 'srv-A',
            incomingEnvelope: env,
            expectedMcpClientId: 'mcp-client-1',
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe(
                'INCOMING_ENVELOPE_BODY_MISSING_MCP_MESSAGE',
            );
        }
    });

    it('should propagate cross-hop fail-closed for any thisServer/nextHop pair where they differ', () => {
        // multiple cases ensure fail-closed cannot be bypassed
        const cases = [
            ['srv-A', 'srv-B'],
            ['srv-1', 'srv-2'],
            ['', 'srv-X'],
            ['srv-X', ''],
        ];
        for (const [a, b] of cases) {
            const result = processSingleHopMCPCall({
                thisServerId: a as string,
                nextHopMcpServer: b as string,
                incomingEnvelope: makeEnvelopeWithMcpBody(),
                expectedMcpClientId: 'mcp-client-1',
            });
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.error.mcp_code).toBe(MCP_ERROR.CROSS_HOP_DEFERRED);
            }
        }
    });
});

describe('MCPEnvelopeAdapterImpl', () => {
    it('should adaptIncoming when envelope body matches mcpMessage', async () => {
        const adapter = new MCPEnvelopeAdapterImpl('srv-A');
        const msg = makeMcpMessage();
        const env = makeEnvelopeWithMcpBody({ mcpMessage: msg });
        const result = await adapter.adaptIncoming(msg, env);
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.envelope).toBe(env);
        }
    });

    it('should reject when envelope body.mcpMessage diverges (id mismatch)', async () => {
        const adapter = new MCPEnvelopeAdapterImpl('srv-A');
        const msg1 = makeMcpMessage({ id: 'req-A' });
        const msg2 = makeMcpMessage({ id: 'req-B' });
        const env = makeEnvelopeWithMcpBody({ mcpMessage: msg1 });
        const result = await adapter.adaptIncoming(msg2, env);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.error.internal_code).toBe(
                'MCP_MESSAGE_ENVELOPE_BODY_MISMATCH',
            );
        }
    });
});

describe('extractMCPCallParams helper', () => {
    it('should return params when envelope body has mcpMessage with params', () => {
        const env = makeEnvelopeWithMcpBody();
        const params = extractMCPCallParams(env);
        expect(params).not.toBeNull();
        expect(params!.tool).toBe('echo');
        expect(params!.arguments.value).toBe(100);
        expect(params!.arguments.currency).toBe('USD');
    });

    it('should return null when envelope body missing mcpMessage', () => {
        const env: NegotiationEnvelope = {
            ...makeEnvelopeWithMcpBody(),
            body: {} as Record<string, unknown>,
        };
        expect(extractMCPCallParams(env)).toBeNull();
    });
});

// ─── OUT-OF-SCOPE guard ──────────────────────────────

describe('OUT-OF-SCOPE guard', () => {
    it('source file envelope-adapter.ts must NOT contain "mint" / "sign-holder" / "forward-envelope" tokens', () => {
        // grep verify: the envelope-adapter.ts source contains no sub-token mint / holderProof / forward-envelope keyword
        // the cross-hop branch is fully deleted; fail-closed forbids partial-acceptance
        const sourcePath = resolve(__dirname, '../envelope-adapter.ts');
        const source = readFileSync(sourcePath, 'utf-8');

        // forbidden: mint / sign-holder / forward-envelope (cross-hop sub-token mint+sign dead code)
        // note: comments may reference these words to explain OUT-OF-SCOPE — the test excludes comment lines
        const codeOnly = source
            .split('\n')
            .filter((line) => {
                const trimmed = line.trim();
                // exclude single-line comments
                if (trimmed.startsWith('//')) return false;
                // exclude jsdoc / block comments (rough — only excludes lines starting with *)
                if (trimmed.startsWith('*')) return false;
                if (trimmed.startsWith('/*')) return false;
                if (trimmed.startsWith('*/')) return false;
                return true;
            })
            .join('\n');

        // grep: non-comment source lines must not contain
        expect(codeOnly).not.toMatch(/\bmint\b/i);
        expect(codeOnly).not.toMatch(/sign[-_]holder/i);
        expect(codeOnly).not.toMatch(/forward[-_]envelope/i);
    });

    it('MCPCrossHopDeferredError must be importable from envelope-adapter via cross-hop guard', () => {
        // invariant: envelope-adapter achieves fail-closed by importing cross-hop-guard.assertSameHop
        // collaborates with the already-implemented cross-hop guard
        const err = new MCPCrossHopDeferredError('srv-A', 'srv-B');
        expect(err.mcp_code).toBe(MCP_ERROR.CROSS_HOP_DEFERRED);
        expect(err.internal_code).toBe('CROSS_HOP_DEFERRED_PHASE6');
    });
});
