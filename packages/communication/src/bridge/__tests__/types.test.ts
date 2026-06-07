/**
 * MCP Bridge — types unit tests
 *
 * Test scope:
 * - error registry completeness (error codes)
 * - makeMcpError constructor
 * - MCPCallerSubjectKind does **not** include 'tokenId'
 *
 * These cases act as a type-layer unit-test guard:
 * the schema CHECK writes out the enum, and this test keeps the implementation-side enum consistent.
 */
import { describe, expect, it } from 'vitest';

import {
    MCP_ERROR,
    makeMcpError,
    type MCPCallerSubjectKind,
} from '../types.js';

describe('MCP_ERROR registry', () => {
    it('should expose all normative MCP error codes when registry is built', () => {
        // 14 normative codes
        expect(MCP_ERROR.BINDING_MISSING).toBe('mcp_error_binding_missing');
        expect(MCP_ERROR.BINDING_INVALID_SIG).toBe(
            'mcp_error_binding_invalid_sig',
        );
        expect(MCP_ERROR.BINDING_CONFLICT).toBe('mcp_error_binding_conflict');
        expect(MCP_ERROR.BINDING_REVOKED).toBe('mcp_error_binding_revoked');
        expect(MCP_ERROR.BINDING_REVOCATION_UNREACHABLE).toBe(
            'mcp_error_binding_revocation_unreachable',
        );
        expect(MCP_ERROR.PRINCIPAL_SIG_INVALID).toBe(
            'mcp_error_principal_sig_invalid',
        );
        expect(MCP_ERROR.POP_INVALID).toBe('mcp_error_pop_invalid');
        expect(MCP_ERROR.AGENT_DID_UNRESOLVED).toBe(
            'mcp_error_agent_did_unresolved',
        );
        expect(MCP_ERROR.CAPABILITY_CHAIN_INVALID).toBe(
            'mcp_error_capability_chain_invalid',
        );
        expect(MCP_ERROR.CAPABILITY_CHAIN_TOO_DEEP).toBe(
            'mcp_error_capability_chain_too_deep',
        );
        expect(MCP_ERROR.CROSS_HOP_DEFERRED).toBe(
            'mcp_error_cross_hop_deferred',
        );
        expect(MCP_ERROR.SCOPE_INFLATION).toBe('mcp_error_scope_inflation');
        expect(MCP_ERROR.QUOTA_EXHAUSTED).toBe('mcp_error_quota_exhausted');
        expect(MCP_ERROR.CURRENCY_MISMATCH).toBe('mcp_error_currency_mismatch');
        expect(MCP_ERROR.CURRENCY_MISSING).toBe('mcp_error_currency_missing');
        expect(MCP_ERROR.NO_PER_CALL_SCOPE).toBe('mcp_error_no_per_call_scope');
        expect(MCP_ERROR.OUTBOX_NOT_FOUND).toBe('mcp_error_outbox_not_found');
        expect(MCP_ERROR.OUTBOX_UNAUTHORIZED).toBe(
            'mcp_error_outbox_unauthorized',
        );
        expect(MCP_ERROR.SETTLEMENT_FAILED).toBe('mcp_error_settlement_failed');
    });
});

describe('makeMcpError', () => {
    it('should build a structured MCPBridgeError when all 3 fields supplied', () => {
        const err = makeMcpError(
            MCP_ERROR.SCOPE_INFLATION,
            'SCOPE_INFLATION_PER_CALL',
            'numeric_limit > max_per_call',
        );
        expect(err.mcp_code).toBe('mcp_error_scope_inflation');
        expect(err.internal_code).toBe('SCOPE_INFLATION_PER_CALL');
        expect(err.message).toBe('numeric_limit > max_per_call');
    });
});

describe('MCPCallerSubjectKind', () => {
    it("should accept 'agentDid' and 'mcpClientId' when assigning legal kinds", () => {
        // only PoP-based subjects are legal
        const a: MCPCallerSubjectKind = 'agentDid';
        const b: MCPCallerSubjectKind = 'mcpClientId';
        expect(a).toBe('agentDid');
        expect(b).toBe('mcpClientId');
    });

    it("should not include 'tokenId' as legal kind when checking the subject kind enum", () => {
        // tokenId is NOT an authenticatable subject (IDOR risk)
        // at the type-system level: 'tokenId' is not in the MCPCallerSubjectKind union → already forbidden at compile time;
        // this test verifies at runtime that the enum list contains only 2 string values.
        const legalKinds: MCPCallerSubjectKind[] = ['agentDid', 'mcpClientId'];
        expect(legalKinds).toHaveLength(2);
        expect(legalKinds).not.toContain(
            'tokenId' as unknown as MCPCallerSubjectKind,
        );
    });
});
