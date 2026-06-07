import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import type {
    CapabilityToken,
    DelegationProof,
    DID,
    Signature,
    Timestamp,
} from '@coivitas/types';

import {
    checkTokenForAction,
    didKeyFromPublicKey,
    issueCapabilityToken,
    verifyCapabilityToken,
} from '../index.js';

describe('verifyCapabilityToken', () => {
    it('detects tampering and expiry while leaving revocation to other layers', () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const issuedTo =
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID;

        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'QUOTE',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount_usd',
                        max: 500,
                        currency: 'USD',
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        expect(
            verifyCapabilityToken(
                token,
                '2026-04-21T10:05:00.000Z' as Timestamp,
            ),
        ).toEqual({
            valid: true,
        });

        expect(
            verifyCapabilityToken(
                {
                    ...token,
                    capabilities: [
                        {
                            action: 'QUOTE',
                            scope: {
                                type: 'numeric_limit',
                                field: 'amount_usd',
                                max: 600,
                                currency: 'USD',
                            },
                        },
                    ],
                },
                '2026-04-21T10:05:00.000Z' as Timestamp,
            ),
        ).toEqual({
            valid: false,
            code: 'SIGNATURE_INVALID',
            message: 'Capability token signature verification failed.',
        });

        expect(
            verifyCapabilityToken(
                token,
                '2026-04-23T10:00:00.000Z' as Timestamp,
            ),
        ).toEqual({
            valid: false,
            code: 'TOKEN_EXPIRED',
            message: 'Capability token has expired.',
        });
    });

    it('checks action and scope semantics', () => {
        const issuer = generateKeyPair();
        const issuerDid = didKeyFromPublicKey(
            Buffer.from(issuer.publicKey, 'hex'),
        );
        const issuedTo =
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID;

        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
                {
                    action: 'QUOTE',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 500,
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        expect(
            checkTokenForAction(
                token,
                'INQUIRY',
                { recipient: 'supplier-a' },
                issuedTo,
            ),
        ).toEqual({
            allowed: true,
        });
        expect(
            checkTokenForAction(token, 'QUOTE', { amount: 500 }, issuedTo),
        ).toEqual({
            allowed: true,
        });
        expect(
            checkTokenForAction(token, 'QUOTE', { amount: 700 }, issuedTo),
        ).toEqual({
            allowed: false,
            code: 'SCOPE_EXCEEDED',
            message: 'Field amount exceeds the numeric limit.',
        });
        expect(
            checkTokenForAction(
                token,
                'INQUIRY',
                { recipient: 'supplier-b' },
                issuedTo,
            ),
        ).toEqual({
            allowed: false,
            code: 'SCOPE_EXCEEDED',
            message: 'Field recipient is outside the allowlist.',
        });
    });
});

// Transition-period gate tests for the delegation (0.2.0) format.
// verifyCapabilityToken must intercept 0.2.0-specific formats before signature verification,
// to avoid the single-hop verifier mis-judging them as SIGNATURE_INVALID or wrongly admitting an unverified delegation chain.
describe('verifyCapabilityToken transition gates', () => {
    const issuer = generateKeyPair();
    const issuerDid = didKeyFromPublicKey(Buffer.from(issuer.publicKey, 'hex'));
    const issuedTo =
        'did:agent:00112233445566778899aabbccddeeff00112233' as DID;
    const delegateeDid =
        'did:agent:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1' as DID;
    const now = '2026-04-21T10:05:00.000Z' as Timestamp;

    const issueBaseToken = (): CapabilityToken =>
        issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'recipient',
                        values: ['supplier-a'],
                    },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

    it('rejects 0.1.0 token containing temporal_scope', () => {
        const base = issueBaseToken();
        const forged: CapabilityToken = {
            ...base,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2026-04-21T00:00:00.000Z' as Timestamp,
                        notAfter: '2026-04-22T00:00:00.000Z' as Timestamp,
                    },
                },
            ],
        };
        const result = verifyCapabilityToken(forged, now);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/temporal_scope/);
    });

    it('rejects token with non-empty delegationChain', () => {
        const base = issueBaseToken();
        const delegationProof: DelegationProof = {
            parentTokenId: 'urn:cap:11111111-1111-4111-8111-111111111111',
            delegatorDid: issuedTo,
            delegateeDid,
            parentCapabilities: base.capabilities,
            parentExpiresAt: base.expiresAt,
            attenuatedCapabilities: base.capabilities,
            proof: {
                type: 'Ed25519Signature2026',
                created: base.issuedAt,
                verificationMethod: `${issuedTo}#key-1`,
                value: 'b'.repeat(128) as Signature,
            },
        };
        const delegated: CapabilityToken = {
            ...base,
            specVersion: '0.2.0',
            delegationChain: [delegationProof],
        };
        const result = verifyCapabilityToken(delegated, now);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/delegation/i);
    });

    it('passes a 0.2.0 token with empty delegationChain + single-hop scopes', () => {
        const base = issueBaseToken();
        // An empty delegationChain array is equivalent to a single-hop token; the transition gate only intercepts non-empty chains.
        const versionedNoChain: CapabilityToken = {
            ...base,
            specVersion: '0.2.0',
            delegationChain: [],
        };
        // Note: because the token signing payload is based on specVersion, mutating specVersion here
        // breaks the signature. This is not the transition gate's expected pass path; it only confirms
        // that delegationChain=[] does not trigger the transition gate; the full 0.2.0 flow is handled elsewhere.
        const result = verifyCapabilityToken(versionedNoChain, now);
        expect(result.code).not.toBe('INVALID_TOKEN_FORMAT');
    });

    // Supplemental gate: after the schema relaxed verificationMethod,
    // a non-delegated token can declare a did:agent verificationMethod yet verify only against issuerDid,
    // creating an unaudited-field gap outside the signature. This must be explicitly rejected in the verifier.
    it('rejects non-delegated token whose verificationMethod is did:agent', () => {
        const base = issueBaseToken();
        const forgedAgentVm: CapabilityToken = {
            ...base,
            proof: {
                ...base.proof,
                verificationMethod:
                    'did:agent:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2#key-1',
            },
        };
        const result = verifyCapabilityToken(forgedAgentVm, now);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/did:key/);
    });
});
