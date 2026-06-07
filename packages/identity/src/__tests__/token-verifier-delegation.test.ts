/**
 * Test: token verifier integration with the delegation chain
 *
 * 03a: verifyCapabilityTokenWithChain() behavior for tokens with/without a chain
 * 03b: checkTokenForAction() uses the leaf attenuatedCapabilities for scope evaluation
 * 03c: action checks for tokens with/without a chain
 */
import { describe, expect, it, vi } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import type {
    Capability,
    CapabilityToken,
    DID,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';

import {
    checkTokenForAction,
    delegateCapabilityToken,
    didKeyFromPublicKey,
    issueCapabilityToken,
    verifyCapabilityToken,
    verifyCapabilityTokenWithChain,
} from '../index.js';

// Test mock that wraps a string public key into ResolvedPublicKeys in the STABLE state
// (single-key fixture, no key rotation; the ROTATING path is covered by key-rotation.integration.test.ts).
function wrapKey(publicKey: string): ResolvedPublicKeys {
    return { current: publicKey, rotationState: 'STABLE' };
}

// ─── Helper functions ─────────────────────────────────────────────────────────────────

function makeIssuer() {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    return { ...kp, did };
}

const AGENT_A = 'did:agent:aabbccddee112233445566778899aabbccddeeff' as DID;
const AGENT_B = 'did:agent:bbccddee11223344556677889900aabbccddeeff' as DID;

const FUTURE = '2030-01-01T00:00:00.000Z' as Timestamp;
const NOW = '2026-04-21T12:00:00.000Z' as Timestamp;
const ISSUED_AT = '2026-01-01T00:00:00.000Z' as Timestamp;
const REVOCATION_URL = 'https://revocation.example.com/v1/{id}';

function makeRootToken(
    issuer: ReturnType<typeof makeIssuer>,
    caps: Capability[],
    issuedTo: DID = AGENT_A,
): CapabilityToken {
    return issueCapabilityToken({
        issuerDid: issuer.did,
        issuedTo,
        capabilities: caps,
        expiresAt: FUTURE,
        revocationUrl: REVOCATION_URL,
        issuerPrivateKey: issuer.privateKey,
        issuedAt: ISSUED_AT,
    });
}

function makeDelegated(
    rootToken: CapabilityToken,
    delegatorPrivateKey: string,
    delegateeDid: DID,
    attenuatedCapabilities: Capability[],
): CapabilityToken {
    return delegateCapabilityToken({
        parentToken: rootToken,
        delegatorPrivateKey,
        delegateeDid,
        attenuatedCapabilities,
        expiresAt: FUTURE,
        revocationUrl: REVOCATION_URL,
        issuedAt: '2026-04-21T00:00:00.000Z' as Timestamp,
    });
}

// ─── 03a: verifyCapabilityTokenWithChain ─────────────────────────────────────

describe('verifyCapabilityTokenWithChain — 03a', () => {
    it('should pass a valid single-hop token without delegationChain when resolvePublicKey provided', async () => {
        const issuer = makeIssuer();
        const token = makeRootToken(issuer, [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['books'] },
            },
        ]);

        const resolvePublicKey = vi.fn().mockResolvedValue(null);
        const result = await verifyCapabilityTokenWithChain(
            token,
            NOW,
            resolvePublicKey,
        );
        expect(result.valid).toBe(true);
        expect(resolvePublicKey).not.toHaveBeenCalled();
    });

    it('should pass a valid delegated token when chain resolves correctly', async () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books', 'electronics'],
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
        );

        const resolvePublicKey = vi.fn().mockImplementation((did: string) => {
            if (did === AGENT_A)
                return Promise.resolve(wrapKey(agentAKp.publicKey));
            return Promise.resolve(null);
        });
        // A non-empty chain requires resolveToken (fail-closed); otherwise the
        // delegation chain is judged INVALID_TOKEN_FORMAT. Once integrated, a parent-token resolution port must be provided.
        const resolveToken = vi
            .fn()
            .mockImplementation(
                (tokenId: string): Promise<CapabilityToken | null> => {
                    if (tokenId === rootToken.id)
                        return Promise.resolve(rootToken);
                    return Promise.resolve(null);
                },
            );

        const result = await verifyCapabilityTokenWithChain(
            delegated,
            NOW,
            resolvePublicKey,
            resolveToken,
            // A non-empty chain requires isRevoked (fail-closed)
            async () => false,
        );
        expect(result.valid).toBe(true);
    });

    it('should reject a delegated token when chain signature is invalid', async () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
        );

        // Return the wrong public key -> signature verification fails
        const wrongKp = generateKeyPair();
        const resolvePublicKey = vi
            .fn()
            .mockResolvedValue(wrapKey(wrongKp.publicKey));

        const result = await verifyCapabilityTokenWithChain(
            delegated,
            NOW,
            resolvePublicKey,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('DELEGATION_CHAIN_INVALID');
    });

    it('should reject expired token even with valid chain', async () => {
        const issuer = makeIssuer();
        const token = makeRootToken(issuer, [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['books'] },
            },
        ]);

        const resolvePublicKey = vi.fn().mockResolvedValue(null);
        const expiredNow = '2031-01-01T00:00:00.000Z' as Timestamp;
        const result = await verifyCapabilityTokenWithChain(
            token,
            expiredNow,
            resolvePublicKey,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('TOKEN_EXPIRED');
    });

    it('should preserve existing verifyCapabilityToken sync behavior for non-delegated tokens', () => {
        const issuer = makeIssuer();
        const token = makeRootToken(issuer, [
            {
                action: 'INQUIRY',
                scope: { type: 'allowlist', field: 'cat', values: ['books'] },
            },
        ]);

        const result = verifyCapabilityToken(token, NOW);
        expect(result.valid).toBe(true);
    });
});

// ─── Additional delegation-chain gates ───────────────────────────────────────────────────────────

describe('verifyCapabilityTokenWithChain — additional gates', () => {
    it('should reject delegated token with tampered top-level proof', async () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
        );

        // Tamper with the top-level token.proof.value: the chain structure is valid but the top-level signature is invalid
        const tampered = {
            ...delegated,
            proof: {
                ...delegated.proof,
                value: 'a'.repeat(
                    128,
                ) as import('@coivitas/types').Signature,
            },
        };

        const resolvePublicKey = vi.fn().mockImplementation((did: string) => {
            if (did === AGENT_A)
                return Promise.resolve(wrapKey(agentAKp.publicKey));
            return Promise.resolve(null);
        });
        // Semantics: the chain structure is valid (it passes the validator), but the top-level signature
        // is tampered. It must fail as SIGNATURE_INVALID at top-level proof verification — so resolveToken
        // must correctly return rootToken to let chain verification pass first.
        const resolveToken = vi
            .fn()
            .mockImplementation(
                (tokenId: string): Promise<CapabilityToken | null> => {
                    if (tokenId === rootToken.id)
                        return Promise.resolve(rootToken);
                    return Promise.resolve(null);
                },
            );

        const result = await verifyCapabilityTokenWithChain(
            tampered,
            NOW,
            resolvePublicKey,
            resolveToken,
            // A non-empty chain requires isRevoked (fail-closed)
            async () => false,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('SIGNATURE_INVALID');
    });

    it('should reject 0.1.0 delegated token even when chain is otherwise valid', async () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
        );

        // Forge specVersion as 0.1.0 (delegation chains are a 0.2.0 feature)
        const oldVersion = { ...delegated, specVersion: '0.1.0' as const };

        const resolvePublicKey = vi.fn().mockImplementation((did: string) => {
            if (did === AGENT_A)
                return Promise.resolve(wrapKey(agentAKp.publicKey));
            return Promise.resolve(null);
        });

        const result = await verifyCapabilityTokenWithChain(
            oldVersion,
            NOW,
            resolvePublicKey,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/0\.1\.0/);
    });
});

// ─── 03b+03c: checkTokenForAction with the delegation chain ────────────────────────────────────

describe('checkTokenForAction with delegation chain — 03b + 03c', () => {
    it('should allow action within leaf attenuatedCapabilities when chain is present', () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books', 'electronics'],
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
        );

        // AGENT_B holds this delegated token; operations within the attenuated scope should be allowed
        const result = checkTokenForAction(
            delegated,
            'INQUIRY',
            { cat: 'books' },
            AGENT_B,
        );
        expect(result.allowed).toBe(true);
    });

    it('should deny action that exceeds leaf attenuatedCapabilities even if parent allowed it', () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books', 'electronics'],
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
        );

        // 'electronics' is allowed by the root token, but the chain leaf only allows 'books', so it should be denied
        const result = checkTokenForAction(
            delegated,
            'INQUIRY',
            { cat: 'electronics' },
            AGENT_B,
        );
        expect(result.allowed).toBe(false);
        expect(result.code).toBe('SCOPE_EXCEEDED');
    });

    it('should deny action that is not in leaf attenuatedCapabilities', () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
                // TRANSFER has been attenuated away
            ],
        );

        const result = checkTokenForAction(
            delegated,
            'TRANSFER',
            { amount: 500 },
            AGENT_B,
        );
        expect(result.allowed).toBe(false);
        expect(result.code).toBe('INVALID_ACTION');
    });

    it('should apply numeric limit from leaf attenuatedCapabilities not parent', () => {
        const issuer = makeIssuer();
        const agentAKp = generateKeyPair();

        const rootToken = makeRootToken(
            issuer,
            [
                {
                    action: 'TRANSFER',
                    scope: {
                        type: 'numeric_limit',
                        field: 'amount',
                        max: 1000,
                    },
                },
            ],
            AGENT_A,
        );

        const delegated = makeDelegated(
            rootToken,
            agentAKp.privateKey,
            AGENT_B,
            [
                {
                    action: 'TRANSFER',
                    scope: { type: 'numeric_limit', field: 'amount', max: 200 },
                },
            ],
        );

        expect(
            checkTokenForAction(
                delegated,
                'TRANSFER',
                { amount: 200 },
                AGENT_B,
            ),
        ).toEqual({ allowed: true });
        expect(
            checkTokenForAction(
                delegated,
                'TRANSFER',
                { amount: 201 },
                AGENT_B,
            ),
        ).toMatchObject({
            allowed: false,
            code: 'SCOPE_EXCEEDED',
        });
    });

    it('should work normally for non-delegated token without chain', () => {
        const issuer = makeIssuer();
        const token = makeRootToken(
            issuer,
            [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'allowlist',
                        field: 'cat',
                        values: ['books'],
                    },
                },
            ],
            AGENT_A,
        );

        expect(
            checkTokenForAction(token, 'INQUIRY', { cat: 'books' }, AGENT_A),
        ).toEqual({ allowed: true });
        expect(
            checkTokenForAction(
                token,
                'INQUIRY',
                { cat: 'electronics' },
                AGENT_A,
            ),
        ).toMatchObject({
            allowed: false,
            code: 'SCOPE_EXCEEDED',
        });
    });
});
