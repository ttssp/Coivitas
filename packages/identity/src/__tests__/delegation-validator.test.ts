import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import type {
    Capability,
    CapabilityToken,
    DcErrorCode,
    DelegationProof,
    DID,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';
import { DC_VERSION, SPEC_VERSION_0_2_0 } from '@coivitas/types';

import {
    assertNeverDcError,
    handleDcError,
    resolveDcVersion,
    validateDelegationChain,
} from '../delegation-validator.js';
import {
    delegateCapabilityToken,
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '../index.js';

// ─── Shared test utilities ─────────────────────────────────────────────────────────────

function makeIssuer() {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    return { ...kp, did };
}

function makeAgentKeypair(suffix: string) {
    const kp = generateKeyPair();
    // did:agent: format: 40 hex chars
    const did = `did:agent:${suffix.padStart(40, '0')}` as DID;
    return { ...kp, did };
}

const ROOT_EXPIRES = '2030-01-01T00:00:00.000Z' as Timestamp;
const ISSUED_AT = '2026-01-01T00:00:00.000Z' as Timestamp;
const CHILD_EXPIRES = '2029-06-01T00:00:00.000Z' as Timestamp;
const CHILD_EXPIRES_2 = '2028-01-01T00:00:00.000Z' as Timestamp;

// The original fixture's action='TRANSFER' is not in ACTION_VOCABULARY (schema would reject it).
// Switched to INQUIRY (allowlist) + CONFIRM (numeric_limit) to align with ACTION_VOCABULARY.
const CAPS_FULL: Capability[] = [
    {
        action: 'INQUIRY',
        scope: {
            type: 'allowlist',
            field: 'category',
            values: ['electronics', 'books'],
        },
    },
    {
        action: 'CONFIRM',
        scope: { type: 'numeric_limit', field: 'amount', max: 1000 },
    },
];

const CAPS_REDUCED: Capability[] = [
    {
        action: 'INQUIRY',
        scope: {
            type: 'allowlist',
            field: 'category',
            values: ['electronics'],
        },
    },
    {
        action: 'CONFIRM',
        scope: { type: 'numeric_limit', field: 'amount', max: 500 },
    },
];

const CAPS_FURTHER_REDUCED: Capability[] = [
    {
        action: 'INQUIRY',
        scope: {
            type: 'allowlist',
            field: 'category',
            values: ['electronics'],
        },
    },
    {
        action: 'CONFIRM',
        scope: { type: 'numeric_limit', field: 'amount', max: 200 },
    },
];

function makeRootToken(
    issuer: ReturnType<typeof makeIssuer>,
    issuedTo: DID,
    caps = CAPS_FULL,
): CapabilityToken {
    return issueCapabilityToken({
        issuerDid: issuer.did,
        issuedTo,
        capabilities: caps,
        expiresAt: ROOT_EXPIRES,
        revocationUrl: 'https://rev.example.com/v1/{id}',
        issuerPrivateKey: issuer.privateKey,
        issuedAt: ISSUED_AT,
    });
}

/**
 * Create a token with a single-hop delegation chain (parent → agent1)
 */
function makeOneLevelChain(
    issuer: ReturnType<typeof makeIssuer>,
    agent1: ReturnType<typeof makeAgentKeypair>,
) {
    const rootToken = makeRootToken(issuer, agent1.did);
    const child = delegateCapabilityToken({
        parentToken: rootToken,
        delegatorPrivateKey: agent1.privateKey,
        delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
        attenuatedCapabilities: CAPS_REDUCED,
        expiresAt: CHILD_EXPIRES,
        revocationUrl: 'https://rev.example.com/v1/{id}',
        issuedAt: ISSUED_AT,
    });
    return { rootToken, child };
}

/**
 * Dual-key resolver mock (DID → ResolvedPublicKeys)
 *
 * validateDelegationChain's 2nd argument was upgraded from (did) => string|null
 * to (did) => ResolvedPublicKeys|null, supporting ROTATING dual-key fallback.
 */
function makeResolver(entries: [DID, string][]) {
    // Wrap a string public key into a STABLE-state ResolvedPublicKeys
    const map = new Map(entries);
    return (did: DID): Promise<ResolvedPublicKeys | null> => {
        const key = map.get(did);
        if (key === undefined) return Promise.resolve(null);
        return Promise.resolve({ current: key, rotationState: 'STABLE' });
    };
}

/**
 * Dual-key resolver mock that supports the full ResolvedPublicKeys structure
 * Used for ROTATING dual-key fallback tests
 */
function makeResolvedKeysResolver(entries: [DID, ResolvedPublicKeys][]) {
    const map = new Map(entries);
    return (did: DID): Promise<ResolvedPublicKeys | null> =>
        Promise.resolve(map.get(did) ?? null);
}

/**
 * A non-empty chain requires resolveToken.
 * Utility that returns a preset token map by tokenId for happy-path tests.
 */
function makeResolveToken(tokens: CapabilityToken[]) {
    const map = new Map(tokens.map((t) => [t.id, t] as const));
    return (tokenId: string): Promise<CapabilityToken | null> =>
        Promise.resolve(map.get(tokenId) ?? null);
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

describe('validateDelegationChain', () => {
    describe('non-delegated token (no delegation chain)', () => {
        it('should return valid=true with depth=0 when delegationChain is undefined', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const rootToken = makeRootToken(issuer, agent1.did);

            const result = await validateDelegationChain(rootToken, () =>
                Promise.resolve(null),
            );
            expect(result).toEqual({ valid: true, depth: 0 });
        });

        it('should return valid=true with depth=0 when delegationChain is empty array', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const rootToken = makeRootToken(issuer, agent1.did);
            const tokenWithEmptyChain: CapabilityToken = {
                ...rootToken,
                delegationChain: [],
            };

            const result = await validateDelegationChain(
                tokenWithEmptyChain,
                () => Promise.resolve(null),
            );
            expect(result).toEqual({ valid: true, depth: 0 });
        });
    });

    describe('normal single-hop delegation chain validation', () => {
        it('should return valid=true for a valid 1-level delegation chain', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
            expect(result.depth).toBe(1);
        });

        it('should return depth=1 for single-hop chain', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.depth).toBe(1);
        });
    });

    describe('three-level delegation chain validation', () => {
        it('should return valid=true for a valid 3-level delegation chain', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            // Root → agent1
            const rootToken = makeRootToken(issuer, agent1.did);
            // agent1 → agent2
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            // agent2 → agent3
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = makeResolveToken([rootToken, hop1]);
            const result = await validateDelegationChain(
                hop2,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
            expect(result.depth).toBe(2);
        });
    });

    describe('depth-limit check', () => {
        it('should return DEPTH_EXCEEDED when chain length exceeds MAX_DELEGATION_DEPTH', async () => {
            const issuer = makeIssuer();
            const agents = Array.from({ length: 7 }, (_, i) =>
                makeAgentKeypair(`${i.toString(16).repeat(40)}`),
            );

            // Construct an over-depth fake token (inject delegationChain directly, skipping signature verification to focus on the depth test)
            const rootToken = makeRootToken(issuer, agents[0]!.did);
            // Create 6 DelegationProofs (exceeding MAX_DELEGATION_DEPTH=5)
            const fakeChain: DelegationProof[] = Array.from(
                { length: 6 },
                (_, i) => ({
                    parentTokenId: `urn:cap:fake-${i}`,
                    delegatorDid: agents[i]!.did,
                    delegateeDid: agents[i + 1]!.did,
                    parentCapabilities: CAPS_FULL,
                    parentExpiresAt: ROOT_EXPIRES,
                    attenuatedCapabilities: CAPS_REDUCED,
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: ISSUED_AT,
                        verificationMethod: `${agents[i]!.did}#key-1`,
                        value: '0'.repeat(
                            128,
                        ) as CapabilityToken['proof']['value'],
                    },
                }),
            );
            // A synthesized delegated token must have specVersion=0.2.0 (rootToken is 0.1.0)
            const deepToken: CapabilityToken = {
                ...rootToken,
                specVersion: SPEC_VERSION_0_2_0,
                delegationChain: fakeChain,
            };

            const result = await validateDelegationChain(deepToken, () =>
                Promise.resolve(null),
            );
            expect(result.valid).toBe(false);
            // The schema gate hits first (schema limits chain length); only if the schema
            // lets it through does it reach the validator's DEPTH_EXCEEDED. Both are fail-closed rejections.
            expect(['DEPTH_EXCEEDED', 'INVALID_TOKEN_FORMAT']).toContain(
                result.reason,
            );
        });
    });

    describe('cycle detection', () => {
        it('should return CYCLE_DETECTED when a DID appears multiple times in delegation path', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );

            // Manually construct a cycle: agent1 → agent2 → agent1
            const rootToken = makeRootToken(issuer, agent1.did);
            const fakeChain: DelegationProof[] = [
                {
                    parentTokenId: rootToken.id,
                    delegatorDid: agent1.did,
                    delegateeDid: agent2.did,
                    parentCapabilities: CAPS_FULL,
                    parentExpiresAt: ROOT_EXPIRES,
                    attenuatedCapabilities: CAPS_REDUCED,
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: ISSUED_AT,
                        verificationMethod: `${agent1.did}#key-1`,
                        value: '0'.repeat(
                            128,
                        ) as CapabilityToken['proof']['value'],
                    },
                },
                {
                    parentTokenId: 'urn:cap:fake-2',
                    delegatorDid: agent2.did,
                    delegateeDid: agent1.did, // cycle!
                    parentCapabilities: CAPS_REDUCED,
                    parentExpiresAt: ROOT_EXPIRES,
                    attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                    proof: {
                        type: 'Ed25519Signature2026',
                        created: ISSUED_AT,
                        verificationMethod: `${agent2.did}#key-1`,
                        value: '0'.repeat(
                            128,
                        ) as CapabilityToken['proof']['value'],
                    },
                },
            ];
            // A synthesized delegated token must have specVersion=0.2.0
            const cyclicToken: CapabilityToken = {
                ...rootToken,
                specVersion: SPEC_VERSION_0_2_0,
                delegationChain: fakeChain,
                issuedTo: agent1.did,
            };

            // A non-empty chain requires resolveToken (this case returns at the CYCLE_DETECTED
            // step; resolveToken is never called).
            const result = await validateDelegationChain(
                cyclicToken,
                () => Promise.resolve(null),
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                () => Promise.resolve(null),
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('CYCLE_DETECTED');
        });
    });

    describe('signature verification', () => {
        it('should return SIGNATURE_INVALID when resolver cannot find public key for delegator', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { child } = makeOneLevelChain(issuer, agent1);

            // resolver returns null (unknown DID); resolveToken must also be non-undefined
            // A non-empty chain requires isRevoked (fail-closed)
            const result = await validateDelegationChain(
                child,
                () => Promise.resolve(null),
                async () => false,
                undefined,
                () => Promise.resolve(null),
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should return SIGNATURE_INVALID when DelegationProof signature is tampered', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Tamper with the first DelegationProof's signature
            const tamperedProof: DelegationProof = {
                ...(child.delegationChain![0] as DelegationProof),
                proof: {
                    ...(child.delegationChain![0] as DelegationProof).proof,
                    value: 'deadbeef'.repeat(
                        16,
                    ) as DelegationProof['proof']['value'],
                },
            };
            const tamperedToken: CapabilityToken = {
                ...child,
                delegationChain: [tamperedProof],
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                tamperedToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            expect(result.brokenAtIndex).toBe(0);
        });
    });

    describe('cascade revocation check', () => {
        it('should return PARENT_TOKEN_REVOKED when a parentTokenId in chain is revoked', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const parentTokenId = (child.delegationChain![0] as DelegationProof)
                .parentTokenId;
            const isRevoked = (tokenId: string): Promise<boolean> =>
                Promise.resolve(tokenId === parentTokenId);
            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);

            const result = await validateDelegationChain(
                child,
                resolver,
                isRevoked,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('PARENT_TOKEN_REVOKED');
            expect(result.revokedTokenId).toBe(parentTokenId);
        });

        it('should return valid=true when no tokens are revoked', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const isRevoked = (): Promise<boolean> => Promise.resolve(false);
            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);

            const result = await validateDelegationChain(
                child,
                resolver,
                isRevoked,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(true);
        });

        it('should cascade revocation: mid-chain parent revoked should fail', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Revoke hop1 (the second proof's parentTokenId)
            const hop1Id = hop1.id;
            const isRevoked = (tokenId: string): Promise<boolean> =>
                Promise.resolve(tokenId === hop1Id);
            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = makeResolveToken([rootToken, hop1]);

            const result = await validateDelegationChain(
                hop2,
                resolver,
                isRevoked,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('PARENT_TOKEN_REVOKED');
            expect(result.revokedTokenId).toBe(hop1Id);
        });
    });

    describe('attenuation rule validation', () => {
        it('should return ATTENUATION_VIOLATED when attenuatedCapabilities exceed parentCapabilities in chain', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);

            // Manually construct a DelegationProof that violates attenuation (attenuated exceeds parent):
            // parentCapabilities must match the real rootToken.capabilities (otherwise
            // capabilitiesEqual's DELEGATION_CHAIN_INVALID would hit first, rather than
            // ATTENUATION_VIOLATED). attenuatedCapabilities adds an extra action that the root
            // does not have (PUBLISH), making attenuated ⊄ parent → violating attenuation.
            const OVER_CAPS: Capability[] = [
                ...CAPS_FULL,
                {
                    action: 'PUBLISH',
                    scope: {
                        type: 'allowlist',
                        field: 'topic',
                        values: ['weather'],
                    },
                },
            ];
            const badProof: DelegationProof = {
                parentTokenId: rootToken.id,
                delegatorDid: agent1.did,
                delegateeDid: agent2.did,
                parentCapabilities: CAPS_FULL, // align with the real parent, bypassing capabilitiesEqual
                parentExpiresAt: ROOT_EXPIRES,
                // attenuated contains an action the parent lacks → validateAttenuation fails
                attenuatedCapabilities: OVER_CAPS,
                proof: (
                    makeOneLevelChain(issuer, agent1).child
                        .delegationChain![0] as DelegationProof
                ).proof,
            };

            // To avoid hitting signature-verification failure first, we need a genuine signature covering it
            // Create with a real chain, then manually modify attenuatedCapabilities (the signature will fail)
            // Here we change the test strategy: directly inject a proof with a genuine signature but with attenuation bypassed
            // In reality this is impossible (the signature protects attenuatedCapabilities)
            // So signature verification fails first, but brokenAtIndex=0 is also a failure
            // To test ATTENUATION_VIOLATED, the signature must pass
            // We cannot forge a signature without knowing the private key → use another approach:
            // Directly create a proof genuinely signed by agent1 but whose parentCaps and attenuatedCaps truly violate the rules

            // Signature construction: re-sign the violating payload with agent1's private key
            const { canonicalize: _canon, sign: _sign } =
                await import('@coivitas/crypto');
            const payload = {
                parentTokenId: badProof.parentTokenId,
                delegatorDid: badProof.delegatorDid,
                delegateeDid: badProof.delegateeDid,
                parentCapabilities: badProof.parentCapabilities,
                parentExpiresAt: badProof.parentExpiresAt,
                attenuatedCapabilities: badProof.attenuatedCapabilities,
            };
            const payloadBytes = new TextEncoder().encode(
                _canon(payload as unknown as Record<string, unknown>),
            );
            const sig = _sign(payloadBytes, agent1.privateKey);

            const realBadProof: DelegationProof = {
                ...badProof,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod: `${agent1.did}#key-1`,
                    value: sig as DelegationProof['proof']['value'],
                },
            };

            const badToken: CapabilityToken = {
                ...rootToken,
                specVersion: SPEC_VERSION_0_2_0, // a delegated token must be 0.2.0
                issuedTo: agent2.did,
                capabilities: CAPS_FULL,
                delegationChain: [realBadProof],
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                badToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('ATTENUATION_VIOLATED');
            expect(result.brokenAtIndex).toBe(0);
        });
    });

    describe('continuity check', () => {
        it('should return DELEGATION_CHAIN_INVALID when chain continuity is broken', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Create a proof for hop2 with wrong parentCapabilities (discontinuous)
            const { sign: cryptoSign, canonicalize: cryptoCanonicalize } =
                await import('@coivitas/crypto');
            const brokenPayload = {
                parentTokenId: hop1.id,
                delegatorDid: agent2.did,
                delegateeDid: agent3.did,
                // parentCapabilities should be CAPS_REDUCED, but CAPS_FULL is used here (discontinuous)
                parentCapabilities: CAPS_FULL,
                parentExpiresAt: hop1.expiresAt,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
            };
            const brokenBytes = new TextEncoder().encode(
                cryptoCanonicalize(
                    brokenPayload as unknown as Record<string, unknown>,
                ),
            );
            const brokenSig = cryptoSign(brokenBytes, agent2.privateKey);
            const brokenProof: DelegationProof = {
                ...brokenPayload,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod: `${agent2.did}#key-1`,
                    value: brokenSig as DelegationProof['proof']['value'],
                },
            };

            const brokenChainToken: CapabilityToken = {
                ...hop1,
                issuedTo: agent3.did,
                capabilities: CAPS_FURTHER_REDUCED,
                delegationChain: [...(hop1.delegationChain ?? []), brokenProof],
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = makeResolveToken([rootToken, hop1]);
            const result = await validateDelegationChain(
                brokenChainToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATION_CHAIN_INVALID');
            expect(result.brokenAtIndex).toBe(1); // breaks at the 2nd node
        });
    });

    describe('leaf capability consistency check', () => {
        it('should return DELEGATION_CHAIN_INVALID when token.capabilities does not match last proof attenuatedCapabilities', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );

            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Tamper with token.capabilities (inconsistent with the attenuatedCapabilities of the last proof in delegationChain)
            // Note: do not modify issuedTo, to avoid triggering DELEGATOR_MISMATCH instead of DELEGATION_CHAIN_INVALID
            const tamperedToken: CapabilityToken = {
                ...child,
                capabilities: CAPS_FULL, // but the chain has CAPS_REDUCED
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                tamperedToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATION_CHAIN_INVALID');
        });
    });

    describe('expiry check', () => {
        it('should return EXPIRY_EXCEEDED when token expiresAt exceeds parentExpiresAt', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );

            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Tamper with the child token's expiresAt (exceeding the root token)
            const overExpiredToken: CapabilityToken = {
                ...child,
                expiresAt: '2035-01-01T00:00:00.000Z' as Timestamp, // > ROOT_EXPIRES (2030)
                issuedTo: agent2.did,
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                overExpiredToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('EXPIRY_EXCEEDED');
        });
    });

    describe('root-node check', () => {
        it('should return ROOT_NOT_PRINCIPAL when token.issuerDid !== token.principalDid', async () => {
            const issuer = makeIssuer();
            const issuer2 = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );

            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Manually modify principalDid so it differs from issuerDid
            const mismatchedToken: CapabilityToken = {
                ...child,
                principalDid: issuer2.did, // differs from issuerDid
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                mismatchedToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('ROOT_NOT_PRINCIPAL');
        });
    });

    describe('delegator DID mismatch', () => {
        it('should return DELEGATOR_MISMATCH when lastProof.delegateeDid !== token.issuedTo', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // child.issuedTo is agent2 (hardcoded in makeOneLevelChain)
            // Change issuedTo to agent3 (mismatching the last proof.delegateeDid)
            const mismatchedToken: CapabilityToken = {
                ...child,
                issuedTo: agent3.did, // not the delegateeDid in the chain
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                mismatchedToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATOR_MISMATCH');
        });

        it('should return DELEGATOR_MISMATCH when mid-chain delegatorDid does not match previous delegateeDid', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );
            const agentX = makeAgentKeypair(
                'ffee1100334455667788990011aabbccddeeffaa',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Manually replace chain[1].delegatorDid with agentX (not hop1's delegateeDid)
            // Requires re-signing (with agentX's private key)
            const { sign: cryptoSign2, canonicalize: cryptoCanonicalize2 } =
                await import('@coivitas/crypto');
            const mismatchPayload = {
                ...(hop2.delegationChain![1] as DelegationProof),
                delegatorDid: agentX.did, // wrong delegator
            };
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const { proof: _, ...signablePayload } = mismatchPayload;
            const mismatchBytes = new TextEncoder().encode(
                cryptoCanonicalize2(
                    signablePayload as unknown as Record<string, unknown>,
                ),
            );
            const mismatchSig = cryptoSign2(mismatchBytes, agentX.privateKey);
            const mismatchedProof: DelegationProof = {
                ...mismatchPayload,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod: `${agentX.did}#key-1`,
                    value: mismatchSig as DelegationProof['proof']['value'],
                },
            };

            const mismatchedToken: CapabilityToken = {
                ...hop2,
                delegationChain: [
                    hop2.delegationChain![0] as DelegationProof,
                    mismatchedProof,
                ],
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agentX.did, agentX.publicKey],
            ]);
            const resolveToken = makeResolveToken([rootToken, hop1]);
            const result = await validateDelegationChain(
                mismatchedToken,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATOR_MISMATCH');
            expect(result.brokenAtIndex).toBe(1);
        });
    });

    describe('resolveToken cross-check', () => {
        it('should return valid=true when resolveToken confirms parent capabilities match', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> =>
                Promise.resolve(tokenId === rootToken.id ? rootToken : null);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(true);
        });

        it('should return PARENT_TOKEN_NOT_FOUND when resolveToken returns null', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            // resolveToken always returns null (cannot find the parent token)
            const resolveToken = (): Promise<CapabilityToken | null> =>
                Promise.resolve(null);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('PARENT_TOKEN_NOT_FOUND');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should return DELEGATION_CHAIN_INVALID when proof parentCapabilities do not match authoritative parent', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Return an "authoritative" parent token whose capabilities differ from the proof snapshot
            const tamperedParent: CapabilityToken = {
                ...rootToken,
                capabilities: CAPS_FURTHER_REDUCED, // inconsistent with proof.parentCapabilities (CAPS_FULL)
            };
            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = (): Promise<CapabilityToken | null> =>
                Promise.resolve(tamperedParent);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATION_CHAIN_INVALID');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should return DELEGATION_CHAIN_INVALID when proof parentExpiresAt does not match authoritative parent', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Return an "authoritative" parent token whose expiresAt differs from the proof snapshot
            const tamperedParent: CapabilityToken = {
                ...rootToken,
                expiresAt: '2035-01-01T00:00:00.000Z' as Timestamp, // inconsistent with proof.parentExpiresAt (ROOT_EXPIRES)
            };
            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = (): Promise<CapabilityToken | null> =>
                Promise.resolve(tamperedParent);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATION_CHAIN_INVALID');
            expect(result.brokenAtIndex).toBe(0);
        });
    });

    // ─── Parent-token binding + verificationMethod check ─────────────────────────────────
    describe('parent-token binding + verificationMethod check', () => {
        it('should reject when root parent token signature is invalid (forged parent attack)', async () => {
            // Attack: the tokenStore returns an attacker-forged "root parent token" — its capabilities
            // match the proof snapshot, but its proof.value was not actually signed by the principal.
            // Before the defense: the validator only compared capabilities/expiresAt and did not verify the signature → let through.
            // After the defense: verifyCapabilityToken verifies the root parent's signature directly → SIGNATURE_INVALID.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Replace rootToken.proof.value with garbage (forged signature)
            const forgedRoot: CapabilityToken = {
                ...rootToken,
                proof: {
                    ...rootToken.proof,
                    value: '0'.repeat(128) as CapabilityToken['proof']['value'],
                },
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> =>
                Promise.resolve(tokenId === rootToken.id ? forgedRoot : null);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should reject when parent token issuer/principal does not match child root', async () => {
            // Attack: the parent token comes from a different principal, but its capabilities happen to match the proof snapshot.
            // Before the defense: chain segments across principals could be spliced.
            // After the defense: compare parent.issuerDid/principalDid === token.issuerDid/principalDid → ROOT_NOT_PRINCIPAL.
            const issuerA = makeIssuer();
            const issuerB = makeIssuer(); // a different principal
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { child } = makeOneLevelChain(issuerA, agent1);

            // Forge a token that "looks like the parent": matching capabilities but issuerDid from B
            const mismatchedParent = issueCapabilityToken({
                issuerDid: issuerB.did,
                issuedTo: agent1.did,
                capabilities: CAPS_FULL,
                expiresAt: ROOT_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuerPrivateKey: issuerB.privateKey,
                issuedAt: ISSUED_AT,
            });

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = (): Promise<CapabilityToken | null> =>
                Promise.resolve(mismatchedParent);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            // The issuer/principal binding check runs before capabilitiesEqual (issuerDid/principalDid mismatch) → ROOT_NOT_PRINCIPAL
            expect(result.reason).toBe('ROOT_NOT_PRINCIPAL');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should reject when delegatorDid does not match parent token issuedTo', async () => {
            // Attack: proof.delegatorDid claims it signed, but the real parent token's issuedTo
            // is someone else — the attacker is not the holder of the parent token.
            // After the defense: compare proof.delegatorDid === parent.issuedTo → DELEGATOR_MISMATCH.
            const issuer = makeIssuer();
            const realHolder = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const attacker = makeAgentKeypair(
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            );

            // The real root token is issued to realHolder
            const rootToken = makeRootToken(issuer, realHolder.did);
            // But child's chain[0].delegatorDid=attacker (claiming it delegated), and attacker signed the leaf
            // Using delegateCapabilityToken would automatically set delegatorDid to parentToken.issuedTo=realHolder
            // So we construct a chain by hand: directly tying the parent token to the attacker
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: attacker.privateKey, // the attacker signs with its own key
                delegateeDid: `did:agent:${'cc'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            // Inside delegateCapabilityToken, delegatorDid=parent.issuedTo=realHolder.did
            // But because the signature uses the attacker's private key while claiming delegator=realHolder, signature verification will fail.
            // What is tested here: even if the signature happened to pass (simulating a bypass), the delegator/issuedTo binding check should still intercept it.
            
            // Directly reconstruct chain[0]: change delegatorDid to attacker, re-sign the proof with attacker
            const originalProof = child.delegationChain![0]!;
            const rebuiltPayload = {
                parentTokenId: originalProof.parentTokenId,
                delegatorDid: attacker.did, // claims the attacker is the delegator
                delegateeDid: originalProof.delegateeDid,
                parentCapabilities: originalProof.parentCapabilities,
                parentExpiresAt: originalProof.parentExpiresAt,
                attenuatedCapabilities: originalProof.attenuatedCapabilities,
            };
            // Dynamically import crypto to avoid a top-level dependency
            const { canonicalize, sign } =
                await import('@coivitas/crypto');
            const payloadBytes = new TextEncoder().encode(
                canonicalize(
                    rebuiltPayload as unknown as Record<string, unknown>,
                ),
            );
            const proofSig = sign(payloadBytes, attacker.privateKey);
            const rebuiltProof: DelegationProof = {
                ...rebuiltPayload,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod: `${attacker.did}#key-1`,
                    value: proofSig as DelegationProof['proof']['value'],
                },
            };
            const tamperedChild: CapabilityToken = {
                ...child,
                delegationChain: [rebuiltProof],
            };

            const resolver = makeResolver([
                [attacker.did, attacker.publicKey],
                [realHolder.did, realHolder.publicKey],
            ]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> =>
                Promise.resolve(tokenId === rootToken.id ? rootToken : null);

            const result = await validateDelegationChain(
                tamperedChild,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATOR_MISMATCH');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should reject when chain[i].proof.verificationMethod points to a different DID than delegatorDid', async () => {
            // Attack: proof.verificationMethod points at the attacker's DID (not delegatorDid),
            // but the signature happens to have been signed with the attacker's private key (or an impersonation scenario).
            // After the defense: the vm's DID prefix !== delegatorDid → SIGNATURE_INVALID.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const attacker = makeAgentKeypair(
                '1111111111111111111111111111111111111111',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Replace chain[0].proof.verificationMethod with one pointing at the attacker's DID
            const originalProof = child.delegationChain![0]!;
            const tamperedProof: DelegationProof = {
                ...originalProof,
                proof: {
                    ...originalProof.proof,
                    verificationMethod: `${attacker.did}#key-1`,
                },
            };
            const tamperedChild: CapabilityToken = {
                ...child,
                delegationChain: [tamperedProof],
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [attacker.did, attacker.publicKey],
            ]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> =>
                Promise.resolve(tokenId === rootToken.id ? rootToken : null);

            const result = await validateDelegationChain(
                tamperedChild,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should reject when leaf token.proof.verificationMethod does not match last hop delegator', async () => {
            // Attack: the leaf token's top-level proof.verificationMethod is swapped to someone else's DID.
            // After the defense: the leaf proof's vm DID !== the last-hop delegatorDid → SIGNATURE_INVALID.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const attacker = makeAgentKeypair(
                '2222222222222222222222222222222222222222',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const tamperedChild: CapabilityToken = {
                ...child,
                proof: {
                    ...child.proof,
                    verificationMethod: `${attacker.did}#key-1`,
                },
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [attacker.did, attacker.publicKey],
            ]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> =>
                Promise.resolve(tokenId === rootToken.id ? rootToken : null);

            const result = await validateDelegationChain(
                tamperedChild,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            // The leaf top-level verificationMethod check is a separate section after all loops finish, brokenAtIndex = chain.length - 1
            expect(result.brokenAtIndex).toBe(0);
        });

        it('should reject when root parent token itself has a non-empty delegationChain (rule: root must not be delegated)', async () => {
            // Attack: place a delegated token as the "root parent" in the tokenStore and try to splice.
            // After the defense: at i===0, check that parentToken.delegationChain must be empty → ROOT_NOT_PRINCIPAL.
            
            // Construction detail: child's proof claims delegator === delegatedAsRoot.issuedTo,
            // and capabilities/expiresAt both align with delegatedAsRoot — so the delegator binding /
            // issuer binding / capabilitiesEqual all pass, letting the flow reach the "root parent delegationChain non-empty" branch.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            // agent1's real root token (capabilities=CAPS_FULL)
            const rootToken1 = makeRootToken(issuer, agent1.did);

            // The real agent1→agent2 delegation (capabilities=CAPS_REDUCED). This is a legitimate
            // delegated token; we misplace it in the "root parent" position to test the defense.
            const delegatedAsFakeRoot = delegateCapabilityToken({
                parentToken: rootToken1,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Then construct a child using delegatedAsFakeRoot as the parentToken:
            // agent2 (the delegated token's issuedTo) → agent3 (delegatee).
            // delegatorDid=agent2 === delegatedAsFakeRoot.issuedTo → passes the delegator binding check.
            const child = delegateCapabilityToken({
                parentToken: delegatedAsFakeRoot,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            // child.delegationChain now contains two hops (inheriting delegatedAsFakeRoot's chain);
            // to trigger the "root parent is not delegated" branch, we need to construct a "single-hop" child
            // whose chain[0].parentTokenId points at delegatedAsFakeRoot.id.
            const singleHopChain = [child.delegationChain![1]!];
            const singleHopChild: CapabilityToken = {
                ...child,
                delegationChain: singleHopChain,
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> =>
                Promise.resolve(
                    tokenId === delegatedAsFakeRoot.id
                        ? delegatedAsFakeRoot
                        : null,
                );

            const result = await validateDelegationChain(
                singleHopChild,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('ROOT_NOT_PRINCIPAL');
            expect(result.brokenAtIndex).toBe(0);
        });
    });

    // ─── Intermediate parent-token signature check (direct verification across the whole chain) ─────────────────
    describe('intermediate parent-token top-level signature check', () => {
        it('should reject when middle parent token is swapped to a forged token with different tokenId (bypass revocation via fake tokenId)', async () => {
            // Attack: a three-hop chain root → agent1 → agent2 → agent3. The attacker controls
            // the tokenStore and points chain[1].parentTokenId at a "forged P1'" — its capabilities
            // and expiresAt/issuerDid/principalDid/issuedTo all align with the real hop1,
            // but it uses a new tokenId and garbage proof.value.
            // The early implementation only verified the i===0 root parent; the intermediate parent (i=1) only compared snapshots → forgery passed.
            // If the revoke list only records the real hop1.id, then proof.parentTokenId (P1')
            // is not on the revoke list, defeating cascade revocation.
            // After the defense: tokenId lock + direct signature verification → SIGNATURE_INVALID / DELEGATION_CHAIN_INVALID.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Forge a "fake hop1": same capabilities/expiresAt/issuerDid/principalDid/issuedTo,
            // but with a new tokenId + garbage proof.value (constructed by hand by the attacker).
            const fakeHop1: CapabilityToken = {
                ...hop1,
                id: 'urn:cap:forged-middle-parent',
                proof: {
                    ...hop1.proof,
                    value: '0'.repeat(128) as CapabilityToken['proof']['value'],
                },
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            // chain[1].parentTokenId points at the real hop1.id; but the tokenStore returns fakeHop1
            // (different id). The tokenId lock hits first → DELEGATION_CHAIN_INVALID.
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> => {
                if (tokenId === rootToken.id) return Promise.resolve(rootToken);
                if (tokenId === hop1.id) return Promise.resolve(fakeHop1);
                return Promise.resolve(null);
            };

            const result = await validateDelegationChain(
                hop2,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('DELEGATION_CHAIN_INVALID');
            expect(result.brokenAtIndex).toBe(1);
        });

        it('should reject when middle parent token signature is tampered (rule: parent top-level proof must verify)', async () => {
            // Attack: the intermediate parent token returned by the tokenStore is fully identical to the real hop1 (including id),
            // with only proof.value tampered to garbage.
            // Early implementation: the i>=1 branch did not verify the signature → let through.
            // After the defense: keyMap.get(chain[i-1].delegatorDid) + verify(parent
            // payload, parent.proof.value, key) → SIGNATURE_INVALID + brokenAtIndex=1.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Keep the id, tamper with hop1.proof.value
            const tamperedHop1: CapabilityToken = {
                ...hop1,
                proof: {
                    ...hop1.proof,
                    value: 'f'.repeat(128) as CapabilityToken['proof']['value'],
                },
            };

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = (
                tokenId: string,
            ): Promise<CapabilityToken | null> => {
                if (tokenId === rootToken.id) return Promise.resolve(rootToken);
                if (tokenId === hop1.id) return Promise.resolve(tamperedHop1);
                return Promise.resolve(null);
            };

            const result = await validateDelegationChain(
                hop2,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            expect(result.brokenAtIndex).toBe(1);
        });
    });

    // ─── schema + specVersion gate + leaf top-level proof verification ──
    describe('schema/specVersion gate + leaf top-level proof', () => {
        it('should reject delegated token with specVersion=0.1.0 (fail-closed)', async () => {
            // Attack: a token with specVersion='0.1.0' + a non-empty delegationChain.
            // The non-delegation-aware validator does not recognize the chain, so this combination would bypass delegation-chain validation.
            // Defense: validateDelegationChain's internal gate rejects directly (INVALID_TOKEN_FORMAT).
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { child } = makeOneLevelChain(issuer, agent1);

            // Downgrade a legitimate child (specVersion=0.2.0) to 0.1.0
            const downgradedChild: CapabilityToken = {
                ...child,
                specVersion: '0.1.0',
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const result = await validateDelegationChain(
                downgradedChild,
                resolver,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('INVALID_TOKEN_FORMAT');
        });

        it('should reject delegated token that fails schema validation', async () => {
            // Attack: token fields do not conform to the schema (e.g. wrong expiresAt format).
            // Defense: validateAgainstSchema rejects directly at the start of the validator.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { child } = makeOneLevelChain(issuer, agent1);

            // Corrupt the expiresAt format (not ISO 8601)
            const malformedChild: CapabilityToken = {
                ...child,
                expiresAt: 'not-a-timestamp' as Timestamp,
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const result = await validateDelegationChain(
                malformedChild,
                resolver,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('INVALID_TOKEN_FORMAT');
        });

        it('should reject delegated token when leaf top-level proof.value is tampered', async () => {
            // Attack: a leaf token is planted in the recipient's local tokenStore, with the top-level signature tampered
            // but the chain-internal signatures and vm bindings all legitimate.
            // After the defense: after the per-hop signature/verificationMethod binding checks, the validator additionally verifies
            // verify(createCapabilityTokenPayload(token), token.proof.value, lastDelegator.publicKey)
            // → SIGNATURE_INVALID.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Replace the top-level proof.value with zeros (the chain-internal proofs stay legitimate)
            const tamperedChild: CapabilityToken = {
                ...child,
                proof: {
                    ...child.proof,
                    value: '0'.repeat(128) as CapabilityToken['proof']['value'],
                },
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                tamperedChild,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
            expect(result.brokenAtIndex).toBe(0); // chain.length-1 = 0
        });
    });

    describe('parallel public-key resolution', () => {
        it('should resolve all DID public keys in parallel (tracked via call counting)', async () => {
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            const callLog: DID[] = [];
            const resolver = (did: DID): Promise<ResolvedPublicKeys | null> => {
                callLog.push(did);
                const map = new Map([
                    [agent1.did, agent1.publicKey],
                    [agent2.did, agent2.publicKey],
                ]);
                const key = map.get(did);
                if (key === undefined) return Promise.resolve(null);
                return Promise.resolve({
                    current: key,
                    rotationState: 'STABLE',
                });
            };
            const resolveToken = makeResolveToken([rootToken, hop1]);

            const result = await validateDelegationChain(
                hop2,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(result.valid).toBe(true);
            // Both delegatorDids (agent1, agent2) should be resolved
            expect(callLog).toContain(agent1.did);
            expect(callLog).toContain(agent2.did);
        });
    });

    // ─── Non-empty chain + missing resolveToken → fail-closed ──────────
    describe('resolveToken required (fail-closed)', () => {
        it('should reject delegated token when resolveToken is omitted', async () => {
            // Attack vector: the public API validateDelegationChain is exported as an L2 boundary;
            // if a caller omits resolveToken, earlier versions would skip parent-token binding + delegator/issuer binding checks
            // + tokenId-lock + root-parent verify + intermediate-parent verify, leaving only proof signature/
            // attenuation — fail-open.
            // Defense: non-empty chain + resolveToken undefined → fail-closed
            // INVALID_TOKEN_FORMAT. The validator is now self-defensive toward consumers,
            // not relying on callers behaving well.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            // Do not pass resolveToken
            const result = await validateDelegationChain(child, resolver);
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('INVALID_TOKEN_FORMAT');
        });
    });

    // ─── ROTATING dual-key fallback ────────────────────────────────
    // Replaces the former explicit rejection of ROTATING (ROTATION_NOT_SUPPORTED):
    // after introducing the dual-key grace period, the validator no longer rejects a ROTATING
    // delegator, but instead falls back to previous when current verification fails (issuedAt ≤ cutoff).
    describe('ROTATING dual-key fallback validation', () => {
        it('should accept chain when ROTATING delegator proof is signed by previous key within grace period', async () => {
            // During ROTATING: a proof signed by the delegator's old private key (issuedAt ≤ previousValidBefore) → should pass.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            // Generate the "old" key pair (the key agent1 used before rotation) and the "new" key pair (the current one)
            const oldKp = generateKeyPair();
            // Issue the delegation proof with the old private key:
            // delegateCapabilityToken internally calls sign(payload, delegatorPrivateKey);
            // in practice delegatorPrivateKey is the old key, while the publicKey agent1 currently holds is the new key.
            // In the test, we let agent1's identity have publicKey=newKey but sign with oldPrivateKey.
            const agentWithOldKey = {
                ...agent1,
                privateKey: oldKp.privateKey, // sign with the old private key
                publicKey: oldKp.publicKey, // but the DID is unchanged, only the private key swapped
            };

            // Issue the delegation with the old private key (proof.created = ISSUED_AT, within the grace period)
            const rootToken = makeRootToken(issuer, agent1.did);
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agentWithOldKey.privateKey, // old private key
                delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // Resolver: agent1 is ROTATING, current is the new public key, previous is the old public key
            // previousValidBefore = the rotation start time (later than proof.created → the proof is within the window)
            const ROTATION_STARTED = '2026-06-01T00:00:00.000Z' as Timestamp; // later than ISSUED_AT
            const resolvedKeys: ResolvedPublicKeys = {
                current: agent1.publicKey, // new key (verification will fail)
                previous: oldKp.publicKey, // old key (should fall back to this)
                previousValidBefore: ROTATION_STARTED,
                rotationState: 'ROTATING',
            };
            const resolver = makeResolvedKeysResolver([
                [agent1.did, resolvedKeys],
            ]);
            const resolveToken = makeResolveToken([rootToken]);

            // proof.created = ISSUED_AT = '2026-01-01' ≤ previousValidBefore = '2026-06-01' → fallback allowed
            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
            expect(result.depth).toBe(1);
        });

        it('should reject chain when ROTATING delegator proof is signed by previous key after grace period cutoff', async () => {
            // During ROTATING: proof.created > previousValidBefore → old-key fallback rejected.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const oldKp = generateKeyPair();
            const agentWithOldKey = {
                ...agent1,
                privateKey: oldKp.privateKey,
                publicKey: oldKp.publicKey,
            };

            // proof.created = ISSUED_AT = '2026-01-01'
            const rootToken = makeRootToken(issuer, agent1.did);
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agentWithOldKey.privateKey, // old private key
                delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            // previousValidBefore is earlier than proof.created → old-key fallback rejected
            const ROTATION_STARTED = '2025-06-01T00:00:00.000Z' as Timestamp; // earlier than ISSUED_AT
            const resolvedKeys: ResolvedPublicKeys = {
                current: agent1.publicKey,
                previous: oldKp.publicKey,
                previousValidBefore: ROTATION_STARTED,
                rotationState: 'ROTATING',
            };
            const resolver = makeResolvedKeysResolver([
                [agent1.did, resolvedKeys],
            ]);
            const resolveToken = makeResolveToken([rootToken]);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
        });

        it('should accept chain when ROTATING delegator proof is signed by current key', async () => {
            // During ROTATING: a proof signed by the new private key (current key) → current verification passes directly, no fallback needed.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const oldKp = generateKeyPair();

            // Issue the delegation with the current (new) private key
            const rootToken = makeRootToken(issuer, agent1.did);
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey, // current new private key
                delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            const ROTATION_STARTED = '2026-06-01T00:00:00.000Z' as Timestamp;
            const resolvedKeys: ResolvedPublicKeys = {
                current: agent1.publicKey, // current matches the actual signature
                previous: oldKp.publicKey, // the old key exists but will not be used
                previousValidBefore: ROTATION_STARTED,
                rotationState: 'ROTATING',
            };
            const resolver = makeResolvedKeysResolver([
                [agent1.did, resolvedKeys],
            ]);
            const resolveToken = makeResolveToken([rootToken]);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
            expect(result.depth).toBe(1);
        });

        it('should accept chain when STABLE delegator uses only current key (no fallback)', async () => {
            // Control group: STABLE state, no previous, the normal single-key path passes.
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
        });

        it('should reject chain when ROTATING delegator proof is signed by previous key but no previousValidBefore set', async () => {
            // ROTATING state but previousValidBefore is missing → old-key fallback is not allowed
            // (no cutoff time means the old key cannot be safely allowed, fail-closed).
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const oldKp = generateKeyPair();
            const agentWithOldKey = { ...agent1, privateKey: oldKp.privateKey };

            const rootToken = makeRootToken(issuer, agent1.did);
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agentWithOldKey.privateKey,
                delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            const resolvedKeys: ResolvedPublicKeys = {
                current: agent1.publicKey,
                previous: oldKp.publicKey,
                // previousValidBefore not set
                rotationState: 'ROTATING',
            };
            const resolver = makeResolvedKeysResolver([
                [agent1.did, resolvedKeys],
            ]);
            const resolveToken = makeResolveToken([rootToken]);

            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            // current verification fails, and fallback is rejected due to no previousValidBefore
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
        });
    });

    // ════════════════════════════════════════════════════════════════════════
    // dc v0.3 NI tests (net increment — dcVersion + DcErrorCode + step ordering)
    // ════════════════════════════════════════════════════════════════════════

    describe('dc v0.3: dcVersion independent namespace (v0.1 compatibility path)', () => {
        it('should accept chain when DelegationProof has no dcVersion field (v0.1 backward compat)', async () => {
            // Compatibility guard: when a v0.1 issuer omits dcVersion, the validator must accept it
            // (falling back to token.specVersion)
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            // Explicitly assert that child.delegationChain[0].dcVersion was not injected
            expect(child.delegationChain?.[0]?.dcVersion).toBeUndefined();

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
        });

        it('should accept chain when DelegationProof has dcVersion=DC_VERSION (v0.3 issuer)', async () => {
            // A v0.3 issuer explicitly declares dcVersion → the signed payload includes dcVersion
            // → the verifier conditionally rebuilds the same payload → signature PASS
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const rootToken = makeRootToken(issuer, agent1.did);
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
                dcVersion: DC_VERSION, // v0.3 net-increment field
            });

            expect(child.delegationChain?.[0]?.dcVersion).toBe(DC_VERSION);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                child,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(true);
        });

        it('should reject chain when dcVersion field is tampered post-issuance (signature breaks)', async () => {
            // Tampering attack: the attacker modifies the dcVersion field of an issued chain (without re-signing)
            // → the verifier rebuilds the signed payload including the tampered dcVersion
            // → it does not match the original signature → SIGNATURE_INVALID
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const rootToken = makeRootToken(issuer, agent1.did);
            const child = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: `did:agent:${'aa'.repeat(20)}` as DID,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
                dcVersion: DC_VERSION,
            });

            // Tamper: modify dcVersion post-issuance
            const tampered: CapabilityToken = {
                ...child,
                delegationChain: child.delegationChain?.map(
                    (p: DelegationProof, i: number) =>
                        i === 0 ? { ...p, dcVersion: '9.9.9' } : p,
                ),
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                tampered,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
        });

        it('should reject chain when dcVersion is added without re-signing (v0.1 issuance → v0.3 metadata injection)', async () => {
            // Injection attack: the attacker adds a dcVersion field to a v0.1-issued chain
            // → the verifier rebuilds the signed payload including dcVersion (which the issuer did not sign at the time)
            // → the bytes do not match → SIGNATURE_INVALID
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const injected: CapabilityToken = {
                ...child,
                delegationChain: child.delegationChain?.map(
                    (p: DelegationProof, i: number) =>
                        i === 0 ? { ...p, dcVersion: DC_VERSION } : p,
                ),
            };

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const result = await validateDelegationChain(
                injected,
                resolver,
                // A non-empty chain requires isRevoked (fail-closed)
                async () => false,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('SIGNATURE_INVALID');
        });

        it('should expose DC_VERSION constant equal to 0.3.0', () => {
            // DC_VERSION = '0.3.0'
            expect(DC_VERSION).toBe('0.3.0');
        });

        it('resolveDcVersion should fall back to token.specVersion when proof.dcVersion is missing', () => {
            // Compatibility path: when absent, fall back to token.specVersion
            const dummyProof: DelegationProof = {
                parentTokenId: 'urn:cap:dummy',
                delegatorDid: 'did:agent:0000000000000000000000000000000000000000' as DID,
                delegateeDid: 'did:agent:1111111111111111111111111111111111111111' as DID,
                parentCapabilities: CAPS_FULL,
                parentExpiresAt: ROOT_EXPIRES,
                attenuatedCapabilities: CAPS_REDUCED,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod: 'did:agent:0000000000000000000000000000000000000000#key-1',
                    value: 'dummy' as DelegationProof['proof']['value'],
                },
            };
            const dummyToken: CapabilityToken = {
                id: 'urn:cap:test',
                specVersion: SPEC_VERSION_0_2_0,
                issuerDid: 'did:key:dummy' as DID,
                principalDid: 'did:key:dummy' as DID,
                issuedTo: 'did:agent:0000000000000000000000000000000000000000' as DID,
                issuedAt: ISSUED_AT,
                expiresAt: CHILD_EXPIRES,
                capabilities: CAPS_REDUCED,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                proof: dummyProof.proof,
            };

            expect(resolveDcVersion(dummyProof, dummyToken)).toBe(SPEC_VERSION_0_2_0);
        });

        it('resolveDcVersion should return proof.dcVersion when present (overrides fallback)', () => {
            const dummyProof: DelegationProof = {
                parentTokenId: 'urn:cap:dummy',
                delegatorDid: 'did:agent:0000000000000000000000000000000000000000' as DID,
                delegateeDid: 'did:agent:1111111111111111111111111111111111111111' as DID,
                parentCapabilities: CAPS_FULL,
                parentExpiresAt: ROOT_EXPIRES,
                attenuatedCapabilities: CAPS_REDUCED,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod: 'did:agent:0000000000000000000000000000000000000000#key-1',
                    value: 'dummy' as DelegationProof['proof']['value'],
                },
                dcVersion: DC_VERSION,
            };
            const dummyToken: CapabilityToken = {
                id: 'urn:cap:test',
                specVersion: SPEC_VERSION_0_2_0,
                issuerDid: 'did:key:dummy' as DID,
                principalDid: 'did:key:dummy' as DID,
                issuedTo: 'did:agent:0000000000000000000000000000000000000000' as DID,
                issuedAt: ISSUED_AT,
                expiresAt: CHILD_EXPIRES,
                capabilities: CAPS_REDUCED,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                proof: dummyProof.proof,
            };

            expect(resolveDcVersion(dummyProof, dummyToken)).toBe(DC_VERSION);
        });
    });

    describe('dc v0.3: DcErrorCode union exhaustive handler', () => {
        it('handleDcError should return non-empty message for every DcErrorCode (exhaustive coverage)', () => {
            // Force enumerating all 13 codes; adding a code but missing a handler → TS compile warning
            const allCodes: DcErrorCode[] = [
                'DEPTH_EXCEEDED',
                'ATTENUATION_VIOLATED',
                'DELEGATION_CHAIN_INVALID',
                'SIGNATURE_INVALID',
                'PARENT_TOKEN_REVOKED',
                'PARENT_TOKEN_NOT_FOUND',
                'PARENT_TOKEN_EXPIRED',
                'EXPIRY_EXCEEDED',
                'DELEGATOR_MISMATCH',
                'CYCLE_DETECTED',
                'ROOT_NOT_PRINCIPAL',
                'INVALID_TOKEN_FORMAT',
                'ROTATION_NOT_SUPPORTED',
            ];

            for (const code of allCodes) {
                const msg = handleDcError(code);
                expect(msg).toBeTruthy();
                expect(typeof msg).toBe('string');
                // fail-closed: vague strings like 'unknown error' are forbidden
                expect(msg.toLowerCase()).not.toContain('unknown error');
            }
        });

        it('handleDcError should include MAX_DELEGATION_DEPTH literal in DEPTH_EXCEEDED message', () => {
            // The error message must reference the actual MAX_DELEGATION_DEPTH value
            const msg = handleDcError('DEPTH_EXCEEDED');
            expect(msg).toContain('5'); // MAX_DELEGATION_DEPTH = 5
        });

        it('handleDcError should describe cascade behavior in PARENT_TOKEN_REVOKED message', () => {
            const msg = handleDcError('PARENT_TOKEN_REVOKED');
            expect(msg).toContain('cascade');
        });

        it('handleDcError should mention cycle detection in CYCLE_DETECTED message', () => {
            const msg = handleDcError('CYCLE_DETECTED');
            expect(msg).toMatch(/cycle/i);
        });

        it('assertNeverDcError should throw with descriptive message when called with unhandled code', () => {
            // Fallback: theoretically unreachable; if called at runtime, throw immediately (fail-closed)
            // Use 'as never' to craft an "uncovered" branch that is compile-time legal but runtime illegal
            expect(() => assertNeverDcError('THEORETICAL_NEW_CODE' as never)).toThrow(
                /Unhandled DcErrorCode/,
            );
        });

        it('assertNeverDcError throw message should reference R15 legislation (L0 SSOT + L1 import) for upgrade guidance', () => {
            // The assertNeverDcError error message must include the caller upgrade-path guidance
            try {
                assertNeverDcError('THEORETICAL_NEW_CODE' as never);
                throw new Error('Expected assertNeverDcError to throw');
            } catch (e) {
                const err = e as Error;
                expect(err.message).toMatch(/R15|L0 SSOT/i);
            }
        });
    });

    describe('dc v0.3 revocation check fail-closed: the revocation check must come before leaf consistency + cycle detection', () => {
        // The revocation check must run before leaf consistency / cycle detection
        // Deferral is strictly forbidden → it would run cycle detection and the leaf-capabilities check in an unrevoked-but-unverified state
        // This verifies: when a mid-chain parent is revoked, the validator must not continue to the leaf
        // capabilities consistency check (i.e. it should abort early and return PARENT_TOKEN_REVOKED)

        it('should return PARENT_TOKEN_REVOKED (not DELEGATION_CHAIN_INVALID) when mid-chain parent revoked AND leaf capabilities also tampered', async () => {
            // Double-fault fixture: the mid-chain parent is revoked + the leaf capabilities are also inconsistent
            // fail-closed step-ordering requirement: revocation aborts early, never reaching the leaf consistency check
            // Counter-example: if revocation were deferred → it would first return DELEGATION_CHAIN_INVALID (wrong attribution)
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
            );
            const agent3 = makeAgentKeypair(
                'ccddee1122334455667788990011aabbccddeeff',
            );

            const rootToken = makeRootToken(issuer, agent1.did);
            const hop1 = delegateCapabilityToken({
                parentToken: rootToken,
                delegatorPrivateKey: agent1.privateKey,
                delegateeDid: agent2.did,
                attenuatedCapabilities: CAPS_REDUCED,
                expiresAt: CHILD_EXPIRES,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });
            const hop2 = delegateCapabilityToken({
                parentToken: hop1,
                delegatorPrivateKey: agent2.privateKey,
                delegateeDid: agent3.did,
                attenuatedCapabilities: CAPS_FURTHER_REDUCED,
                expiresAt: CHILD_EXPIRES_2,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                issuedAt: ISSUED_AT,
            });

            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = makeResolveToken([rootToken, hop1]);
            // Revoke hop1 (mid-chain parent of hop2)
            const isRevoked = (id: string): Promise<boolean> =>
                Promise.resolve(id === hop1.id);
            const result = await validateDelegationChain(
                hop2,
                resolver,
                isRevoked,
                undefined,
                resolveToken,
            );

            // Revocation check fail-closed: must abort early and return PARENT_TOKEN_REVOKED
            // rather than continuing to the leaf consistency check
            expect(result.valid).toBe(false);
            expect(result.reason).toBe('PARENT_TOKEN_REVOKED');
            expect(result.revokedTokenId).toBe(hop1.id);
        });

        it('should return PARENT_TOKEN_REVOKED for root token revocation regardless of downstream chain state', async () => {
            // Revocation check fail-closed enforcement: revoke the root token (chain[0].parentTokenId)
            // → should abort immediately, not continuing subsequent-layer verification
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const { rootToken, child } = makeOneLevelChain(issuer, agent1);

            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const isRevoked = (id: string): Promise<boolean> =>
                Promise.resolve(id === rootToken.id);
            const result = await validateDelegationChain(
                child,
                resolver,
                isRevoked,
                undefined,
                resolveToken,
            );

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('PARENT_TOKEN_REVOKED');
            expect(result.revokedTokenId).toBe(rootToken.id);
        });
    });
});
