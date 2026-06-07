/**
 * delegation-chain v0.3 e2e cross-package test (L0 + L2 interaction)
 *
 * Design principles:
 *   - types and version numbers are imported from the single source @coivitas/types
 *   - L2+ e2e cross-package tests must cover:
 *     case 1: L0 schema validate PASS -> L2 validateDelegationChain PASS
 *     case 2: L0 AJV rejects a malformed DelegationChain
 *     case 3: L2 detectCycle throws CYCLE_DETECTED
 *
 * Coverage dimensions:
 *   - L0 (types): validateAgainstSchema('capabilityToken') schema-validates the chain structure
 *   - L0 (types): DcErrorCode union aligns with the DelegationChainValidationResult.reason type
 *   - L2 (identity): validateDelegationChain runtime behavior
 *   - cross-package: L0 schema reject and L2 runtime reject must be semantically consistent + L0 PASS superset of L2 PASS
 */

import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '@coivitas/crypto';
import type {
    Capability,
    CapabilityToken,
    DcErrorCode,
    DID,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';
import {
    DC_VERSION,
    MAX_DELEGATION_DEPTH,
    SPEC_VERSION_0_2_0,
    validateAgainstSchema,
} from '@coivitas/types';

import { handleDcError, validateDelegationChain } from '../../delegation-validator.js';
import {
    delegateCapabilityToken,
    didKeyFromPublicKey,
    issueCapabilityToken,
} from '../../index.js';

// ─── shared test helpers ─────────────────────────────────────────────────────────────

function makeIssuer() {
    const kp = generateKeyPair();
    const did = didKeyFromPublicKey(Buffer.from(kp.publicKey, 'hex'));
    return { ...kp, did };
}

function makeAgentKeypair(suffix: string) {
    const kp = generateKeyPair();
    const did = `did:agent:${suffix.padStart(40, '0')}` as DID;
    return { ...kp, did };
}

const ROOT_EXPIRES = '2030-01-01T00:00:00.000Z' as Timestamp;
const ISSUED_AT = '2026-01-01T00:00:00.000Z' as Timestamp;
const CHILD_EXPIRES = '2029-06-01T00:00:00.000Z' as Timestamp;

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

function makeRootToken(
    issuer: ReturnType<typeof makeIssuer>,
    issuedTo: DID,
): CapabilityToken {
    return issueCapabilityToken({
        issuerDid: issuer.did,
        issuedTo,
        capabilities: CAPS_FULL,
        expiresAt: ROOT_EXPIRES,
        revocationUrl: 'https://rev.example.com/v1/{id}',
        issuerPrivateKey: issuer.privateKey,
        issuedAt: ISSUED_AT,
    });
}

function makeResolver(entries: [DID, string][]) {
    const map = new Map(entries);
    return (did: DID): Promise<ResolvedPublicKeys | null> => {
        const key = map.get(did);
        if (key === undefined) return Promise.resolve(null);
        return Promise.resolve({ current: key, rotationState: 'STABLE' });
    };
}

function makeResolveToken(tokens: CapabilityToken[]) {
    const map = new Map(tokens.map((t) => [t.id, t] as const));
    return (tokenId: string): Promise<CapabilityToken | null> =>
        Promise.resolve(map.get(tokenId) ?? null);
}

// ─── e2e cross-package test ──────────────────────────────────────────────────────────

describe('dc v0.3 e2e cross-package (L0 + L2)', () => {
    describe('case 1: happy path — L0 schema PASS -> L2 validateDelegationChain PASS', () => {
        it('should produce capabilityToken that passes BOTH L0 schema validation AND L2 runtime chain verification', async () => {
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
            });

            // L0 schema gate — capabilityToken AJV validation
            const schemaResult = validateAgainstSchema(child, 'capabilityToken');
            expect(schemaResult.valid).toBe(true);

            // L2 runtime gate — validateDelegationChain
            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const runtimeResult = await validateDelegationChain(
                child,
                resolver,
                // a non-empty chain requires isRevoked
                // (cascade revocation fail-closed enforce); the test mock returns false (no revocation)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(runtimeResult.valid).toBe(true);
            expect(runtimeResult.depth).toBe(1);
        });

        it('should support optional dcVersion field through L0 schema validate AND L2 runtime verify', async () => {
            // dc v0.3 option A net increment: the dcVersion field is compatible across the whole chain
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

            // the L0 schema must accept a DelegationProof carrying dcVersion
            const schemaResult = validateAgainstSchema(child, 'capabilityToken');
            expect(schemaResult.valid).toBe(true);

            // the L2 runtime must accept the dcVersion field without reporting SIGNATURE_INVALID
            const resolver = makeResolver([[agent1.did, agent1.publicKey]]);
            const resolveToken = makeResolveToken([rootToken]);
            const runtimeResult = await validateDelegationChain(
                child,
                resolver,
                // a non-empty chain requires isRevoked
                // (cascade revocation fail-closed enforce); the test mock returns false (no revocation)
                async () => false,
                undefined,
                resolveToken,
            );
            expect(runtimeResult.valid).toBe(true);
        });
    });

    describe('case 2: L0 AJV schema reject malformed DelegationChain', () => {
        it('should L0-reject token with malformed dcVersion (non-semver pattern)', () => {
            // the schema's required full field set aligns with the source-of-truth type
            // dcVersion pattern ^[0-9]+\.[0-9]+\.[0-9]+$ — AJV rejects non-semver version strings
            const malformedToken = {
                id: 'urn:cap:00000000-0000-4000-8000-000000000000',
                specVersion: SPEC_VERSION_0_2_0,
                issuerDid: 'did:key:z6MkdummyXXXXXXXXXXXXXXXXXXXX' as DID,
                principalDid: 'did:key:z6MkdummyXXXXXXXXXXXXXXXXXXXX' as DID,
                issuedTo: ('did:agent:' + 'a'.repeat(40)) as DID,
                issuedAt: ISSUED_AT,
                expiresAt: CHILD_EXPIRES,
                capabilities: CAPS_REDUCED,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod:
                        'did:agent:' + 'a'.repeat(40) + '#key-1',
                    value: 'a'.repeat(128),
                },
                delegationChain: [
                    {
                        parentTokenId: 'urn:cap:parent',
                        delegatorDid: ('did:agent:' + 'b'.repeat(40)) as DID,
                        delegateeDid: ('did:agent:' + 'a'.repeat(40)) as DID,
                        parentCapabilities: CAPS_FULL,
                        parentExpiresAt: ROOT_EXPIRES,
                        attenuatedCapabilities: CAPS_REDUCED,
                        proof: {
                            type: 'Ed25519Signature2026',
                            created: ISSUED_AT,
                            verificationMethod:
                                'did:agent:' + 'b'.repeat(40) + '#key-1',
                            value: 'b'.repeat(128),
                        },
                        dcVersion: 'INVALID_VERSION_STRING', // not a semver pattern
                    },
                ],
            };

            const result = validateAgainstSchema(
                malformedToken,
                'capabilityToken',
            );
            expect(result.valid).toBe(false);
        });

        it('should L0-reject token with delegationChain exceeding maxItems=5 (depth enforcement at schema layer)', () => {
            // MAX_DELEGATION_DEPTH = 5
            // the schema-layer maxItems: 5 is L0 strict enforcement (does not rely on the L2 runtime)
            // one of the three defense lines
            const tooLongChain = Array.from({ length: 6 }, (_, i) => ({
                parentTokenId: `urn:cap:parent-${i}`,
                delegatorDid: ('did:agent:' + i.toString().repeat(40).slice(0, 40)) as DID,
                delegateeDid: ('did:agent:' + (i + 1).toString().repeat(40).slice(0, 40)) as DID,
                parentCapabilities: CAPS_FULL,
                parentExpiresAt: ROOT_EXPIRES,
                attenuatedCapabilities: CAPS_REDUCED,
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod:
                        'did:agent:' + i.toString().repeat(40).slice(0, 40) + '#key-1',
                    value: 'a'.repeat(128),
                },
            }));

            const tooDeepToken = {
                id: 'urn:cap:00000000-0000-4000-8000-000000000000',
                specVersion: SPEC_VERSION_0_2_0,
                issuerDid: 'did:key:z6MkdummyXXXXXXXXXXXXXXXXXXXX' as DID,
                principalDid: 'did:key:z6MkdummyXXXXXXXXXXXXXXXXXXXX' as DID,
                issuedTo: ('did:agent:' + 'a'.repeat(40)) as DID,
                issuedAt: ISSUED_AT,
                expiresAt: CHILD_EXPIRES,
                capabilities: CAPS_REDUCED,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod:
                        'did:agent:' + 'a'.repeat(40) + '#key-1',
                    value: 'a'.repeat(128),
                },
                delegationChain: tooLongChain,
            };

            const result = validateAgainstSchema(tooDeepToken, 'capabilityToken');
            expect(result.valid).toBe(false);
        });

        it('should L0-reject DelegationProof missing required field (additionalProperties + required enforcement)', () => {
            // JSON Schema additionalProperties false +
            // required full field set aligned with the source-of-truth type
            const missingFieldToken = {
                id: 'urn:cap:00000000-0000-4000-8000-000000000000',
                specVersion: SPEC_VERSION_0_2_0,
                issuerDid: 'did:key:z6MkdummyXXXXXXXXXXXXXXXXXXXX' as DID,
                principalDid: 'did:key:z6MkdummyXXXXXXXXXXXXXXXXXXXX' as DID,
                issuedTo: ('did:agent:' + 'a'.repeat(40)) as DID,
                issuedAt: ISSUED_AT,
                expiresAt: CHILD_EXPIRES,
                capabilities: CAPS_REDUCED,
                revocationUrl: 'https://rev.example.com/v1/{id}',
                proof: {
                    type: 'Ed25519Signature2026',
                    created: ISSUED_AT,
                    verificationMethod:
                        'did:agent:' + 'a'.repeat(40) + '#key-1',
                    value: 'a'.repeat(128),
                },
                delegationChain: [
                    {
                        parentTokenId: 'urn:cap:parent',
                        delegatorDid: ('did:agent:' + 'b'.repeat(40)) as DID,
                        delegateeDid: ('did:agent:' + 'a'.repeat(40)) as DID,
                        // missing parentCapabilities (a required field)
                        parentExpiresAt: ROOT_EXPIRES,
                        attenuatedCapabilities: CAPS_REDUCED,
                        proof: {
                            type: 'Ed25519Signature2026',
                            created: ISSUED_AT,
                            verificationMethod:
                                'did:agent:' + 'b'.repeat(40) + '#key-1',
                            value: 'b'.repeat(128),
                        },
                    },
                ],
            };

            const result = validateAgainstSchema(
                missingFieldToken,
                'capabilityToken',
            );
            expect(result.valid).toBe(false);
        });
    });

    describe('case 3: L2 runtime cycle detection throws CYCLE_DETECTED', () => {
        it('should L0-PASS but L2-REJECT chain with A->B->A cycle (detectCycle runtime semantic)', async () => {
            // the L0 schema does not detect a semantic cycle (it only checks structure <= maxItems) -> the L2 runtime gate is mandatory
            // cycle detection is implemented inside validateDelegationChain
            const issuer = makeIssuer();
            const agent1 = makeAgentKeypair(
                'aabbccddee112233445566778899aabbccddeeff',
            );
            const agent2 = makeAgentKeypair(
                'bbccddee11223344556677889900aabbccddeeff',
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

            // build an A -> B -> A cycle: manually inject a second hop pointing back to agent1
            // existing chain[0]: delegator=agent1, delegatee=agent2
            // build chain[1]: delegator=agent2, delegatee=agent1 -> CYCLE_DETECTED
            const cyclicChain = [
                ...(hop1.delegationChain ?? []),
                {
                    parentTokenId: hop1.id,
                    delegatorDid: agent2.did,
                    delegateeDid: agent1.did, // ← cycle back to agent1
                    parentCapabilities: CAPS_REDUCED,
                    parentExpiresAt: CHILD_EXPIRES,
                    attenuatedCapabilities: CAPS_REDUCED,
                    proof: {
                        type: 'Ed25519Signature2026' as const,
                        created: ISSUED_AT,
                        verificationMethod: `${agent2.did}#key-1`,
                        value: 'a'.repeat(128) as never,
                    },
                },
            ];

            const cyclicToken: CapabilityToken = {
                ...hop1,
                delegationChain: cyclicChain,
                issuedTo: agent1.did, // leaf token issued back to agent1
            };

            // L0 schema: structurally valid (maxItems 5 >= 2; all fields present) -> PASS
            // Note: the schema does not verify signatures / does not detect a semantic cycle -> structure layer only
            const schemaResult = validateAgainstSchema(
                cyclicToken,
                'capabilityToken',
            );
            expect(schemaResult.valid).toBe(true);

            // L2 runtime: cycle detection rejects early at step 4
            // Note: it must throw before signature verification — otherwise SIGNATURE_INVALID would be reported first
            // the current implementation places cycle detection before the loop (a fail-fast optimization) -> verified here
            const resolver = makeResolver([
                [agent1.did, agent1.publicKey],
                [agent2.did, agent2.publicKey],
            ]);
            const resolveToken = makeResolveToken([rootToken, hop1]);
            const runtimeResult = await validateDelegationChain(
                cyclicToken,
                resolver,
                // a non-empty chain requires isRevoked
                async () => false,
                undefined,
                resolveToken,
            );

            expect(runtimeResult.valid).toBe(false);
            expect(runtimeResult.reason).toBe('CYCLE_DETECTED');
        });
    });

    describe('cross-package error code namespace alignment', () => {
        it('every DcErrorCode value from L0 must be handleable by L2 handleDcError', () => {
            // forces alignment between the L0 DcErrorCode union <-> the L2 handleDcError switch
            // any misalignment -> TS compile-time error (assertNeverDcError default throw)
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

            // each code -> L2 handleDcError should return a non-empty string
            const seen = new Set<string>();
            for (const code of allCodes) {
                const msg = handleDcError(code);
                expect(msg).toBeTruthy();
                seen.add(msg);
            }
            // each code's message should be unique (to prevent copy-paste misalignment)
            expect(seen.size).toBe(allCodes.length);
        });

        it('MAX_DELEGATION_DEPTH constant must match dc v0.3 max-depth literal value', () => {
            // single source of truth for the constant: MAX_DELEGATION_DEPTH = 5
            expect(MAX_DELEGATION_DEPTH).toBe(5);
        });

        it('DC_VERSION constant must match dc v0.3 spec version literal', () => {
            expect(DC_VERSION).toBe('0.3.0');
        });
    });
});
