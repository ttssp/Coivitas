/**
 * Grace Period verification unit tests
 *
 * Covered scenarios:
 *   resolvePublicKeys:
 *     - ACTIVE/RETIRED returns only current
 *     - ROTATING + not expired + previousPublicKey present -> dual keys
 *     - ROTATING + expired -> returns only current
 *     - ROTATING + previousPublicKey missing -> returns only current
 *     - ROTATING + rotationStartedAt=null -> degrade, returns only current
 *     - custom gracePeriodMs takes effect
 *
 *   verifyAgentIdentityDocument v>1:
 *     - valid rotationProof -> valid
 *     - rotationProof missing -> error field='rotationProof'
 *     - rotationProof signature invalid -> error field='rotationProof'
 *
 *   verifyCapabilityToken dual keys:
 *     - resolvedKeys provided, signed with current key -> valid
 *     - resolvedKeys provided, signed with previous key + ROTATING -> valid
 *     - resolvedKeys provided, signed with previous key + non-ROTATING -> invalid
 *     - resolvedKeys provided, unknown key + ROTATING -> invalid
 *     - resolvedKeys provided, issuerDid is did:agent -> valid
 *     - resolvedKeys not provided, issuerDid must be did:key (backward compatibility)
 */

import { describe, expect, it } from 'vitest';

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import type {
    AgentIdentityDocument,
    DID,
    ResolvedPublicKeys,
    Signature,
    Timestamp,
} from '@coivitas/types';

import {
    DEFAULT_GRACE_PERIOD_MS,
    buildAgentIdentityDocument,
    checkTokenForAction,
    createAgentIdentity,
    didKeyFromPublicKey,
    issueCapabilityToken,
    resolvePublicKeys,
    verifyAgentIdentityDocument,
    verifyCapabilityToken,
} from '../index.js';
import {
    completeKeyRotation,
    initiateKeyRotation,
} from '../key-rotation.js';

// -------- Test helpers --------

/**
 * Build the principal pre-signature (consistent with key-rotation.ts's internal buildSignedPayloadBytes)
 */
function signRotationPayload(
    payload: {
        agentDid: string;
        newPublicKey: string;
        oldPublicKey: string;
        rotatedAt: string;
    },
    privateKey: string,
): Signature {
    const bytes = new TextEncoder().encode(
        canonicalize({
            agentDid: payload.agentDid,
            newPublicKey: payload.newPublicKey,
            oldPublicKey: payload.oldPublicKey,
            rotatedAt: payload.rotatedAt,
        }),
    );
    return sign(bytes, privateKey) as Signature;
}

/**
 * Create a minimal usable AgentIdentityDocument plus the related key material.
 */
function makeTestIdentity() {
    const principal = generateKeyPair();
    const principalDid = didKeyFromPublicKey(
        Buffer.from(principal.publicKey, 'hex'),
    );
    const result = createAgentIdentity({
        principalDid,
        principalPrivateKey: principal.privateKey,
        capabilities: ['INQUIRY'],
    });
    return {
        doc: result.document,
        agentPrivateKey: result.privateKey,
        principal,
        principalDid,
    };
}

/**
 * Perform one complete key rotation and return the rotated document and the new private key.
 */
function performRotation(params: {
    doc: AgentIdentityDocument;
    agentPrivateKey: string;
    principal: ReturnType<typeof generateKeyPair>;
    rotatedAt?: Timestamp;
}) {
    const newKeyPair = generateKeyPair();
    const rotatedAt = (params.rotatedAt ?? new Date().toISOString()) as Timestamp;
    const principalApproval = signRotationPayload(
        {
            agentDid: params.doc.id,
            newPublicKey: newKeyPair.publicKey,
            oldPublicKey: params.doc.publicKey,
            rotatedAt,
        },
        params.principal.privateKey,
    );
    const rotatingDoc = initiateKeyRotation({
        currentDoc: params.doc,
        currentPrivateKey: params.agentPrivateKey,
        newKeyPair,
        principalApproval,
        rotatedAt,
    });
    return { rotatingDoc, newKeyPair, rotatedAt };
}

// -------- resolvePublicKeys test group --------

describe('resolvePublicKeys', () => {
    it('should return only current when rotationState is ACTIVE', () => {
        const { doc } = makeTestIdentity();
        const result = resolvePublicKeys({
            document: doc,
            rotationState: 'ACTIVE',
            rotationStartedAt: null,
        });

        expect(result.current).toBe(doc.publicKey);
        expect(result.previous).toBeUndefined();
        // previousValidBefore/version have been removed from ResolvedPublicKeys (v0.3.0)
        expect(result.rotationState).toBe('STABLE');
    });

    it('should return only current when rotationState is RETIRED', () => {
        const { doc } = makeTestIdentity();
        const result = resolvePublicKeys({
            document: doc,
            rotationState: 'RETIRED',
            rotationStartedAt: null,
        });

        expect(result.current).toBe(doc.publicKey);
        expect(result.previous).toBeUndefined();
        // RETIRED -> STABLE (v0.3.0 state mapping)
        expect(result.rotationState).toBe('STABLE');
    });

    it('should return previous when ROTATING and within grace period', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPublicKey = doc.publicKey;
        const rotatedAt = new Date(Date.now() - 1000).toISOString() as Timestamp; // 1 second ago
        const { rotatingDoc } = performRotation({
            doc,
            agentPrivateKey,
            principal,
            rotatedAt,
        });

        const result = resolvePublicKeys(
            {
                document: rotatingDoc,
                rotationState: 'ROTATING',
                rotationStartedAt: rotatedAt,
            },
            { gracePeriodMs: DEFAULT_GRACE_PERIOD_MS },
        );

        expect(result.current).toBe(rotatingDoc.publicKey);
        expect(result.previous).toBe(oldPublicKey);
        // previousValidBefore has been removed from ResolvedPublicKeys (v0.3.0);
        // callers should read it from AgentRegistryRecord.rotationStartedAt
        expect(result.rotationState).toBe('ROTATING');
    });

    it('should not return previous when ROTATING and grace period expired', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        // rotationStartedAt set to 25 hours ago (beyond the default 24h Grace Period)
        const expiredAt = new Date(
            Date.now() - 25 * 60 * 60 * 1000,
        ).toISOString() as Timestamp;
        const { rotatingDoc } = performRotation({
            doc,
            agentPrivateKey,
            principal,
            rotatedAt: expiredAt,
        });

        const result = resolvePublicKeys({
            document: rotatingDoc,
            rotationState: 'ROTATING',
            rotationStartedAt: expiredAt,
        });

        expect(result.current).toBe(rotatingDoc.publicKey);
        expect(result.previous).toBeUndefined();
    });

    it('should not return previous when ROTATING but previousPublicKey missing', () => {
        const { doc } = makeTestIdentity();
        // Manually construct a document missing previousPublicKey (not via initiateKeyRotation)
        const docWithoutPrevious: AgentIdentityDocument = {
            ...doc,
            version: 2,
            // previousPublicKey intentionally missing
        };

        const result = resolvePublicKeys({
            document: docWithoutPrevious,
            rotationState: 'ROTATING',
            rotationStartedAt: new Date(Date.now() - 1000).toISOString() as Timestamp,
        });

        expect(result.current).toBe(doc.publicKey);
        expect(result.previous).toBeUndefined();
    });

    it('should map to STABLE when ROTATING but rotationStartedAt is null', () => {
        // rotationStartedAt missing -> cannot compute the cutoff
        // (rotationStartedAt serves as the previousValidBefore starting point).
        // The schema has hardened "ROTATING required [previous, previousValidBefore]";
        // missing rotationStartedAt = "cannot prove a rotation is in progress" = equivalent to STABLE semantics,
        // a schema-runtime consistent fail-closed.
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const { rotatingDoc } = performRotation({ doc, agentPrivateKey, principal });

        const result = resolvePublicKeys({
            document: rotatingDoc,
            rotationState: 'ROTATING',
            rotationStartedAt: null, // no rotation start time -> degrade
        });

        expect(result.current).toBe(rotatingDoc.publicKey);
        expect(result.previous).toBeUndefined();
        expect(result.previousValidBefore).toBeUndefined();
        // The degrade path maps to STABLE, consistent with the schema
        expect(result.rotationState).toBe('STABLE');
    });

    it('should use custom gracePeriodMs when provided', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPublicKey = doc.publicKey;
        // Rotation started 30 minutes ago
        const rotatedAt = new Date(
            Date.now() - 30 * 60 * 1000,
        ).toISOString() as Timestamp;
        const { rotatingDoc } = performRotation({
            doc,
            agentPrivateKey,
            principal,
            rotatedAt,
        });

        // Custom Grace Period = 1 hour (30 minutes < 1 hour, should return previous)
        const result1 = resolvePublicKeys(
            {
                document: rotatingDoc,
                rotationState: 'ROTATING',
                rotationStartedAt: rotatedAt,
            },
            { gracePeriodMs: 60 * 60 * 1000 },
        );
        expect(result1.previous).toBe(oldPublicKey);

        // Custom Grace Period = 10 minutes (30 minutes > 10 minutes, should not return previous)
        const result2 = resolvePublicKeys(
            {
                document: rotatingDoc,
                rotationState: 'ROTATING',
                rotationStartedAt: rotatedAt,
            },
            { gracePeriodMs: 10 * 60 * 1000 },
        );
        expect(result2.previous).toBeUndefined();
    });
});

// -------- verifyAgentIdentityDocument v>1 test group --------

describe('verifyAgentIdentityDocument v>1', () => {
    it('should return valid when version > 1 and rotationProof is valid', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const { rotatingDoc } = performRotation({ doc, agentPrivateKey, principal });
        // completeKeyRotation returns a normal document (with a valid rotationProof)
        const completedDoc = completeKeyRotation(rotatingDoc);

        const result = verifyAgentIdentityDocument(completedDoc);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('should return error when version > 1 and rotationProof is missing', () => {
        const { doc } = makeTestIdentity();
        const noProof: AgentIdentityDocument = {
            ...doc,
            version: 2,
            // rotationProof intentionally missing
        };

        const result = verifyAgentIdentityDocument(noProof);
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'rotationProof'),
        ).toBe(true);
        expect(
            result.errors.find((e) => e.field === 'rotationProof')?.message,
        ).toMatch(/required when version > 1/);
    });

    it('should return error when version > 1 and rotationProof signature is invalid', () => {
        const { doc } = makeTestIdentity();
        const invalidProof: AgentIdentityDocument = {
            ...doc,
            version: 2,
            previousPublicKey: 'a'.repeat(64),
            rotationProof: {
                oldPublicKey: 'a'.repeat(64),
                newPublicKey: doc.publicKey,
                // Intentionally use invalid signatures
                oldKeySignature: 'b'.repeat(128) as unknown as Signature,
                newKeySignature: 'b'.repeat(128) as unknown as Signature,
                principalSignature: 'b'.repeat(128) as unknown as Signature,
                agentDid: doc.id,
                rotatedAt: doc.createdAt,
            },
        };

        const result = verifyAgentIdentityDocument(invalidProof);
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'rotationProof'),
        ).toBe(true);
        expect(
            result.errors.find((e) => e.field === 'rotationProof')?.message,
        ).toMatch(/triple-signature verification failed/);
    });
});

// -------- verifyCapabilityToken dual-key test group --------

describe('verifyCapabilityToken dual keys', () => {
    const issuedTo = 'did:agent:00112233445566778899aabbccddeeff00112233' as DID;
    const expiresAt = '2099-12-31T23:59:59.000Z' as Timestamp;
    const revocationUrl = 'https://revocation.example.com/v1/{id}';
    const now = '2026-04-21T10:00:00.000Z' as Timestamp;

    /**
     * Issue a capability token (issuerDid may be did:key or did:agent).
     * Note: issueCapabilityToken internally requires issuerDid to be did:key,
     * so for dual-key scenarios we construct a token with a did:agent issuerDid directly.
     */
    function issueTokenWithKey(privateKey: string, publicKey: string) {
        const issuerDid = didKeyFromPublicKey(Buffer.from(publicKey, 'hex'));
        return issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'recipient', values: ['supplier-a'] },
                },
            ],
            expiresAt,
            revocationUrl,
            issuerPrivateKey: privateKey,
            issuedAt: now,
        });
    }

    it('should verify token signed with current key when resolvedKeys provided', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const { newKeyPair, rotatedAt } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // Issue the token with the new key
        const token = issueTokenWithKey(newKeyPair.privateKey, newKeyPair.publicKey);

        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type (including previousValidBefore)
        // verifyCapabilityToken's parameter type has been widened to ResolvedKeysWithGrace (internal type)
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: doc.publicKey,
            previousValidBefore: rotatedAt,
            rotationState: 'ROTATING' as const,
        };

        const result = verifyCapabilityToken(token, now, resolvedKeys);
        expect(result.valid).toBe(true);
    });

    it('should verify token signed with previous key when ROTATING and within grace period', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPrivateKey = agentPrivateKey;
        const oldPublicKey = doc.publicKey;

        // rotatedAt is explicitly set after now to ensure token.issuedAt (= now) <= previousValidBefore (= rotatedAt)
        // Semantics: the rotation is triggered after the token issuance time, so existing tokens issued with the old key are legitimate
        const rotatedAt = '2026-04-21T12:00:00.000Z' as Timestamp;
        const { newKeyPair } = performRotation({
            doc,
            agentPrivateKey,
            principal,
            rotatedAt,
        });

        // Issue the token with the old key (simulating an existing token issued with the old key within the Grace Period)
        const token = issueTokenWithKey(oldPrivateKey, oldPublicKey);

        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: oldPublicKey,
            previousValidBefore: rotatedAt,
            rotationState: 'ROTATING' as const,
        };

        const result = verifyCapabilityToken(token, now, resolvedKeys);
        expect(result.valid).toBe(true);
    });

    it('should reject token signed with previous key when rotationState is ACTIVE (not ROTATING)', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPrivateKey = agentPrivateKey;
        const oldPublicKey = doc.publicKey;

        const { newKeyPair } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // Issue the token with the old key
        const token = issueTokenWithKey(oldPrivateKey, oldPublicKey);

        // ACTIVE -> STABLE (v0.3.0 state mapping); test semantics unchanged: the old key is not accepted when not ROTATING
        const resolvedKeys: ResolvedPublicKeys = {
            current: newKeyPair.publicKey,
            previous: oldPublicKey,
            rotationState: 'STABLE', // not ROTATING, mapped from v0.2 ACTIVE
        };

        const result = verifyCapabilityToken(token, now, resolvedKeys);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('SIGNATURE_INVALID');
    });

    it('should reject token signed with unknown key even when ROTATING', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const { newKeyPair, rotatedAt } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // Issue the token with a completely unrelated key
        const unknownKeyPair = generateKeyPair();
        const token = issueTokenWithKey(unknownKeyPair.privateKey, unknownKeyPair.publicKey);

        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: doc.publicKey,
            previousValidBefore: rotatedAt,
            rotationState: 'ROTATING' as const,
        };

        const result = verifyCapabilityToken(token, now, resolvedKeys);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('SIGNATURE_INVALID');
    });

    it('should accept did:agent verificationMethod when resolvedKeys provided', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const { rotatingDoc, newKeyPair, rotatedAt } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // Issue a valid token with the new key (issuerDid is did:key, conforming to the capabilityToken schema)
        const currentKeyToken = issueTokenWithKey(newKeyPair.privateKey, newKeyPair.publicKey);

        // Replace proof.verificationMethod with the did:agent format
        // verificationMethod is not in the signing payload (CapabilityTokenPayload = Omit<CapabilityToken, 'proof'>),
        // so modifying this field does not affect signature validity.
        const tokenWithAgentVerificationMethod = {
            ...currentKeyToken,
            proof: {
                ...currentKeyToken.proof,
                verificationMethod: `${rotatingDoc.id}#key-1`,
            },
        };

        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: doc.publicKey,
            previousValidBefore: rotatedAt,
            rotationState: 'ROTATING' as const,
        };

        // When resolvedKeys is present, verificationMethod should not be restricted to did:key,
        // and the signature is still valid (the payload excludes proof), so the result should be valid: true
        const result = verifyCapabilityToken(
            tokenWithAgentVerificationMethod as typeof currentKeyToken,
            now,
            resolvedKeys,
        );
        expect(result.valid).toBe(true);
    });

    it('should reject token signed with previous key when issuedAt is after previousValidBefore', () => {
        // C-1 scenario: the token is signed with the old key but issuedAt is later than previousValidBefore -> should return SIGNATURE_INVALID
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPrivateKey = agentPrivateKey;
        const oldPublicKey = doc.publicKey;

        const { newKeyPair } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // previousValidBefore set to a time earlier than issuedAt
        const previousValidBefore = '2026-04-20T10:00:00.000Z' as Timestamp;
        // The token's issuedAt is later than previousValidBefore
        const lateIssuedAt = '2026-04-21T10:00:00.000Z' as Timestamp;

        // Issue the token with the old key (but issuedAt is later than the grace cutoff)
        const token = issueTokenWithKey(oldPrivateKey, oldPublicKey);
        // Manually replace issuedAt with a time later than previousValidBefore (issuedAt is not in the signed proof, but is in the payload)
        // In fact issueTokenWithKey already used now = lateIssuedAt; just override issuedAt directly
        const tokenWithLateIssuedAt = {
            ...token,
            issuedAt: lateIssuedAt,
        };

        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: oldPublicKey,
            previousValidBefore,
            rotationState: 'ROTATING' as const,
        };

        const result = verifyCapabilityToken(
            tokenWithLateIssuedAt as typeof token,
            lateIssuedAt,
            resolvedKeys,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('SIGNATURE_INVALID');
    });

    it('should reject previous key when previousValidBefore is undefined (fail-closed)', () => {
        // C-1 fail-closed: resolvedKeys has previous but no previousValidBefore -> do not attempt the old key
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPrivateKey = agentPrivateKey;
        const oldPublicKey = doc.publicKey;

        const { newKeyPair } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // Issue the token with the old key
        const token = issueTokenWithKey(oldPrivateKey, oldPublicKey);

        // resolvedKeys has previous but no previousValidBefore
        // Drop the version field (removed from v0.3.0 ResolvedPublicKeys)
        const resolvedKeys: ResolvedPublicKeys = {
            current: newKeyPair.publicKey,
            previous: oldPublicKey,
            // previousValidBefore intentionally missing (tests fail-closed semantics)
            rotationState: 'ROTATING',
        };

        const result = verifyCapabilityToken(token, now, resolvedKeys);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('SIGNATURE_INVALID');
    });

    it('should accept previous key when issuedAt equals previousValidBefore (boundary)', () => {
        // C-1 boundary: issuedAt === previousValidBefore -> <= semantics, should pass
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const oldPrivateKey = agentPrivateKey;
        const oldPublicKey = doc.publicKey;

        const { newKeyPair } = performRotation({
            doc,
            agentPrivateKey,
            principal,
        });

        // issuedAt is exactly equal to previousValidBefore (boundary value)
        const boundaryTime = '2026-04-21T10:00:00.000Z' as Timestamp;

        // Issue the token with the old key, issuedAt = boundaryTime
        const token = issueTokenWithKey(oldPrivateKey, oldPublicKey);

        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: oldPublicKey,
            previousValidBefore: boundaryTime, // same as issuedAt
            rotationState: 'ROTATING' as const,
        };

        // The token's issuedAt = now = boundaryTime, previousValidBefore = boundaryTime
        // issuedAt <= previousValidBefore -> the old key should be allowed for verification
        const result = verifyCapabilityToken(token, boundaryTime, resolvedKeys);
        expect(result.valid).toBe(true);
    });

    it('should still enforce did:key when resolvedKeys not provided (backward compat)', () => {
        // Attempt to create a token whose issuerDid is did:agent (no resolvedKeys)
        // issueCapabilityToken requires did:key, so we construct it manually
        const agentPair = generateKeyPair();
        const validToken = issueTokenWithKey(agentPair.privateKey, agentPair.publicKey);

        // Replace issuerDid with did:agent and do not pass resolvedKeys
        const tokenWithAgentIssuer = {
            ...validToken,
            issuerDid: 'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
        };

        // No resolvedKeys passed -> did:key should be strictly required
        const result = verifyCapabilityToken(
            tokenWithAgentIssuer as typeof validToken,
            now,
            // resolvedKeys omitted
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/did:key/);
    });

    it('should reject issuerDid that passes schema but fails isDidKey check when no resolvedKeys (dead-code guard)', () => {
        // Covers the defensive check at token-verifier.ts lines 64-69:
        // did:key's base58btc charset excludes '0', but the schema pattern [a-zA-Z0-9._%-]+ allows '0'.
        // 'did:key:abc0' passes JSON Schema but isDidKey() returns false (contains '0').
        // No resolvedKeys passed -> hits the else branch (line 63) -> !isDidKey -> returns INVALID_TOKEN_FORMAT.
        const agentPair = generateKeyPair();
        const validToken = issueTokenWithKey(agentPair.privateKey, agentPair.publicKey);
        const tokenWithMalformedKey = {
            ...validToken,
            issuerDid: 'did:key:abc0xyz' as DID, // contains '0': not valid base58btc, but passes the schema
        };

        const result = verifyCapabilityToken(
            tokenWithMalformedKey as typeof validToken,
            now,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
    });

    it('should reject issuerDid that is neither did:key nor did:agent when resolvedKeys provided (dead-code guard)', () => {
        // Covers the defensive check at token-verifier.ts lines 56-61:
        // When resolvedKeys is provided, did:key or did:agent is allowed; other formats should be rejected.
        // 'did:key:abc0xyz' passes the schema but fails isDidKey (contains '0') and fails isDidAgent.
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const { newKeyPair, rotatedAt } = performRotation({ doc, agentPrivateKey, principal });
        const validToken = issueTokenWithKey(agentPrivateKey, doc.publicKey);
        const tokenWithMalformedKey = {
            ...validToken,
            issuerDid: 'did:key:abc0xyz' as DID,
        };
        // Drop the : ResolvedPublicKeys annotation so TS infers the wide type
        const resolvedKeys = {
            current: newKeyPair.publicKey,
            previous: doc.publicKey,
            previousValidBefore: rotatedAt,
            rotationState: 'ROTATING' as const,
        };

        const result = verifyCapabilityToken(
            tokenWithMalformedKey as typeof validToken,
            now,
            resolvedKeys,
        );
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/did:key or did:agent/);
    });
});

describe('checkTokenForAction coverage supplement (changed file token-verifier.ts)', () => {
    const issuer = generateKeyPair();
    const issuerDid = didKeyFromPublicKey(Buffer.from(issuer.publicKey, 'hex'));
    const issuedTo = 'did:agent:00112233445566778899aabbccddeeff00112233' as DID;

    it('should return SCOPE_TYPE_UNKNOWN for unsupported scope type in checkTokenForAction', () => {
        // Construct a token carrying temporal_scope (a not-yet-supported scope type)
        // Note: call checkTokenForAction directly, bypassing verifyCapabilityToken,
        // because verifyCapabilityToken rejects the unsupported scope of a 0.1.0 token early.
        // checkTokenForAction is a standalone function whose fail-closed branch must be covered separately.
        const baseToken = issueCapabilityToken({
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

        // Manually replace the scope in capabilities with an unknown type
        const tokenWithUnknownScope = {
            ...baseToken,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: {
                        type: 'temporal_scope',
                        notBefore: '2026-04-21T00:00:00.000Z',
                        notAfter: '2026-04-22T00:00:00.000Z',
                    },
                },
            ],
        };

        const result = checkTokenForAction(
            tokenWithUnknownScope as typeof baseToken,
            'INQUIRY',
            { recipient: 'supplier-a' },
            issuedTo,
        );
        expect(result.allowed).toBe(false);
        expect(result.code).toBe('SCOPE_TYPE_UNKNOWN');
        expect(result.message).toMatch(/temporal_scope/);
    });

    it('should allow action when numeric_limit field is absent from params', () => {
        // In numeric_limit, when fieldValue is undefined it should continue (allow)
        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
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

        // Do not pass the amount field (no 'amount' key in params) -> fieldValue is undefined -> continue
        const result = checkTokenForAction(token, 'QUOTE', {}, issuedTo);
        expect(result.allowed).toBe(true);
    });

    it('should return TOKEN_NOT_FOR_THIS_AGENT when agentDid does not match issuedTo', () => {
        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'x', values: ['y'] },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        const wrongAgent =
            'did:agent:aabbccddeeff00112233445566778899aabbccdd' as DID;
        const result = checkTokenForAction(token, 'INQUIRY', { x: 'y' }, wrongAgent);
        expect(result.allowed).toBe(false);
        expect(result.code).toBe('TOKEN_NOT_FOR_THIS_AGENT');
    });

    it('should return INVALID_ACTION when action is not in token capabilities', () => {
        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'x', values: ['y'] },
                },
            ],
            expiresAt: '2026-04-22T10:00:00.000Z' as Timestamp,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: '2026-04-21T10:00:00.000Z' as Timestamp,
        });

        const result = checkTokenForAction(token, 'QUOTE', {}, issuedTo);
        expect(result.allowed).toBe(false);
        expect(result.code).toBe('INVALID_ACTION');
    });

    it('should reject token where issuedAt is in the future', () => {
        // Issue a token and set issuedAt to a future time
        const futureIssuedAt = '2026-04-22T10:00:00.000Z' as Timestamp;
        const futureExpiresAt = '2026-04-23T10:00:00.000Z' as Timestamp;
        const token = issueCapabilityToken({
            issuerDid,
            issuedTo,
            capabilities: [
                {
                    action: 'INQUIRY',
                    scope: { type: 'allowlist', field: 'x', values: ['y'] },
                },
            ],
            expiresAt: futureExpiresAt,
            revocationUrl: 'https://revocation.example.com/v1/{id}',
            issuerPrivateKey: issuer.privateKey,
            issuedAt: futureIssuedAt,
        });

        // now is earlier than issuedAt -> issuedAt is in the future
        const pastNow = '2026-04-21T10:00:00.000Z' as Timestamp;
        const result = verifyCapabilityToken(token, pastNow);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('INVALID_TOKEN_FORMAT');
        expect(result.message).toMatch(/issuedAt/);
    });
});

describe('verifyAgentIdentityDocument coverage supplement (changed file did-agent.ts)', () => {
    it('should detect bindingProof principalDid mismatch', () => {
        const principal1 = generateKeyPair();
        const principal2 = generateKeyPair();
        const principalDid1 = didKeyFromPublicKey(
            Buffer.from(principal1.publicKey, 'hex'),
        );
        const principalDid2 = didKeyFromPublicKey(
            Buffer.from(principal2.publicKey, 'hex'),
        );

        // Binding signed by principal1, but document.principalDid is replaced with principal2
        const { document } = createAgentIdentity({
            principalDid: principalDid1,
            principalPrivateKey: principal1.privateKey,
        });

        const tampered = {
            ...document,
            principalDid: principalDid2, // tampered to a different principal
            // bindingProof.principalDid still points to principalDid1
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'bindingProof.principalDid'),
        ).toBe(true);
    });

    it('should detect invalid bindingProof signature', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Tamper with bindingProof.signature to make verifyBinding fail
        const tampered = {
            ...document,
            bindingProof: {
                ...document.bindingProof,
                signature: 'b'.repeat(128) as Signature,
            },
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'bindingProof'),
        ).toBe(true);
    });

    it('should detect publicKey mismatch with document.id when version=1', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Replace publicKey with another key but keep id unchanged (when version=1, id must be derived from publicKey)
        const anotherKey = generateKeyPair();
        const tampered = {
            ...document,
            publicKey: anotherKey.publicKey,
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.field === 'publicKey')).toBe(true);
    });

    it('should detect bindingProof agentDid mismatch with document.id', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const { document: doc1 } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });
        const { document: doc2 } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Replace doc1's bindingProof with doc2's bindingProof (different agentDid)
        const tampered = {
            ...doc1,
            bindingProof: doc2.bindingProof,
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'bindingProof.agentDid'),
        ).toBe(true);
    });

    it('should detect invalid id format (not did:agent)', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Replace id with a non-did:agent format
        const tampered = {
            ...document,
            id: 'did:key:z6MkHasInvalidFormat' as DID,
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.field === 'id')).toBe(true);
    });

    it('should detect invalid principalDid format (not did:key)', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Replace principalDid with a non-did:key format (did:agent format)
        const tampered = {
            ...document,
            principalDid:
                'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'principalDid'),
        ).toBe(true);
    });

    it('should use current timestamp when createdAt is not provided to buildAgentIdentityDocument', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );
        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Call buildAgentIdentityDocument directly without createdAt to trigger the new Date().toISOString() branch
        const doc = buildAgentIdentityDocument({
            agentDid: document.id,
            agentPublicKeyHex: document.publicKey,
            principalDid,
            bindingProof: document.bindingProof,
            // createdAt intentionally omitted
        });

        expect(doc.createdAt).toBeDefined();
        expect(new Date(doc.createdAt).getTime()).toBeLessThanOrEqual(
            Date.now(),
        );
    });

    it('should detect unsupported specVersion', () => {
        const principal = generateKeyPair();
        const principalDid = didKeyFromPublicKey(
            Buffer.from(principal.publicKey, 'hex'),
        );

        const { document } = createAgentIdentity({
            principalDid,
            principalPrivateKey: principal.privateKey,
        });

        // Replace specVersion with an unsupported version
        const tampered = {
            ...document,
            specVersion: '9.9.9',
        };

        const result = verifyAgentIdentityDocument(
            tampered as AgentIdentityDocument,
        );
        expect(result.valid).toBe(false);
        expect(
            result.errors.some((e) => e.field === 'specVersion'),
        ).toBe(true);
    });
});
