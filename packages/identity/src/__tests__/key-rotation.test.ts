/**
 * Key rotation executor unit tests
 *
 * Covered scenarios:
 *   - normal single-rotation full flow
 *   - consecutive rotations (must complete before initiating again)
 *   - rejection of all three signature-tamper cases
 *   - rejection when new and old keys are identical
 *   - initiateKeyRotation throws when already in ROTATING state (in-memory flag + currentRotationState parameter)
 *   - completeKeyRotation throws for a non-rotating document
 *   - verifyRotationProof returns false when principalDid format is invalid
 *   - verifyRotationProof returns false when agentDid format is invalid
 *   - verifyRotationProof returns false when rotatedAt is invalid
 *   - initiateKeyRotation throws when principalApproval is invalid
 *   - initiateKeyRotation throws when currentRotationState: 'ROTATING'
 */

import { describe, expect, it } from 'vitest';

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import type { DID, Signature, Timestamp } from '@coivitas/types';

import {
    createAgentIdentity,
    didKeyFromPublicKey,
} from '../index.js';
import {
    completeKeyRotation,
    initiateKeyRotation,
    verifyRotationProof,
    type RotatingDocument,
} from '../key-rotation.js';

// -------- Test helpers --------

/**
 * Generate the principal pre-signature for a rotation payload (simulating an external signer's behavior, per spec).
 * The payload must be built exactly the same way as key-rotation.ts's internal buildSignedPayloadBytes.
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
 * Reuses createAgentIdentity to avoid hand-assembling the struct.
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
 * Helper that builds the principal pre-signature and calls initiateKeyRotation.
 * Wraps the full "caller generates rotatedAt -> principal pre-signs -> pass in" flow.
 */
function initiateWithPrincipalApproval(params: {
    doc: ReturnType<typeof makeTestIdentity>['doc'];
    agentPrivateKey: string;
    newKeyPair: ReturnType<typeof generateKeyPair>;
    principal: ReturnType<typeof generateKeyPair>;
    rotatedAt?: Timestamp;
}) {
    const rotatedAt = (params.rotatedAt ?? new Date().toISOString()) as Timestamp;
    const principalApproval = signRotationPayload(
        {
            agentDid: params.doc.id,
            newPublicKey: params.newKeyPair.publicKey,
            oldPublicKey: params.doc.publicKey,
            rotatedAt,
        },
        params.principal.privateKey,
    );
    return initiateKeyRotation({
        currentDoc: params.doc,
        currentPrivateKey: params.agentPrivateKey,
        newKeyPair: params.newKeyPair,
        principalApproval,
        rotatedAt,
    });
}

// -------- Normal rotation --------

describe('initiateKeyRotation', () => {
    it('should produce a RotatingDocument when given valid inputs', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // publicKey has switched to the new key
        expect(rotating.publicKey).toBe(newKeyPair.publicKey);
        // previousPublicKey retains the old key
        expect(rotating.previousPublicKey).toBe(doc.publicKey);
        // version auto-increments
        expect(rotating.version).toBe((doc.version ?? 1) + 1);
        // rotationProof fields are complete
        expect(rotating.rotationProof.oldPublicKey).toBe(doc.publicKey);
        expect(rotating.rotationProof.newPublicKey).toBe(newKeyPair.publicKey);
        expect(rotating.rotationProof.agentDid).toBe(doc.id);
        // specVersion bumped to 0.2.0
        expect(rotating.specVersion).toBe('0.2.0');
        // principalDid unchanged
        expect(rotating.principalDid).toBe(principalDid);
    });

    it('should throw when document is already in ROTATING state', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const newKeyPair = generateKeyPair();

        // First rotation -> obtain a RotatingDocument (carries _rotatingState in memory)
        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Initiating again without completing -> the in-memory flag is detected, should throw
        const newKeyPair2 = generateKeyPair();
        const rotatedAt2 = new Date().toISOString() as Timestamp;
        const principalApproval2 = signRotationPayload(
            {
                agentDid: rotating.id,
                newPublicKey: newKeyPair2.publicKey,
                oldPublicKey: rotating.publicKey,
                rotatedAt: rotatedAt2,
            },
            principal.privateKey,
        );
        expect(() =>
            initiateKeyRotation({
                currentDoc: rotating,
                currentPrivateKey: newKeyPair.privateKey,
                newKeyPair: newKeyPair2,
                principalApproval: principalApproval2,
                rotatedAt: rotatedAt2,
            }),
        ).toThrow('already in ROTATING state');
    });

    it('should throw when newKeyPair publicKey is invalid format', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const fakePublicKey = 'tooshort';
        const principalApproval = signRotationPayload(
            {
                agentDid: doc.id,
                newPublicKey: fakePublicKey,
                oldPublicKey: doc.publicKey,
                rotatedAt,
            },
            principal.privateKey,
        );

        expect(() =>
            initiateKeyRotation({
                currentDoc: doc,
                currentPrivateKey: agentPrivateKey,
                newKeyPair: { publicKey: fakePublicKey, privateKey: 'a'.repeat(128) },
                principalApproval,
                rotatedAt,
            }),
        ).toThrow('publicKey must be a 64-character hex string');
    });

    it('should throw when newKeyPair privateKey is invalid format', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const fakePublicKey = 'a'.repeat(64);
        const principalApproval = signRotationPayload(
            {
                agentDid: doc.id,
                newPublicKey: fakePublicKey,
                oldPublicKey: doc.publicKey,
                rotatedAt,
            },
            principal.privateKey,
        );

        expect(() =>
            initiateKeyRotation({
                currentDoc: doc,
                currentPrivateKey: agentPrivateKey,
                newKeyPair: { publicKey: fakePublicKey, privateKey: 'short' },
                principalApproval,
                rotatedAt,
            }),
        ).toThrow('privateKey must be a 128-character hex string');
    });

    it('should throw when new public key equals current public key', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = signRotationPayload(
            {
                agentDid: doc.id,
                newPublicKey: doc.publicKey,
                oldPublicKey: doc.publicKey,
                rotatedAt,
            },
            principal.privateKey,
        );

        expect(() =>
            initiateKeyRotation({
                currentDoc: doc,
                currentPrivateKey: agentPrivateKey,
                // Intentionally use the same public key (privateKey does not matter; the check happens after the public-key equality test)
                newKeyPair: {
                    publicKey: doc.publicKey,
                    privateKey: agentPrivateKey,
                },
                principalApproval,
                rotatedAt,
            }),
        ).toThrow('identical to the current public key');
    });

    it('should throw when principalApproval is an invalid signature', () => {
        // CRITICAL-2: throw SIGNATURE_INVALID when principalApproval verification fails
        const { doc, agentPrivateKey } = makeTestIdentity();
        const newKeyPair = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;

        // Random 128-char hex, not a valid signature over the correct payload
        const badApproval = 'deadbeef'.repeat(16) as Signature;

        expect(() =>
            initiateKeyRotation({
                currentDoc: doc,
                currentPrivateKey: agentPrivateKey,
                newKeyPair,
                principalApproval: badApproval,
                rotatedAt,
            }),
        ).toThrow('SIGNATURE_INVALID');
    });

    it('should throw when currentRotationState is ROTATING', () => {
        // The Registry passes the authoritative state ROTATING; even without the _rotatingState in-memory flag, it should be rejected
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const newKeyPair = generateKeyPair();
        const rotatedAt = new Date().toISOString() as Timestamp;
        const principalApproval = signRotationPayload(
            {
                agentDid: doc.id,
                newPublicKey: newKeyPair.publicKey,
                oldPublicKey: doc.publicKey,
                rotatedAt,
            },
            principal.privateKey,
        );

        expect(() =>
            initiateKeyRotation({
                currentDoc: doc,
                currentPrivateKey: agentPrivateKey,
                newKeyPair,
                principalApproval,
                rotatedAt,
                currentRotationState: 'ROTATING',
            }),
        ).toThrow('already in ROTATING state');
    });
});

// -------- verifyRotationProof --------

describe('verifyRotationProof', () => {
    it('should return true for a valid RotationProof', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        expect(
            verifyRotationProof(rotating.rotationProof, principalDid),
        ).toBe(true);
    });

    it('should return false when oldKeySignature is tampered', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Replace the entire signature with all zeros -- it can never be a valid signature
        const tampered = {
            ...rotating.rotationProof,
            oldKeySignature: '0'.repeat(128) as Signature,
        };

        expect(verifyRotationProof(tampered, principalDid)).toBe(false);
    });

    it('should return false when newKeySignature is tampered', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Replace the entire signature with all zeros -- it can never be a valid signature
        const tampered = {
            ...rotating.rotationProof,
            newKeySignature: '0'.repeat(128) as Signature,
        };

        expect(verifyRotationProof(tampered, principalDid)).toBe(false);
    });

    it('should return false when principalSignature is tampered', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Replace the entire signature with all zeros -- it can never be a valid signature
        const tampered = {
            ...rotating.rotationProof,
            principalSignature: '0'.repeat(128) as Signature,
        };

        expect(verifyRotationProof(tampered, principalDid)).toBe(false);
    });

    it('should return false when oldPublicKey equals newPublicKey', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Force newPublicKey to equal oldPublicKey
        const sameKeyProof = {
            ...rotating.rotationProof,
            newPublicKey: rotating.rotationProof.oldPublicKey,
        };

        expect(verifyRotationProof(sameKeyProof, principalDid)).toBe(false);
    });

    it('should return false when principalDid format is invalid', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        expect(
            verifyRotationProof(
                rotating.rotationProof,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                'did:invalid:notavalidkey' as unknown as DID,
            ),
        ).toBe(false);
    });

    it('should return false when oldPublicKey has invalid format', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        const badProof = {
            ...rotating.rotationProof,
            oldPublicKey: 'not-valid-hex',
        };

        expect(verifyRotationProof(badProof, principalDid)).toBe(false);
    });

    it('should return false when agentDid format is invalid', () => {
        // Returns false when agentDid does not match the did:agent: format
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        const badProof = {
            ...rotating.rotationProof,
            agentDid: 'did:invalid:notanagentdid' as DID,
        };

        expect(verifyRotationProof(badProof, principalDid)).toBe(false);
    });

    it('should return false when rotatedAt is not a valid ISO 8601 timestamp', () => {
        // Returns false when rotatedAt is not a valid timestamp
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        const badProof = {
            ...rotating.rotationProof,
            rotatedAt: 'not-a-date' as Timestamp,
        };

        expect(verifyRotationProof(badProof, principalDid)).toBe(false);
    });

    it('should return false when rotatedAt has no milliseconds (non-canonical)', () => {
        // P2: an ISO timestamp missing the milliseconds part does not conform to the wire format spec
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        const badProof = {
            ...rotating.rotationProof,
            rotatedAt: '2026-04-21T12:00:00Z' as Timestamp,
        };

        expect(verifyRotationProof(badProof, principalDid)).toBe(false);
    });

    it('should return false when rotatedAt has timezone offset instead of Z', () => {
        // P2: a timestamp with a timezone offset does not conform to the spec's required UTC Z-suffixed format
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        const badProof = {
            ...rotating.rotationProof,
            rotatedAt: '2026-04-21T20:00:00.000+08:00' as Timestamp,
        };

        expect(verifyRotationProof(badProof, principalDid)).toBe(false);
    });
});

// -------- completeKeyRotation --------

describe('completeKeyRotation', () => {
    it('should return an AgentIdentityDocument with all rotation fields preserved', () => {
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        const completed = completeKeyRotation(rotating);

        // publicKey is now the new key
        expect(completed.publicKey).toBe(newKeyPair.publicKey);
        // previousPublicKey retained
        expect(completed.previousPublicKey).toBe(doc.publicKey);
        // rotationProof retained
        expect(completed.rotationProof).toBeDefined();
        expect(completed.rotationProof?.oldPublicKey).toBe(doc.publicKey);
        // version has auto-incremented
        expect(completed.version).toBe((doc.version ?? 1) + 1);
    });

    it('should throw when document is not in ROTATING state', () => {
        const { doc } = makeTestIdentity();

        // Plain document (no rotationProof / previousPublicKey)
        expect(() => completeKeyRotation(doc as RotatingDocument)).toThrow(
            'not in ROTATING state',
        );
    });

    it('should succeed with Registry-loaded doc when currentRotationState ROTATING is passed', () => {
        // P1 Registry path: after JSON serialize/deserialize, _rotatingState is lost; pass the authoritative state via opts
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Simulate persist to Registry then load: _rotatingState is a runtime internal brand,
        // the Registry stores a clean AgentIdentityDocument without this field.
        // Remove it explicitly via destructuring to simulate the document state after loading from the Registry.
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { _rotatingState: _dropped, ...registryLoaded } = rotating;

        // Should not contain the _rotatingState field (the core premise of simulating the Registry path)
        expect('_rotatingState' in registryLoaded).toBe(false);

        // With the authoritative state passed via opts, complete should succeed
        const completed = completeKeyRotation(registryLoaded, { currentRotationState: 'ROTATING' });
        expect(completed.publicKey).toBe(newKeyPair.publicKey);
        expect(completed.rotationProof).toBeDefined();
        expect('_rotatingState' in completed).toBe(false);
    });

    it('should throw with Registry-loaded doc when no currentRotationState option passed', () => {
        // P1: when _rotatingState is lost and no opts is passed, reject (to prevent misoperating a non-rotating document)
        const { doc, agentPrivateKey, principal } = makeTestIdentity();
        const newKeyPair = generateKeyPair();

        const rotating = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair,
            principal,
        });

        // Simulate Registry load: explicitly remove the runtime brand field
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { _rotatingState: _dropped, ...registryLoaded } = rotating;

        expect(() => completeKeyRotation(registryLoaded)).toThrow(
            'not in ROTATING state',
        );
    });
});

// -------- Consecutive rotations --------

describe('consecutive key rotations', () => {
    it('should allow second rotation after completing the first', () => {
        const { doc, agentPrivateKey, principal, principalDid } =
            makeTestIdentity();
        const newKeyPair1 = generateKeyPair();
        const newKeyPair2 = generateKeyPair();

        // First rotation
        const rotating1 = initiateWithPrincipalApproval({
            doc,
            agentPrivateKey,
            newKeyPair: newKeyPair1,
            principal,
        });
        expect(
            verifyRotationProof(rotating1.rotationProof, principalDid),
        ).toBe(true);

        const completed1 = completeKeyRotation(rotating1);

        // Second rotation (based on the document completed in the first)
        const rotating2 = initiateWithPrincipalApproval({
            doc: completed1,
            agentPrivateKey: newKeyPair1.privateKey,
            newKeyPair: newKeyPair2,
            principal,
        });

        expect(rotating2.publicKey).toBe(newKeyPair2.publicKey);
        expect(rotating2.previousPublicKey).toBe(newKeyPair1.publicKey);
        expect(rotating2.version).toBe((doc.version ?? 1) + 2);
        expect(
            verifyRotationProof(rotating2.rotationProof, principalDid),
        ).toBe(true);

        const completed2 = completeKeyRotation(rotating2);
        expect(completed2.publicKey).toBe(newKeyPair2.publicKey);
    });
});
