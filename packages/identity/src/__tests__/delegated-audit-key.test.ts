/**
 * DelegatedAuditKey L2 real verifier unit tests
 *
 * Scenarios covered:
 *   - createDelegatedAuditKey field population + purpose enforcement
 *   - all paths of the 5-step fail-closed verify:
 *     Step 1: resolve the delegatedFrom public key (null -> DELEGATOR_SIGNATURE_INVALID)
 *     Step 2: Ed25519 verify (signature mismatch -> DELEGATOR_SIGNATURE_INVALID)
 *     Step 3: signedBy === delegatedFrom (mismatch -> DELEGATOR_SIGNATURE_INVALID)
 *     Step 4: validFrom <= now <= validUntil (out of window -> TOKEN_EXPIRED)
 *     Step 5: revoked !== true (revoked -> TOKEN_INVALID)
 *   - happy path (all 5 steps pass; return void)
 *   - grep verify that AuditEvaluatorNotImplemented is fully removed
 */

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import { AuditShareError } from '@coivitas/types';
import type { DID, Signature, Timestamp } from '@coivitas/types';
import { describe, expect, it } from 'vitest';

import {
    createDelegatedAuditKey,
    verifyDelegatedAuditKey,
    type CreateDelegatedAuditKeyParams,
    type DelegatedAuditKey,
    type DelegatedAuditKeyProof,
    type ResolvePublicKeyFn,
} from '../delegated-audit-key.js';

// ── test helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a valid delegator key + real Ed25519 signature (real-implementation test fixture)
 */
function buildSignedKey(overrides: {
    auditKeyId?: string;
    delegatedFrom?: DID;
    delegatedTo?: DID;
    validFrom?: Timestamp;
    validUntil?: Timestamp;
    revoked?: boolean;
}): { key: DelegatedAuditKey; publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = generateKeyPair();
    const delegatedFrom =
        overrides.delegatedFrom ?? ('did:key:principal-001' as DID);

    // test fixture scope binding:
    // DelegatedAuditKey.scope is a mandatory field; the test fixture's default scope uses a sentinel binding
    const scope = {
        tenantId: '00000000-0000-4000-8000-000000000001',
        auditClass: 'L1',
    } as unknown as import('@coivitas/types').AuditShareScope;

    // scope via store-level integrity (not signed in the payload)
    const baseFieldsForSign = {
        auditKeyId:
            overrides.auditKeyId ?? '11111111-2222-4333-8444-555555555555',
        delegatedFrom,
        delegatedTo: overrides.delegatedTo ?? ('did:key:auditor-001' as DID),
        purpose: 'AUDIT' as const,
        validFrom:
            overrides.validFrom ?? ('2026-01-01T00:00:00.000Z' as Timestamp),
        validUntil:
            overrides.validUntil ?? ('2027-01-01T00:00:00.000Z' as Timestamp),
        ...(overrides.revoked !== undefined && { revoked: overrides.revoked }),
    };
    const baseFields = { ...baseFieldsForSign, scope };

    // canonicalize the same payload that the verifier will reconstruct (the signature excludes scope; store-level integrity)
    const canonicalPayload = canonicalize(baseFieldsForSign);
    const payloadBytes = new TextEncoder().encode(canonicalPayload);
    const signature = sign(payloadBytes, privateKey) as Signature;

    const proof: DelegatedAuditKeyProof = {
        signature,
        signedAt: '2026-05-17T12:00:00.000Z' as Timestamp,
        signedBy: delegatedFrom,
    };
    const key = createDelegatedAuditKey({
        ...baseFields,
        proof,
    } as CreateDelegatedAuditKeyParams);

    return { key, publicKey, privateKey };
}

const NOW_IN_WINDOW = '2026-06-01T00:00:00.000Z' as Timestamp;

// ── createDelegatedAuditKey factory ──────────────────────────────────────────

describe('createDelegatedAuditKey factory', () => {
    it('should fill all mandatory fields when given valid params', () => {
        const { key } = buildSignedKey({});
        expect(key.auditKeyId).toBe('11111111-2222-4333-8444-555555555555');
        expect(key.delegatedFrom).toBe('did:key:principal-001');
        expect(key.delegatedTo).toBe('did:key:auditor-001');
    });

    it('should always set purpose to AUDIT regardless of input', () => {
        const { key } = buildSignedKey({});
        expect(key.purpose).toBe('AUDIT');
    });

    it('should fill proof structure with signature signedAt signedBy', () => {
        const { key } = buildSignedKey({});
        expect(key.proof).toBeDefined();
        expect(key.proof.signature).toBeTruthy();
        expect(key.proof.signedBy).toBe(key.delegatedFrom);
    });

    it('should not include revoked field when not provided in params', () => {
        const { key } = buildSignedKey({});
        expect(Object.prototype.hasOwnProperty.call(key, 'revoked')).toBe(
            false,
        );
    });

    it('should include revoked:true when explicitly set in params', () => {
        const { key } = buildSignedKey({ revoked: true });
        expect(key.revoked).toBe(true);
    });
});

// ── verifyDelegatedAuditKey real verifier 5-step fail-closed ─────────────

describe('verifyDelegatedAuditKey — real verifier 5-step fail-closed', () => {
    it('should pass happy path when 5 steps all valid (return void)', async () => {
        const { key, publicKey } = buildSignedKey({});
        const resolvePublicKey: ResolvePublicKeyFn = (did: DID) =>
            Promise.resolve(did === key.delegatedFrom ? publicKey : null);

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).resolves.toBeUndefined();
    });

    // ── Step 1: resolve the delegatedFrom public key, fail-closed ────────────────────────

    it('should throw AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID when resolvePublicKey returns null (step 1)', async () => {
        const { key } = buildSignedKey({});
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(null);

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).rejects.toMatchObject({
            name: 'AuditShareError',
            code: 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            invariant: 'step-1-resolve-public-key',
        });
    });

    it('should throw AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID when resolvePublicKey returns empty string (step 1)', async () => {
        const { key } = buildSignedKey({});
        const resolvePublicKey: ResolvePublicKeyFn = () => Promise.resolve('');

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
        });
    });

    // ── Step 2: Ed25519 verify, fail-closed ────────────────────────────────

    it('should throw AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID when Ed25519 signature does not match (step 2)', async () => {
        const { key } = buildSignedKey({});
        // use a different public key; Ed25519 verify returns false
        const { publicKey: wrongPublicKey } = generateKeyPair();
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(wrongPublicKey);

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            invariant: 'step-2-ed25519-verify',
        });
    });

    it('should throw AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID when crypto verify throws (step 2)', async () => {
        const { key } = buildSignedKey({});
        // provide a malformed public key (shorter than 64 characters) -> crypto verify throws CryptoError
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve('not-a-valid-public-key');

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            invariant: 'step-2-ed25519-verify',
        });
    });

    // ── Step 3: signedBy === delegatedFrom, fail-closed ────────────────────

    it('should throw AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID when signedBy !== delegatedFrom (step 3)', async () => {
        const { key, publicKey } = buildSignedKey({});
        // tamper with the key.proof.signedBy field
        const tamperedKey: DelegatedAuditKey = {
            ...key,
            proof: {
                ...key.proof,
                signedBy: 'did:key:malicious-other' as DID,
            },
        };
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(publicKey);

        await expect(
            verifyDelegatedAuditKey(
                tamperedKey,
                resolvePublicKey,
                NOW_IN_WINDOW,
            ),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            invariant: 'step-3-signed-by-binding',
        });
    });

    // ── Step 4: validFrom <= now <= validUntil, fail-closed ──────────────────

    it('should throw AUDIT_SHARE_TOKEN_EXPIRED when now < validFrom (step 4)', async () => {
        const { key, publicKey } = buildSignedKey({});
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(publicKey);
        const beforeWindow = '2025-12-31T23:59:59.999Z' as Timestamp;

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, beforeWindow),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_TOKEN_EXPIRED',
            invariant: 'step-4-validity-window',
        });
    });

    it('should throw AUDIT_SHARE_TOKEN_EXPIRED when now > validUntil (step 4)', async () => {
        const { key, publicKey } = buildSignedKey({});
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(publicKey);
        const afterWindow = '2028-01-01T00:00:00.001Z' as Timestamp;

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, afterWindow),
        ).rejects.toMatchObject({
            code: 'AUDIT_SHARE_TOKEN_EXPIRED',
            invariant: 'step-4-validity-window',
        });
    });

    // ── Step 5: revoked !== true, fail-closed ──────────────────────────────

    it('should throw AUDIT_SHARE_TOKEN_INVALID when revoked === true (step 5)', async () => {
        const { key, publicKey } = buildSignedKey({ revoked: true });
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(publicKey);

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).rejects.toMatchObject({
            name: 'AuditShareError',
            code: 'AUDIT_SHARE_TOKEN_INVALID',
            invariant: 'step-5-revoked',
        });
    });

    it('should pass when revoked === false (explicitly false treated as not-revoked)', async () => {
        const { key, publicKey } = buildSignedKey({ revoked: false });
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(publicKey);

        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).resolves.toBeUndefined();
    });

    // ── verify: AuditEvaluatorNotImplemented fully removed ─────

    it('should never throw AuditEvaluatorNotImplemented (grep verify)', async () => {
        const { key, publicKey } = buildSignedKey({});
        const resolvePublicKey: ResolvePublicKeyFn = () =>
            Promise.resolve(publicKey);

        // happy path does not throw
        await expect(
            verifyDelegatedAuditKey(key, resolvePublicKey, NOW_IN_WINDOW),
        ).resolves.toBeUndefined();

        // fail-closed path throws AuditShareError (not AuditEvaluatorNotImplemented)
        const resolveNull: ResolvePublicKeyFn = () => Promise.resolve(null);
        try {
            await verifyDelegatedAuditKey(key, resolveNull, NOW_IN_WINDOW);
            expect.fail('should have thrown');
        } catch (err) {
            expect(err).toBeInstanceOf(AuditShareError);
            expect((err as Error).name).toBe('AuditShareError');
            // should not be AuditEvaluatorNotImplemented (the stub class has been removed)
            expect((err as Error).name).not.toBe(
                'AuditEvaluatorNotImplemented',
            );
        }
    });
});
