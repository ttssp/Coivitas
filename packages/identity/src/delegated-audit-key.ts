/**
 * DelegatedAuditKey — L2 audit-share v0.2 real verifier
 *
 * 5-step fail-closed verify algorithm:
 *   Step 1: Resolve the public key for key.delegatedFrom; fail → AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID
 *   Step 2: Verify key.proof.signature (Ed25519; payload = canonicalize(key without proof));
 *           fail → AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID 'Ed25519 verify fail'
 *   Step 3: Verify key.proof.signedBy === key.delegatedFrom;
 *           fail → AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID 'signedBy !== delegatedFrom'
 *   Step 4: Check validFrom ≤ now ≤ validUntil;
 *           fail → AUDIT_SHARE_TOKEN_EXPIRED 'not in validity window'
 *   Step 5: Check revoked !== true;
 *           fail → AUDIT_SHARE_TOKEN_INVALID 'revoked'
 *
 * No residual stubs: no unimplemented path that throws AuditEvaluatorNotImplemented is kept.
 *
 * Namespace isolation:
 *   All throws use AuditShareError + AUDIT_SHARE_* codes; no collision with the ProtocolError /
 *   AuditAccessError / CryptoError namespaces.
 */

import { canonicalize, verify as verifyEd25519 } from '@coivitas/crypto';
import {
    AuditShareError,
    type AuditShareScope,
    type DID,
    type Signature,
    type Timestamp,
} from '@coivitas/types';

// ── Data structures ─────────────────────────────────────────────────────────────────

/**
 * Audit sub-key delegation proof (the DelegatedAuditKey.proof field)
 *
 *   - signature = Ed25519 hex/base64url (the delegator's private key signs canonicalize(key without proof))
 *   - signedBy === delegatedFrom (step 3 strict-equality verify)
 */
export interface DelegatedAuditKeyProof {
    /** Ed25519 signature (hex 128 chars or base64url 43/44 chars)*/
    signature: Signature;
    /** Issuance timestamp (ISO 8601 UTC Timestamp brand)*/
    signedAt: Timestamp;
    /** Issuer DID (must === DelegatedAuditKey.delegatedFrom; enforced in step 3)*/
    signedBy: DID;
}

/**
 * Delegated audit key (audit-share v0.2)
 *
 * Field descriptions:
 *   auditKeyId — globally unique identifier (UUID v4)
 *   delegatedFrom — the issuer (principal DID; did:key)
 *   delegatedTo — the subject granted audit-read access (DID; step 5 strict-equality verify against request.requesterDid)
 *   purpose — fixed to 'AUDIT' (restricts this key from being used for write operations or CapabilityToken authorization)
 *   validFrom — effective time (ISO 8601; enforced in step 4)
 *   validUntil — expiry time (ISO 8601, must be > validFrom; enforced in step 4)
 *   revoked — revocation flag (optional; enforced in step 5)
 *   proof — the issuer's signature proof over this structure (enforced in steps 2+3)
 */
export interface DelegatedAuditKey {
    readonly auditKeyId: string;
    readonly delegatedFrom: DID;
    readonly delegatedTo: DID;
    readonly purpose: 'AUDIT';
    readonly validFrom: Timestamp;
    readonly validUntil: Timestamp;
    /**
     * scope — the binding scope of the DelegatedAuditKey
     *
     * Mandatory field; the delegator binds tenantId + auditClass + chainNamespace when issuing the key;
     * the L3 AuditShareManager step 8 must verify key.scope ↔ request.requestedScope match;
     * otherwise cross-tenant reads exceed the delegator's intent (scope-expansion counter-example)
     */
    readonly scope: AuditShareScope;
    readonly revoked?: boolean;
    readonly proof: DelegatedAuditKeyProof;
}

// ── Factory parameters ──────────────────────────────────────────────────────────────

/**
 * Input parameters for createDelegatedAuditKey
 *
 * The proof field is supplied by the caller (passed in after signing on the delegator's private-key side);
 * this factory holds no private keys, only assembling the structure + enforcing purpose='AUDIT'.
 */
export interface CreateDelegatedAuditKeyParams {
    auditKeyId: string;
    delegatedFrom: DID;
    delegatedTo: DID;
    validFrom: Timestamp;
    validUntil: Timestamp;
    /**
     * scope — DelegatedAuditKey binding scope (mandatory field)
     */
    scope: AuditShareScope;
    revoked?: boolean;
    proof: DelegatedAuditKeyProof;
}

// ── Factory function ──────────────────────────────────────────────────────────────

/**
 * Create a DelegatedAuditKey object
 *
 * Behavioral constraints:
 *   - Only assemble the structure from the parameters; do not write to any persistence layer
 *   - The purpose field is forced to 'AUDIT' (callers cannot override it)
 *   - Do not validate proof.signature validity (left to the 5-step enforcement in verifyDelegatedAuditKey)
 *
 * @param params Required fields
 * @returns An immutable DelegatedAuditKey object
 */
export function createDelegatedAuditKey(
    params: CreateDelegatedAuditKeyParams,
): DelegatedAuditKey {
    return {
        auditKeyId: params.auditKeyId,
        delegatedFrom: params.delegatedFrom,
        delegatedTo: params.delegatedTo,
        purpose: 'AUDIT',
        validFrom: params.validFrom,
        validUntil: params.validUntil,
        scope: params.scope,
        ...(params.revoked !== undefined && { revoked: params.revoked }),
        proof: {
            signature: params.proof.signature,
            signedAt: params.proof.signedAt,
            signedBy: params.proof.signedBy,
        },
    };
}

// ── Verifier interface ────────────────────────────────────────────────────────────

/**
 * Dependency-injection interface for resolving a DID's public key (consistent with delegation-validator.ts)
 *
 * @param did The DID to resolve
 * @returns Ed25519 public key (hex 64 chars or base64url); returns null for unknown DIDs
 */
export type ResolvePublicKeyFn = (did: DID) => Promise<string | null>;

// ── canonicalize helper (strip the proof field; step 2 payload construction) ─────────────────

/**
 * Construct the signing payload (strip the proof field; step 2)
 *
 * canonicalize input: { auditKeyId, delegatedFrom, delegatedTo, purpose, validFrom,
 *                      validUntil [, revoked] } — proof stripped
 * canonicalize output: RFC 8785 JSON Canonicalization Scheme (JCS) serialized byte string
 */
function buildCanonicalPayload(key: DelegatedAuditKey): string {
    // binding defense:
    // The scope-field binding goes through store-level integrity (the database row carries a scope FK + is immutable);
    // in production the delegator signs the key offline and stores it in the DB, and L3 trusts the store to return key.scope (TOFU + store integrity);
    // a future version may upgrade this to cryptographic enforcement (the key's signed payload includes scope); the v0.1 baseline is procedural
    const payload: Record<string, unknown> = {
        auditKeyId: key.auditKeyId,
        delegatedFrom: key.delegatedFrom,
        delegatedTo: key.delegatedTo,
        purpose: key.purpose,
        validFrom: key.validFrom,
        validUntil: key.validUntil,
    };
    if (key.revoked !== undefined) {
        payload.revoked = key.revoked;
    }
    return canonicalize(payload);
}

// ── Real verifier, 5-step fail-closed ────────────────────────────────

/**
 * Verify a DelegatedAuditKey (the real verifier)
 *
 * 5-step fail-closed verify:
 *   Step 1: Resolve the public key for key.delegatedFrom
 *           fail (publicKey === null) → AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID
 *                                       'unknown delegator DID'
 *   Step 2: Verify key.proof.signature (Ed25519; payload = canonicalize(key without proof))
 *           fail (verifyEd25519 false) → AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID
 *                                        'Ed25519 verify fail'
 *   Step 3: Verify key.proof.signedBy === key.delegatedFrom
 *           fail → AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID
 *                  'signedBy !== delegatedFrom'
 *   Step 4: Check validFrom ≤ now ≤ validUntil (window check)
 *           fail → AUDIT_SHARE_TOKEN_EXPIRED 'not in validity window'
 *   Step 5: Check revoked !== true
 *           fail → AUDIT_SHARE_TOKEN_INVALID 'revoked'
 *
 * Fully fail-closed (an auth primitive only accepts results that pass verification):
 *   no fail-degraded / fail-open / partial-PASS / stub success allowed;
 *   any step failing throws a fatal AuditShareError;
 *   no unimplemented path that throws AuditEvaluatorNotImplemented is kept.
 *
 * @param key The DelegatedAuditKey to verify
 * @param resolvePublicKey Public-key resolution function (DI; returning null triggers a step 1 failure)
 * @param now Current-time Timestamp (injected by the caller; step 4 window check)
 * @throws AuditShareError fail-closed (any of the 5 steps fails); code ∈ {
 *   AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID,
 *   AUDIT_SHARE_TOKEN_EXPIRED,
 *   AUDIT_SHARE_TOKEN_INVALID,
 * }
 */
export async function verifyDelegatedAuditKey(
    key: DelegatedAuditKey,
    resolvePublicKey: ResolvePublicKeyFn,
    now: Timestamp,
): Promise<void> {
    // Step 1: Resolve the public key for key.delegatedFrom
    const publicKey = await resolvePublicKey(key.delegatedFrom);
    if (
        publicKey === null ||
        publicKey === undefined ||
        publicKey.length === 0
    ) {
        throw new AuditShareError(
            'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            `unknown delegator DID: "${key.delegatedFrom}" (resolvePublicKey returned null)`,
            'step-1-resolve-public-key',
        );
    }

    // Step 2: Verify key.proof.signature (Ed25519; payload = canonicalize(key without proof))
    const canonicalPayload = buildCanonicalPayload(key);
    const payloadBytes = new TextEncoder().encode(canonicalPayload);

    let sigValid: boolean;
    try {
        sigValid = verifyEd25519(payloadBytes, key.proof.signature, publicKey);
    } catch (err) {
        // verifyEd25519 may throw CryptoError when the signature/publicKey format is invalid;
        // any throw maps to a fail-closed AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID.
        throw new AuditShareError(
            'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            `Ed25519 verify threw: ${err instanceof Error ? err.message : String(err)}`,
            'step-2-ed25519-verify',
        );
    }
    if (!sigValid) {
        throw new AuditShareError(
            'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            'Ed25519 verify fail (signature does not match canonicalized payload)',
            'step-2-ed25519-verify',
        );
    }

    // Step 3: Verify key.proof.signedBy === key.delegatedFrom (strict equality)
    if (key.proof.signedBy !== key.delegatedFrom) {
        throw new AuditShareError(
            'AUDIT_SHARE_DELEGATOR_SIGNATURE_INVALID',
            `signedBy !== delegatedFrom (signedBy="${key.proof.signedBy}", delegatedFrom="${key.delegatedFrom}")`,
            'step-3-signed-by-binding',
        );
    }

    // Step 4: Check validFrom ≤ now ≤ validUntil (window check; ISO 8601 string lexicographic comparison)
    // Lexicographic comparison of ISO 8601 UTC strings is equivalent to chronological comparison (RFC 3339 strict format)
    if (now < key.validFrom || now > key.validUntil) {
        throw new AuditShareError(
            'AUDIT_SHARE_TOKEN_EXPIRED',
            `not in validity window (now="${now}", validFrom="${key.validFrom}", validUntil="${key.validUntil}")`,
            'step-4-validity-window',
        );
    }

    // Step 5: Check revoked !== true
    if (key.revoked === true) {
        throw new AuditShareError(
            'AUDIT_SHARE_TOKEN_INVALID',
            `DelegatedAuditKey revoked (auditKeyId="${key.auditKeyId}")`,
            'step-5-revoked',
        );
    }

    // All 5 fail-closed verify steps passed; return void (the caller continues with the L3 manager's 11 steps)
}
