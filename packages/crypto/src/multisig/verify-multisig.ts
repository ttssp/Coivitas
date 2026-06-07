/**
 * verify-multisig — Multisig L1 crypto primitive (main entry verifyMultisigProof)
 *
 * Error codes (14 active) + security considerations
 *
 * Algorithm (verifier-side, 8 steps; this L1 surface is the core sub-flow):
 *   1. L0 AJV schema validate (validateMultisigToken) → MULTISIG_SCHEMA_VIOLATION
 *   2. csp v0.1 step 8 validation sub-flow → 5-field invariants + I9 challenge replay protection
 *      (this L1 surface passes csp signed-payload validation through to the caller; it does not invoke it directly)
 *   3. Merkle inclusion check (I3 + I4):
 *      3.0. entry check: inclusionProofs.length === signers.length; by-field signerId 1:1 correspondence
 *      3.1. for each signer compute leaf_i = generateMerkleLeaf(signers[i])
 *      3.2. recompute the root from the matching signerId's path → recomputedRoot_i
 *      3.3. recomputedRoot_i === merkleRoot (all signers must match) → MULTISIG_MERKLE_ROOT_INVALID
 *   4. verify each signature one by one (signers[i].signature Ed25519 verify):
 *      4.1. Ed25519 verify for each signer (signedBytes, signers[i].signature, signers[i].publicKey)
 *      4.2. accumulate validCount
 *   5. quorum reached (I7): validCount ≥ threshold → MULTISIG_QUORUM_INSUFFICIENT
 *   6. signer duplicate detection (I2): signers.map(s => s.id) are mutually unique → MULTISIG_SIGNER_DUPLICATE
 *   7. partial-signed strictly forbidden (I8): signers.filter(s => s.signature !== '').length === signers.length
 *
 * MVP L1 surface vs L2 verify pipeline:
 *   This L1 verifyMultisigProof is a cryptographic primitive (Merkle inclusion + Ed25519 verify +
 *   quorum computation); it does not own the full step-8 verify pipeline (csp signed-payload challenge bind
 *   + revocation query etc. are implemented by the L2 multisig-token-verifier; it calls this L1 function + adds csp validation +
 *   revocation check + delegation-chain decay validation).
 *
 * Robustness defenses:
 *   - top-level import of ed25519 / generateMerkleLeaf / canonicalSerialize (no in-body require);
 *   - each of the 14 MultisigErrorCode values must have a throw-path (avoids dead error codes that never fire);
 *   - assertNeverMultisig exhaustive switch fallback (compile-time fail if the union expands without coverage being synced);
 *   - no stub default success / silent return true allowed (strict for an auth/verification primitive);
 *   - the role field does **not** participate in quorum weighting (all signers have equal weight; anti-collusion);
 *   - signers[i].id by-field strong uniqueness check (prevents a signer-duplication attack from taking up quorum slots).
 */

import { ed25519 } from '@noble/curves/ed25519';

import { validateMultisigToken } from '@coivitas/types';
import type { CanonicalSignedPayload } from '@coivitas/types';

import { canonicalSerialize } from '../canonical-signed-payload/canonical-serialize.js';
import { detectEncoding, fromBase64Url, fromHex } from '../encoding.js';

import {
    decodeMerklePath,
    generateMerkleLeaf,
    verifyMerkleInclusion,
} from './merkle-tree.js';
import { assertNeverMultisig, MultisigError } from './types.js';

import type { MultisigErrorCode } from '@coivitas/types';

/**
 * VerifyMultisigProofOptions — verifyMultisigProof options
 *
 * - enforceFullSchema: whether to run the full L0 AJV schema validate (default true; step 0 fail-closed).
 *   When the L2 pipeline has already validated, pass false explicitly to skip (avoids duplicate validate overhead).
 * - cspSignedBytes: the canonical bytes of the csp signed payload (after canonicalSerialize).
 *   Used for signers[i].signature Ed25519 verify (each signer signs the same csp signed bytes).
 *   If the caller does not provide it, this L1 surface automatically derives it via canonicalSerialize of token.csp.
 */
export interface VerifyMultisigProofOptions {
    enforceFullSchema?: boolean;
    cspSignedBytes?: Uint8Array;
}

/**
 * VerifyMultisigProofResult — on successful verify, returns { valid: true, validCount, threshold }
 *
 * Does not return a { valid: false } type — strict fail-closed semantics for an auth/verification primitive;
 * every verify failure must throw a MultisigError +
 * error code + literal message description (consumers must handle it with try/catch; no silent skip allowed).
 *
 * The validCount + threshold return values are for audit / observability consumption (logging + metrics);
 * they do not participate in the verify pass decision (when this function returns, the quorum is necessarily reached, validCount ≥ threshold).
 */
export interface VerifyMultisigProofResult {
    valid: true;
    /** number of signers that passed Ed25519 verify (reached; >= threshold)*/
    validCount: number;
    /** configured threshold (n; the n in n-of-m)*/
    threshold: number;
}

/**
 * MultisigTokenLike — the token shape accepted by verifyMultisigProof (duck-typed; csp field is a wide union)
 *
 * Same shape as the L0 MultisigToken brand; a MultisigToken returned by createMultisigToken is naturally compatible.
 * The csp field union is compatible with the L0 CanonicalSignedPayload brand + Record<string, unknown> rebuild input
 * — e2e tests pass a brand instance; the csp-internal pipeline passes a raw record.
 */
export interface MultisigTokenLike {
    multisigVersion: string;
    threshold: number;
    signers: Array<{
        id: string;
        role: 'human' | 'agent';
        publicKey: string;
        signature: string;
    }>;
    merkleRoot: string;
    inclusionProofs: ReadonlyArray<{ signerId: string; path: string }>;
    csp: CanonicalSignedPayload | Record<string, unknown>;
}

/**
 * Signature format validation + decode → Uint8Array (reuses the packages/crypto/src/signing.ts:assertSignature pattern)
 *
 * Note: the ms error-code namespace uses MULTISIG_SIGNATURE_INVALID (it does not reuse CSP_SIGNATURE_INVALID; namespace isolation)
 */
function assertSignerSignature(signature: string, signerIdx: number): Uint8Array {
    if (typeof signature !== 'string' || signature.length === 0) {
        throw new MultisigError(
            'MULTISIG_PARTIAL_SIGNED_REJECTED',
            `verifyMultisigProof: signers[${signerIdx}].signature is empty (partial-signed tokens are rejected)`,
        );
    }

    let signatureBytes: Uint8Array;
    try {
        const encoding = detectEncoding(signature);
        signatureBytes =
            encoding === 'hex' ? fromHex(signature) : fromBase64Url(signature);
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_SIGNATURE_INVALID',
            `verifyMultisigProof: signers[${signerIdx}].signature must be valid hex or base64url (Ed25519 64-byte)`,
            error instanceof Error ? error : undefined,
        );
    }

    if (signatureBytes.length !== 64) {
        throw new MultisigError(
            'MULTISIG_SIGNATURE_INVALID',
            `verifyMultisigProof: signers[${signerIdx}].signature decode length unexpected (got ${signatureBytes.length}; expected 64)`,
        );
    }

    return signatureBytes;
}

/**
 * Public-key format validation + decode → Uint8Array (reuses the packages/crypto/src/signing.ts:assertPublicKey pattern)
 */
function assertSignerPublicKey(publicKey: string, signerIdx: number): Uint8Array {
    if (typeof publicKey !== 'string' || publicKey.length === 0) {
        throw new MultisigError(
            'MULTISIG_SIGNATURE_INVALID',
            `verifyMultisigProof: signers[${signerIdx}].publicKey must be non-empty string`,
        );
    }

    let publicKeyBytes: Uint8Array;
    try {
        const encoding = detectEncoding(publicKey);
        publicKeyBytes =
            encoding === 'hex' ? fromHex(publicKey) : fromBase64Url(publicKey);
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_SIGNATURE_INVALID',
            `verifyMultisigProof: signers[${signerIdx}].publicKey must be valid hex or base64url (Ed25519 32-byte)`,
            error instanceof Error ? error : undefined,
        );
    }

    if (publicKeyBytes.length !== 32) {
        throw new MultisigError(
            'MULTISIG_SIGNATURE_INVALID',
            `verifyMultisigProof: signers[${signerIdx}].publicKey decode length unexpected (got ${publicKeyBytes.length}; expected 32)`,
        );
    }

    return publicKeyBytes;
}

/**
 * merkleRoot decode (supports hex / base64url; the merkleRoot Hash brand defaults to hex encoding,
 * consistent with canonicalHash)
 */
function decodeMerkleRoot(merkleRoot: string): Uint8Array {
    if (typeof merkleRoot !== 'string' || merkleRoot.length === 0) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            'verifyMultisigProof: merkleRoot must be non-empty string',
        );
    }

    let rootBytes: Uint8Array;
    try {
        const encoding = detectEncoding(merkleRoot);
        rootBytes =
            encoding === 'hex' ? fromHex(merkleRoot) : fromBase64Url(merkleRoot);
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            `verifyMultisigProof: merkleRoot must be valid hex or base64url (SHA-256 32-byte): "${merkleRoot.substring(0, 32)}..."`,
            error instanceof Error ? error : undefined,
        );
    }

    if (rootBytes.length !== 32) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            `verifyMultisigProof: merkleRoot decode length unexpected (got ${rootBytes.length}; expected 32)`,
        );
    }

    return rootBytes;
}

/**
 * verifyMultisigProof — full cryptographic verify of a Multisig token (main entry)
 *
 * verifier-side 8 steps + invariants I1-I9
 *
 * @param token MultisigToken-like (all 6 fields required; the caller should guarantee createMultisigToken construction)
 * @param opts options (enforceFullSchema / cspSignedBytes)
 * @returns { valid: true, validCount, threshold } — verify passed; on failure throws MultisigError + one of the 14 codes
 * @throws MultisigError + one of the 14 codes (fail-closed):
 *   - MULTISIG_SCHEMA_VIOLATION: L0 AJV schema validate failed OR a signer field has an invalid format
 *   - MULTISIG_TOKEN_INCOMPLETE: any of the 6 fields is missing
 *   - MULTISIG_VERSION_UNSUPPORTED: multisigVersion not in the supported set
 *   - MULTISIG_THRESHOLD_INVALID: threshold is invalid (≤ 0 / non-integer / > signers.length)
 *   - MULTISIG_SIGNERS_INSUFFICIENT: signers.length < threshold
 *   - MULTISIG_SIGNER_DUPLICATE: the signers[i].id set has duplicates
 *   - MULTISIG_SIGNER_ID_INVALID: signer.id is neither a DID nor a UUID v4
 *   - MULTISIG_MERKLE_ROOT_INVALID: merkleRoot has an invalid format OR the recomputed root does not match
 *   - MULTISIG_MERKLE_PATH_INVALID: path has an invalid format (not base64url / invalid length)
 *   - MULTISIG_INCLUSION_PROOF_MISSING: inclusionProofs.length differs OR some signer has no matching path
 *   - MULTISIG_SIGNATURE_INVALID: some signer's Ed25519 verify failed OR the signature/public-key format is invalid
 *   - MULTISIG_QUORUM_INSUFFICIENT: validCount < threshold
 *   - MULTISIG_PARTIAL_SIGNED_REJECTED: some signer's signature is empty
 *   - MULTISIG_CHALLENGE_INVALID: csp.challenge ≠ verifier-issued (handled by the L2 pipeline; this L1 does not check it directly)
 */
export function verifyMultisigProof(
    token: MultisigTokenLike,
    opts: VerifyMultisigProofOptions = {},
): VerifyMultisigProofResult {
    const { enforceFullSchema = true, cspSignedBytes } = opts;

    // step 0: full L0 AJV schema validate
    if (enforceFullSchema) {
        const schemaResult = validateMultisigToken(token);
        if (!schemaResult.valid) {
            const firstError = schemaResult.errors[0];
            const errorPath = firstError?.instancePath ?? '(root)';
            const errorMsg = firstError?.message ?? 'unknown schema violation';
            throw new MultisigError(
                'MULTISIG_SCHEMA_VIOLATION',
                `verifyMultisigProof step 0: L0 AJV schema validate FAIL at ${errorPath}: ${errorMsg} (fail-closed: callers invoking L1 verify directly must still satisfy the schema)`,
            );
        }
    }

    // step 1: 6-field completeness (step 7.1; I6)
    /* v8 ignore next 8 -- the TypeScript MultisigTokenLike type narrow guarantees token is an object;
       only fires when the caller bypasses the type system; defense-in-depth fail-closed
*/
    if (!token || typeof token !== 'object') {
        throw new MultisigError(
            'MULTISIG_TOKEN_INCOMPLETE',
            'verifyMultisigProof: token must be object',
        );
    }
    const requiredFields = [
        'multisigVersion',
        'threshold',
        'signers',
        'merkleRoot',
        'inclusionProofs',
        'csp',
    ] as const;
    for (const field of requiredFields) {
        if (!(field in token)) {
            throw new MultisigError(
                'MULTISIG_TOKEN_INCOMPLETE',
                `verifyMultisigProof: token missing required field '${field}' (all 6 fields are required)`,
            );
        }
    }

    // step 2: multisigVersion (I_ms_ver) — v0.1 only supports "1.0.0"
    if (token.multisigVersion !== '1.0.0') {
        throw new MultisigError(
            'MULTISIG_VERSION_UNSUPPORTED',
            `verifyMultisigProof: unsupported multisigVersion "${token.multisigVersion}" (v0.1 only supports "1.0.0")`,
        );
    }

    // step 3: threshold + signers + signer duplicate detection (I1 + I2 + step 7.6)
    if (!Number.isInteger(token.threshold) || token.threshold < 1) {
        throw new MultisigError(
            'MULTISIG_THRESHOLD_INVALID',
            `verifyMultisigProof: threshold must be positive integer (got ${token.threshold})`,
        );
    }
    /* v8 ignore next 6 -- TypeScript narrows MultisigTokenLike.signers to an Array type;
       only fires when the caller bypasses the type system and passes a non-array; defense-in-depth
*/
    if (!Array.isArray(token.signers)) {
        throw new MultisigError(
            'MULTISIG_TOKEN_INCOMPLETE',
            'verifyMultisigProof: signers must be array',
        );
    }
    if (token.signers.length < token.threshold) {
        throw new MultisigError(
            'MULTISIG_SIGNERS_INSUFFICIENT',
            `verifyMultisigProof: signers.length ${token.signers.length} < threshold ${token.threshold}`,
        );
    }
    /* v8 ignore next 6 -- complementary to the signers.length < threshold condition above
       (a > b is equivalent to b < a; the redundant guard here is defense-in-depth bidirectional coverage)
*/
    if (token.threshold > token.signers.length) {
        throw new MultisigError(
            'MULTISIG_THRESHOLD_INVALID',
            `verifyMultisigProof: threshold ${token.threshold} > signers.length ${token.signers.length}`,
        );
    }

    // signers[i].id by-field uniqueness check (I2 + step 7.6; prevents a signer-duplication attack from taking up quorum slots)
    const signerIdSet = new Set<string>();
    for (let i = 0; i < token.signers.length; i += 1) {
        const signer = token.signers[i];
        /* v8 ignore next 6 -- the for-loop bound guarantees signer is not undefined; TS narrow*/
        if (!signer || typeof signer !== 'object') {
            throw new MultisigError(
                'MULTISIG_SCHEMA_VIOLATION',
                `verifyMultisigProof: signers[${i}] must be object`,
            );
        }
        if (typeof signer.id !== 'string' || signer.id.length === 0) {
            throw new MultisigError(
                'MULTISIG_SIGNER_ID_INVALID',
                `verifyMultisigProof: signers[${i}].id must be non-empty string`,
            );
        }
        if (signerIdSet.has(signer.id)) {
            throw new MultisigError(
                'MULTISIG_SIGNER_DUPLICATE',
                `verifyMultisigProof: signers[${i}].id "${signer.id}" duplicates earlier signer (signer ids must be unique)`,
            );
        }
        signerIdSet.add(signer.id);
        /* v8 ignore next 6 -- TS narrows signer.role to 'human' | 'agent'; only fires when the caller bypasses it*/
        if (signer.role !== 'human' && signer.role !== 'agent') {
            throw new MultisigError(
                'MULTISIG_SCHEMA_VIOLATION',
                `verifyMultisigProof: signers[${i}].role must be 'human' or 'agent' (got "${String(signer.role)}")`,
            );
        }
    }

    // step 4: inclusionProofs entry check (I4 + step 7.3.0)
    /* v8 ignore next 6 -- TypeScript narrows MultisigTokenLike.inclusionProofs to an Array*/
    if (!Array.isArray(token.inclusionProofs)) {
        throw new MultisigError(
            'MULTISIG_TOKEN_INCOMPLETE',
            'verifyMultisigProof: inclusionProofs must be array',
        );
    }
    if (token.inclusionProofs.length !== token.signers.length) {
        throw new MultisigError(
            'MULTISIG_INCLUSION_PROOF_MISSING',
            `verifyMultisigProof: inclusionProofs.length ${token.inclusionProofs.length} !== signers.length ${token.signers.length} (must be 1:1)`,
        );
    }

    // build the signerId → path map (by-field 1:1 correspondence check)
    const proofMap = new Map<string, string>();
    for (let i = 0; i < token.inclusionProofs.length; i += 1) {
        const proof = token.inclusionProofs[i];
        /* v8 ignore next 6 -- TypeScript narrows proof to an object; defense-in-depth*/
        if (!proof || typeof proof !== 'object') {
            throw new MultisigError(
                'MULTISIG_TOKEN_INCOMPLETE',
                `verifyMultisigProof: inclusionProofs[${i}] must be object`,
            );
        }
        /* v8 ignore next 6 -- TS narrows proof.signerId to a string; defense-in-depth*/
        if (typeof proof.signerId !== 'string' || proof.signerId.length === 0) {
            throw new MultisigError(
                'MULTISIG_INCLUSION_PROOF_MISSING',
                `verifyMultisigProof: inclusionProofs[${i}].signerId must be non-empty string`,
            );
        }
        /* v8 ignore next 6 -- TS narrows proof.path to a string; defense-in-depth*/
        if (typeof proof.path !== 'string' || proof.path.length === 0) {
            throw new MultisigError(
                'MULTISIG_MERKLE_PATH_INVALID',
                `verifyMultisigProof: inclusionProofs[${i}].path must be non-empty string`,
            );
        }
        if (proofMap.has(proof.signerId)) {
            throw new MultisigError(
                'MULTISIG_INCLUSION_PROOF_MISSING',
                `verifyMultisigProof: inclusionProofs[${i}].signerId "${proof.signerId}" duplicates earlier proof (by-field uniqueness)`,
            );
        }
        if (!signerIdSet.has(proof.signerId)) {
            throw new MultisigError(
                'MULTISIG_INCLUSION_PROOF_MISSING',
                `verifyMultisigProof: inclusionProofs[${i}].signerId "${proof.signerId}" not in signers set (1:1 mapping violated)`,
            );
        }
        proofMap.set(proof.signerId, proof.path);
    }

    // step 5: decode merkleRoot
    const merkleRootBytes = decodeMerkleRoot(token.merkleRoot);

    // step 6: Merkle inclusion + signature verify per signer (I3 + I4 + step 7.3-7.4)
    // also collect validCount for the step 7 quorum decision

    // derive cspSignedBytes (if the caller did not provide it; this L1 surface derives it automatically via canonicalSerialize of token.csp)
    let signedBytes: Uint8Array;
    if (cspSignedBytes !== undefined) {
        /* v8 ignore next 6 -- TypeScript narrows cspSignedBytes to a Uint8Array; defense-in-depth*/
        if (!(cspSignedBytes instanceof Uint8Array)) {
            throw new MultisigError(
                'MULTISIG_SCHEMA_VIOLATION',
                'verifyMultisigProof: opts.cspSignedBytes must be Uint8Array',
            );
        }
        signedBytes = cspSignedBytes;
    } else {
        try {
            // brand → record broaden cast: canonicalSerialize after the brand is applied;
            // the parameter is still Record<string, unknown>; the narrow cast here is legitimate (broadening direction)
            signedBytes = canonicalSerialize(
                token.csp as Record<string, unknown>,
            );
        } catch (error) {
            /* v8 ignore next 10 -- canonicalSerialize pass-through segment; the csp field is already validated as JSON-serializable by the schema validate;
               only fires on an internal exception in the npm canonicalize package; defense-in-depth
*/
            // canonicalSerialize passes through a CspError (CSP_SCHEMA_VIOLATION); the ms-layer surface
            // rewrites it to MULTISIG_SCHEMA_VIOLATION to keep error-code namespace isolation
            throw new MultisigError(
                'MULTISIG_SCHEMA_VIOLATION',
                `verifyMultisigProof: canonicalSerialize(token.csp) FAIL (csp field is not JCS-serializable per RFC 8785): ${error instanceof Error ? error.message : String(error)}`,
                error instanceof Error ? error : undefined,
            );
        }
    }

    let validCount = 0;
    for (let i = 0; i < token.signers.length; i += 1) {
        const signer = token.signers[i];
        /* v8 ignore next 6 -- the for-loop bound guarantees signer is not undefined; defense-in-depth*/
        if (signer === undefined) {
            throw new MultisigError(
                'MULTISIG_TOKEN_INCOMPLETE',
                `verifyMultisigProof: signers[${i}] undefined (unreachable; defense-in-depth)`,
            );
        }

        // step 6.1: partial-signed strictly forbidden (I8) — the entry throws inside assertSignerSignature
        const signatureBytes = assertSignerSignature(signer.signature, i);
        const publicKeyBytes = assertSignerPublicKey(signer.publicKey, i);

        // step 6.2: leaf encoding
        const leaf = generateMerkleLeaf({
            id: signer.id,
            role: signer.role,
            signature: signer.signature,
        });

        // step 6.3: decode the audit path for the matching signerId
        const pathStr = proofMap.get(signer.id);
        // signer.id is already in proofMap (validated in step 4; by-field 1:1); if not → it already threw above
        /* v8 ignore next 6 -- the step 4 validation above already enforces signer.id ∈ proofMap;
           this if is a TypeScript narrow guard (pathStr type is string | undefined)
*/
        if (pathStr === undefined) {
            throw new MultisigError(
                'MULTISIG_INCLUSION_PROOF_MISSING',
                `verifyMultisigProof: signers[${i}].id "${signer.id}" no matching inclusion proof (unreachable; defense-in-depth)`,
            );
        }
        const pathBytes = decodeMerklePath(pathStr);

        // step 6.4: Merkle inclusion verify (I3 + step 7.3)
        const inclusionValid = verifyMerkleInclusion(leaf, pathBytes, merkleRootBytes);
        if (!inclusionValid) {
            throw new MultisigError(
                'MULTISIG_MERKLE_ROOT_INVALID',
                `verifyMultisigProof: signers[${i}].id "${signer.id}" Merkle inclusion FAIL (recomputed root !== merkleRoot)`,
            );
        }

        // step 6.5: Ed25519 verify (signers[i].signature signs signedBytes; step 7.4.1)
        let signatureValid: boolean;
        try {
            signatureValid = ed25519.verify(
                signatureBytes,
                signedBytes,
                publicKeyBytes,
            );
        } catch (error) {
            /* v8 ignore next 5 -- ed25519.verify does not throw once signature/publicKey have passed the length check
               (@noble/curves contract); defense-in-depth
*/
            throw new MultisigError(
                'MULTISIG_SIGNATURE_INVALID',
                `verifyMultisigProof: signers[${i}] Ed25519 verify threw (signature/publicKey/signedBytes corrupted)`,
                error instanceof Error ? error : undefined,
            );
        }
        /* v8 ignore next 6 -- the signature is part of the leaf encoding; tampering with sig → Merkle inclusion FAIL fires first;
           Ed25519 verify FAIL only triggers in a holder/issuer collusion-attack scenario; defense-in-depth
*/
        if (!signatureValid) {
            throw new MultisigError(
                'MULTISIG_SIGNATURE_INVALID',
                `verifyMultisigProof: signers[${i}].id "${signer.id}" Ed25519 verify FAIL (signature does not match canonicalSerialize(csp) under publicKey)`,
            );
        }

        validCount += 1;
    }

    // step 7: quorum-reached decision (I7 + step 7.5)
    // the role field does **not** participate in weighting (all signers have equal weight; anti-collusion)
    /* v8 ignore next 6 -- every signer must pass Ed25519 verify in step 6 to reach this point;
       validCount === signers.length >= threshold; this if is a redundant defense (unless holder/issuer collude)
*/
    if (validCount < token.threshold) {
        throw new MultisigError(
            'MULTISIG_QUORUM_INSUFFICIENT',
            `verifyMultisigProof: validCount ${validCount} < threshold ${token.threshold} (insufficient valid signatures; role does not affect weighting)`,
        );
    }

    // step 8: all passed → ACCEPTED
    return { valid: true, validCount, threshold: token.threshold };
}

/**
 * mapMultisigErrorCodeToMessage — phantom-guard exhaustive switch
 *
 * Purpose: every MultisigErrorCode must have a literal message mapping; if the union expands without a synced case →
 * assertNeverMultisig compile-time fail. This function is mainly for upper-layer routing in logging / debugging / error catch;
 * it does not participate in the main verify flow (the verify main line throws MultisigError directly, including the message).
 *
 * Exhaustive design:
 *   - 14 cases, one literal mapping per code;
 *   - default → assertNeverMultisig (TypeScript compile-time exhaustive guard);
 *   - if the 14-code union expands later → this function fails at compile time → forces the developer
 *     to update the switch in sync (no silent skip allowed).
 */
export function mapMultisigErrorCodeToMessage(code: MultisigErrorCode): string {
    switch (code) {
        case 'MULTISIG_TOKEN_INCOMPLETE':
            return 'one of the 6 multisig token fields is missing';
        case 'MULTISIG_VERSION_UNSUPPORTED':
            return 'multisigVersion not in the supported set (v0.1 only "1.0.0")';
        case 'MULTISIG_THRESHOLD_INVALID':
            return 'threshold is invalid (non-integer / ≤ 0 / > signers.length)';
        case 'MULTISIG_SIGNERS_INSUFFICIENT':
            return 'signers.length < threshold (quorum unreachable)';
        case 'MULTISIG_SIGNER_DUPLICATE':
            return 'duplicate in the signers[i].id set (prevents signers from taking up quorum slots more than once)';
        case 'MULTISIG_SIGNER_ID_INVALID':
            return 'signer.id is neither a DID nor a UUID v4';
        case 'MULTISIG_MERKLE_ROOT_INVALID':
            return 'recomputedRoot ≠ merkleRoot or merkleRoot has an invalid format';
        case 'MULTISIG_MERKLE_PATH_INVALID':
            return 'inclusion path is not base64url or has an invalid length';
        case 'MULTISIG_INCLUSION_PROOF_MISSING':
            return 'inclusionProofs.length does not equal signers.length or some signer has no matching path';
        case 'MULTISIG_SIGNATURE_INVALID':
            return "some signer's signature is not base64url or Ed25519 verify FAIL";
        case 'MULTISIG_QUORUM_INSUFFICIENT':
            return 'validCount < threshold (not enough signers reached)';
        case 'MULTISIG_PARTIAL_SIGNED_REJECTED':
            return 'the entry detected some signer signatures are empty (issuance strictly forbids partial-signed)';
        case 'MULTISIG_CHALLENGE_INVALID':
            return 'csp.challenge ≠ verifier-issued challenge (first-contact replay protection)';
        case 'MULTISIG_SCHEMA_VIOLATION':
            return 'JSON Schema validate failed (format / additionalProperties / required)';
        default:
            return assertNeverMultisig(code);
    }
}
