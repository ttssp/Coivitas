/**
 * multisig-token-issuer — Multisig L2 identity primitive (issuer-side issuance pipeline)
 *
 * Issuer-side issuance flow (8 steps):
 *   1. Issuer receives the multisig issuance request (capabilities + audience + notAfter + threshold + signers)
 *      Validation: m >= n >= 1; signer ID set is mutually distinct; all publicKeys non-empty
 *   2. Issuer constructs the CanonicalSignedPayload (csp v0.1 issuance flow)
 *   3. Issuer JCS-canonicalizes csp -> signedBytes
 *   4. Co-sign with each signer (off-band signing channel; v0.1 does not standardize the signing channel)
 *      4.1. Issuer sends signedBytes to signers[i]
 *      4.2. signers[i] Ed25519-signs signedBytes with its private key -> signature_i
 *      4.3. signers[i] returns {signerId: i, signature: signature_i}
 *      4.4. Issuer collects signature_i
 *   5. Quorum sufficiency check (issuance stage; partial-signed must not leak into verify)
 *      5.1. Collect all: signatures.length === m (every signer returned a signature) -> else MULTISIG_PARTIAL_SIGNED_REJECTED
 *      5.3. Issuer-side pre-verify quorum: at least n signers' signatures pass Ed25519 verify
 *      5.4. Else -> MULTISIG_QUORUM_INSUFFICIENT
 *   6. Merkle commitment construction
 *      6.1. Compute leaf_i = generateMerkleLeaf(signers[i]) for each signer
 *      6.2. Construct the Merkle tree (RFC 6962) -> merkleRoot
 *      6.3. Construct inclusion path_i for each signer (RFC 6962 audit path)
 *   7. Construct the MultisigToken (6 fields; no aggregatedSignature)
 *   8. Issuer returns the MultisigToken
 *
 * Anti-phantom defenses:
 *   - Top-level import of canonicalSerialize / buildMerkleTree / verifyMultisigProof (no in-body require);
 *   - partial-signed strictly forbidden (issuance stage uses strict m collection; step 5.2 fail-closed);
 *   - issuer-side pre-verify of quorum (avoids the verifier side repeatedly failing after issuance completes);
 *   - the role field does not participate in quorum weighting (anti-collusion);
 *   - no stub default success / unverified signatures allowed.
 */

import {
    buildMerkleTree,
    canonicalSerialize,
    encodeMerklePath,
    generateMerkleLeaf,
    MultisigError,
    sign as signEd25519Hex,
    toBase64Url,
    toHex,
    verify as verifyEd25519,
} from '@coivitas/crypto';
import {
    createMultisigToken,
    type CanonicalSignedPayload,
    type Hash,
    type MultisigToken,
    type Signature,
    type SignerInfoInput,
    type SignerRole,
} from '@coivitas/types';

/**
 * SignerKeyMaterial — issuer-side signer input (includes the private key; used for issuer co-signing)
 *
 * In production deployment, signer private keys should be HSM-isolated (a production-deployment-side measure);
 * this interface is for demo / test / e2e usage only; production code should not pass plaintext private keys directly.
 */
export interface SignerKeyMaterial {
    /** signer ID (DID or UUID v4)*/
    id: string;
    /** signer role (human / agent; does not participate in quorum weighting)*/
    role: SignerRole;
    /** signer public key (Ed25519 32-byte hex / base64url)*/
    publicKey: string;
    /** signer private key (Ed25519 32-byte seed hex / base64url; a production HSM should replace this field)*/
    privateKey: string;
}

/**
 * IssueMultisigTokenInput — input to issueMultisigToken
 *
 * Required fields:
 *   - signers: complete key material for m candidate signers (includes publicKey + privateKey)
 *   - threshold: the n in n-of-m (1 <= n <= m)
 *   - csp: the embedded CanonicalSignedPayload (already constructed issuer-side per csp v0.1)
 *
 * Invariant checks (step 1):
 *   - m >= n >= 1
 *   - signer ID set is mutually distinct
 *   - all publicKeys + privateKeys non-empty
 */
export interface IssueMultisigTokenInput {
    /** signer key material array (m entries; includes private keys; a production HSM should replace this)*/
    signers: SignerKeyMaterial[];
    /** the n in the n-of-m threshold*/
    threshold: number;
    /** the embedded CanonicalSignedPayload (constructed by the issuer per csp v0.1)*/
    csp: CanonicalSignedPayload;
    /**
     * merkleRoot encoding ('hex' by default, matching the wire format convention; 'base64url' for compact scenarios)
     */
    merkleRootEncoding?: 'hex' | 'base64url';
}

/**
 * signSignerEd25519 — internal helper: single-signer Ed25519 sign wrapper (reuses @coivitas/crypto sign)
 *
 * @returns the hex encoding of the 64-byte signature (matching the wire format convention)
 * @throws MultisigError(MULTISIG_SIGNATURE_INVALID) — sign failure / malformed private key
 */
function signSignerEd25519(
    message: Uint8Array,
    privateKey: string,
    signerIdx: number,
): string {
    try {
        // Reuse @coivitas/crypto sign (hex output matches the wire format convention)
        return signEd25519Hex(message, privateKey, 'hex');
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_SIGNATURE_INVALID',
            `issueMultisigToken: signers[${signerIdx}] Ed25519 sign FAIL (privateKey decode or sign threw)`,
            error instanceof Error ? error : undefined,
        );
    }
}

/**
 * issueMultisigToken — Multisig token issuance (issuer-side main entry point)
 *
 * Implements the 8-step flow (issuer-side co-signing with m signers + Merkle commitment construction)
 *
 * Pre-condition:
 *   - input.signers all have non-empty publicKey + privateKey (off-band signing channel; production HSM)
 *   - input.threshold in [1, signers.length] (m >= n >= 1)
 *   - input.csp has been fully constructed by the issuer per the csp v0.1 issuance flow (incl. cspVersion + token + audience + notAfter)
 *
 * Post-condition (step 7 invariants):
 *   - returns a MultisigToken with all 6 fields populated
 *   - every signers[i].signature is non-empty (partial-signed strictly forbidden; issuance stage uses strict m collection)
 *   - merkleRoot + inclusionProofs map by-field 1:1 to signers[i].id
 *   - quorum has been pre-verified issuer-side (validCount >= threshold)
 *
 * @param input issuance input (signers key material + threshold + csp + encoding options)
 * @returns MultisigToken (all 6 fields required; passed createMultisigToken factory)
 * @throws MultisigError with one of 14 codes (fail-closed):
 *   - MULTISIG_SIGNERS_INSUFFICIENT: m < n
 *   - MULTISIG_THRESHOLD_INVALID: n < 1 or non-integer
 *   - MULTISIG_SIGNER_DUPLICATE: signers[i].id set has duplicates
 *   - MULTISIG_PARTIAL_SIGNED_REJECTED: some signer did not sign (should not trigger implementation-side; internal sanity)
 *   - MULTISIG_QUORUM_INSUFFICIENT: issuer-side pre-verify quorum not met
 *   - MULTISIG_SIGNATURE_INVALID: Ed25519 sign / verify failure / malformed private key
 */
export function issueMultisigToken(
    input: IssueMultisigTokenInput,
): MultisigToken {
    // step 1: input validation
    if (!Array.isArray(input.signers) || input.signers.length === 0) {
        throw new MultisigError(
            'MULTISIG_SIGNERS_INSUFFICIENT',
            'issueMultisigToken: signers must be non-empty array',
        );
    }
    if (!Number.isInteger(input.threshold) || input.threshold < 1) {
        throw new MultisigError(
            'MULTISIG_THRESHOLD_INVALID',
            `issueMultisigToken: threshold must be positive integer (got ${input.threshold})`,
        );
    }
    if (input.signers.length < input.threshold) {
        throw new MultisigError(
            'MULTISIG_SIGNERS_INSUFFICIENT',
            `issueMultisigToken: signers.length ${input.signers.length} < threshold ${input.threshold}`,
        );
    }

    // signers[i].id by-field uniqueness check (step 1 "signer ID set is mutually distinct")
    const signerIdSet = new Set<string>();
    for (let i = 0; i < input.signers.length; i += 1) {
        const signer = input.signers[i];
        /* v8 ignore next 6 -- the for loop bound guarantees signer is not undefined*/
        if (signer === undefined) {
            throw new MultisigError(
                'MULTISIG_TOKEN_INCOMPLETE',
                `issueMultisigToken: signers[${i}] undefined (unreachable; defense-in-depth)`,
            );
        }
        if (typeof signer.id !== 'string' || signer.id.length === 0) {
            throw new MultisigError(
                'MULTISIG_SIGNER_ID_INVALID',
                `issueMultisigToken: signers[${i}].id must be non-empty string`,
            );
        }
        if (signerIdSet.has(signer.id)) {
            throw new MultisigError(
                'MULTISIG_SIGNER_DUPLICATE',
                `issueMultisigToken: signers[${i}].id "${signer.id}" duplicates earlier signer (by-field uniqueness)`,
            );
        }
        signerIdSet.add(signer.id);
        if (signer.role !== 'human' && signer.role !== 'agent') {
            throw new MultisigError(
                'MULTISIG_SIGNATURE_INVALID',
                `issueMultisigToken: signers[${i}].role must be 'human' or 'agent' (got "${String(signer.role)}")`,
            );
        }
        if (typeof signer.publicKey !== 'string' || signer.publicKey.length === 0) {
            throw new MultisigError(
                'MULTISIG_SIGNATURE_INVALID',
                `issueMultisigToken: signers[${i}].publicKey must be non-empty string`,
            );
        }
        if (typeof signer.privateKey !== 'string' || signer.privateKey.length === 0) {
            throw new MultisigError(
                'MULTISIG_SIGNATURE_INVALID',
                `issueMultisigToken: signers[${i}].privateKey must be non-empty string (off-band signing channel)`,
            );
        }
    }

    // step 2+3: derive csp signed bytes (issuer-side canonicalize csp -> signedBytes)
    // CanonicalSignedPayload is an L0 brand interface; canonicalSerialize accepts Record<string, unknown>
    // Convert via an unknown intermediary (the csp fields cspVersion/token/disclosedClaims/challenge/audience/notAfter
    // are all JSON-serializable; canonicalSerialize does an internal assertSerializable pre-check)
    let signedBytes: Uint8Array;
    try {
        signedBytes = canonicalSerialize(
            input.csp as unknown as Record<string, unknown>,
        );
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `issueMultisigToken: canonicalSerialize(csp) FAIL (csp non-JCS-serializable): ${error instanceof Error ? error.message : String(error)}`,
            error instanceof Error ? error : undefined,
        );
    }

    // step 4: co-sign with each signer (issuer-side ed25519.sign — simulating the off-band channel)
    // In production deployment this should be replaced with an actual off-band signing channel (HSM call)
    const signatures: string[] = input.signers.map((signer, idx) =>
        signSignerEd25519(signedBytes, signer.privateKey, idx),
    );

    // step 5.1: collect all: signatures.length === m (strict m collection; partial-signed strictly forbidden)
    /* v8 ignore next 6 -- signatures.map guarantees 1:1 correspondence with signers; defense-in-depth*/
    if (signatures.length !== input.signers.length) {
        throw new MultisigError(
            'MULTISIG_PARTIAL_SIGNED_REJECTED',
            `issueMultisigToken: signatures.length ${signatures.length} !== signers.length ${input.signers.length} (strict m collection; unreachable internal sanity)`,
        );
    }

    // step 5.3: issuer-side pre-verify quorum (avoids the verifier side repeatedly failing after issuance completes)
    // Note: since the issuer signs with input.privateKey, all should be valid in theory; but in production the
    // off-band channel may error out, so verify once + count uniformly here.
    // Reuse @coivitas/crypto verify (hex/base64url auto-detected; no inline ed25519 call)
    let validCount = 0;
    for (let i = 0; i < input.signers.length; i += 1) {
        const signer = input.signers[i];
        const signature = signatures[i];
        /* v8 ignore next 6 -- the for loop bound guarantees not undefined*/
        if (signer === undefined || signature === undefined) {
            throw new MultisigError(
                'MULTISIG_PARTIAL_SIGNED_REJECTED',
                `issueMultisigToken: signers[${i}] or signatures[${i}] undefined (unreachable)`,
            );
        }
        let valid: boolean;
        try {
            valid = verifyEd25519(signedBytes, signature, signer.publicKey);
        } catch (error) {
            throw new MultisigError(
                'MULTISIG_SIGNATURE_INVALID',
                `issueMultisigToken: signers[${i}] Ed25519 verify FAIL (signature/publicKey format invalid)`,
                error instanceof Error ? error : undefined,
            );
        }
        if (valid) {
            validCount += 1;
        }
    }

    if (validCount < input.threshold) {
        throw new MultisigError(
            'MULTISIG_QUORUM_INSUFFICIENT',
            `issueMultisigToken: issuer-side pre-verify quorum FAIL (validCount ${validCount} < threshold ${input.threshold}; off-band signing channel error?)`,
        );
    }

    // step 6: Merkle commitment construction
    // step 6.1: compute leaf_i = generateMerkleLeaf(signers[i]) for each signer
    const leaves: Uint8Array[] = input.signers.map((signer, idx) => {
        const signature = signatures[idx];
        /* v8 ignore next 6 -- signatures.length === signers.length (per step 5.1 above)*/
        if (signature === undefined) {
            throw new MultisigError(
                'MULTISIG_TOKEN_INCOMPLETE',
                `issueMultisigToken: signatures[${idx}] undefined (unreachable)`,
            );
        }
        return generateMerkleLeaf({
            id: signer.id,
            role: signer.role,
            signature,
        });
    });

    // step 6.2+6.3: construct the Merkle tree -> merkleRoot + audit paths
    const { root, paths } = buildMerkleTree(leaves);

    // merkleRoot encoding (hex by default, matching the wire format convention)
    const merkleRootEncoded =
        input.merkleRootEncoding === 'base64url' ? toBase64Url(root) : toHex(root);

    // inclusionProofs encoding (base64url)
    const inclusionProofs = input.signers.map((signer, idx) => {
        const pathBytes = paths[idx];
        /* v8 ignore next 6 -- paths.length === leaves.length === signers.length*/
        if (pathBytes === undefined) {
            throw new MultisigError(
                'MULTISIG_INCLUSION_PROOF_MISSING',
                `issueMultisigToken: paths[${idx}] undefined (unreachable)`,
            );
        }
        return {
            signerId: signer.id,
            path: encodeMerklePath(pathBytes),
        };
    });

    // step 7: construct the MultisigToken (via the L0 createMultisigToken factory; single-cast enforcement, no brand coercion)
    const signersForToken: SignerInfoInput[] = input.signers.map((signer, idx) => {
        const signature = signatures[idx];
        /* v8 ignore next 6 -- signatures.length === signers.length*/
        if (signature === undefined) {
            throw new MultisigError(
                'MULTISIG_TOKEN_INCOMPLETE',
                `issueMultisigToken: signatures[${idx}] undefined (unreachable)`,
            );
        }
        return {
            id: signer.id,
            role: signer.role,
            publicKey: signer.publicKey,
            signature: signature as Signature,
        };
    });

    const token = createMultisigToken({
        multisigVersion: '1.0.0',
        threshold: input.threshold,
        signers: signersForToken,
        // merkleRoot: hex 64-char or base64url 43-char; validated by the L0 createMultisigToken factory's internal schema;
        // the Hash brand is validated by the L0 createMultisigToken internal schema (pattern ^[A-Za-z0-9_-]+=*$|^[0-9a-f]{64}$)
        merkleRoot: merkleRootEncoded as Hash,
        inclusionProofs,
        csp: input.csp,
    });

    // step 8: return MultisigToken
    return token;
}
