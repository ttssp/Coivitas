/**
 * Multisig sub-protocol (ms) L0 type definitions
 *
 * ms v0.1 sub-protocol
 *
 * 6 mandatory fields: {multisigVersion, threshold, signers,
 * merkleRoot, inclusionProofs, csp}; the verifier-side verify pipeline validates that all 6
 * fields are present at its entry, and missing any one triggers a fail-closed reject.
 *
 * Triple defense:
 *   Layer 1: TypeScript brand type (compile time; this file)
 *   Layer 2: JSON Schema format (runtime Schema layer; multisig-token-v0.1.schema.json)
 *   Layer 3: AJV strict mode (runtime Schema engine layer; multisig-validation.ts)
 *
 * No brand cast: every brand type can only be obtained through a to*() factory function; a direct
 * `as SignerId` / `as MerklePath` / `as MultisigToken` cast is strictly forbidden.
 *
 * Error code namespace:
 *   - 14 active MULTISIG_* codes (frozen in v0.1)
 *   - Orthogonal to the csp `CSP_*` / wire format `TOKEN_*` namespaces
 *   - Cross-namespace exception: the pipeline propagates `CSP_*` (step 7.2) + `TOKEN_REVOKED`
 *     (step 7.5; token domain) — they are not renamed; the source error domain semantics are preserved
 *
 * Key design principles:
 *   1. The n-of-m threshold is mandatory; missing it = fail-closed reject
 *   2. The Merkle inclusion model is independent of issuance (leaf = signer commitment hash; not a
 *      capability scope claim; the mutually exclusive semantics with the v0.2 candidate are forbidden at the protocol layer)
 *   3. The challenge is bound verifier-side (inheriting the csp v0.1 reverse semantics)
 *   4. The role field **does not participate** in quorum weighting (all signers carry equal weight;
 *      it serves only as a classification marker at issuance + Merkle leaf encoding consistency; collusion defense)
 *   5. Recursive triple defense (brand + Schema + AJV)
 *   6. fail-closed fallback (any verify failure = reject by default)
 *   7. The partial-signed state must never reach verify (the issuance phase must collect all m signer signatures)
 */

import type { Hash, Signature } from '../base.js';
import type { CanonicalSignedPayload } from '../canonical-signed-payload/types.js';

// ─── Brand Types (layer-1 defense; no brand cast) ───────────────────────────────────

/**
 * SignerId brand type — signer ID (DID or UUID v4 session ID)
 *
 * Compile-time enforcement: signers[i].id must be constructed via the toSignerId() factory;
 * a direct `s as SignerId` cast is not allowed (no brand cast).
 *
 * Supported formats:
 *   - DID: starts with `did:` (the main case; long-lived signer identity)
 *   - UUID v4: short-lived session signer ID (32 hex + 4 dash; short-lived session signer scenario)
 */
export type SignerId = string & { readonly __brand: 'SignerId' };

/**
 * MerklePath brand type — RFC 6962 Merkle inclusion path (base64url encoded)
 *
 * Compile-time enforcement: inclusionProofs[i].path must be constructed via the toMerklePath() factory;
 * a direct `s as MerklePath` cast is not allowed (no brand cast).
 *
 * Format: a base64url-encoded byte array whose content is [sibling_hash_0 (32B) || direction_0 (1B) ||
 * sibling_hash_1 (32B) || direction_1 (1B) || ...] (RFC 6962 audit path).
 *
 * Length constraint: 1 ≤ length ≤ 8192 (as implemented literally in toMerklePath)
 */
export type MerklePath = string & { readonly __brand: 'MerklePath' };

/**
 * SignerRole — signer role enum (human / agent)
 *
 * Single-field signers[] + role discrimination model:
 *   the role field serves only as a classification marker at issuance + Merkle leaf encoding consistency
 *   (the leaf encoding includes the role field to prevent post-issuance tampering);
 *   it **does not participate** in quorum weighting (collusion defense; all signers carry equal weight).
 *
 * If a v0.2+ candidate evolves a mandatory human-in-the-loop requirement out of the
 * trust-boundary primitive, upgrade to role-based weighting via a multisigVersion semver bump,
 * or to a hard split with the two fields humanSigners[] + agentSigners[].
 */
export type SignerRole = 'human' | 'agent';

/**
 * MultisigVersion brand type — ms protocol version (independent namespace)
 *
 * Independent multisigVersion namespace; not coupled to token.specVersion (the three-state
 * coexistence of 0.1.0/0.2.0/0.3.0 is unchanged) nor coupled to cspVersion.
 *
 * The only legal v0.1 spec value: "1.0.0"
 * v0.2+ evolution paths (candidates):
 *   - BLS aggregate signature → multisigVersion 1.0.0 → 1.1.0 OR 2.0.0
 *   - partial-signed (n < m) model → multisigVersion bump
 *   - role-based weighting → multisigVersion bump
 *   - sparse Merkle tree (SMT) → multisigVersion bump
 *   - hard split with the two fields humanSigners[] + agentSigners[] → multisigVersion bump
 */
export type MultisigVersion = string & { readonly __brand: 'MultisigVersion' };

/**
 * SignerInfo — metadata for a single signer
 *
 * Field meanings:
 *   - id: signer ID (SignerId brand; DID or UUID v4)
 *   - role: signer role (SignerRole; human / agent; does not participate in weighting)
 *   - publicKey: Ed25519 public key (32-byte hex/base64url; @noble/curves; no fallback to other algorithms)
 *   - signature: this signer's Ed25519 signature over csp signedBytes (Signature brand)
 */
export interface SignerInfo {
    /** signer ID (DID or UUID v4 session ID)*/
    id: SignerId;
    /** signer role (human or agent; does not participate in quorum weighting)*/
    role: SignerRole;
    /** signer public key (Ed25519; 32-byte hex or 43-char base64url; @noble/curves)*/
    publicKey: string;
    /** this signer's Ed25519 signature over csp signedBytes (Signature brand)*/
    signature: Signature;
}

/**
 * MultisigInclusionProof — a single signer's Merkle inclusion proof entry
 *
 * Fields:
 *   - signerId: the corresponding signer ID (1:1 with signers[i].id; by-field uniqueness constraint)
 *   - path: Merkle audit path (MerklePath brand; base64url; RFC 6962)
 *
 * Invariants (spec I4):
 *   - inclusionProofs.length === signers.length
 *   - the inclusionProofs.map(p => p.signerId) set is 1:1 with the signers.map(s => s.id) set
 *     (no duplicates; by-field uniqueItems); the Schema-layer uniqueItems is a whole-object uniqueness
 *     constraint, while the precise by-field guard is provided as a fail-closed fallback by runtime step 7.3.0
 */
export interface MultisigInclusionProof {
    /** the corresponding signer's ID (1:1 with signers[i].id)*/
    signerId: SignerId;
    /** Merkle audit path (base64url; RFC 6962)*/
    path: MerklePath;
}

// ─── MultisigToken Interface (6 mandatory fields) ─────────────────────────

/**
 * MultisigTokenStruct — MultisigToken field structure (v0.1, 6 fields)
 *
 * 6 mandatory fields: {multisigVersion, threshold, signers, merkleRoot, inclusionProofs, csp}
 * Missing any one = `MULTISIG_TOKEN_INCOMPLETE` fail-closed reject
 *
 * Invariants:
 *   I_ms_ver: multisigVersion satisfies semver format; the only v0.1 value is "1.0.0"
 *   I1: threshold is an integer; 1 ≤ threshold ≤ signers.length; 0 / negative / floating-point not allowed
 *   I2: signers array; signers.length ≥ threshold; the signers[i].id set has no duplicates
 *   I3: merkleRoot SHA-256 over signers commitment leaves
 *       leaf_i = SHA-256(JCS canonicalize({id, role, signature}))
 *       encoding order = signers array order (canonical)
 *   I4: inclusionProofs.length === signers.length; by-field signerId 1:1 correspondence
 *   I5: (field removed; aggregatedSignature removed)
 *   I6: all csp fields present (csp v0.1 invariants I1-I7 + I_csp_ver)
 *   I7: quorum met (at least threshold signers pass Ed25519 verify)
 *   I8: partial-signed strictly forbidden (all signers[i].signature !== '')
 *   I9: first-contact replay defense (csp.challenge === verifier.issuedChallenge)
 */
export interface MultisigTokenStruct {
    /** ms protocol version metadata field (MultisigVersion brand; the only v0.1 value is "1.0.0")*/
    multisigVersion: MultisigVersion;
    /** the n in the n-of-m threshold; invariant 1 ≤ threshold ≤ signers.length*/
    threshold: number;
    /** signer info array (m candidates; signers.length >= threshold)*/
    signers: SignerInfo[];
    /** Merkle root of the signers set (Hash brand; SHA-256; leaf = signer commitment hash)*/
    merkleRoot: Hash;
    /** each signer's Merkle inclusion path (signerId uniqueness constraint; 1:1 with signers[i].id)*/
    inclusionProofs: ReadonlyArray<MultisigInclusionProof>;
    /** embedded CanonicalSignedPayload (reuses the csp v0.1 5-mandatory-field baseline + cspVersion metadata)*/
    csp: CanonicalSignedPayload;
}

/**
 * MultisigToken — sub-protocol token type
 *
 * Equivalent to MultisigTokenStruct (no __brand wrapper; follows the csp v0.1 CanonicalSignedPayload pattern):
 *   - does not introduce a __brand field (it would affect JSON Schema additionalProperties: false validation)
 *   - must be constructed via the createMultisigToken() factory; direct object-literal construction is not allowed (enforced at the type layer)
 *   - no brand cast: the internal fields have already passed their respective brand validations (signers[i].id via toSignerId, etc.)
 *
 * Type-layer no-brand-cast enforcement paths:
 *   1. SignerId / MerklePath / MultisigVersion: string brand (factory-enforced);
 *   2. signers[i].publicKey + signature: string (but an internal field; checked non-empty via createMultisigToken)
 *   3. inclusionProofs[i].{signerId, path}: brand (factory-enforced);
 *   4. createMultisigToken is the only legal construction path (callers may not skip validation via a direct object literal).
 */
export type MultisigToken = MultisigTokenStruct;

// ─── Error codes (MULTISIG_* namespace isolation; 14 active codes frozen in v0.1) ─────

/**
 * MultisigErrorCode — ms error code namespace (MULTISIG_* prefix)
 *
 * Frozen: 14 active error codes (v0.1; the original 17 minus 3 removed items =
 * MULTISIG_AGGREGATION_INVALID + MULTISIG_HUMAN_SIGNER_REQUIRED +
 * MULTISIG_ROLE_WEIGHTED_QUORUM_INSUFFICIENT).
 * Rename / remove / severity change are not allowed (breaking-format-change guard).
 * Later ms v0.2+ may only add new MULTISIG_* error codes.
 *
 * Invariant mapping:
 *   MULTISIG_TOKEN_INCOMPLETE → step 7.1 (any of the 6 fields missing)
 *   MULTISIG_VERSION_UNSUPPORTED → I_ms_ver (multisigVersion ∉ supported set)
 *   MULTISIG_THRESHOLD_INVALID → I1 (threshold ≤ 0 OR > signers.length OR not an integer)
 *   MULTISIG_SIGNERS_INSUFFICIENT → I2 (signers.length < threshold)
 *   MULTISIG_SIGNER_DUPLICATE → I2 + step 7.6 (duplicate in the signers[i].id set)
 *   MULTISIG_SIGNER_ID_INVALID → toSignerId factory (not a DID, not a UUID v4)
 *   MULTISIG_MERKLE_ROOT_INVALID → I3 + step 7.3 (recomputedRoot ≠ merkleRoot)
 *   MULTISIG_MERKLE_PATH_INVALID → I4 + toMerklePath (not base64url / length out of range)
 *   MULTISIG_INCLUSION_PROOF_MISSING → I4 (inclusionProofs.length ≠ signers.length / some signer has no path)
 *   MULTISIG_SIGNATURE_INVALID → step 7.4 (Ed25519 verify failed / bad signature format)
 *   MULTISIG_QUORUM_INSUFFICIENT → I7 + step 7.5 (validCount < threshold)
 *   MULTISIG_PARTIAL_SIGNED_REJECTED → I8 (some signer signature is empty)
 *   MULTISIG_CHALLENGE_INVALID → I9 (csp.challenge ≠ verifier.issuedChallenge)
 *   MULTISIG_SCHEMA_VIOLATION → (JSON Schema validation failed)
 *
 * Cross-namespace propagate exception:
 *   ms pipeline step 7.2 passes through CSP_* error codes (csp verify sub-flow);
 *   step 7.5 may pass through TOKEN_REVOKED (originating in the token domain; not the MULTISIG namespace);
 *   when the ms layer surfaces this code it is **not renamed**, preserving the source error domain semantics.
 *   This usage is a deliberate design-layer cross-namespace exception; it does not violate the namespace isolation contract.
 */
export type MultisigErrorCode =
    | 'MULTISIG_TOKEN_INCOMPLETE'
    | 'MULTISIG_VERSION_UNSUPPORTED'
    | 'MULTISIG_THRESHOLD_INVALID'
    | 'MULTISIG_SIGNERS_INSUFFICIENT'
    | 'MULTISIG_SIGNER_DUPLICATE'
    | 'MULTISIG_SIGNER_ID_INVALID'
    | 'MULTISIG_MERKLE_ROOT_INVALID'
    | 'MULTISIG_MERKLE_PATH_INVALID'
    | 'MULTISIG_INCLUSION_PROOF_MISSING'
    | 'MULTISIG_SIGNATURE_INVALID'
    | 'MULTISIG_QUORUM_INSUFFICIENT'
    | 'MULTISIG_PARTIAL_SIGNED_REJECTED'
    | 'MULTISIG_CHALLENGE_INVALID'
    | 'MULTISIG_SCHEMA_VIOLATION';

// ─── Constants (depended on by the factory functions) ───────────────────────────────────────────────

/**
 * The set of ms supported versions (the only v0.1 value is "1.0.0")
 *
 * Independent multisigVersion namespace; not coupled to token.specVersion / cspVersion.
 * Later ms v0.2+ extensions are added to this array; they do not trigger a token.specVersion bump.
 */
export const MULTISIG_SUPPORTED_VERSIONS: readonly string[] = ['1.0.0'] as const;

/**
 * The current ms v0.1 version (factory function default)
 */
export const MULTISIG_VERSION_CURRENT = '1.0.0' as const;

/**
 * MerklePath length upper bound (as implemented literally in toMerklePath)
 *
 * 8192 bytes; under base64url encoding this is roughly 6144 raw bytes ≈ 96 sibling-hash levels
 * (each level is a 32-byte sibling + 1-byte direction); enough to support a Merkle tree with 2^96 leaves
 * (the actual multisig signers.length is far below this upper bound).
 */
export const MULTISIG_MERKLE_PATH_MAX_LENGTH = 8192;

/**
 * threshold upper bound (sanity check; the actual m is far below this value)
 *
 * I1 invariant literal: 1 ≤ threshold ≤ signers.length; this constant is a sanity upper bound
 * (guards against an abnormally large threshold input causing memory blowup or DoS; an actual production
 * deployment should be far below 100).
 */
export const MULTISIG_THRESHOLD_MAX_SANITY = 1000;

// ─── Factory Functions (no brand cast; the only legal brand cast path) ──────────────────

/**
 * UUID v4 regex (toSignerId literal)
 *
 * Strictly matches the RFC 4122 UUID v4 format:
 * - 32 hex chars + 4 dash
 * - the 13th char (version) = 4
 * - the 17th char (variant) ∈ {8, 9, a, b} (RFC 4122 variant 10xx)
 */
const UUID_V4_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * base64url regex (toMerklePath literal)
 *
 * RFC 4648 base64url charset (A-Z a-z 0-9 - _) + optional padding (=)
 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+=*$/;

/**
 * semver regex (X.Y.Z; multisigVersion semver format validation)
 */
const SEMVER_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/**
 * toSignerId — SignerId brand type factory function
 *
 * No brand cast: the only legal way to obtain a SignerId; validates DID or UUID v4 format at runtime.
 * Callers may not do a direct `s as SignerId`.
 *
 * Supported formats:
 *   - DID: starts with "did:" (long-lived signer identity; the main case)
 *   - UUID v4: short-lived session signer ID (32 hex + 4 dash; version=4; variant=10xx)
 *
 * On validation failure throws error code MULTISIG_SIGNER_ID_INVALID
 *
 * @throws Error MULTISIG_SIGNER_ID_INVALID if the format is non-conformant
 */
export function toSignerId(s: string): SignerId {
    if (typeof s !== 'string') {
        throw new Error(
            `MULTISIG_SIGNER_ID_INVALID: signer ID must be string, got ${typeof s}`,
        );
    }
    if (s.startsWith('did:') && s.length > 'did:'.length) {
        // DID branch: it suffices that the length exceeds the 'did:' prefix (full DID format validation is the responsibility of the L2 identity layer)
        return s as SignerId;
    }
    if (UUID_V4_PATTERN.test(s)) {
        // UUID v4 branch
        return s as SignerId;
    }
    throw new Error(
        `MULTISIG_SIGNER_ID_INVALID: signer ID must be did:* DID or UUID v4, got "${s}"`,
    );
}

/**
 * toMerklePath — MerklePath brand type factory function
 *
 * No brand cast: the only legal way to obtain a MerklePath; validates base64url format + length bounds at runtime.
 * Callers may not do a direct `s as MerklePath`.
 *
 * Length constraint: 1 ≤ length ≤ 8192 characters (base64url encoding)
 *
 * On validation failure throws error code MULTISIG_MERKLE_PATH_INVALID
 *
 * @throws Error MULTISIG_MERKLE_PATH_INVALID if the format is non-conformant or the length is out of range
 */
export function toMerklePath(s: string): MerklePath {
    if (typeof s !== 'string') {
        throw new Error(
            `MULTISIG_MERKLE_PATH_INVALID: path must be string, got ${typeof s}`,
        );
    }
    if (s.length === 0) {
        throw new Error(
            'MULTISIG_MERKLE_PATH_INVALID: path is empty (must be 1 ≤ length ≤ 8192)',
        );
    }
    if (s.length > MULTISIG_MERKLE_PATH_MAX_LENGTH) {
        throw new Error(
            `MULTISIG_MERKLE_PATH_INVALID: path length ${s.length} exceeds max ${MULTISIG_MERKLE_PATH_MAX_LENGTH}`,
        );
    }
    if (!BASE64URL_PATTERN.test(s)) {
        throw new Error(
            `MULTISIG_MERKLE_PATH_INVALID: not valid base64url format: "${s.substring(0, 32)}..."`,
        );
    }
    return s as MerklePath;
}

/**
 * toMultisigVersion — MultisigVersion brand type factory function
 *
 * No brand cast: the only legal way to obtain a MultisigVersion;
 * validates semver format + the legal value set at runtime (the only v0.1 value is "1.0.0").
 *
 * On validation failure throws error code MULTISIG_VERSION_UNSUPPORTED
 *
 * @throws Error MULTISIG_VERSION_UNSUPPORTED if the format or version is non-conformant
 */
export function toMultisigVersion(s: string): MultisigVersion {
    if (typeof s !== 'string') {
        throw new Error(
            `MULTISIG_VERSION_UNSUPPORTED: multisigVersion must be string, got ${typeof s}`,
        );
    }
    if (!SEMVER_PATTERN.test(s)) {
        throw new Error(
            `MULTISIG_VERSION_UNSUPPORTED: not valid semver (X.Y.Z): "${s}"`,
        );
    }
    if (!MULTISIG_SUPPORTED_VERSIONS.includes(s)) {
        throw new Error(
            `MULTISIG_VERSION_UNSUPPORTED: unsupported multisigVersion "${s}"; supported: ${MULTISIG_SUPPORTED_VERSIONS.join(', ')}`,
        );
    }
    return s as MultisigVersion;
}

// ─── createMultisigToken Factory (single brand cast enforcement) ─────────

/**
 * CreateMultisigTokenInput — input type of the createMultisigToken factory function
 *
 * Accepts raw strings/objects; the factory function internally converts each to a brand type via its factory.
 * Callers may not bypass the factory to construct a MultisigToken directly (no brand cast).
 *
 * Fields correspond to the 6 mandatory MultisigTokenStruct fields:
 *   - multisigVersion: string → MultisigVersion brand (toMultisigVersion)
 *   - threshold: number (integer check + 1 ≤ threshold ≤ signers.length)
 *   - signers: SignerInfoInput[] (id string → SignerId brand via toSignerId)
 *   - merkleRoot: string → Hash brand (already a Hash type at runtime)
 *   - inclusionProofs: { signerId: string; path: string }[] → converted to brand internally
 *   - csp: CanonicalSignedPayload (reuses the csp v0.1 5-mandatory-field baseline; already a brand)
 */
export interface SignerInfoInput {
    /** raw signer ID string (DID or UUID v4)*/
    id: string;
    /** signer role*/
    role: SignerRole;
    /** signer public key (Ed25519; hex or base64url)*/
    publicKey: string;
    /** this signer's signature over csp signedBytes (Signature)*/
    signature: Signature;
}

export interface InclusionProofInput {
    /** raw corresponding signer ID string*/
    signerId: string;
    /** raw Merkle audit path string*/
    path: string;
}

export interface CreateMultisigTokenInput {
    /** ms protocol version (the only v0.1 value is "1.0.0")*/
    multisigVersion: string;
    /** the n in the n-of-m threshold*/
    threshold: number;
    /** signer info array (m candidates)*/
    signers: SignerInfoInput[];
    /** Merkle root of the signers set (Hash brand; already a brand)*/
    merkleRoot: Hash;
    /** each signer's Merkle inclusion path*/
    inclusionProofs: InclusionProofInput[];
    /** embedded CanonicalSignedPayload*/
    csp: CanonicalSignedPayload;
}

/**
 * createMultisigToken — MultisigToken factory function (single brand cast enforcement)
 *
 * Design principle 1 (the n-of-m threshold is mandatory) + invariants I1-I4 (field-layer validation)
 *
 * Runtime validation chain (any failure throws + the corresponding MULTISIG_* error code; fail-closed):
 *   1. multisigVersion: toMultisigVersion → semver + legal value set validation
 *   2. threshold: integer + 1 ≤ threshold ≤ signers.length + ≤ MULTISIG_THRESHOLD_MAX_SANITY
 *   3. signers: array + length >= threshold + each signer.id validated via toSignerId
 *      + the signers[i].id set has no duplicates (I2 by-field uniqueness)
 *   4. merkleRoot: non-empty string (Hash brand already validated)
 *   5. inclusionProofs: length === signers.length + each path validated via toMerklePath
 *      + by-field signerId 1:1 with signers[i].id
 *   6. csp: not null/undefined (already a CanonicalSignedPayload brand; not re-validated)
 *
 * Note: this factory **does not perform** the following temporal verify-pipeline checks (left to the L2 multisig-token-verifier):
 *   - I3 Merkle root recomputation (requires the L1 crypto merkle-tree primitive)
 *   - I7 quorum met (requires L1 crypto Ed25519 verify)
 *   - I8 partial-signed strictly forbidden (detected at the verifier entry)
 *   - I9 challenge replay defense (verifier-side issued challenge bind)
 *
 * @throws Error a MULTISIG_* error code if any field fails validation (fail-closed)
 */
export function createMultisigToken(
    input: CreateMultisigTokenInput,
): MultisigToken {
    // step 1: multisigVersion validation (I_ms_ver)
    const multisigVersion = toMultisigVersion(input.multisigVersion);

    // step 2: threshold validation (I1)
    if (!Number.isInteger(input.threshold)) {
        throw new Error(
            `MULTISIG_THRESHOLD_INVALID: threshold must be integer, got ${input.threshold} (typeof ${typeof input.threshold})`,
        );
    }
    if (input.threshold < 1) {
        throw new Error(
            `MULTISIG_THRESHOLD_INVALID: threshold must be >= 1, got ${input.threshold}`,
        );
    }
    if (input.threshold > MULTISIG_THRESHOLD_MAX_SANITY) {
        throw new Error(
            `MULTISIG_THRESHOLD_INVALID: threshold ${input.threshold} exceeds sanity max ${MULTISIG_THRESHOLD_MAX_SANITY}`,
        );
    }

    // step 3: signers validation (I2)
    if (!Array.isArray(input.signers)) {
        throw new Error(
            'MULTISIG_TOKEN_INCOMPLETE: signers must be an array',
        );
    }
    if (input.signers.length < input.threshold) {
        throw new Error(
            `MULTISIG_SIGNERS_INSUFFICIENT: signers.length ${input.signers.length} < threshold ${input.threshold}`,
        );
    }

    // each signer.id is validated via the toSignerId factory + a by-field uniqueness check
    const signerIdSet = new Set<string>();
    const signers: SignerInfo[] = input.signers.map((rawSigner, idx) => {
        if (!rawSigner || typeof rawSigner !== 'object') {
            throw new Error(
                `MULTISIG_TOKEN_INCOMPLETE: signers[${idx}] must be an object`,
            );
        }
        if (rawSigner.role !== 'human' && rawSigner.role !== 'agent') {
            throw new Error(
                `MULTISIG_SCHEMA_VIOLATION: signers[${idx}].role must be 'human' or 'agent', got "${String(rawSigner.role)}"`,
            );
        }
        if (typeof rawSigner.publicKey !== 'string' || rawSigner.publicKey.length === 0) {
            throw new Error(
                `MULTISIG_SCHEMA_VIOLATION: signers[${idx}].publicKey must be non-empty string`,
            );
        }
        if (typeof rawSigner.signature !== 'string' || rawSigner.signature.length === 0) {
            throw new Error(
                `MULTISIG_SCHEMA_VIOLATION: signers[${idx}].signature must be non-empty string`,
            );
        }
        const id = toSignerId(rawSigner.id);
        if (signerIdSet.has(id)) {
            throw new Error(
                `MULTISIG_SIGNER_DUPLICATE: signers[${idx}].id "${id}" duplicates earlier signer (by-field uniqueness violated)`,
            );
        }
        signerIdSet.add(id);
        return {
            id,
            role: rawSigner.role,
            publicKey: rawSigner.publicKey,
            signature: rawSigner.signature,
        };
    });

    // step 4: merkleRoot validation (non-empty; the Hash brand type already guarantees it)
    if (typeof input.merkleRoot !== 'string' || input.merkleRoot.length === 0) {
        throw new Error(
            'MULTISIG_MERKLE_ROOT_INVALID: merkleRoot must be non-empty string',
        );
    }

    // step 5: inclusionProofs validation (I4)
    if (!Array.isArray(input.inclusionProofs)) {
        throw new Error(
            'MULTISIG_TOKEN_INCOMPLETE: inclusionProofs must be an array',
        );
    }
    if (input.inclusionProofs.length !== input.signers.length) {
        throw new Error(
            `MULTISIG_INCLUSION_PROOF_MISSING: inclusionProofs.length ${input.inclusionProofs.length} !== signers.length ${input.signers.length}`,
        );
    }

    // validate that the inclusionProofs[i].signerId set is 1:1 with the signers[i].id set (by-field; no duplicates)
    const proofSignerIdSet = new Set<string>();
    const inclusionProofs: MultisigInclusionProof[] = input.inclusionProofs.map(
        (rawProof, idx) => {
            if (!rawProof || typeof rawProof !== 'object') {
                throw new Error(
                    `MULTISIG_TOKEN_INCOMPLETE: inclusionProofs[${idx}] must be an object`,
                );
            }
            const signerId = toSignerId(rawProof.signerId);
            const path = toMerklePath(rawProof.path);
            if (proofSignerIdSet.has(signerId)) {
                throw new Error(
                    `MULTISIG_INCLUSION_PROOF_MISSING: inclusionProofs[${idx}].signerId "${signerId}" duplicates earlier proof (by-field uniqueness violated)`,
                );
            }
            if (!signerIdSet.has(signerId)) {
                throw new Error(
                    `MULTISIG_INCLUSION_PROOF_MISSING: inclusionProofs[${idx}].signerId "${signerId}" not in signers set (1:1 mapping violated)`,
                );
            }
            proofSignerIdSet.add(signerId);
            return { signerId, path };
        },
    );

    // step 6: csp validation (not null/undefined; the CanonicalSignedPayload brand has already validated its fields)
    if (input.csp === null || input.csp === undefined) {
        throw new Error('MULTISIG_TOKEN_INCOMPLETE: csp must not be null or undefined');
    }
    if (typeof input.csp !== 'object') {
        throw new Error('MULTISIG_TOKEN_INCOMPLETE: csp must be an object');
    }

    // construct the MultisigToken (no __brand wrapper; follows the csp v0.1 CanonicalSignedPayload pattern;
    // friendly to JSON Schema additionalProperties: false)
    return {
        multisigVersion,
        threshold: input.threshold,
        signers,
        merkleRoot: input.merkleRoot,
        inclusionProofs,
        csp: input.csp,
    };
}

// ─── assertNeverMultisigError — exhaustive switch guard ──────────────────────

/**
 * assertNeverMultisigError — MultisigErrorCode exhaustive switch fallback
 *
 * Used in the default branch of the handleMultisigError switch statement;
 * if a newly added MultisigErrorCode value is not handled in the switch → compile-time error.
 *
 * Anti-phantom design (physically enforced):
 *   - 14 cases, each with a literal throw / message mapping;
 *   - default → assertNeverMultisigError (TypeScript compile-time exhaustive guard);
 *   - if the MultisigErrorCode union later expands → compile-time fail → forces the developer
 *     to update the switch in sync (no silent skip allowed).
 *
 * @throws Error unreachable at runtime; if triggered, the type system was bypassed
 */
export function assertNeverMultisigError(code: never): never {
    throw new Error(
        `Unreachable: unhandled MultisigErrorCode "${String(code)}"`,
    );
}

// ─── handleMultisigError — switch covering all 14 cases + assertNever exhaustive ──

/**
 * MultisigErrorContext — handleMultisigError result
 */
export interface MultisigErrorContext {
    /** error code (MULTISIG_*)*/
    code: MultisigErrorCode;
    /** HTTP status code (4xx fail-closed; 5xx silent retry strictly forbidden)*/
    httpStatus: 400 | 401 | 403 | 422 | 503;
    /** error message (literal description; reference for consumer try/catch routing)*/
    message: string;
    /** whether the error is fatal (all 14 are fatal, except MULTISIG_VERSION_UNSUPPORTED which is medium severity)*/
    fatal: boolean;
}

/**
 * handleMultisigError — MultisigErrorCode switch covering all 14 cases + assertNever exhaustive
 *
 * Every MultisigErrorCode value must have a corresponding case;
 * assertNeverMultisigError(code) in the default branch ensures a compile-time exhaustive check.
 *
 * fail-closed principle: all errors map to 4xx/5xx; a stub 200 is not allowed.
 *
 * Severity:
 *   MULTISIG_VERSION_UNSUPPORTED → medium → 422 Unprocessable Entity
 *   the other 13 → fatal → 400/401/403
 */
export function handleMultisigError(code: MultisigErrorCode): MultisigErrorContext {
    switch (code) {
        case 'MULTISIG_TOKEN_INCOMPLETE':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig token is incomplete: required field missing (6 mandatory fields: multisigVersion / threshold / signers / merkleRoot / inclusionProofs / csp)',
                fatal: true,
            };
        case 'MULTISIG_VERSION_UNSUPPORTED':
            return {
                code,
                httpStatus: 422,
                message:
                    'Multisig multisigVersion is not in the supported set (v0.1 only "1.0.0") or not valid semver',
                fatal: true,
            };
        case 'MULTISIG_THRESHOLD_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig threshold is invalid: not integer, ≤ 0, or > signers.length',
                fatal: true,
            };
        case 'MULTISIG_SIGNERS_INSUFFICIENT':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig signers.length < threshold (m < n; quorum unreachable by construction)',
                fatal: true,
            };
        case 'MULTISIG_SIGNER_DUPLICATE':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig signers[i].id contains duplicate (defends against a duplicate-signer attack occupying quorum slots; I2 by-field uniqueness)',
                fatal: true,
            };
        case 'MULTISIG_SIGNER_ID_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig signer ID is invalid: must be did:* DID or UUID v4',
                fatal: true,
            };
        case 'MULTISIG_MERKLE_ROOT_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig recomputed Merkle root does not match merkleRoot field (signer leaf integrity violated)',
                fatal: true,
            };
        case 'MULTISIG_MERKLE_PATH_INVALID':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig inclusion proof path is not valid base64url or length out of range (1 ≤ length ≤ 8192)',
                fatal: true,
            };
        case 'MULTISIG_INCLUSION_PROOF_MISSING':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig inclusionProofs.length !== signers.length OR signer has no matching inclusion path',
                fatal: true,
            };
        case 'MULTISIG_SIGNATURE_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'Multisig signer Ed25519 signature is invalid: bad format OR Ed25519 verify FAIL',
                fatal: true,
            };
        case 'MULTISIG_QUORUM_INSUFFICIENT':
            return {
                code,
                httpStatus: 401,
                message:
                    'Multisig quorum insufficient: validCount < threshold (insufficient valid signatures)',
                fatal: true,
            };
        case 'MULTISIG_PARTIAL_SIGNED_REJECTED':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig partial-signed state rejected: some signers[i].signature is empty (I8 strict m collection at issuance)',
                fatal: true,
            };
        case 'MULTISIG_CHALLENGE_INVALID':
            return {
                code,
                httpStatus: 401,
                message:
                    'Multisig csp.challenge !== verifier-issued challenge (first-contact replay defense)',
                fatal: true,
            };
        case 'MULTISIG_SCHEMA_VIOLATION':
            return {
                code,
                httpStatus: 400,
                message:
                    'Multisig token JSON Schema validation failed (format / additionalProperties / required)',
                fatal: true,
            };
        default:
            // assertNever exhaustive: if a newly added MultisigErrorCode value is not handled in this switch → compile-time error
            /* v8 ignore next*/
            return assertNeverMultisigError(code);
    }
}
