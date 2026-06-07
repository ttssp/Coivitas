/**
 * merkle-tree — Multisig L1 crypto primitive (RFC 6962 audit-path verification sub-flow)
 *
 * Design: RFC 6962 standard + leaf-encoding canonicalization strategy
 *
 * Algorithm:
 *   1. leaf encoding (authoritative path): leaf_i = SHA-256(JCS canonicalize({id, role, signature}))
 *      - no direct string concatenation (prevents JSON field-order inconsistency → leaf not recomputable);
 *      - reuses the csp v0.1 canonicalize npm library;
 *   2. Merkle tree construction (issuer side): pairwise SHA-256 hash + level-by-level reduce → root
 *   3. inclusion path verify (verifier side):
 *      input: leaf_i, path_i (bytes), expected_root
 *      byte-array decode: [sibling_hash_0 (32B) || direction_0 (1B) || sibling_hash_1 (32B) || direction_1 (1B) || ...]
 *      direction = 0 means sibling is on the left, current on the right (merge = SHA-256(sibling || current))
 *      direction = 1 means sibling is on the right, current on the left (merge = SHA-256(current || sibling))
 *      return recomputed_root === expected_root
 *
 * Anti-phantom defenses:
 *   - top-level import @noble/hashes/sha256 + canonicalSerialize (no in-function require/dynamic import)
 *   - SHA-256 enforced (no fallback to other hash algorithms; protocol-level invariant)
 *   - active invocation required (no stub default success)
 *   - any step failure throws MultisigError + one of the 14 codes (fail-closed)
 */

import { sha256 } from '@noble/hashes/sha256';

import { canonicalSerialize } from '../canonical-signed-payload/canonical-serialize.js';
import { fromBase64Url, toBase64Url, toHex } from '../encoding.js';

import { MultisigError } from './types.js';

/**
 * SignerLeafInput — generateMerkleLeaf input (the leaf-encoding input for a single signer)
 *
 *  leaf algorithm: leaf_i = SHA-256(JCS canonicalize({id, role, signature}))
 *
 * Field order (canonical): JCS canonicalize enforces alphabetical key sort,
 * the actual leaf bytes are output in the RFC 8785-enforced order inside canonicalSerialize, so the input field order
 * has no effect on the leaf computation result (a JCS property).
 */
export interface SignerLeafInput {
    /** signer ID (DID or UUID v4)*/
    id: string;
    /** signer role (human or agent)*/
    role: 'human' | 'agent';
    /** signer's Ed25519 signature over the csp signedBytes (Base64url or hex)*/
    signature: string;
}

/**
 * generateMerkleLeaf — compute the Merkle leaf hash for a single signer
 *
 *  leaf_i = SHA-256(JCS canonicalize({id, role, signature}))
 *
 * Algorithm:
 *   1. build the canonical input object: {id, role, signature}
 *   2. JCS canonicalize → UTF-8 bytes (RFC 8785; canonicalize npm)
 *   3. SHA-256 hash → 32-byte digest
 *
 * Anti-phantom defenses:
 *   - string-concat shorthand strictly forbidden;
 *   - reuses canonicalSerialize to guarantee JCS consistency across the whole sub-protocol;
 *   - any step failure → MultisigError(MULTISIG_SCHEMA_VIOLATION) (canonicalSerialize pass-through) or
 *     MultisigError(MULTISIG_MERKLE_ROOT_INVALID) (sha256 exception path);
 *   - returns a 32-byte Uint8Array (fixed length) — the bytes feed directly into downstream Merkle tree build / inclusion verify.
 *
 * @param input signer leaf input (id + role + signature, 3 fields; field order forced canonical by JCS)
 * @returns 32-byte SHA-256 digest (Uint8Array; consumed by Merkle tree build / inclusion path verify)
 * @throws MultisigError(MULTISIG_SCHEMA_VIOLATION) — canonicalSerialize pass-through (illegal field type)
 * @throws MultisigError(MULTISIG_MERKLE_ROOT_INVALID) — sha256 exception (abnormal digest length)
 */
export function generateMerkleLeaf(input: SignerLeafInput): Uint8Array {
    if (!input || typeof input !== 'object') {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `generateMerkleLeaf: input must be object, got ${typeof input}`,
        );
    }
    if (typeof input.id !== 'string' || input.id.length === 0) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            'generateMerkleLeaf: input.id must be non-empty string',
        );
    }
    if (input.role !== 'human' && input.role !== 'agent') {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `generateMerkleLeaf: input.role must be 'human' or 'agent', got "${String(input.role)}"`,
        );
    }
    if (typeof input.signature !== 'string' || input.signature.length === 0) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            'generateMerkleLeaf: input.signature must be non-empty string',
        );
    }

    // step 1+2: JCS canonicalize → UTF-8 bytes (RFC 8785; reuses csp v0.1 canonicalize npm)
    // top-level import canonicalSerialize; no in-function dynamic require
    let canonicalBytes: Uint8Array;
    try {
        canonicalBytes = canonicalSerialize({
            id: input.id,
            role: input.role,
            signature: input.signature,
        });
    } catch (error) {
        /* v8 ignore next 5 -- canonicalSerialize pass-through segment (input already passed the above type guard;
           only triggered if the npm canonicalize package itself crashes; defense-in-depth fail-closed)
*/
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            'generateMerkleLeaf: canonicalSerialize pass-through failed (input not JCS-serializable per RFC 8785)',
            error instanceof Error ? error : undefined,
        );
    }

    // step 3: SHA-256 hash → 32-byte digest
    let digest: Uint8Array;
    try {
        digest = sha256(canonicalBytes);
    } catch (error) {
        /* v8 ignore next 5 -- sha256 @noble/hashes is stable; only triggered on internal panic; defense-in-depth*/
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            'generateMerkleLeaf: SHA-256 hash threw (canonical bytes corrupted)',
            error instanceof Error ? error : undefined,
        );
    }

    // anti-phantom: sha256 must return 32-byte (BlockHash size fixed)
    /* v8 ignore next 6 -- @noble/hashes sha256 contract guarantees 32-byte output; defense-in-depth*/
    if (digest.length !== 32) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            `generateMerkleLeaf: SHA-256 digest length unexpected (got ${digest.length}; expected 32)`,
        );
    }

    return digest;
}

/**
 * generateMerkleLeafHex — the hex-string version of generateMerkleLeaf (debug/audit scenarios)
 *
 * Internally converts to hex encoding (64-char); for testing / debug logs / merkleRoot field persistence (hex encoding by default)
 * The production hot-path should use generateMerkleLeaf (Uint8Array; avoids string ↔ bytes conversion overhead)
 */
export function generateMerkleLeafHex(input: SignerLeafInput): string {
    return toHex(generateMerkleLeaf(input));
}

/**
 * buildMerkleTree — construct the Merkle tree and return (root + audit paths) — used on the issuer side
 *
 *  step 6 (issuer-side Merkle commitment construction):
 *   6.1. for each signer, compute leaf_i = generateMerkleLeaf(signers[i])
 *   6.2. construct the Merkle tree (RFC 6962) → merkleRoot
 *   6.3. for each signer, construct inclusion path_i (RFC 6962 audit path)
 *
 * RFC 6962 simplified algorithm (v0.1 does not introduce leaf prefix 0x00 / node prefix 0x01):
 *   - leaf layer: leaves = [leaf_0, leaf_1, ..., leaf_{m-1}]
 *   - internal node: parent = SHA-256(left || right); on an odd count the last leaf is promoted directly to the next layer
 *     (no duplication; this differs from the Bitcoin merkle tree; the RFC 6962-specified unbalanced-tree behavior)
 *   - root is returned when level == 1 has a single node
 *
 * audit path: for each leaf, record the sibling node + direction (0 = sibling on the left, current on the right
 * → merge SHA-256(sibling || current); 1 = sibling on the right → merge SHA-256(current || sibling))
 *
 * Encoding: path bytes = concat([sibling_hash (32B) || direction (1B), ...]) → base64url
 *
 * @param leaves the array of already-computed leaf hashes (each 32-byte; in signers-array order)
 * @returns { root: Uint8Array, paths: Uint8Array[] } — root 32-byte; paths[i] is the audit path of leaves[i]
 * @throws MultisigError(MULTISIG_MERKLE_ROOT_INVALID) — leaves empty OR abnormal leaf length
 */
export function buildMerkleTree(leaves: Uint8Array[]): {
    root: Uint8Array;
    paths: Uint8Array[];
} {
    /* v8 ignore next 6 -- TS narrows leaves to Uint8Array[]; defense-in-depth*/
    if (!Array.isArray(leaves)) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            'buildMerkleTree: leaves must be array',
        );
    }
    if (leaves.length === 0) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            'buildMerkleTree: leaves array must be non-empty',
        );
    }
    for (let i = 0; i < leaves.length; i += 1) {
        const leaf = leaves[i];
        if (!(leaf instanceof Uint8Array) || leaf.length !== 32) {
            throw new MultisigError(
                'MULTISIG_MERKLE_ROOT_INVALID',
                `buildMerkleTree: leaves[${i}] must be 32-byte Uint8Array (got length ${leaf instanceof Uint8Array ? leaf.length : 'non-Uint8Array'})`,
            );
        }
    }

    // single-leaf case: root === leaf; audit path is empty (no sibling to record)
    if (leaves.length === 1) {
        const onlyLeaf = leaves[0];
        // invariant: leaves.length === 1 → leaves[0] is necessarily not undefined
        /* v8 ignore next 6 -- defense-in-depth; noUncheckedIndexedAccess narrow*/
        if (onlyLeaf === undefined) {
            throw new MultisigError(
                'MULTISIG_MERKLE_ROOT_INVALID',
                'buildMerkleTree: leaves[0] undefined (unreachable; defense-in-depth)',
            );
        }
        return {
            root: onlyLeaf,
            paths: [new Uint8Array(0)],
        };
    }

    // construct the Merkle tree level by level; also record each leaf's audit path
    // use the levels array to store each layer's nodes; levels[0] = leaves
    const levels: Uint8Array[][] = [leaves];

    // keep constructing until only the root remains
    // local helper: safely get the last level (noUncheckedIndexedAccess-friendly)
    function lastLevel(): Uint8Array[] {
        const last = levels[levels.length - 1];
        /* v8 ignore next 6 -- levels is always non-empty (the constructor initializes leaves); defense-in-depth*/
        if (last === undefined) {
            throw new MultisigError(
                'MULTISIG_MERKLE_ROOT_INVALID',
                'buildMerkleTree: levels abnormal (unreachable; defense-in-depth)',
            );
        }
        return last;
    }

    while (lastLevel().length > 1) {
        const current = lastLevel();
        const next: Uint8Array[] = [];
        for (let i = 0; i < current.length; i += 2) {
            const left = current[i];
            const right = i + 1 < current.length ? current[i + 1] : undefined;
            /* v8 ignore next 6 -- for loop bound guarantees left is not undefined; defense-in-depth*/
            if (left === undefined) {
                throw new MultisigError(
                    'MULTISIG_MERKLE_ROOT_INVALID',
                    `buildMerkleTree: current[${i}] undefined (unreachable; defense-in-depth)`,
                );
            }
            if (right === undefined) {
                // odd node count; the last one is promoted to the next layer (RFC 6962 unbalanced; no duplication)
                next.push(left);
            } else {
                // pairwise SHA-256(left || right)
                const combined = new Uint8Array(64);
                combined.set(left, 0);
                combined.set(right, 32);
                next.push(sha256(combined));
            }
        }
        levels.push(next);
    }

    const rootLevel = lastLevel();
    const root = rootLevel[0];
    /* v8 ignore next 6 -- while loop exit condition lastLevel().length === 1; root is necessarily not undefined*/
    if (root === undefined) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            'buildMerkleTree: root undefined (unreachable; defense-in-depth)',
        );
    }

    // compute the audit path for each leaf
    const paths: Uint8Array[] = leaves.map((_leaf, leafIdx) => {
        const pathSegments: { sibling: Uint8Array; direction: number }[] = [];
        let currentIdx = leafIdx;
        // traverse from levels[0] (leaves) to levels[length-2] (the layer below the root)
        for (let level = 0; level < levels.length - 1; level += 1) {
            const currentLevel = levels[level];
            /* v8 ignore next 6 -- level is within the levels range; currentLevel is necessarily not undefined*/
            if (currentLevel === undefined) {
                throw new MultisigError(
                    'MULTISIG_MERKLE_ROOT_INVALID',
                    `buildMerkleTree: levels[${level}] undefined (unreachable; defense-in-depth)`,
                );
            }
            const isRightChild = currentIdx % 2 === 1;
            const siblingIdx = isRightChild ? currentIdx - 1 : currentIdx + 1;
            if (siblingIdx < currentLevel.length && siblingIdx >= 0) {
                const sibling = currentLevel[siblingIdx];
                /* v8 ignore next 6 -- siblingIdx < length guard; sibling is necessarily not undefined*/
                if (sibling === undefined) {
                    throw new MultisigError(
                        'MULTISIG_MERKLE_ROOT_INVALID',
                        `buildMerkleTree: currentLevel[${siblingIdx}] undefined (unreachable)`,
                    );
                }
                // sibling exists
                pathSegments.push({
                    sibling,
                    // direction: 0 = sibling on the left, current on the right; 1 = sibling on the right
                    direction: isRightChild ? 0 : 1,
                });
            }
            // otherwise: the last of an odd node count (promoted to the next layer; no sibling)
            currentIdx = Math.floor(currentIdx / 2);
        }
        // encode audit path bytes: [sibling_hash_0 (32B) || direction_0 (1B) || ...]
        const pathBytes = new Uint8Array(pathSegments.length * 33);
        for (let i = 0; i < pathSegments.length; i += 1) {
            const segment = pathSegments[i];
            /* v8 ignore next 6 -- for loop bound; segment is necessarily not undefined*/
            if (segment === undefined) {
                throw new MultisigError(
                    'MULTISIG_MERKLE_ROOT_INVALID',
                    `buildMerkleTree: pathSegments[${i}] undefined (unreachable)`,
                );
            }
            pathBytes.set(segment.sibling, i * 33);
            pathBytes[i * 33 + 32] = segment.direction;
        }
        return pathBytes;
    });

    return { root, paths };
}

/**
 * encodeMerklePath — encode audit path bytes to base64url (for MultisigToken.inclusionProofs[i].path)
 */
export function encodeMerklePath(pathBytes: Uint8Array): string {
    return toBase64Url(pathBytes);
}

/**
 * verifyMerkleInclusion — verify a single leaf's inclusion proof under the Merkle root (RFC 6962 audit path)
 *
 *  Signature:
 *   input: leaf_i, path_i, expected_root
 *   output: bool (recomputed root === expected_root)
 *
 * Algorithm:
 *   1. decode path_i (base64url → byte array)
 *   2. byte array = [sibling_hash_0 || direction_0 || sibling_hash_1 || direction_1 || ...]
 *      sibling_hash length = 32 (SHA-256 byte length)
 *      direction = 1 byte (0 = sibling on the left, current on the right; 1 = sibling on the right)
 *   3. current_hash = leaf_i
 *   4. for each (sibling_hash_k, direction_k) in path:
 *        if direction_k == 0: current_hash = SHA-256(sibling_hash_k || current_hash)
 *        else: current_hash = SHA-256(current_hash || sibling_hash_k)
 *   5. return current_hash === expected_root
 *
 * Anti-phantom defenses:
 *   - leaf / expected_root must be 32-byte Uint8Array; direction must be 0 or 1; otherwise throw
 *   - path length must be a multiple of 33 (32-byte sibling + 1-byte direction); otherwise throw
 *   - an empty path returns true only when leaf === expected_root (single-leaf scenario)
 *   - no silent return false allowed — exception paths must throw + MULTISIG_MERKLE_PATH_INVALID
 *
 * @param leaf the leaf hash to verify (32-byte Uint8Array; usually from generateMerkleLeaf)
 * @param pathBytes the audit path byte array (decoded; converted by fromBase64Url)
 * @param expectedRoot the expected Merkle root (32-byte Uint8Array; usually from MultisigToken.merkleRoot)
 * @returns boolean — true: leaf is under expectedRoot; false: it is not
 * @throws MultisigError(MULTISIG_MERKLE_PATH_INVALID) — abnormal path format (length not a multiple of 33 / abnormal leaf length)
 * @throws MultisigError(MULTISIG_MERKLE_ROOT_INVALID) — abnormal expectedRoot length (not 32-byte)
 */
export function verifyMerkleInclusion(
    leaf: Uint8Array,
    pathBytes: Uint8Array,
    expectedRoot: Uint8Array,
): boolean {
    if (!(leaf instanceof Uint8Array) || leaf.length !== 32) {
        throw new MultisigError(
            'MULTISIG_MERKLE_PATH_INVALID',
            `verifyMerkleInclusion: leaf must be 32-byte Uint8Array (got ${leaf instanceof Uint8Array ? `length ${leaf.length}` : typeof leaf})`,
        );
    }
    /* v8 ignore next 6 -- TS narrows pathBytes to Uint8Array; defense-in-depth*/
    if (!(pathBytes instanceof Uint8Array)) {
        throw new MultisigError(
            'MULTISIG_MERKLE_PATH_INVALID',
            `verifyMerkleInclusion: pathBytes must be Uint8Array (got ${typeof pathBytes})`,
        );
    }
    if (!(expectedRoot instanceof Uint8Array) || expectedRoot.length !== 32) {
        throw new MultisigError(
            'MULTISIG_MERKLE_ROOT_INVALID',
            `verifyMerkleInclusion: expectedRoot must be 32-byte Uint8Array (got ${expectedRoot instanceof Uint8Array ? `length ${expectedRoot.length}` : typeof expectedRoot})`,
        );
    }
    if (pathBytes.length % 33 !== 0) {
        throw new MultisigError(
            'MULTISIG_MERKLE_PATH_INVALID',
            `verifyMerkleInclusion: pathBytes length ${pathBytes.length} not multiple of 33 (each segment = 32-byte sibling + 1-byte direction; RFC 6962 audit path encoding)`,
        );
    }

    // empty path: single-leaf scenario (root === leaf)
    if (pathBytes.length === 0) {
        return constantTimeEquals(leaf, expectedRoot);
    }

    let currentHash = leaf;
    const segmentCount = pathBytes.length / 33;
    for (let i = 0; i < segmentCount; i += 1) {
        const siblingStart = i * 33;
        const siblingHash = pathBytes.subarray(siblingStart, siblingStart + 32);
        const direction = pathBytes[siblingStart + 32];

        if (direction !== 0 && direction !== 1) {
            throw new MultisigError(
                'MULTISIG_MERKLE_PATH_INVALID',
                `verifyMerkleInclusion: invalid direction byte ${direction} at segment ${i} (must be 0 or 1)`,
            );
        }

        const combined = new Uint8Array(64);
        if (direction === 0) {
            // sibling on the left, current on the right → SHA-256(sibling || current)
            combined.set(siblingHash, 0);
            combined.set(currentHash, 32);
        } else {
            // sibling on the right, current on the left → SHA-256(current || sibling)
            combined.set(currentHash, 0);
            combined.set(siblingHash, 32);
        }

        try {
            currentHash = sha256(combined);
        } catch (error) {
            /* v8 ignore next 5 -- @noble/hashes sha256 contract; defense-in-depth*/
            throw new MultisigError(
                'MULTISIG_MERKLE_ROOT_INVALID',
                `verifyMerkleInclusion: SHA-256 threw at segment ${i} (combined bytes corrupted)`,
                error instanceof Error ? error : undefined,
            );
        }
    }

    return constantTimeEquals(currentHash, expectedRoot);
}

/**
 * decodeMerklePath — base64url → Uint8Array (for the verifier side to decode inclusionProofs[i].path)
 *
 * @throws MultisigError(MULTISIG_MERKLE_PATH_INVALID) — base64url decode failed
 */
export function decodeMerklePath(pathStr: string): Uint8Array {
    if (typeof pathStr !== 'string') {
        throw new MultisigError(
            'MULTISIG_MERKLE_PATH_INVALID',
            `decodeMerklePath: pathStr must be string, got ${typeof pathStr}`,
        );
    }
    try {
        return fromBase64Url(pathStr);
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_MERKLE_PATH_INVALID',
            `decodeMerklePath: base64url decode failed for "${pathStr.substring(0, 32)}..."`,
            error instanceof Error ? error : undefined,
        );
    }
}

/**
 * constantTimeEquals — 32-byte constant-time comparison (timing-attack defense)
 *
 * Defends against the timing side channel: no short-circuit early return allowed;
 * XOR-accumulate over all bytes, then check accumulator === 0 at the end.
 *
 * Note: this function is only for hash comparison (32-byte SHA-256 digest);
 * not suitable for variable-length string comparison (length leakage still exists).
 */
function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    /* v8 ignore next 3 -- internal usage: a is always 32-byte (current_hash), b is 32-byte (expectedRoot);
       length inequality never triggers; defense-in-depth
*/
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) {
        // noUncheckedIndexedAccess: a[i] / b[i] are typed number | undefined;
        // the for loop bound guarantees they are not undefined; the || 0 is a narrowing fallback
        diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
    }
    return diff === 0;
}
