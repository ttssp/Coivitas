import { canonicalize } from './canonicalization.js';
import { detectEncoding, fromBase64Url, fromHex, toHex } from './encoding.js';
import { hash } from './hashing.js';
import { CryptoError, type HashChainVerifyResult, type MerkleProof, type MerkleProofNode } from './types.js';

const textEncoder = new TextEncoder();

// Normalize prevHash to a hex string (or null).
// Accepts both hex (the wire-format default) and base64url (the legacy-chain compatibility path).
function normalizePrevHash(record: Record<string, unknown>): string | null {
    const prevHash = record.prevHash;

    if (prevHash === null || prevHash === undefined) {
        return null;
    }

    if (typeof prevHash !== 'string') {
        throw new CryptoError(
            'HASH_CHAIN_BROKEN',
            'prevHash must be a string or null.',
        );
    }

    if (prevHash.length === 0) {
        throw new CryptoError(
            'INVALID_HASH_FORMAT',
            'prevHash must not be an empty string; use null for the genesis record.',
        );
    }

    const encoding = detectEncoding(prevHash);

    if (encoding === 'base64url') {
        // base64url compatibility path: decode to bytes then convert to hex, unifying to wire-format
        const bytes = fromBase64Url(prevHash);
        if (bytes.length !== 32) {
            throw new CryptoError(
                'INVALID_HASH_FORMAT',
                'prevHash base64url must decode to 32 bytes.',
            );
        }
        return toHex(bytes);
    }

    // hex path (default)
    const bytes = fromHex(prevHash);
    if (bytes.length !== 32) {
        throw new CryptoError(
            'INVALID_HASH_FORMAT',
            'prevHash must decode to 32 bytes.',
        );
    }

    return prevHash.toLowerCase();
}

// For append() use only: strictly requires hex or null (wire-format compliant)
function getPrevHashStrict(record: Record<string, unknown>): string | null {
    const prevHash = record.prevHash;

    if (prevHash === null || prevHash === undefined) {
        return null;
    }

    if (typeof prevHash !== 'string') {
        throw new CryptoError(
            'HASH_CHAIN_BROKEN',
            'prevHash must be a string or null.',
        );
    }

    if (prevHash.length === 0) {
        throw new CryptoError(
            'INVALID_HASH_FORMAT',
            'prevHash must not be an empty string; use null for the genesis record.',
        );
    }
    const bytes = fromHex(prevHash);
    if (bytes.length !== 32) {
        throw new CryptoError(
            'INVALID_HASH_FORMAT',
            'prevHash must decode to 32 bytes.',
        );
    }
    return prevHash;
}

function computeRecordHash(record: Record<string, unknown>): string {
    const prevHash = getPrevHashStrict(record) ?? '';
    const payload = textEncoder.encode(canonicalize(record));
    const previousBytes = textEncoder.encode(prevHash);
    const input = new Uint8Array(previousBytes.length + payload.length);

    input.set(previousBytes, 0);
    input.set(payload, previousBytes.length);

    return hash(input);
}

export class HashChain {
    public readonly headHash: string | null;
    public readonly length: number;

    public constructor(headHash: string | null = null, length = 0) {
        this.headHash = headHash;
        this.length = length;
    }

    public append(record: Record<string, unknown>): string {
        const prevHash = getPrevHashStrict(record);
        const expectedPrevHash = this.headHash;

        if (prevHash !== expectedPrevHash) {
            throw new CryptoError(
                'HASH_CHAIN_BROKEN',
                'Record prevHash does not match the current chain head.',
            );
        }

        const nextHash = computeRecordHash(record);
        Object.defineProperty(this, 'headHash', {
            value: nextHash,
            enumerable: true,
        });
        Object.defineProperty(this, 'length', {
            value: this.length + 1,
            enumerable: true,
        });

        return nextHash;
    }

    public verify(records: Record<string, unknown>[]): HashChainVerifyResult {
        let expectedPrevHash: string | null = null;

        for (const [index, record] of records.entries()) {
            // 03a: support legacy-chain records with base64url prevHash, normalizing uniformly to hex for comparison
            const actualPrevHash = normalizePrevHash(record);

            if (actualPrevHash !== expectedPrevHash) {
                return {
                    valid: false,
                    chainLength: index,
                    brokenAtIndex: index,
                    expectedHash: expectedPrevHash,
                    actualHash: actualPrevHash,
                };
            }

            // computeRecordHash depends on getPrevHashStrict, which needs a hex version of the record
            const normalizedRecord = actualPrevHash === null
                ? { ...record, prevHash: null }
                : { ...record, prevHash: actualPrevHash };

            expectedPrevHash = computeRecordHash(normalizedRecord);
        }

        return { valid: true, chainLength: records.length };
    }

    /**
     * @experimental Preparatory capability for a future root-anchor contract. Generates a Merkle proof for local verification.
     * Not exported from the @coivitas/crypto package entry point.
     * The current protocol does not define a root-anchor contract; the root field is a locally computed result with no external commitment.
     *
     * Node-merge convention: hash(hexLeft + hexRight) computes SHA-256 over the hex string text, not over the raw bytes.
     * This is a deliberate internal convention, incompatible with standard Bitcoin Merkle (raw bytes).
     * When the root-anchor contract is introduced, an explicit decision is needed on whether to migrate to raw-bytes merging.
     *
     * @param recordIndex the target record's index in the records array
     * @param records the complete record set (must match the one used at append() time)
     */
    public generateProof(recordIndex: number, records: Record<string, unknown>[]): MerkleProof {
        if (records.length === 0 || recordIndex < 0 || recordIndex >= records.length) {
            throw new CryptoError(
                'INVALID_HASH_FORMAT',
                `recordIndex ${recordIndex} out of bounds for records length ${records.length}.`,
            );
        }

        // Compute all leaf-node hashes (using the normalized record, consistent with normalizedRecord in verify())
        const leaves = records.map((record) => {
            const normalizedPrevHash = normalizePrevHash(record);
            const normalizedRecord = normalizedPrevHash === null
                ? { ...record, prevHash: null }
                : { ...record, prevHash: normalizedPrevHash };
            return computeRecordHash(normalizedRecord);
        });

        const recordHash = leaves[recordIndex]!;

        // If there is only 1 leaf node, root = leaf, no siblings
        if (leaves.length === 1) {
            return { recordIndex, recordHash, siblings: [], root: recordHash };
        }

        // Build the Merkle tree level by level, collecting siblings along the way
        const siblings: MerkleProofNode[] = [];
        let currentLayer = [...leaves];
        let targetIndex = recordIndex;

        while (currentLayer.length > 1) {
            // On an odd node count, duplicate the last node (standard padding)
            if (currentLayer.length % 2 !== 0) {
                currentLayer.push(currentLayer[currentLayer.length - 1]!);
            }

            const nextLayer: string[] = [];
            const pairIndex = targetIndex % 2 === 0 ? targetIndex : targetIndex - 1;

            for (let i = 0; i < currentLayer.length; i += 2) {
                const left = currentLayer[i]!;
                const right = currentLayer[i + 1]!;
                nextLayer.push(hash(left + right));

                // If the current node pair is the one containing the target node, record the sibling
                if (i === pairIndex) {
                    if (targetIndex % 2 === 0) {
                        siblings.push({ hash: right, position: 'right' });
                    } else {
                        siblings.push({ hash: left, position: 'left' });
                    }
                }
            }

            targetIndex = Math.floor(targetIndex / 2);
            currentLayer = nextLayer;
        }

        return {
            recordIndex,
            recordHash,
            siblings,
            root: currentLayer[0]!,
        };
    }
}
