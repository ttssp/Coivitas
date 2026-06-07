/**
 * merkle-tree.test.ts — Multisig L1 crypto Merkle inclusion sub-flow unit tests
 *
 * Implements: ms v0.1 L1 crypto
 *
 * Coverage targets:
 *   - generateMerkleLeaf: SHA-256(JCS({id, role, signature})) determinism + field-order independence
 *   - buildMerkleTree: 1/2/3/4/5/odd-leaf scenarios + root + audit path generation
 *   - verifyMerkleInclusion: happy + leaf not in tree + path anomaly + root anomaly
 *   - decodeMerklePath: base64url decode + anomaly paths
 */

import { describe, expect, it } from 'vitest';

import { fromHex } from '../../encoding.js';
import {
    buildMerkleTree,
    decodeMerklePath,
    encodeMerklePath,
    generateMerkleLeaf,
    generateMerkleLeafHex,
    MultisigError,
    type MultisigErrorCode,
    verifyMerkleInclusion,
} from '../../multisig/index.js';

/**
 * expectMultisigCode — helper: runs fn, expecting it to throw MultisigError with a matching code
 *
 * Usage pattern (replaces .toThrow(/MULTISIG_X/) — error.message has no code prefix):
 *   expectMultisigCode(() => fn(args), 'MULTISIG_X');
 */
function expectMultisigCode(
    fn: () => unknown,
    expectedCode: MultisigErrorCode,
): MultisigError {
    try {
        fn();
        throw new Error(`expected MultisigError(${expectedCode}) but no throw`);
    } catch (e) {
        if (!(e instanceof MultisigError)) {
            throw new Error(
                `expected MultisigError(${expectedCode}) but got ${(e as Error).constructor?.name}: ${(e as Error).message}`,
            );
        }
        expect(e.code).toBe(expectedCode);
        return e;
    }
}

// ─── generateMerkleLeaf — leaf encoding determinism + JCS properties ──────────────────

describe('generateMerkleLeaf — determinism + JCS canonicality', () => {
    const baseInput = {
        id: 'did:key:signer-001',
        role: 'human' as const,
        signature: 'abc123',
    };

    it('should produce identical leaf for same input', () => {
        const leaf1 = generateMerkleLeaf(baseInput);
        const leaf2 = generateMerkleLeaf(baseInput);
        expect(leaf1).toEqual(leaf2);
    });

    it('should produce 32-byte Uint8Array (SHA-256 digest size)', () => {
        const leaf = generateMerkleLeaf(baseInput);
        expect(leaf).toBeInstanceOf(Uint8Array);
        expect(leaf.length).toBe(32);
    });

    it('should produce identical leaf regardless of input key order (JCS canonical)', () => {
        const leafAlpha = generateMerkleLeaf({
            id: baseInput.id,
            role: baseInput.role,
            signature: baseInput.signature,
        });
        // Field order changed (JCS canonicalize enforces alphabetical sort by key)
        const leafReordered = generateMerkleLeaf({
            signature: baseInput.signature,
            role: baseInput.role,
            id: baseInput.id,
        });
        expect(leafAlpha).toEqual(leafReordered);
    });

    it('should produce different leaf when id changes', () => {
        const leaf1 = generateMerkleLeaf(baseInput);
        const leaf2 = generateMerkleLeaf({ ...baseInput, id: 'did:key:signer-002' });
        expect(leaf1).not.toEqual(leaf2);
    });

    it('should produce different leaf when role changes (guards against post-issuance role tampering)', () => {
        const leaf1 = generateMerkleLeaf(baseInput);
        const leaf2 = generateMerkleLeaf({ ...baseInput, role: 'agent' });
        expect(leaf1).not.toEqual(leaf2);
    });

    it('should produce different leaf when signature changes', () => {
        const leaf1 = generateMerkleLeaf(baseInput);
        const leaf2 = generateMerkleLeaf({ ...baseInput, signature: 'xyz789' });
        expect(leaf1).not.toEqual(leaf2);
    });

    it('should throw MultisigError for null input', () => {
        try {
            generateMerkleLeaf(null as unknown as typeof baseInput);
            throw new Error('expected throw');
        } catch (e) {
            expect(e).toBeInstanceOf(MultisigError);
            expect((e as MultisigError).code).toBe('MULTISIG_SCHEMA_VIOLATION');
        }
    });

    it('should throw MULTISIG_SCHEMA_VIOLATION for empty id', () => {
        try {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            generateMerkleLeaf({ id: '', role: 'human', signature: 's' } as any);
            throw new Error('expected throw');
        } catch (e) {
            expect((e as MultisigError).code).toBe('MULTISIG_SCHEMA_VIOLATION');
            expect((e as MultisigError).message).toContain('id');
        }
    });

    it('should throw MULTISIG_SCHEMA_VIOLATION for invalid role', () => {
        expect(() =>
            generateMerkleLeaf({
                id: 'did:key:s',
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                role: 'admin' as any,
                signature: 's',
            }),
        ).toThrow(/MULTISIG_SCHEMA_VIOLATION.*role/);
    });

    it('should throw MULTISIG_SCHEMA_VIOLATION for empty signature', () => {
        expect(() =>
            generateMerkleLeaf({
                id: 'did:key:s',
                role: 'human',
                signature: '',
            }),
        ).toThrow(/MULTISIG_SCHEMA_VIOLATION.*signature/);
    });

    it('generateMerkleLeafHex should return 64-char hex of same leaf', () => {
        const bytes = generateMerkleLeaf(baseInput);
        const hex = generateMerkleLeafHex(baseInput);
        expect(hex).toMatch(/^[0-9a-f]{64}$/);
        // The hex decodes back to the same bytes
        const decoded = fromHex(hex);
        expect(decoded).toEqual(bytes);
    });
});

// ─── buildMerkleTree — multi-leaf scenarios ─────────────────────────────────────────

describe('buildMerkleTree — multi-leaf scenarios', () => {
    function makeLeaves(n: number): Uint8Array[] {
        return Array.from({ length: n }, (_v, i) =>
            generateMerkleLeaf({
                id: `did:key:signer-${i}`,
                role: 'human',
                signature: `sig-${i}`,
            }),
        );
    }

    it('should throw MULTISIG_MERKLE_ROOT_INVALID for empty leaves', () => {
        expect(() => buildMerkleTree([])).toThrow(/MULTISIG_MERKLE_ROOT_INVALID/);
    });

    it('should throw for non-Uint8Array leaf', () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect(() => buildMerkleTree(['bad-leaf' as any])).toThrow(
            /MULTISIG_MERKLE_ROOT_INVALID/,
        );
    });

    it('should throw for leaf with wrong byte length', () => {
        expect(() => buildMerkleTree([new Uint8Array(16)])).toThrow(
            /MULTISIG_MERKLE_ROOT_INVALID/,
        );
    });

    it('should handle 1 leaf — root === leaf, empty path', () => {
        const leaves = makeLeaves(1);
        const { root, paths } = buildMerkleTree(leaves);
        expect(root).toEqual(leaves[0]);
        expect(paths).toHaveLength(1);
        expect(paths[0]?.length).toBe(0);
    });

    it('should handle 2 leaves — root has 1 sibling per leaf', () => {
        const leaves = makeLeaves(2);
        const { root, paths } = buildMerkleTree(leaves);
        expect(root.length).toBe(32);
        expect(paths).toHaveLength(2);
        // Each path should be exactly 33 bytes (1 sibling + 1 direction byte)
        expect(paths[0]?.length).toBe(33);
        expect(paths[1]?.length).toBe(33);
    });

    it('should handle 3 leaves (odd) — RFC 6962 unbalanced promotion', () => {
        const leaves = makeLeaves(3);
        const { root, paths } = buildMerkleTree(leaves);
        expect(root.length).toBe(32);
        expect(paths).toHaveLength(3);
    });

    it('should handle 4 leaves (balanced) — full binary tree', () => {
        const leaves = makeLeaves(4);
        const { root, paths } = buildMerkleTree(leaves);
        expect(root.length).toBe(32);
        expect(paths).toHaveLength(4);
        // 4 leaves, depth = 2 (sibling count = 2 per leaf; path = 66 bytes expected)
        expect(paths[0]?.length).toBe(66);
    });

    it('should handle 8 leaves (balanced;3-level tree)', () => {
        const leaves = makeLeaves(8);
        const { root, paths } = buildMerkleTree(leaves);
        expect(root.length).toBe(32);
        expect(paths).toHaveLength(8);
        // 8 leaves, depth = 3 (sibling count = 3 per leaf)
        expect(paths[0]?.length).toBe(99); // 3 * 33
    });

    it('should produce deterministic root for same input', () => {
        const leaves = makeLeaves(5);
        const { root: r1 } = buildMerkleTree(leaves);
        const { root: r2 } = buildMerkleTree(leaves);
        expect(r1).toEqual(r2);
    });

    it('should produce different root when leaf changes', () => {
        const leaves = makeLeaves(4);
        const { root: r1 } = buildMerkleTree(leaves);
        const modifiedLeaves = [...leaves];
        modifiedLeaves[0] = generateMerkleLeaf({
            id: 'did:key:signer-tampered',
            role: 'human',
            signature: 'sig-x',
        });
        const { root: r2 } = buildMerkleTree(modifiedLeaves);
        expect(r1).not.toEqual(r2);
    });
});

// ─── verifyMerkleInclusion — happy + fail-closed paths ────────────────────

describe('verifyMerkleInclusion — happy path + fail-closed', () => {
    function makeLeaves(n: number): Uint8Array[] {
        return Array.from({ length: n }, (_v, i) =>
            generateMerkleLeaf({
                id: `did:key:signer-${i}`,
                role: 'human',
                signature: `sig-${i}`,
            }),
        );
    }

    it('should verify all leaves in a 2-leaf tree (happy)', () => {
        const leaves = makeLeaves(2);
        const { root, paths } = buildMerkleTree(leaves);
        for (let i = 0; i < leaves.length; i += 1) {
            const valid = verifyMerkleInclusion(leaves[i]!, paths[i]!, root);
            expect(valid).toBe(true);
        }
    });

    it('should verify all leaves in a 3-leaf tree (odd; unbalanced)', () => {
        const leaves = makeLeaves(3);
        const { root, paths } = buildMerkleTree(leaves);
        for (let i = 0; i < leaves.length; i += 1) {
            const valid = verifyMerkleInclusion(leaves[i]!, paths[i]!, root);
            expect(valid).toBe(true);
        }
    });

    it('should verify all leaves in a 4-leaf tree (balanced)', () => {
        const leaves = makeLeaves(4);
        const { root, paths } = buildMerkleTree(leaves);
        for (let i = 0; i < leaves.length; i += 1) {
            const valid = verifyMerkleInclusion(leaves[i]!, paths[i]!, root);
            expect(valid).toBe(true);
        }
    });

    it('should verify all leaves in an 8-leaf tree', () => {
        const leaves = makeLeaves(8);
        const { root, paths } = buildMerkleTree(leaves);
        for (let i = 0; i < leaves.length; i += 1) {
            const valid = verifyMerkleInclusion(leaves[i]!, paths[i]!, root);
            expect(valid).toBe(true);
        }
    });

    it('should reject leaf not in tree (different leaf;same path)', () => {
        const leaves = makeLeaves(4);
        const { root, paths } = buildMerkleTree(leaves);
        const fakeLeaf = generateMerkleLeaf({
            id: 'did:key:not-in-tree',
            role: 'human',
            signature: 'fake-sig',
        });
        // Use leaves[0]'s path + fakeLeaf → recompute does not equal root
        const valid = verifyMerkleInclusion(fakeLeaf, paths[0]!, root);
        expect(valid).toBe(false);
    });

    it('should reject wrong path for valid leaf', () => {
        const leaves = makeLeaves(4);
        const { root, paths } = buildMerkleTree(leaves);
        // Use leaves[0] + path[1] (mismatched)
        const valid = verifyMerkleInclusion(leaves[0]!, paths[1]!, root);
        expect(valid).toBe(false);
    });

    it('should reject when root is tampered', () => {
        const leaves = makeLeaves(4);
        const { root, paths } = buildMerkleTree(leaves);
        const tamperedRoot = new Uint8Array(root);
        tamperedRoot[0] = (tamperedRoot[0] ?? 0) ^ 0xff;
        const valid = verifyMerkleInclusion(leaves[0]!, paths[0]!, tamperedRoot);
        expect(valid).toBe(false);
    });

    it('should handle single leaf (empty path) — root === leaf', () => {
        const leaves = makeLeaves(1);
        const valid = verifyMerkleInclusion(leaves[0]!, new Uint8Array(0), leaves[0]!);
        expect(valid).toBe(true);
    });

    it('should reject single leaf with wrong expected root (empty path)', () => {
        const leaves = makeLeaves(1);
        const wrongRoot = new Uint8Array(32).fill(0xff);
        const valid = verifyMerkleInclusion(leaves[0]!, new Uint8Array(0), wrongRoot);
        expect(valid).toBe(false);
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for non-Uint8Array leaf', () => {
        expect(() =>
            verifyMerkleInclusion(
                'bad' as unknown as Uint8Array,
                new Uint8Array(33),
                new Uint8Array(32),
            ),
        ).toThrow(/MULTISIG_MERKLE_PATH_INVALID/);
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for leaf with wrong length', () => {
        expect(() =>
            verifyMerkleInclusion(
                new Uint8Array(16),
                new Uint8Array(33),
                new Uint8Array(32),
            ),
        ).toThrow(/MULTISIG_MERKLE_PATH_INVALID/);
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for path length not multiple of 33', () => {
        expect(() =>
            verifyMerkleInclusion(
                new Uint8Array(32),
                new Uint8Array(35),
                new Uint8Array(32),
            ),
        ).toThrow(/MULTISIG_MERKLE_PATH_INVALID.*multiple of 33/);
    });

    it('should throw MULTISIG_MERKLE_ROOT_INVALID for root wrong length', () => {
        expect(() =>
            verifyMerkleInclusion(
                new Uint8Array(32),
                new Uint8Array(33),
                new Uint8Array(16),
            ),
        ).toThrow(/MULTISIG_MERKLE_ROOT_INVALID/);
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for invalid direction byte (not 0 or 1)', () => {
        const path = new Uint8Array(33);
        path[32] = 5; // the direction byte must be 0 or 1
        expect(() =>
            verifyMerkleInclusion(new Uint8Array(32), path, new Uint8Array(32)),
        ).toThrow(/MULTISIG_MERKLE_PATH_INVALID.*direction/);
    });
});

// ─── encodeMerklePath / decodeMerklePath — roundtrip + anomalies ───────────────

describe('encodeMerklePath / decodeMerklePath — roundtrip', () => {
    it('should roundtrip arbitrary bytes through base64url', () => {
        const original = new Uint8Array([1, 2, 3, 4, 5, 0xff, 0x00]);
        const encoded = encodeMerklePath(original);
        const decoded = decodeMerklePath(encoded);
        expect(decoded).toEqual(original);
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for non-string input', () => {
        expect(() => decodeMerklePath(null as unknown as string)).toThrow(
            /MULTISIG_MERKLE_PATH_INVALID/,
        );
    });

    it('should throw MULTISIG_MERKLE_PATH_INVALID for invalid base64url', () => {
        expect(() => decodeMerklePath('!@#$%^&*')).toThrow(
            /MULTISIG_MERKLE_PATH_INVALID/,
        );
    });
});
