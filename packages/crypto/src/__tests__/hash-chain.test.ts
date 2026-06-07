import { describe, expect, it } from 'vitest';

import { HashChain, fromHex, toBase64Url } from '../index.js';
import { hash } from '../hashing.js';
import type { MerkleProof } from '../types.js';

// Recompute the Merkle root upward from the leaf hash and the siblings path.
// Convention: hash(left + right) runs SHA-256 over the hex string text (consistent with generateProof() internals).
function recomputeRoot(proof: MerkleProof): string {
    let current = proof.recordHash;
    for (const sibling of proof.siblings) {
        if (sibling.position === 'left') {
            current = hash(sibling.hash + current);
        } else {
            current = hash(current + sibling.hash);
        }
    }
    return current;
}

function createRecord(id: number, prevHash: string | null) {
    return {
        id: `record-${id}`,
        action: `ACTION_${id}`,
        timestamp: `2026-04-02T00:00:0${id}Z`,
        prevHash,
    };
}

describe('HashChain', () => {
    it('treats an empty chain as valid', () => {
        const chain = new HashChain();

        expect(chain.verify([])).toEqual({ valid: true, chainLength: 0 });
    });

    it('appends and verifies ten records', () => {
        const chain = new HashChain();
        const records: Array<ReturnType<typeof createRecord>> = [];
        let prevHash: string | null = null;

        for (let index = 0; index < 10; index += 1) {
            const record = createRecord(index, prevHash);
            prevHash = chain.append(record);
            records.push(record);
        }

        expect(chain.length).toBe(10);
        expect(chain.headHash).toBe(prevHash);
        expect(chain.verify(records)).toEqual({ valid: true, chainLength: 10 });
    });

    it('reports the exact broken index when a record is tampered', () => {
        const chain = new HashChain();
        const records: Array<ReturnType<typeof createRecord>> = [];
        let prevHash: string | null = null;

        for (let index = 0; index < 5; index += 1) {
            const record = createRecord(index, prevHash);
            prevHash = chain.append(record);
            records.push(record);
        }

        const targetRecord = records[3]!;
        records[3] = {
            ...targetRecord,
            prevHash: targetRecord.prevHash,
            action: 'ACTION_TAMPERED',
        };

        const result = chain.verify(records);

        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(4);
    });
});

describe('HashChain error-boundary coverage', () => {
    it('should throw when append() prevHash does not match chain head', () => {
        const chain = new HashChain();
        // Append one record first so the chain head becomes non-null
        const firstRec = { id: 'r-0', action: 'A', prevHash: null };
        chain.append(firstRec);
        // Attempt to append with a wrong prevHash
        const fakeHash = 'a'.repeat(64);
        expect(() =>
            chain.append({ id: 'r-1', action: 'B', prevHash: fakeHash }),
        ).toThrow();
    });

    it('should throw when verify() receives a record with non-string prevHash', () => {
        const chain = new HashChain();
        expect(() =>
            chain.verify([{ id: 'r-0', action: 'A', prevHash: 12345 }]),
        ).toThrow();
    });

    it('should throw when verify() receives a hex prevHash that decodes to wrong byte length', () => {
        const chain = new HashChain();
        // Valid hex but only 4 bytes (8 hexadecimal characters)
        expect(() =>
            chain.verify([{ id: 'r-0', action: 'A', prevHash: 'deadbeef' }]),
        ).toThrow();
    });

    it('should throw when verify() receives a base64url prevHash that decodes to wrong byte length', () => {
        const chain = new HashChain();
        // Valid base64url but fewer than 43 characters (not a 32-byte SHA-256)
        // 'Zm9v' decodes to the 4 bytes 'foo'; detectEncoding classifies it as base64url
        // Note: 'Zm9v' is length 4, even; hex detection: z/v are not in [0-9a-f], so it falls into base64url
        expect(() =>
            chain.verify([{ id: 'r-0', action: 'A', prevHash: 'Zm9v' }]),
        ).toThrow();
    });

    it('should throw when append() receives a non-string prevHash', () => {
        const chain = new HashChain();
        expect(() =>
            chain.append({ id: 'r-0', action: 'A', prevHash: 42 }),
        ).toThrow();
    });

    it('should throw when append() receives a hex prevHash that decodes to wrong byte length', () => {
        const chain = new HashChain();
        // Valid hex but only 4 bytes (8 hexadecimal characters)
        expect(() =>
            chain.append({ id: 'r-0', action: 'A', prevHash: 'deadbeef' }),
        ).toThrow();
    });

    it('should throw when append() receives an empty string prevHash', () => {
        const chain = new HashChain();
        // An empty string in getPrevHashStrict() should throw immediately (symmetric with normalizePrevHash)
        expect(() =>
            chain.append({ id: 'r-0', action: 'A', prevHash: '' }),
        ).toThrow('prevHash must not be an empty string');
    });

    it('should throw when verify() receives an empty string prevHash', () => {
        const chain = new HashChain();
        // wire-format contract: prevHash must be a valid 64-character hex or null; an empty string is invalid
        const rec = { id: 'r-0', action: 'A', prevHash: '' };
        expect(() => chain.verify([rec])).toThrow(
            'prevHash must not be an empty string',
        );
    });
});

describe('HashChain.verify() base64url prevHash compatibility', () => {
    it('should verify a chain where prevHash fields are base64url encoded', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 5; i++) {
            const rec = {
                id: `r-${i}`,
                action: 'A',
                timestamp: `T${i}`,
                prevHash,
            };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        // Convert all prevHash fields from hex to base64url
        const b64Records = records.map((r) => ({
            ...r,
            prevHash:
                r.prevHash === null
                    ? null
                    : toBase64Url(fromHex(r.prevHash as string)),
        }));

        const result = chain.verify(b64Records);
        expect(result.valid).toBe(true);
        expect(result.chainLength).toBe(5);
    });

    it('should detect broken chain in base64url prevHash records', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 4; i++) {
            const rec = {
                id: `r-${i}`,
                action: 'A',
                timestamp: `T${i}`,
                prevHash,
            };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        const b64Records: Record<string, unknown>[] = records.map((r) => ({
            ...r,
            prevHash:
                r.prevHash === null
                    ? null
                    : toBase64Url(fromHex(r.prevHash as string)),
        }));
        b64Records[1] = { ...b64Records[1], action: 'TAMPERED' };

        const result = chain.verify(b64Records);
        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(2);
        expect(result.chainLength).toBe(2);
    });
});

describe('HashChain.verify() enriched return value', () => {
    it('should return chainLength equal to records length when valid', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;
        for (let i = 0; i < 10; i++) {
            const rec = { id: `r-${i}`, action: 'A', prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }
        const result = chain.verify(records);
        expect(result.valid).toBe(true);
        expect(result.chainLength).toBe(10);
    });

    it('should return chainLength as brokenAtIndex when chain is broken', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;
        for (let i = 0; i < 6; i++) {
            const rec = { id: `r-${i}`, action: 'A', prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }
        records[3] = { ...records[3], action: 'TAMPERED' };
        const result = chain.verify(records);
        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(4);
        expect(result.chainLength).toBe(4);
        expect(result.expectedHash).toBeDefined();
        expect(result.actualHash).toBeDefined();
    });

    it('should return chainLength 0 for empty chain', () => {
        const chain = new HashChain();
        expect(chain.verify([])).toEqual({ valid: true, chainLength: 0 });
    });
});

describe('HashChain.generateProof() @experimental', () => {
    it('should generate a proof for a single-record chain', () => {
        const chain = new HashChain();
        const rec = { id: 'r-0', action: 'A', prevHash: null };
        chain.append(rec);

        const proof = chain.generateProof(0, [rec]);
        expect(proof.recordIndex).toBe(0);
        expect(proof.recordHash).toMatch(/^[0-9a-f]{64}$/);
        expect(proof.root).toMatch(/^[0-9a-f]{64}$/);
        expect(proof.root).toBe(proof.recordHash);
        expect(proof.siblings).toHaveLength(0);
    });

    it('should generate a proof for a 4-record chain', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;
        for (let i = 0; i < 4; i++) {
            const rec = { id: `r-${i}`, action: 'A', prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        const proof = chain.generateProof(1, records);
        expect(proof.recordIndex).toBe(1);
        expect(proof.siblings).toHaveLength(2);
        expect(proof.root).toMatch(/^[0-9a-f]{64}$/);
        expect(proof.siblings.every((s) => /^[0-9a-f]{64}$/.test(s.hash))).toBe(
            true,
        );
        // index 1 is a right node (1 % 2 !== 0); the first sibling (index 0) sits on the left
        expect(proof.siblings[0]!.position).toBe('left');

        // index 0 is a left node (0 % 2 === 0); the first sibling (index 1) sits on the right
        const proof0 = chain.generateProof(0, records);
        expect(proof0.siblings[0]!.position).toBe('right');
    });

    it('should generate consistent roots for all proofs of the same chain', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;
        for (let i = 0; i < 8; i++) {
            const rec = { id: `r-${i}`, action: 'A', prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        const roots = records.map(
            (_, i) => chain.generateProof(i, records).root,
        );
        expect(new Set(roots).size).toBe(1);
    });

    /**
     * Deferred (not a "permanent skip"): external-root anchor verification needs a
     * verifyProof(proof, externalRoot) API, which is not yet defined in the spec.
     *
     * Revision rationale: the original comment labeled this a "permanent skip" based on a
     * wrong assumption — HashChain.generateProof() is in fact already publicly exported from
     * @coivitas/crypto, and callers can compare proof.root against an external anchor today. The other
     * tests only cover algorithmic self-consistency (local root recomputation) and cannot catch
     * external-anchor drift: if a future caller writes logic that "takes generateProof(i).root and
     * compares it against some archived root string" while the algorithm is upgraded, this
     * class of test cannot detect the wire-compatibility break.
     *
     * Revision action: only the skip semantics comment is changed (keep it.skip — the current release
     * introduces no new API; a later release must first define the verifyProof(proof, externalRoot)
     * anchor contract in the spec, then implement this test and remove the skip).
     */
    it.skip('should verify proof against an external root anchor (deferred)', () => {
        // No implementation: the verifyProof(proof, externalRoot) interface awaits a later anchor-contract definition
    });

    it('should throw when recordIndex is out of bounds', () => {
        const chain = new HashChain();
        expect(() => chain.generateProof(0, [])).toThrow();
        expect(() =>
            chain.generateProof(5, [
                { id: 'r-0', action: 'A', prevHash: null },
            ]),
        ).toThrow();
    });
});

describe('HashChain 100+ record chain verification', () => {
    it('should verify a 100-record chain', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 100; i++) {
            const rec = { seq: i, data: `record-${i}`, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        const result = chain.verify(records);
        expect(result).toEqual({ valid: true, chainLength: 100 });
    });

    it('should detect break caused by tampering record 50 data in a 100-record chain', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 100; i++) {
            const rec = { seq: i, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        // Tamper the data field of the record at index 50 (but leave prevHash unchanged).
        // verify() logic: check whether each record's prevHash equals the hash of the previous record.
        // Record 50's prevHash is still correct (it points to record 49's hash), so index 50 passes.
        // Record 50's content changed, so its hash changes, and record 51's prevHash will no longer match → break at index 51.
        records[50] = { ...records[50], data: 'tampered' };

        const result = chain.verify(records);
        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(51);
        expect(result.chainLength).toBe(51);
    });

    it('should return chainLength 1 and brokenAtIndex 1 when first record data is tampered', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 5; i++) {
            const rec = { seq: i, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        // Tamper the data field of the first record (keep prevHash: null).
        // Check at index 0: prevHash=null matches the expected null → passes.
        // Check at index 1: prevHash points to the original record 0's hash, but after tampering the hash differs → break at index 1.
        records[0] = { ...records[0], data: 'tampered-first' };

        const result = chain.verify(records);
        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(1);
        expect(result.chainLength).toBe(1);
    });

    it('should return chainLength 0 and brokenAtIndex 0 when first record prevHash is tampered', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 5; i++) {
            const rec = { seq: i, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        // Tamper the first record's prevHash (null → a forged hash), breaking immediately at index 0
        const fakeHash = 'a'.repeat(64);
        records[0] = { ...records[0], prevHash: fakeHash };

        const result = chain.verify(records);
        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(0);
        expect(result.chainLength).toBe(0);
    });
});

describe('HashChain.generateProof() local Merkle proof verification on a 100-record chain', () => {
    it('should locally recompute root for indices [0, 1, 49, 50, 98, 99] in a 100-record chain', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 100; i++) {
            const rec = { seq: i, data: `record-${i}`, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        for (const idx of [0, 1, 49, 50, 98, 99]) {
            const proof = chain.generateProof(idx, records);
            const computedRoot = recomputeRoot(proof);
            expect(computedRoot, `index ${idx} root mismatch`).toBe(proof.root);
        }
    });

    it('should produce the same root for all 7 proofs of a 7-record chain (odd number)', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 7; i++) {
            const rec = { seq: i, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        const roots = records.map(
            (_, i) => chain.generateProof(i, records).root,
        );
        // All proofs' roots must be identical
        expect(new Set(roots).size).toBe(1);
    });

    it('should produce correct sibling structure for a 2-record chain', () => {
        const chain = new HashChain();
        const records: Record<string, unknown>[] = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 2; i++) {
            const rec = { seq: i, prevHash };
            prevHash = chain.append(rec);
            records.push(rec);
        }

        // index 0 (left node): its sibling is index 1 (on the right)
        const proof0 = chain.generateProof(0, records);
        expect(proof0.siblings).toHaveLength(1);
        expect(proof0.siblings[0]!.position).toBe('right');

        // index 1 (right node): its sibling is index 0 (on the left)
        const proof1 = chain.generateProof(1, records);
        expect(proof1.siblings).toHaveLength(1);
        expect(proof1.siblings[0]!.position).toBe('left');

        // The two proofs' roots should be identical
        expect(proof0.root).toBe(proof1.root);

        // The locally recomputed root should match proof.root
        expect(recomputeRoot(proof0)).toBe(proof0.root);
        expect(recomputeRoot(proof1)).toBe(proof1.root);
    });
});
