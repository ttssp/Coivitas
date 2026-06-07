/**
 * preimage-helpers.test.ts — HCC v0.2 L1 crypto preimage helpers unit tests
 *
 * Scope (hcc v0.2 L1 crypto preimage + verify helpers):
 *   - ChainIdentity JCS canonicalize edge-case refinement (Case 1-7)
 *   - verifyCanonicalizeConsistency anti-self-equal
 *   - concatPreimage (canonicalPayloadBytes ‖ chainIdentityJcsBytes)
 *   - recomputeCanonicalPayloadHash + assertCanonicalPayloadHashConsistent
 *
 * Cases covered:
 *   - Case 1: chainIdentity edge cases — undefined / null / sentinel / empty string
 *   - Case 2: anti-self-equal consistency verify (deterministic canonicalize)
 *   - Case 3: cross-chain partition — chainIdentity field differences -> preimage difference -> unequal hash
 *   - Case 4: preimage concat order verify (payload first; identity after)
 *   - Case 5: tampering detection (chainIdentity OR canonicalPayload tampered -> assertCanonicalPayloadHashConsistent throws)
 */

import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';

import { HashChainError } from '@coivitas/types';

import {
    assertCanonicalPayloadHashConsistent,
    canonicalizeChainIdentity,
    computeCanonicalPayloadHashHex,
    concatPreimage,
    recomputeCanonicalPayloadHash,
    verifyCanonicalizeConsistency,
    type ChainIdentityShape,
    type HashChainEntryV02Shape,
} from '../../hash-chain-canonicalize/index.js';

// ── helper: build v0.2 entry shape with correct canonicalPayloadHash ──────
function buildValidEntry(
    canonicalPayload: string,
    chainIdentity: ChainIdentityShape,
): HashChainEntryV02Shape {
    const chainIdentityJcs = canonicalizeChainIdentity(chainIdentity);
    const preimage = concatPreimage(canonicalPayload, chainIdentityJcs);
    const canonicalPayloadHash = computeCanonicalPayloadHashHex(preimage);
    return { canonicalPayload, canonicalPayloadHash, chainIdentity };
}

// ─── Case 1: chainIdentity edge cases ─────────────────────────────────────
describe('Case 1: canonicalizeChainIdentity — edge cases', () => {
    it('should produce {"chainNamespace":"atp"} when tenantId/auditClass undefined', () => {
        const result = canonicalizeChainIdentity({ chainNamespace: 'atp' });
        expect(result).toBe('{"chainNamespace":"atp"}');
    });

    it('should produce same output for explicit undefined as for missing field', () => {
        const r1 = canonicalizeChainIdentity({ chainNamespace: 'policy' });
        const r2 = canonicalizeChainIdentity({
            chainNamespace: 'policy',
            tenantId: undefined,
            auditClass: undefined,
        });
        expect(r1).toBe(r2);
        expect(r1).toBe('{"chainNamespace":"policy"}');
    });

    it('should alphabetical sort keys when all 3 fields present', () => {
        const result = canonicalizeChainIdentity({
            chainNamespace: 'atp',
            tenantId: 'tenant-uuid',
            auditClass: 'L1',
        });
        // RFC 8785 alphabetical sort: auditClass < chainNamespace < tenantId
        expect(result).toBe(
            '{"auditClass":"L1","chainNamespace":"atp","tenantId":"tenant-uuid"}',
        );
    });

    it('should reject sentinel "__NULL__" chainNamespace', () => {
        expect(() =>
            canonicalizeChainIdentity({ chainNamespace: '__NULL__' }),
        ).toThrow(HashChainError);
        try {
            canonicalizeChainIdentity({ chainNamespace: '__NULL__' });
        } catch (err) {
            expect(err).toBeInstanceOf(HashChainError);
            expect((err as HashChainError).code).toBe('HC_SCHEMA_VIOLATION');
            expect((err as HashChainError).message).toContain('__NULL__');
        }
    });

    it('should reject empty chainNamespace', () => {
        expect(() => canonicalizeChainIdentity({ chainNamespace: '' })).toThrow(
            HashChainError,
        );
        try {
            canonicalizeChainIdentity({ chainNamespace: '' });
        } catch (err) {
            expect((err as HashChainError).code).toBe('HC_SCHEMA_VIOLATION');
            expect((err as HashChainError).message).toContain(
                'non-empty string',
            );
        }
    });

    it('should reject non-string chainNamespace', () => {
        expect(() =>
            canonicalizeChainIdentity({
                chainNamespace: 123 as unknown as string,
            }),
        ).toThrow(HashChainError);
    });

    it('should reject empty tenantId when present', () => {
        expect(() =>
            canonicalizeChainIdentity({
                chainNamespace: 'atp',
                tenantId: '',
            }),
        ).toThrow(HashChainError);
    });

    it('should reject empty auditClass when present', () => {
        expect(() =>
            canonicalizeChainIdentity({
                chainNamespace: 'atp',
                tenantId: 'tenant-uuid',
                auditClass: '',
            }),
        ).toThrow(HashChainError);
    });

    it('should reject non-string tenantId when present', () => {
        expect(() =>
            canonicalizeChainIdentity({
                chainNamespace: 'atp',
                tenantId: 123 as unknown as string,
            }),
        ).toThrow(HashChainError);
    });

    it('should reject non-string auditClass when present', () => {
        expect(() =>
            canonicalizeChainIdentity({
                chainNamespace: 'atp',
                tenantId: 'tenant-uuid',
                auditClass: 123 as unknown as string,
            }),
        ).toThrow(HashChainError);
    });
});

// ─── Case 2: anti-self-equal canonicalize consistency ────────────────────
describe('Case 2: verifyCanonicalizeConsistency — anti-self-equal', () => {
    it('should return canonical string when consistent (deterministic canonicalize)', () => {
        const result = verifyCanonicalizeConsistency({ a: 1, b: 2 });
        // canonicalize sorted output
        expect(result).toBe('{"a":1,"b":2}');
    });

    it('should produce stable output for nested objects across two passes', () => {
        const payload = { z: { b: 1, a: 2 }, x: [3, 2, 1] };
        const result = verifyCanonicalizeConsistency(payload);
        // alphabetical key sort + arrays preserve order (RFC 8785)
        expect(result).toBe('{"x":[3,2,1],"z":{"a":2,"b":1}}');
    });

    it('should produce same string when called repeatedly (idempotent)', () => {
        const payload = { foo: 'bar', timestamp: '2026-05-19T00:00:00Z' };
        const r1 = verifyCanonicalizeConsistency(payload);
        const r2 = verifyCanonicalizeConsistency(payload);
        const r3 = verifyCanonicalizeConsistency(payload);
        expect(r1).toBe(r2);
        expect(r2).toBe(r3);
    });

    it('should throw HC_CANONICALIZE_FAILED when canonicalize returns undefined (undefined input)', () => {
        // canonicalize npm returns undefined for a top-level undefined (not serializable per RFC 8785)
        expect(() =>
            verifyCanonicalizeConsistency(undefined as unknown),
        ).toThrow(HashChainError);
        try {
            verifyCanonicalizeConsistency(undefined as unknown);
        } catch (err) {
            expect((err as HashChainError).code).toBe('HC_CANONICALIZE_FAILED');
        }
    });
});

// ─── Case 3: cross-chain partition (different chainIdentity -> different hash) ───
describe('Case 3: cross-chain partition — chainIdentity difference -> preimage difference -> unequal hash', () => {
    const payload = '{"action":"audit","value":42}';

    it('should produce different canonicalPayloadHash for different chainNamespace (same payload)', () => {
        const idAtp: ChainIdentityShape = { chainNamespace: 'atp' };
        const idPolicy: ChainIdentityShape = { chainNamespace: 'policy' };

        const jcsAtp = canonicalizeChainIdentity(idAtp);
        const jcsPolicy = canonicalizeChainIdentity(idPolicy);
        const preimageAtp = concatPreimage(payload, jcsAtp);
        const preimagePolicy = concatPreimage(payload, jcsPolicy);
        const hashAtp = computeCanonicalPayloadHashHex(preimageAtp);
        const hashPolicy = computeCanonicalPayloadHashHex(preimagePolicy);

        expect(jcsAtp).not.toBe(jcsPolicy);
        expect(hashAtp).not.toBe(hashPolicy);
        expect(hashAtp).toMatch(/^[a-f0-9]{64}$/);
        expect(hashPolicy).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hash when tenantId differs (same chainNamespace + payload)', () => {
        const idA: ChainIdentityShape = {
            chainNamespace: 'atp',
            tenantId: 'tenant-a',
            auditClass: 'L1',
        };
        const idB: ChainIdentityShape = {
            chainNamespace: 'atp',
            tenantId: 'tenant-b',
            auditClass: 'L1',
        };

        const hashA = computeCanonicalPayloadHashHex(
            concatPreimage(payload, canonicalizeChainIdentity(idA)),
        );
        const hashB = computeCanonicalPayloadHashHex(
            concatPreimage(payload, canonicalizeChainIdentity(idB)),
        );

        expect(hashA).not.toBe(hashB);
    });

    it('should produce different hash when auditClass differs (same chainNamespace + tenantId + payload)', () => {
        const idL1: ChainIdentityShape = {
            chainNamespace: 'atp',
            tenantId: 'tenant-x',
            auditClass: 'L1',
        };
        const idL3: ChainIdentityShape = {
            chainNamespace: 'atp',
            tenantId: 'tenant-x',
            auditClass: 'L3',
        };

        const hashL1 = computeCanonicalPayloadHashHex(
            concatPreimage(payload, canonicalizeChainIdentity(idL1)),
        );
        const hashL3 = computeCanonicalPayloadHashHex(
            concatPreimage(payload, canonicalizeChainIdentity(idL3)),
        );

        expect(hashL1).not.toBe(hashL3);
    });
});

// ─── Case 4: preimage concat order verify (payload first; identity after) ────────
describe('Case 4: concatPreimage concat order — payload first; identity after', () => {
    it('should produce preimage with canonicalPayloadBytes first, then chainIdentityJcsBytes', () => {
        const payload = '{"a":1}';
        const jcs = '{"chainNamespace":"atp"}';
        const preimage = concatPreimage(payload, jcs);

        const expectedLength = payload.length + jcs.length;
        expect(preimage.length).toBe(expectedLength);

        // prefix = canonicalPayloadBytes
        const payloadBytes = new TextEncoder().encode(payload);
        for (let i = 0; i < payloadBytes.length; i++) {
            expect(preimage[i]).toBe(payloadBytes[i]);
        }

        // suffix = chainIdentityJcsBytes
        const jcsBytes = new TextEncoder().encode(jcs);
        for (let i = 0; i < jcsBytes.length; i++) {
            expect(preimage[payloadBytes.length + i]).toBe(jcsBytes[i]);
        }
    });

    it('should produce different preimage when payload and identity swapped (order-sensitive)', () => {
        const payload = '{"a":1}';
        const jcs = '{"chainNamespace":"atp"}';

        const correctOrder = concatPreimage(payload, jcs);
        const swappedOrder = concatPreimage(jcs, payload);

        // Equal length (same byte count) but different byte order in content -> unequal SHA-256 digest
        expect(correctOrder.length).toBe(swappedOrder.length);
        const hashCorrect = computeCanonicalPayloadHashHex(correctOrder);
        const hashSwapped = computeCanonicalPayloadHashHex(swappedOrder);
        expect(hashCorrect).not.toBe(hashSwapped);
    });

    it('should match manual SHA-256 of concatenated bytes (cross-check with @noble/hashes)', () => {
        const payload = '{"event":"test"}';
        const jcs = '{"chainNamespace":"atp","tenantId":"t1"}';
        const preimage = concatPreimage(payload, jcs);

        // Manual SHA-256 computation (cross-check)
        const manualBytes = new Uint8Array(payload.length + jcs.length);
        manualBytes.set(new TextEncoder().encode(payload), 0);
        manualBytes.set(new TextEncoder().encode(jcs), payload.length);
        const manualDigest = sha256(manualBytes);
        let manualHex = '';
        for (const b of manualDigest) {
            manualHex += b.toString(16).padStart(2, '0');
        }

        const helperHex = computeCanonicalPayloadHashHex(preimage);
        expect(helperHex).toBe(manualHex);
        expect(helperHex).toMatch(/^[a-f0-9]{64}$/);
        expect(helperHex).toHaveLength(64);
    });

    it('should produce lowercase hex output (consistent with toCanonicalPayloadHash factory)', () => {
        const preimage = concatPreimage('{"x":1}', '{"chainNamespace":"atp"}');
        const hash = computeCanonicalPayloadHashHex(preimage);
        expect(hash).toBe(hash.toLowerCase());
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
});

// ─── Case 5: tampering detection (chainIdentity OR canonicalPayload tampered) ──────
describe('Case 5: assertCanonicalPayloadHashConsistent — tampering detection', () => {
    it('should PASS when entry is consistent (recomputed hash equals stored hash)', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
            tenantId: 'tenant-1',
            auditClass: 'L1',
        });
        expect(() =>
            assertCanonicalPayloadHashConsistent(entry, 0),
        ).not.toThrow();
    });

    it('should throw when canonicalPayload tampered (single-char mutate)', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
            tenantId: 'tenant-1',
            auditClass: 'L1',
        });
        // mutate canonicalPayload (tampering scenario; canonicalPayloadHash is not recomputed)
        const tampered: HashChainEntryV02Shape = {
            ...entry,
            canonicalPayload: '{"action":"audit-TAMPERED"}',
        };
        expect(() => assertCanonicalPayloadHashConsistent(tampered, 0)).toThrow(
            HashChainError,
        );
        try {
            assertCanonicalPayloadHashConsistent(tampered, 0);
        } catch (err) {
            expect((err as HashChainError).code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');
            expect((err as HashChainError).message).toContain(
                'cryptographic enforce fail',
            );
        }
    });

    it('should throw when chainIdentity.chainNamespace tampered', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
            tenantId: 'tenant-1',
            auditClass: 'L1',
        });
        const tampered: HashChainEntryV02Shape = {
            ...entry,
            chainIdentity: {
                ...entry.chainIdentity,
                chainNamespace: 'policy', // tampered
            },
        };
        expect(() => assertCanonicalPayloadHashConsistent(tampered, 1)).toThrow(
            HashChainError,
        );
        try {
            assertCanonicalPayloadHashConsistent(tampered, 1);
        } catch (err) {
            expect((err as HashChainError).code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');
            expect((err as HashChainError).message).toContain('entries[1]');
        }
    });

    it('should throw when chainIdentity.tenantId tampered', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
            tenantId: 'tenant-1',
            auditClass: 'L1',
        });
        const tampered: HashChainEntryV02Shape = {
            ...entry,
            chainIdentity: {
                ...entry.chainIdentity,
                tenantId: 'tenant-2', // tampered
            },
        };
        expect(() => assertCanonicalPayloadHashConsistent(tampered, 2)).toThrow(
            HashChainError,
        );
    });

    it('should throw when chainIdentity.auditClass tampered (L1 -> L3 privilege escalation scenario)', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
            tenantId: 'tenant-1',
            auditClass: 'L1',
        });
        const tampered: HashChainEntryV02Shape = {
            ...entry,
            chainIdentity: {
                ...entry.chainIdentity,
                auditClass: 'L3', // L1 -> L3 privilege escalation tamper
            },
        };
        expect(() => assertCanonicalPayloadHashConsistent(tampered, 3)).toThrow(
            HashChainError,
        );
    });

    it('should throw when canonicalPayloadHash directly tampered (change hash without changing payload/identity)', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
        });
        const tampered: HashChainEntryV02Shape = {
            ...entry,
            canonicalPayloadHash:
                '0000000000000000000000000000000000000000000000000000000000000000', // literally change the hash
        };
        expect(() => assertCanonicalPayloadHashConsistent(tampered, 4)).toThrow(
            HashChainError,
        );
    });

    it('should report entry index in error message', () => {
        const entry = buildValidEntry('{"action":"audit"}', {
            chainNamespace: 'atp',
        });
        const tampered: HashChainEntryV02Shape = {
            ...entry,
            canonicalPayload: '{"action":"audit-TAMPERED"}',
        };
        try {
            assertCanonicalPayloadHashConsistent(tampered, 42);
        } catch (err) {
            expect((err as HashChainError).message).toContain('entries[42]');
        }
    });
});

// ─── recomputeCanonicalPayloadHash direct verify ──────────────────────────
describe('recomputeCanonicalPayloadHash — verify path reuses write path algorithm', () => {
    it('should produce same hash as concatPreimage + computeCanonicalPayloadHashHex pipeline', () => {
        const entry: HashChainEntryV02Shape = {
            canonicalPayload: '{"foo":"bar"}',
            canonicalPayloadHash: '', // placeholder; recompute does not depend on it
            chainIdentity: {
                chainNamespace: 'atp',
                tenantId: 'tenant-x',
                auditClass: 'L1',
            },
        };

        const recomputed = recomputeCanonicalPayloadHash(entry);

        // Equivalent pipeline (verifies the verify path and write path use the same algorithm)
        const jcs = canonicalizeChainIdentity(entry.chainIdentity);
        const preimage = concatPreimage(entry.canonicalPayload, jcs);
        const expected = computeCanonicalPayloadHashHex(preimage);

        expect(recomputed).toBe(expected);
        expect(recomputed).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hash for different chainIdentity (same payload)', () => {
        const baseEntry = {
            canonicalPayload: '{"x":1}',
            canonicalPayloadHash: '',
        };
        const h1 = recomputeCanonicalPayloadHash({
            ...baseEntry,
            chainIdentity: { chainNamespace: 'atp' },
        });
        const h2 = recomputeCanonicalPayloadHash({
            ...baseEntry,
            chainIdentity: { chainNamespace: 'policy' },
        });
        expect(h1).not.toBe(h2);
    });

    it('should throw when chainIdentity.chainNamespace empty (factory cascades)', () => {
        expect(() =>
            recomputeCanonicalPayloadHash({
                canonicalPayload: '{}',
                canonicalPayloadHash: '',
                chainIdentity: { chainNamespace: '' },
            }),
        ).toThrow(HashChainError);
    });
});

// ─── computeCanonicalPayloadHashHex unit tests ────────────────────────────
describe('computeCanonicalPayloadHashHex — SHA-256 hex encode (RFC 6234)', () => {
    it('should produce 64-char lowercase hex digest', () => {
        const preimage = new TextEncoder().encode('hello');
        const hash = computeCanonicalPayloadHashHex(preimage);
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should match known SHA-256 test vector for "abc"', () => {
        // RFC 6234 test vector: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        const preimage = new TextEncoder().encode('abc');
        const hash = computeCanonicalPayloadHashHex(preimage);
        expect(hash).toBe(
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        );
    });

    it('should match known SHA-256 test vector for empty string', () => {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        const preimage = new Uint8Array(0);
        const hash = computeCanonicalPayloadHashHex(preimage);
        expect(hash).toBe(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        );
    });

    it('should be deterministic (same input → same output)', () => {
        const preimage = new TextEncoder().encode('deterministic-test');
        const h1 = computeCanonicalPayloadHashHex(preimage);
        const h2 = computeCanonicalPayloadHashHex(preimage);
        const h3 = computeCanonicalPayloadHashHex(preimage);
        expect(h1).toBe(h2);
        expect(h2).toBe(h3);
    });
});
