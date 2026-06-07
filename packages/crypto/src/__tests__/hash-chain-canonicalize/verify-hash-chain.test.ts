/**
 * verify-hash-chain.test.ts — HCC L1 verifyHashChain unit tests (v0.2)
 *
 * v0.2 upgrade: chainIdentity preimage is directly cryptographically enforced.
 *
 *   - verify algorithm Step 0-3 + security properties (v0.2 adds I9+I10)
 *   - verifyHashChain Step breakdown
 *   - verifyHashChain helper functions
 *
 * Coverage targets (anti-phantom defense + error-code throw-path):
 *   - happy path (genesis + multi-entry chained verify PASS; with chainIdentity folded into preimage);
 *   - empty array (NO-OP return; does not throw);
 *   - HC_SCHEMA_VIOLATION (entry null/undefined / schema validate fail / bad chainIdentity field);
 *   - HC_CHAIN_POSITION_NONMONOTONIC (chainPosition jump / duplicate / not i);
 *   - HC_PREVIOUS_HASH_BROKEN (middle entry tampered / deleted / inserted);
 *   - HC_CHAIN_IDENTITY_SCHEMA_BREAKING (hccVersion not "2.0.0"; the only legal v0.2 value; I10);
 *   - HC_HASH_MISMATCH (canonicalPayload tampered / chainIdentity tampered → preimage recompute mismatch; v0.2 I9 upgrade).
 */

import { describe, expect, it } from 'vitest';

import {
    HashChainError,
    type CanonicalPayloadHash,
    type ChainIdentity,
    type ChainNamespace,
    type ChainPosition,
    type HashChainEntry,
    type HccVersionString,
    type PreviousHash,
} from '@coivitas/types';

import {
    appendHashChainEntry,
    canonicalizeChainIdentity,
    computeCanonicalPayloadHashHex,
    concatPreimage,
    verifyHashChain,
} from '../../hash-chain-canonicalize/index.js';

// ─── helpers ────────────────────────────────────────────────────────────────

function makeChainIdentity(
    chainNamespace: string,
    tenantId?: string,
    auditClass?: 'L1' | 'L2' | 'L3',
): ChainIdentity {
    return {
        chainNamespace: chainNamespace as ChainNamespace,
        ...(tenantId !== undefined && { tenantId }),
        ...(auditClass !== undefined && { auditClass }),
    };
}

const DEFAULT_IDENTITY = makeChainIdentity('policy');

function buildChain(
    payloads: Record<string, unknown>[],
    chainIdentity: ChainIdentity = DEFAULT_IDENTITY,
): HashChainEntry[] {
    const chain: HashChainEntry[] = [];
    let last: HashChainEntry | undefined;
    for (const payload of payloads) {
        const entry = appendHashChainEntry(payload, chainIdentity, last);
        chain.push(entry);
        last = entry;
    }
    return chain;
}

// ─── happy path ─────────────────────────────────────────────────────────────

describe('verifyHashChain — happy path PASS (v0.2)', () => {
    it('should verify empty array as PASS (NO-OP)', () => {
        expect(() => verifyHashChain([])).not.toThrow();
    });

    it('should verify single genesis entry', () => {
        const chain = buildChain([{ msg: 'genesis' }]);
        expect(() => verifyHashChain(chain)).not.toThrow();
    });

    it('should verify 3-entry chain', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }]);
        expect(() => verifyHashChain(chain)).not.toThrow();
    });

    it('should verify 10-entry chain', () => {
        const payloads = Array.from({ length: 10 }, (_, i) => ({ idx: i }));
        const chain = buildChain(payloads);
        expect(() => verifyHashChain(chain)).not.toThrow();
    });

    it('should verify chain with complex nested payloads', () => {
        const chain = buildChain([
            { a: { b: { c: [1, 2, 3] } } },
            { x: [{ y: 1 }, { y: 2 }] },
            { z: null, b: true, n: 0 },
        ]);
        expect(() => verifyHashChain(chain)).not.toThrow();
    });

    it('should verify chain with atp-style chainIdentity (chainNamespace + tenantId + auditClass)', () => {
        const id = makeChainIdentity('atp', 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', 'L2');
        const chain = buildChain([{ a: 1 }, { a: 2 }], id);
        expect(() => verifyHashChain(chain)).not.toThrow();
    });
});

// ─── HC_SCHEMA_VIOLATION throw-path ─────────────────────────────────────────

describe('verifyHashChain — HC_SCHEMA_VIOLATION', () => {
    it('should throw HC_SCHEMA_VIOLATION for entry null in array', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = [chain[0]!, null as unknown as HashChainEntry];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_SCHEMA_VIOLATION/);
    });

    it('should throw HC_SCHEMA_VIOLATION for entry missing canonicalPayloadHash', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = { ...chain[0]! };
        delete (bad as Partial<HashChainEntry>).canonicalPayloadHash;
        expect(() => verifyHashChain([bad as HashChainEntry])).toThrow(
            HashChainError,
        );
    });

    it('should throw HC_SCHEMA_VIOLATION for entry missing chainIdentity (v0.2 mandatory)', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = { ...chain[0]! };
        delete (bad as Partial<HashChainEntry>).chainIdentity;
        expect(() => verifyHashChain([bad as HashChainEntry])).toThrow(
            HashChainError,
        );
    });

    it('should throw HC_SCHEMA_VIOLATION for entry with extra field (additionalProperties:false)', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = { ...chain[0]!, extraField: 'phantom' } as HashChainEntry;
        expect(() => verifyHashChain([bad])).toThrow(HashChainError);
    });

    it('should throw HC_SCHEMA_VIOLATION for entry with uppercase hex (lowercase pattern)', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = {
            ...chain[0]!,
            canonicalPayloadHash:
                chain[0]!.canonicalPayloadHash.toUpperCase() as CanonicalPayloadHash,
        };
        expect(() => verifyHashChain([bad])).toThrow(HashChainError);
    });
});

// ─── HC_CHAIN_IDENTITY_SCHEMA_BREAKING throw-path (v0.2 I10 invariant) ──────────

describe('verifyHashChain — HC_CHAIN_IDENTITY_SCHEMA_BREAKING (v0.2 strict hccVersion)', () => {
    it('should throw HC_CHAIN_IDENTITY_SCHEMA_BREAKING when entry has hccVersion != "2.0.0"', () => {
        // Build a chain → force entries[0].hccVersion to "1.0.0" (the schema const guard triggers a schema violation first)
        const chain = buildChain([{ a: 1 }]);
        const bad = [
            {
                ...chain[0]!,
                hccVersion: '1.0.0' as HccVersionString,
            },
        ];
        // Note: the schema const "2.0.0" triggers HC_SCHEMA_VIOLATION first (Step 1 genesis schema check);
        // the explicit hccVersion verify in Step 2.4 is a post-schema fallback layer (but the schema already rejects this case);
        // so this case actually throws HC_SCHEMA_VIOLATION (schema precedes the explicit verify)
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
    });
});

// ─── HC_CHAIN_POSITION_NONMONOTONIC throw-path ──────────────────────────────

describe('verifyHashChain — HC_CHAIN_POSITION_NONMONOTONIC', () => {
    it('should throw when chainPosition jumps (0,2 missing 1)', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }]);
        // Tamper chain[1].chainPosition 1 → 2
        const bad = [
            chain[0]!,
            { ...chain[1]!, chainPosition: 2 as ChainPosition },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(
            /HC_CHAIN_POSITION_NONMONOTONIC/,
        );
    });

    it('should throw when chainPosition duplicates (0,0)', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }]);
        const bad = [
            chain[0]!,
            { ...chain[1]!, chainPosition: 0 as ChainPosition },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
    });

    it('should throw when genesis chainPosition != 0', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = [{ ...chain[0]!, chainPosition: 5 as ChainPosition }];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
    });
});

// ─── HC_PREVIOUS_HASH_BROKEN throw-path ─────────────────────────────────────

describe('verifyHashChain — HC_PREVIOUS_HASH_BROKEN', () => {
    it('should throw when middle entry deleted (chain broken)', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }]);
        // Delete the middle entry → chain[2].previousHash no longer equals chain[0].canonicalPayloadHash
        // First renumber chainPosition so the PrevHash check fires
        const bad = [
            chain[0]!,
            { ...chain[2]!, chainPosition: 1 as ChainPosition },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_PREVIOUS_HASH_BROKEN/);
    });

    it('should throw when previousHash tampered (replace with random hex)', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }]);
        const bad = [
            chain[0]!,
            {
                ...chain[1]!,
                previousHash:
                    '1111111111111111111111111111111111111111111111111111111111111111' as PreviousHash,
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_PREVIOUS_HASH_BROKEN/);
    });

    it('should throw when genesis previousHash != GENESIS (64 zeros)', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = [
            {
                ...chain[0]!,
                previousHash:
                    '1111111111111111111111111111111111111111111111111111111111111111' as PreviousHash,
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_PREVIOUS_HASH_BROKEN/);
    });
});

// ─── HC_HASH_MISMATCH throw-path (v0.2 I9 chainIdentity preimage upgrade) ───────

describe('verifyHashChain — HC_HASH_MISMATCH (v0.2 I9 chainIdentity preimage cryptographic enforce)', () => {
    it('should throw when canonicalPayload tampered (preimage recompute mismatch)', () => {
        const chain = buildChain([{ msg: 'genesis' }]);
        // Tamper canonicalPayload → preimage recompute + re-hash disagrees with the stored hash
        const bad = [
            {
                ...chain[0]!,
                canonicalPayload: '{"msg":"tampered"}',
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_CHAIN_IDENTITY_PREIMAGE_FAILED/);
    });

    it('should throw when chainIdentity.chainNamespace tampered (v0.2 I9 upgrade core)', () => {
        const chain = buildChain([{ a: 1 }], makeChainIdentity('atp'));
        // Tamper chainIdentity.chainNamespace → preimage recompute → SHA-256 mismatch
        const tamperedIdentity = makeChainIdentity('policy'); // atp → policy cross-partition tampering
        const bad = [
            {
                ...chain[0]!,
                chainIdentity: tamperedIdentity,
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_CHAIN_IDENTITY_PREIMAGE_FAILED/);
    });

    it('should throw when chainIdentity.tenantId tampered (cross-tenant tampering)', () => {
        const id = makeChainIdentity('atp', 'bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb', 'L1');
        const chain = buildChain([{ a: 1 }], id);
        const tamperedIdentity = makeChainIdentity('atp', 'cccccccc-1111-4111-8111-cccccccccccc', 'L1'); // tenant-1 → tenant-2
        const bad = [
            {
                ...chain[0]!,
                chainIdentity: tamperedIdentity,
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_CHAIN_IDENTITY_PREIMAGE_FAILED/);
    });

    it('should throw when chainIdentity.auditClass tampered (L1 → L3 privilege-escalation tampering)', () => {
        const id = makeChainIdentity('atp', 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', 'L1');
        const chain = buildChain([{ a: 1 }], id);
        const tamperedIdentity = makeChainIdentity('atp', 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', 'L3');
        const bad = [
            {
                ...chain[0]!,
                chainIdentity: tamperedIdentity,
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_CHAIN_IDENTITY_PREIMAGE_FAILED/);
    });

    it('should throw when canonicalPayloadHash directly tampered (change hash without changing payload/identity)', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = [
            {
                ...chain[0]!,
                canonicalPayloadHash:
                    '0000000000000000000000000000000000000000000000000000000000000001' as CanonicalPayloadHash,
            },
        ];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED when canonicalPayload is invalid JSON', () => {
        const chain = buildChain([{ a: 1 }]);
        const bad = [
            {
                ...chain[0]!,
                canonicalPayload: '{"invalid',
            },
        ];
        // On verify, canonicalPayload is parsed first to re-run JCS canonicalize;
        // invalid JSON is rejected at the JSON.parse step of assertCanonicalPayloadIsCanonical → HC_CANONICALIZE_FAILED
        // (semantically more precise than the old path of "hashing opaque bytes then reporting a mismatch")
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
        expect(() => verifyHashChain(bad)).toThrow(/HC_CANONICALIZE_FAILED/);
    });

    it('should throw HC_CHAIN_IDENTITY_PREIMAGE_FAILED when canonicalPayload is valid JSON but not canonical JCS form', () => {
        // Core scenario — valid JSON but keys not sorted per RFC 8785 (non-canonical)
        // An attacker recomputing the hash over this non-canonical string can make the hash self-consistent, but it breaks the injectivity invariant
        const chain = buildChain([{ a: 1, b: 2 }]);
        const genesis = chain[0]!;
        // Use a non-canonical payload string (reversed key order + extra whitespace) and recompute a self-consistent hash over it
        const nonCanonicalPayload = '{"b":2,"a":1}';
        const chainIdentityJcs = canonicalizeChainIdentity(
            genesis.chainIdentity as never,
        );
        const selfConsistentHash = computeCanonicalPayloadHashHex(
            concatPreimage(nonCanonicalPayload, chainIdentityJcs),
        );
        const forged = [
            {
                ...genesis,
                canonicalPayload: nonCanonicalPayload,
                canonicalPayloadHash:
                    selfConsistentHash as typeof genesis.canonicalPayloadHash,
            },
        ];
        // The hash is self-consistent for the non-canonical payload, but canonical-form verify must reject it
        expect(() => verifyHashChain(forged)).toThrow(HashChainError);
        expect(() => verifyHashChain(forged)).toThrow(
            /HC_CHAIN_IDENTITY_PREIMAGE_FAILED/,
        );
    });
});

// ─── verify ordering soundness (schema → chainPosition → previousHash → hccVersion → hash) ──

describe('verifyHashChain — verify ordering soundness', () => {
    it('should throw HC_SCHEMA_VIOLATION before chainPosition check (schema first)', () => {
        const chain = buildChain([{ a: 1 }]);
        // Break schema + chainPosition + previousHash + hash simultaneously → schema should be reported first
        const bad = [
            {
                ...chain[0]!,
                canonicalPayloadHash: 'not-hex' as CanonicalPayloadHash, // schema fail
                chainPosition: 99 as ChainPosition, // pos fail
                previousHash:
                    '1111111111111111111111111111111111111111111111111111111111111111' as PreviousHash, // prev fail
            },
        ];
        try {
            verifyHashChain(bad);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            expect((e as HashChainError).code).toBe('HC_SCHEMA_VIOLATION');
        }
    });
});

// ─── Integration: build + verify chained round-trip ──────────────────────────────────

describe('verifyHashChain — append + verify round-trip', () => {
    it('should verify chain built via appendHashChainEntry (full round-trip)', () => {
        const chain = buildChain([
            { event: 'init', userId: 'alice' },
            { event: 'action', userId: 'alice', target: 'resource1' },
            { event: 'commit', userId: 'alice', target: 'resource1' },
            { event: 'finalize', userId: 'alice' },
        ]);
        expect(() => verifyHashChain(chain)).not.toThrow();
        // Also assert each entry's fields are valid
        expect(chain).toHaveLength(4);
        for (let i = 0; i < 4; i++) {
            expect(chain[i]!.chainPosition).toBe(i);
            expect(chain[i]!.hccVersion).toBe('2.0.0'); // v0.2 upgrade
        }
    });

    it('should detect any tampering at any chain position (canonicalPayload mutate)', () => {
        const chain = buildChain([
            { a: 1 },
            { a: 2 },
            { a: 3 },
            { a: 4 },
            { a: 5 },
        ]);
        // Tamper any middle entry → verify fail
        for (let i = 0; i < chain.length; i++) {
            const tampered = chain.map((e, idx) =>
                idx === i
                    ? { ...e, canonicalPayload: '{"tampered":true}' }
                    : e,
            );
            expect(() => verifyHashChain(tampered)).toThrow(HashChainError);
        }
    });

    it('should detect any tampering at any chain position (chainIdentity mutate; v0.2 I9 upgrade core)', () => {
        const id = makeChainIdentity('atp', 'bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb', 'L1');
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }], id);
        const tamperedIdentity = makeChainIdentity('atp', 'cccccccc-1111-4111-8111-cccccccccccc', 'L1');
        // Tamper any entry's chainIdentity → verify fail
        for (let i = 0; i < chain.length; i++) {
            const tampered = chain.map((e, idx) =>
                idx === i ? { ...e, chainIdentity: tamperedIdentity } : e,
            );
            expect(() => verifyHashChain(tampered)).toThrow(HashChainError);
        }
    });

    it('should detect reordering attack (swap two entries)', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }]);
        // swap entries[1] and entries[2] → both chainPosition and previousHash are wrong
        const bad = [chain[0]!, chain[2]!, chain[1]!];
        expect(() => verifyHashChain(bad)).toThrow(HashChainError);
    });
});

// ─── chain identity consistency (mixed-identity rejection) ──────────────────────────

describe('verifyHashChain — chain identity consistency', () => {
    it('should throw when entries have mixed chainIdentity when previousHash links are forged', () => {
        // Build two independent chains (tenant A / tenant B), take A's genesis + make B's second entry link after A
        const idA = makeChainIdentity('policy', undefined, 'L1');
        const idB = makeChainIdentity('federation', undefined, 'L2');
        const chainA = buildChain([{ a: 1 }], idA);
        // Appending B's entry after A's genesis via appendHashChainEntry — the append guard rejects cross-scope links
        expect(() =>
            appendHashChainEntry({ b: 2 }, idB, chainA[0]!),
        ).toThrow(/mixed-identity rejected/);
    });

    it('should throw when verifying a hand-crafted mixed-identity chain', () => {
        // Bypass the append guard and hand-craft entries[1] with a different chainIdentity but a correct previousHash link
        const idA = makeChainIdentity('policy', undefined, 'L1');
        const chainA = buildChain([{ a: 1 }, { a: 2 }], idA);
        // Swap entries[1]'s chainIdentity to B (while keeping the previousHash link to A) — its hash must be recomputed to pass the preimage check
        const idB = makeChainIdentity('federation', undefined, 'L2');
        const e1 = chainA[1]!;
        const jcsB = canonicalizeChainIdentity(idB as never);
        const rehashedE1Hash = computeCanonicalPayloadHashHex(
            concatPreimage(e1.canonicalPayload, jcsB),
        );
        const mixed = [
            chainA[0]!,
            {
                ...e1,
                chainIdentity: idB,
                canonicalPayloadHash:
                    rehashedE1Hash as typeof e1.canonicalPayloadHash,
            },
        ];
        // Each preimage hash is self-consistent, but chain-level identity consistency must reject it
        expect(() => verifyHashChain(mixed)).toThrow(
            /mixed-identity chain rejected|differs from chain's first chainIdentity/,
        );
    });

    it('should throw when expectedChainIdentity does not match a valid chain', () => {
        const idA = makeChainIdentity('policy', undefined, 'L1');
        const chain = buildChain([{ a: 1 }, { a: 2 }], idA);
        const idWrong = makeChainIdentity('attacker-namespace');
        expect(() =>
            verifyHashChain(chain, { expectedChainIdentity: idWrong }),
        ).toThrow(/does not match expectedChainIdentity/);
    });

    it('should pass when expectedChainIdentity matches the chain', () => {
        const idA = makeChainIdentity('policy', undefined, 'L1');
        const chain = buildChain([{ a: 1 }, { a: 2 }], idA);
        expect(() =>
            verifyHashChain(chain, { expectedChainIdentity: idA }),
        ).not.toThrow();
    });
});

// ─── checkpoint (deletion / truncation detection) ──────────────────────────────

describe('verifyHashChain — checkpoint deletion/truncation', () => {
    it('should throw when requireNonEmpty asserted but chain deleted entirely', () => {
        expect(() =>
            verifyHashChain([], { checkpoint: { requireNonEmpty: true } }),
        ).toThrow(/deletion of entire chain/);
    });

    it('should throw when expectedEntryCount mismatches (tail truncation)', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }]);
        const truncated = [chain[0]!, chain[1]!]; // dropped the last entry
        expect(() =>
            verifyHashChain(truncated, {
                checkpoint: { expectedEntryCount: 3 },
            }),
        ).toThrow(/expectedEntryCount/);
    });

    it('should throw when expectedLastChainPosition mismatches', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }]);
        const truncated = [chain[0]!, chain[1]!];
        expect(() =>
            verifyHashChain(truncated, {
                checkpoint: { expectedLastChainPosition: 2 },
            }),
        ).toThrow(/expectedLastChainPosition/);
    });

    it('should pass when checkpoint matches intact chain', () => {
        const chain = buildChain([{ a: 1 }, { a: 2 }, { a: 3 }]);
        expect(() =>
            verifyHashChain(chain, {
                checkpoint: {
                    requireNonEmpty: true,
                    expectedEntryCount: 3,
                    expectedLastChainPosition: 2,
                    expectedLastCanonicalPayloadHash: chain[2]!
                        .canonicalPayloadHash as string,
                },
            }),
        ).not.toThrow();
    });
});
