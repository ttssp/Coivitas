/**
 * append-hash-chain-entry.test.ts — HCC L1 appendHashChainEntry unit tests (v0.2)
 *
 *   - appendHashChainEntry step refinement
 *   - ChainIdentity edge-case factory guards (Case 1-7)
 *
 * Coverage goals (v0.2 upgrade + I1-I10 invariant guards):
 *   - genesis entry (lastEntry undefined -> chainPosition 0 + previousHash GENESIS + all 8 fields populated including chainIdentity);
 *   - append after genesis (chainPosition 1 + previousHash = prev.hash);
 *   - chained appends (3+ entries linked);
 *   - chainIdentity mandatory-presence defense (null / undefined -> HC_SCHEMA_VIOLATION);
 *   - chainIdentity edge cases (empty chainNamespace / sentinel "__NULL__" / empty tenantId / non-string);
 *   - cross-chain partition (different chainIdentity -> different canonicalPayloadHash; same payload);
 *   - lastEntry field missing / wrong type -> HC_SCHEMA_VIOLATION;
 *   - non-JCS-serializable payload -> HC_CANONICALIZE_FAILED;
 *   - chainPosition overflow -> HC_SCHEMA_VIOLATION;
 *   - hccVersion hard upgrade to "2.0.0" (HCC_VERSION_CURRENT).
 */

import { describe, expect, it } from 'vitest';

import {
    GENESIS_PREVIOUS_HASH,
    HCC_VERSION_CURRENT,
    HashChainError,
    type CanonicalPayloadHash,
    type ChainIdentity,
    type ChainNamespace,
    type ChainPosition,
    type HashChainEntry,
    type HashChainEntryId,
    type HccVersionString,
    type PreviousHash,
    type Timestamp,
} from '@coivitas/types';

import { appendHashChainEntry } from '../../hash-chain-canonicalize/index.js';

// ─── helpers ────────────────────────────────────────────────────────────────

/**
 * makeChainIdentity — build a ChainIdentity triple (chainNamespace mandatory + optional fields)
 * Corresponds to the ChainIdentity interface; the chainNamespace brand is applied via an `as ChainNamespace` cast
 * (this is a test fixture only; the brand-cast guard is enforced inside production code's canonicalizeChainIdentity)
 */
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

// ─── genesis entry ──────────────────────────────────────────────────────────

describe('appendHashChainEntry — genesis (lastEntry undefined; v0.2)', () => {
    it('should produce genesis entry with chainPosition=0 + previousHash=GENESIS', () => {
        const entry = appendHashChainEntry(
            { message: 'genesis' },
            DEFAULT_IDENTITY,
            undefined,
        );
        expect(entry.chainPosition).toBe(0);
        expect(entry.previousHash).toBe(GENESIS_PREVIOUS_HASH);
    });

    it('should produce hccVersion = HCC_VERSION_CURRENT ("2.0.0"; v0.2 upgrade)', () => {
        const entry = appendHashChainEntry(
            { a: 1 },
            DEFAULT_IDENTITY,
            undefined,
        );
        expect(entry.hccVersion).toBe(HCC_VERSION_CURRENT);
        expect(entry.hccVersion).toBe('2.0.0');
    });

    it('should produce valid UUID v4 entryId', () => {
        const entry = appendHashChainEntry(
            { a: 1 },
            DEFAULT_IDENTITY,
            undefined,
        );
        expect(entry.entryId).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        );
    });

    it('should produce valid ISO 8601 timestamp', () => {
        const before = Date.now();
        const entry = appendHashChainEntry(
            { a: 1 },
            DEFAULT_IDENTITY,
            undefined,
        );
        const after = Date.now();
        const ts = new Date(entry.timestamp).getTime();
        expect(ts).toBeGreaterThanOrEqual(before);
        expect(ts).toBeLessThanOrEqual(after);
    });

    it('should produce 64 lowercase hex canonicalPayloadHash', () => {
        const entry = appendHashChainEntry(
            { a: 1 },
            DEFAULT_IDENTITY,
            undefined,
        );
        expect(entry.canonicalPayloadHash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce canonicalPayload = JCS canonical string', () => {
        const entry = appendHashChainEntry(
            { b: 2, a: 1 },
            DEFAULT_IDENTITY,
            undefined,
        );
        // JCS sort: a before b
        expect(entry.canonicalPayload).toBe('{"a":1,"b":2}');
    });

    it('should produce deterministic canonicalPayloadHash for same payload + same chainIdentity', () => {
        // same payload + same chainIdentity (genesis; previousHash fixed at GENESIS) -> same canonicalPayloadHash
        // (entryId and timestamp do not affect the hash; the hash is based only on the canonicalPayload + chainIdentityJcs preimage)
        const e1 = appendHashChainEntry({ x: 1 }, DEFAULT_IDENTITY, undefined);
        const e2 = appendHashChainEntry({ x: 1 }, DEFAULT_IDENTITY, undefined);
        expect(e1.canonicalPayloadHash).toBe(e2.canonicalPayloadHash);
    });

    it('should produce different canonicalPayloadHash for different payload (same identity)', () => {
        const e1 = appendHashChainEntry({ x: 1 }, DEFAULT_IDENTITY, undefined);
        const e2 = appendHashChainEntry({ x: 2 }, DEFAULT_IDENTITY, undefined);
        expect(e1.canonicalPayloadHash).not.toBe(e2.canonicalPayloadHash);
    });

    it('should include chainIdentity field (v0.2 all 8 fields mandatory)', () => {
        const id = makeChainIdentity('atp', 'bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb', 'L1');
        const entry = appendHashChainEntry({ a: 1 }, id, undefined);
        expect(entry.chainIdentity).toEqual(id);
        expect(entry.chainIdentity.chainNamespace).toBe('atp');
        expect(entry.chainIdentity.tenantId).toBe('bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb');
        expect(entry.chainIdentity.auditClass).toBe('L1');
    });
});

// ─── chainIdentity cross-partition (v0.2 I9 invariant — preimage cryptographic enforce) ─

describe('appendHashChainEntry — chainIdentity cross-partition (v0.2 I9 preimage enforce)', () => {
    it('should produce different canonicalPayloadHash for different chainNamespace (same payload)', () => {
        const payload = { event: 'audit', value: 42 };
        const idAtp = makeChainIdentity('atp');
        const idPolicy = makeChainIdentity('policy');

        const eAtp = appendHashChainEntry(payload, idAtp, undefined);
        const ePolicy = appendHashChainEntry(payload, idPolicy, undefined);

        expect(eAtp.canonicalPayload).toBe(ePolicy.canonicalPayload); // same payload -> same canonicalPayload
        expect(eAtp.canonicalPayloadHash).not.toBe(ePolicy.canonicalPayloadHash); // but hashes differ (chainIdentity enters the preimage)
    });

    it('should produce different hash when tenantId differs (same chainNamespace + payload)', () => {
        const payload = { event: 'audit' };
        const idA = makeChainIdentity('atp', 'dddddddd-1111-4111-8111-dddddddddddd', 'L1');
        const idB = makeChainIdentity('atp', 'eeeeeeee-1111-4111-8111-eeeeeeeeeeee', 'L1');

        const eA = appendHashChainEntry(payload, idA, undefined);
        const eB = appendHashChainEntry(payload, idB, undefined);

        expect(eA.canonicalPayloadHash).not.toBe(eB.canonicalPayloadHash);
    });

    it('should produce different hash when auditClass differs (L1 vs L3; same chainNamespace + tenantId + payload)', () => {
        const payload = { event: 'audit' };
        const idL1 = makeChainIdentity('atp', 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', 'L1');
        const idL3 = makeChainIdentity('atp', 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', 'L3');

        const eL1 = appendHashChainEntry(payload, idL1, undefined);
        const eL3 = appendHashChainEntry(payload, idL3, undefined);

        expect(eL1.canonicalPayloadHash).not.toBe(eL3.canonicalPayloadHash);
    });
});

// ─── append after genesis ───────────────────────────────────────────────────

describe('appendHashChainEntry — append after genesis (I3 + I4 guards)', () => {
    it('should link previousHash = lastEntry.canonicalPayloadHash', () => {
        const g = appendHashChainEntry(
            { msg: 'genesis' },
            DEFAULT_IDENTITY,
            undefined,
        );
        const next = appendHashChainEntry(
            { msg: 'second' },
            DEFAULT_IDENTITY,
            g,
        );
        expect(next.previousHash).toBe(g.canonicalPayloadHash);
    });

    it('should increment chainPosition by 1 (I4 monotonic)', () => {
        const g = appendHashChainEntry(
            { msg: 'g' },
            DEFAULT_IDENTITY,
            undefined,
        );
        const e1 = appendHashChainEntry(
            { msg: 'e1' },
            DEFAULT_IDENTITY,
            g,
        );
        const e2 = appendHashChainEntry(
            { msg: 'e2' },
            DEFAULT_IDENTITY,
            e1,
        );
        expect(g.chainPosition).toBe(0);
        expect(e1.chainPosition).toBe(1);
        expect(e2.chainPosition).toBe(2);
    });

    it('should chain 5 entries with monotonic positions + hash links', () => {
        let last: HashChainEntry | undefined;
        const chain: HashChainEntry[] = [];
        for (let i = 0; i < 5; i++) {
            const entry = appendHashChainEntry(
                { idx: i },
                DEFAULT_IDENTITY,
                last,
            );
            chain.push(entry);
            last = entry;
        }
        // Verify chainPosition values are 0,1,2,3,4
        for (let i = 0; i < 5; i++) {
            expect(chain[i]!.chainPosition).toBe(i);
        }
        // Verify previousHash linkage
        expect(chain[0]!.previousHash).toBe(GENESIS_PREVIOUS_HASH);
        for (let i = 1; i < 5; i++) {
            expect(chain[i]!.previousHash).toBe(
                chain[i - 1]!.canonicalPayloadHash,
            );
        }
    });
});

// ─── HC_SCHEMA_VIOLATION throw-path (chainIdentity field errors) ────────────────────

describe('appendHashChainEntry — HC_SCHEMA_VIOLATION chainIdentity edge case (v0.2)', () => {
    it('should throw HC_SCHEMA_VIOLATION when chainIdentity is null', () => {
        expect(() =>
            appendHashChainEntry(
                { a: 1 },
                null as unknown as ChainIdentity,
                undefined,
            ),
        ).toThrow(HashChainError);
        expect(() =>
            appendHashChainEntry(
                { a: 1 },
                null as unknown as ChainIdentity,
                undefined,
            ),
        ).toThrow(/HC_SCHEMA_VIOLATION/);
    });

    it('should throw HC_SCHEMA_VIOLATION when chainIdentity is undefined', () => {
        expect(() =>
            appendHashChainEntry(
                { a: 1 },
                undefined as unknown as ChainIdentity,
                undefined,
            ),
        ).toThrow(HashChainError);
    });

    it('should throw HC_SCHEMA_VIOLATION when chainNamespace empty string', () => {
        const bad = makeChainIdentity('');
        expect(() => appendHashChainEntry({ a: 1 }, bad, undefined)).toThrow(
            HashChainError,
        );
        expect(() => appendHashChainEntry({ a: 1 }, bad, undefined)).toThrow(
            /HC_SCHEMA_VIOLATION/,
        );
    });

    it('should throw HC_SCHEMA_VIOLATION when chainNamespace is sentinel "__NULL__"', () => {
        const bad = makeChainIdentity('__NULL__');
        expect(() => appendHashChainEntry({ a: 1 }, bad, undefined)).toThrow(
            HashChainError,
        );
        expect(() => appendHashChainEntry({ a: 1 }, bad, undefined)).toThrow(
            /__NULL__/,
        );
    });

    it('should throw HC_SCHEMA_VIOLATION when chainNamespace non-string', () => {
        const bad = {
            chainNamespace: 123 as unknown as ChainNamespace,
        } as ChainIdentity;
        expect(() => appendHashChainEntry({ a: 1 }, bad, undefined)).toThrow(
            HashChainError,
        );
    });

    it('should throw HC_SCHEMA_VIOLATION when tenantId is empty string (present-but-empty)', () => {
        const bad = makeChainIdentity('atp', '');
        expect(() => appendHashChainEntry({ a: 1 }, bad, undefined)).toThrow(
            HashChainError,
        );
    });

    it('should throw HC_SCHEMA_VIOLATION when auditClass is empty string (present-but-empty)', () => {
        const bad = makeChainIdentity('atp', 'bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb');
        // Inject an empty auditClass (bypassing makeChainIdentity's undefined check)
        const badWithEmptyAudit = {
            ...bad,
            auditClass: '' as unknown as 'L1',
        } as ChainIdentity;
        expect(() =>
            appendHashChainEntry({ a: 1 }, badWithEmptyAudit, undefined),
        ).toThrow(HashChainError);
    });
});

// ─── HC_SCHEMA_VIOLATION throw-path (lastEntry field errors; still enforced in v0.2) ────────

describe('appendHashChainEntry — HC_SCHEMA_VIOLATION lastEntry field errors', () => {
    it('should throw HC_SCHEMA_VIOLATION when lastEntry.canonicalPayloadHash missing', () => {
        const bad = {
            entryId: '550e8400-e29b-41d4-a716-446655440000' as HashChainEntryId,
            canonicalPayload: '{}',
            // canonicalPayloadHash missing
            previousHash: GENESIS_PREVIOUS_HASH as PreviousHash,
            chainPosition: 0 as ChainPosition,
            chainIdentity: DEFAULT_IDENTITY,
            timestamp: '2026-05-18T00:00:00.000Z' as Timestamp,
            hccVersion: '2.0.0' as HccVersionString,
        } as unknown as HashChainEntry;
        expect(() =>
            appendHashChainEntry({ a: 1 }, DEFAULT_IDENTITY, bad),
        ).toThrow(HashChainError);
        expect(() =>
            appendHashChainEntry({ a: 1 }, DEFAULT_IDENTITY, bad),
        ).toThrow(/HC_SCHEMA_VIOLATION/);
    });

    it('should throw HC_SCHEMA_VIOLATION when lastEntry.canonicalPayloadHash empty string', () => {
        const bad: HashChainEntry = {
            entryId: '550e8400-e29b-41d4-a716-446655440000' as HashChainEntryId,
            canonicalPayload: '{}',
            canonicalPayloadHash: '' as CanonicalPayloadHash,
            previousHash: GENESIS_PREVIOUS_HASH as PreviousHash,
            chainPosition: 0 as ChainPosition,
            chainIdentity: DEFAULT_IDENTITY,
            timestamp: '2026-05-18T00:00:00.000Z' as Timestamp,
            hccVersion: '2.0.0' as HccVersionString,
        };
        expect(() =>
            appendHashChainEntry({ a: 1 }, DEFAULT_IDENTITY, bad),
        ).toThrow(HashChainError);
    });

    it('should throw HC_SCHEMA_VIOLATION when lastEntry.chainPosition not number', () => {
        const bad = {
            entryId: '550e8400-e29b-41d4-a716-446655440000' as HashChainEntryId,
            canonicalPayload: '{}',
            canonicalPayloadHash:
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' as CanonicalPayloadHash,
            previousHash: GENESIS_PREVIOUS_HASH as PreviousHash,
            chainPosition: 'zero' as unknown as ChainPosition,
            chainIdentity: DEFAULT_IDENTITY,
            timestamp: '2026-05-18T00:00:00.000Z' as Timestamp,
            hccVersion: '2.0.0' as HccVersionString,
        } as HashChainEntry;
        expect(() =>
            appendHashChainEntry({ a: 1 }, DEFAULT_IDENTITY, bad),
        ).toThrow(HashChainError);
    });

    it('should throw HC_SCHEMA_VIOLATION when chainPosition overflow MAX_SAFE_INTEGER', () => {
        const bad: HashChainEntry = {
            entryId: '550e8400-e29b-41d4-a716-446655440000' as HashChainEntryId,
            canonicalPayload: '{}',
            canonicalPayloadHash:
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' as CanonicalPayloadHash,
            previousHash: GENESIS_PREVIOUS_HASH as PreviousHash,
            chainPosition: Number.MAX_SAFE_INTEGER as ChainPosition,
            chainIdentity: DEFAULT_IDENTITY,
            timestamp: '2026-05-18T00:00:00.000Z' as Timestamp,
            hccVersion: '2.0.0' as HccVersionString,
        };
        expect(() =>
            appendHashChainEntry({ a: 1 }, DEFAULT_IDENTITY, bad),
        ).toThrow(HashChainError);
        expect(() =>
            appendHashChainEntry({ a: 1 }, DEFAULT_IDENTITY, bad),
        ).toThrow(/overflow/);
    });
});

// ─── HC_CANONICALIZE_FAILED throw-path (propagating a canonicalize failure) ──────────────

describe('appendHashChainEntry — HC_CANONICALIZE_FAILED (propagating a canonicalize failure)', () => {
    it('should throw HC_CANONICALIZE_FAILED for payload with undefined field', () => {
        expect(() =>
            appendHashChainEntry(
                { x: undefined } as unknown as Record<string, unknown>,
                DEFAULT_IDENTITY,
                undefined,
            ),
        ).toThrow(HashChainError);
        expect(() =>
            appendHashChainEntry(
                { x: undefined } as unknown as Record<string, unknown>,
                DEFAULT_IDENTITY,
                undefined,
            ),
        ).toThrow(/HC_CANONICALIZE_FAILED/);
    });

    it('should throw HC_CANONICALIZE_FAILED for payload with NaN field', () => {
        expect(() =>
            appendHashChainEntry({ n: NaN }, DEFAULT_IDENTITY, undefined),
        ).toThrow(HashChainError);
    });

    it('should throw HC_CANONICALIZE_FAILED for circular ref payload', () => {
        const obj: Record<string, unknown> = { a: 1 };
        obj.self = obj;
        expect(() =>
            appendHashChainEntry(obj, DEFAULT_IDENTITY, undefined),
        ).toThrow(HashChainError);
    });
});

// ─── canonicalPayload + hash consistency ─────────────────────────────────────────

describe('appendHashChainEntry — canonicalPayload + canonicalPayloadHash consistency (I1+I2+I9)', () => {
    it('should produce canonicalPayload that re-canonicalizes to itself (I1 JCS idempotence)', () => {
        const entry = appendHashChainEntry(
            { b: 2, a: 1, c: [3, 2, 1] },
            DEFAULT_IDENTITY,
            undefined,
        );
        const parsed = JSON.parse(entry.canonicalPayload) as Record<
            string,
            unknown
        >;
        // Re-canonicalizing equals the stored value exactly
        const entry2 = appendHashChainEntry(parsed, DEFAULT_IDENTITY, undefined);
        expect(entry2.canonicalPayload).toBe(entry.canonicalPayload);
        // same chainIdentity + same canonicalPayload -> same canonicalPayloadHash (I9 confirm)
        expect(entry2.canonicalPayloadHash).toBe(entry.canonicalPayloadHash);
    });

    it('should produce same hash for different field order in input (JCS sort)', () => {
        // {a:1,b:2} JCS -> {"a":1,"b":2}; canonicalPayload uniqueness -> same hash
        const e1 = appendHashChainEntry(
            { a: 1, b: 2 },
            DEFAULT_IDENTITY,
            undefined,
        );
        const e2 = appendHashChainEntry(
            { b: 2, a: 1 },
            DEFAULT_IDENTITY,
            undefined,
        );
        expect(e1.canonicalPayload).toBe(e2.canonicalPayload);
        expect(e1.canonicalPayloadHash).toBe(e2.canonicalPayloadHash);
    });
});
