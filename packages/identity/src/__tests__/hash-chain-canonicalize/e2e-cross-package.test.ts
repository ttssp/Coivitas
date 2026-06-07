/**
 * e2e-cross-package.test.ts — HCC L0 (types) + L1 (crypto) cross-package end-to-end integration test
 *
 * Scope: hcc v0.1 L1 crypto
 *
 * Placement (same pattern as csp e2e-cross-package.test.ts):
 *   The identity (L2) package is the first layer to depend on both @coivitas/types (L0) and @coivitas/crypto (L1);
 *   L1 is strictly forbidden from depending on L0 (anti-layering), so the e2e test spanning L0+L1 must live in an L2+ package (identity chosen here).
 *
 * Coverage targets (>=3 cases):
 *   - case 1 (happy): L0 schema PASS -> L1 append -> L1 verify PASS;
 *   - case 2 (schema reject): payload missing entryId / wrong field -> L0 validateHashChainEntrySchema reject;
 *   - case 3 (chain reject): tamper canonicalPayload / previousHash -> L1 verifyHashChain throws HC_*;
 *
 * Cross-package contract (anti-phantom + anti cross-package drift):
 *   - L0 (@coivitas/types): HashChainEntry schema + HccErrorCode union covering the 6 frozen items;
 *   - L1 (@coivitas/crypto): canonicalizeHashChainEntry + appendHashChainEntry + verifyHashChain
 *     throw the spec's 6 frozen error codes;
 *   - L0/L1 bidirectional contract: schema reject <-> AJV 3rd defense layer; chain reject <-> verify-hash recompute 1st defense layer;
 *   - the L3 manager chains these e2e three layers + the chainIdentity contract;
 *     this file does not cover L3.
 */

import { describe, expect, it } from 'vitest';

import {
    appendHashChainEntry,
    canonicalizeHashChainEntryToString,
    verifyHashChain,
} from '@coivitas/crypto';
import {
    GENESIS_PREVIOUS_HASH,
    HashChainError,
    toChainNamespace,
    validateHashChainEntrySchema,
    type CanonicalPayloadHash,
    type ChainIdentity,
    type HashChainEntry,
    type PreviousHash,
} from '@coivitas/types';

// main session inline cascade fix anchor — v0.2 upgraded appendHashChainEntry(payload, chainIdentity, lastEntry)
// Default test ChainIdentity (chainNamespace brand via the toChainNamespace factory + tenantId/auditClass valid UUID)
const TEST_CHAIN_IDENTITY: ChainIdentity = {
    chainNamespace: toChainNamespace('atp'),
    tenantId: '11111111-1111-4111-8111-111111111111',
    auditClass: 'L1',
};

// ─── case 1: happy path full round-trip ─────────────────────────────────────

describe('e2e cross-package — case 1 happy path L0 schema + L1 append + L1 verify', () => {
    it('should round-trip L0 schema validate → L1 append → L1 verify (3 entries chain)', () => {
        // step 1: L1 append (generate entry)
        const entry0 = appendHashChainEntry(
            { event: 'init', userId: 'alice' },
            TEST_CHAIN_IDENTITY,
            undefined,
        );
        const entry1 = appendHashChainEntry(
            { event: 'action', userId: 'alice', target: 'res1' },
            TEST_CHAIN_IDENTITY,
            entry0,
        );
        const entry2 = appendHashChainEntry(
            { event: 'commit', userId: 'alice', target: 'res1' },
            TEST_CHAIN_IDENTITY,
            entry1,
        );

        // step 2: L0 schema validate (each entry must PASS; contract verification)
        for (const entry of [entry0, entry1, entry2]) {
            const result = validateHashChainEntrySchema(entry);
            expect(result.valid).toBe(true);
        }

        // step 3: L1 verifyHashChain (full chain PASS)
        expect(() => verifyHashChain([entry0, entry1, entry2])).not.toThrow();

        // Additional contract: chain identity fields stay stable
        expect(entry0.chainPosition).toBe(0);
        expect(entry0.previousHash).toBe(GENESIS_PREVIOUS_HASH);
        expect(entry1.previousHash).toBe(entry0.canonicalPayloadHash);
        expect(entry2.previousHash).toBe(entry1.canonicalPayloadHash);
    });

    it('should produce deterministic canonicalPayload across L0+L1 boundaries (JCS uniqueness I1)', () => {
        // L1 append produces entry.canonicalPayload (JCS) ->
        // an L0/L1 cross-package call to canonicalizeHashChainEntryToString with the same input -> the same output
        const payload = { z: 1, a: 2, m: { y: 3, x: 4 } };
        const entry = appendHashChainEntry(payload, TEST_CHAIN_IDENTITY, undefined);
        const reCanonical = canonicalizeHashChainEntryToString(payload);
        expect(entry.canonicalPayload).toBe(reCanonical);
    });

    it('should pass L0 schema for valid entry built by L1 append', () => {
        const entry = appendHashChainEntry(
            { complex: { nested: { array: [1, 2, 3] } } },
            TEST_CHAIN_IDENTITY,
            undefined,
        );
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(true);
    });
});

// ─── case 2: L0 schema reject (cross-package contract — schema is the 2nd+3rd defense layer) ─

describe('e2e cross-package — case 2 schema reject', () => {
    it('should L0 reject entry missing required entryId field', () => {
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        const bad = { ...entry } as Partial<HashChainEntry>;
        delete bad.entryId;
        const result = validateHashChainEntrySchema(bad);
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(
                result.errors.some(
                    (e) =>
                        e.keyword === 'required' ||
                        e.message.includes('entryId'),
                ),
            ).toBe(true);
        }
    });

    it('should L0 reject entry with additionalProperties (strict closed schema)', () => {
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        const bad = {
            ...entry,
            phantomField: 'should-not-pass',
        };
        const result = validateHashChainEntrySchema(bad);
        expect(result.valid).toBe(false);
    });

    it('should L0 reject entry with malformed UUID entryId (format check)', () => {
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        const bad = { ...entry, entryId: 'not-a-uuid' };
        const result = validateHashChainEntrySchema(bad);
        expect(result.valid).toBe(false);
    });

    it('should L0 reject entry with hccVersion != "2.0.0" (v0.2 const enforce)', () => {
        // v0.2 upgrade: hccVersion's only valid value is "2.0.0"; anything other than "2.0.0" is rejected (including the old "1.0.0")
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        const bad = { ...entry, hccVersion: '1.0.0' };
        const result = validateHashChainEntrySchema(bad);
        expect(result.valid).toBe(false);
    });

    it('should L0 reject entry with negative chainPosition', () => {
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        const bad = { ...entry, chainPosition: -1 };
        const result = validateHashChainEntrySchema(bad);
        expect(result.valid).toBe(false);
    });
});

// ─── case 3: L1 chain reject (cross-package contract — verifyHashChain fail-closed) ─

describe('e2e cross-package — case 3 chain verify reject', () => {
    it('should L1 verifyHashChain throw HC_CHAIN_IDENTITY_PREIMAGE_FAILED on canonicalPayload tamper', () => {
        const entry = appendHashChainEntry({ msg: 'original' }, TEST_CHAIN_IDENTITY, undefined);
        const tampered: HashChainEntry = {
            ...entry,
            canonicalPayload: '{"msg":"tampered"}',
        };
        expect(() => verifyHashChain([tampered])).toThrow(HashChainError);
        try {
            verifyHashChain([tampered]);
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            // recomputed canonicalPayload hash does not match -> HC_CHAIN_IDENTITY_PREIMAGE_FAILED
            expect((e as HashChainError).code).toBe(
                'HC_CHAIN_IDENTITY_PREIMAGE_FAILED',
            );
        }
    });

    it('should L1 verifyHashChain throw HC_PREVIOUS_HASH_BROKEN on chain break (middle entry deleted)', () => {
        const e0 = appendHashChainEntry({ a: 0 }, TEST_CHAIN_IDENTITY, undefined);
        const e1 = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, e0);
        const e2 = appendHashChainEntry({ a: 2 }, TEST_CHAIN_IDENTITY, e1);
        // Delete e1 -> e2 is reindexed to chainPosition 1 (relative to the array index; but previousHash still points to e1)
        const bad = [
            e0,
            { ...e2, chainPosition: 1 as HashChainEntry['chainPosition'] },
        ];
        try {
            verifyHashChain(bad);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            // After deleting e1, e2 is at array[1]; e2.previousHash === e1.canonicalPayloadHash != e0.canonicalPayloadHash -> HC_PREVIOUS_HASH_BROKEN
            expect((e as HashChainError).code).toBe('HC_PREVIOUS_HASH_BROKEN');
        }
    });

    it('should L1 verifyHashChain throw HC_CHAIN_POSITION_NONMONOTONIC on chainPosition jump', () => {
        const e0 = appendHashChainEntry({ a: 0 }, TEST_CHAIN_IDENTITY, undefined);
        const e1 = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, e0);
        const bad = [
            e0,
            {
                ...e1,
                chainPosition: 5 as HashChainEntry['chainPosition'],
            },
        ];
        try {
            verifyHashChain(bad);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            expect((e as HashChainError).code).toBe(
                'HC_CHAIN_POSITION_NONMONOTONIC',
            );
        }
    });

    it('should L1 verifyHashChain throw HC_SCHEMA_VIOLATION on schema-invalid entry', () => {
        const e0 = appendHashChainEntry({ a: 0 }, TEST_CHAIN_IDENTITY, undefined);
        // Tamper the entry to be schema-invalid (multiple mistakes: hex case + chainPosition int -> string)
        const bad = {
            ...e0,
            canonicalPayloadHash: 'NOT-VALID-HEX' as CanonicalPayloadHash,
        };
        try {
            verifyHashChain([bad]);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            expect((e as HashChainError).code).toBe('HC_SCHEMA_VIOLATION');
        }
    });
});

// ─── case 4: bonus — L0 PASS ⊃ L1 PASS contract verify (bidirectional cross-package loop) ────────

describe('e2e cross-package — case 4 contract verify (L0 PASS ⊃ L1 PASS; bidirectional)', () => {
    it('should every L1-built entry pass L0 schema validate (contract: L1 append -> L0 schema PASS)', () => {
        // 5 entries, each must pass L0 schema
        let last: HashChainEntry | undefined;
        const chain: HashChainEntry[] = [];
        for (let i = 0; i < 5; i++) {
            const entry = appendHashChainEntry({ idx: i, data: `e${i}` }, TEST_CHAIN_IDENTITY, last);
            chain.push(entry);
            last = entry;
        }
        for (const entry of chain) {
            const result = validateHashChainEntrySchema(entry);
            expect(result.valid).toBe(true);
        }
    });

    it('should L1 verifyHashChain PASS for all L1-built chains (contract: L1 append -> L1 verify PASS)', () => {
        // Chains of different sizes (1/3/10) must all verify PASS
        for (const size of [1, 3, 10]) {
            const payloads = Array.from({ length: size }, (_, i) => ({
                idx: i,
                seed: Math.random(),
            }));
            let last: HashChainEntry | undefined;
            const chain: HashChainEntry[] = [];
            for (const payload of payloads) {
                const entry = appendHashChainEntry(payload, TEST_CHAIN_IDENTITY, last);
                chain.push(entry);
                last = entry;
            }
            expect(() => verifyHashChain(chain)).not.toThrow();
        }
    });

    it('should L0+L1 contract: schema reject <-> verifyHashChain throw HC_SCHEMA_VIOLATION stay in sync', () => {
        // A schema-rejected entry must make verifyHashChain throw HC_SCHEMA_VIOLATION (not some other HC_* code)
        const e0 = appendHashChainEntry({ a: 0 }, TEST_CHAIN_IDENTITY, undefined);
        // Tamper to schema-invalid (timestamp not ISO 8601)
        const bad = {
            ...e0,
            timestamp: '2026/05/18' as HashChainEntry['timestamp'],
        };
        // L0 reject
        expect(validateHashChainEntrySchema(bad).valid).toBe(false);
        // L1 verifyHashChain also rejects (HC_SCHEMA_VIOLATION from the same source)
        try {
            verifyHashChain([bad]);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            expect((e as HashChainError).code).toBe('HC_SCHEMA_VIOLATION');
        }
    });
});

// ─── case 5: genesis anchor + previousHash verification ────────────────────────────

describe('e2e cross-package — case 5 GENESIS_PREVIOUS_HASH (L0 const + L1 use)', () => {
    it('should L0 expose GENESIS_PREVIOUS_HASH = "0".repeat(64)', () => {
        expect(GENESIS_PREVIOUS_HASH).toBe('0'.repeat(64));
        expect(GENESIS_PREVIOUS_HASH.length).toBe(64);
    });

    it('should L1 appendHashChainEntry use GENESIS_PREVIOUS_HASH for genesis', () => {
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        expect(entry.previousHash).toBe(GENESIS_PREVIOUS_HASH);
    });

    it('should L1 verifyHashChain enforce GENESIS_PREVIOUS_HASH for entry[0]', () => {
        const entry = appendHashChainEntry({ a: 1 }, TEST_CHAIN_IDENTITY, undefined);
        const bad = {
            ...entry,
            previousHash: '1'.repeat(64) as PreviousHash,
        };
        try {
            verifyHashChain([bad]);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            expect((e as HashChainError).code).toBe('HC_PREVIOUS_HASH_BROKEN');
        }
    });
});
