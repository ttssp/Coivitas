/**
 * cross-lang-reverse-fixture.test.ts — cross-lang HCC reverse fixture consumer (Python Producer -> TS Consumer)
 *
 * Role
 * ----
 * Python HCC v0.2 (packages/sdk-python/src/coivitas/hash_chain_canonicalize)
 * acts as the Python Producer of cross-lang golden bytes; this file is the TS-side consumer test.
 * fixture path: tests/fixtures/cross-lang/hcc-reverse-vectors.json
 * generation command: cd packages/sdk-python && python3 scripts/generate-hcc-reverse-fixtures.py --regenerate
 *
 * Path adjustment note (vs the literal task requirement packages/crypto/test/):
 *   crypto vitest.config.ts include = ['src/**\/*.test.ts']
 *   existing HCC tests all live under src/__tests__/hash-chain-canonicalize/ (consistent with project convention)
 *   this test is placed in the same directory so vitest picks it up automatically; no vitest.config change needed
 *
 * A21 anti-self-equal principle
 * ---------------------
 * The expected value must be read from the fixture JSON; the same test must not both compute and assert the expected value.
 * Correct form:
 *   const expectedHash = vector.expected_canonical_payload_hash_per_position[i]; // from fixture
 *   const actualHash = computeCanonicalPayloadHashHex(preimage); // TS recompute
 *   expect(actualHash).toBe(expectedHash);
 *
 * cross-lang anchor coverage (reverse round-trip)
 * --------------------------------------
 * 1. JCS canonicalize (Python jcs/stdlib fallback <-> TS canonicalize npm): RFC 8785 byte-level
 * 2. preimage concat order (canonicalPayloadBytes || chainIdentityJcsBytes)
 * 3. SHA-256 hash byte-level (Python hashlib <-> TS @noble/hashes)
 * 4. recursive hash linkage (previousHash linkage across entries)
 * 5. NEGATIVE: mixed-identity reject (RV6) + tampered hash reject (RV7)
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
    HashChainError,
    type CanonicalPayloadHash,
    type ChainIdentity,
    type ChainNamespace,
    type HashChainEntry,
} from '@coivitas/types';

import {
    canonicalizeChainIdentity,
    computeCanonicalPayloadHashHex,
    concatPreimage,
    verifyHashChain,
} from '../../hash-chain-canonicalize/index.js';

// ─── path constants ──────────────────────────────────────────────────────────────
// __tests__/hash-chain-canonicalize -> src/ -> crypto/ -> packages/ -> REPO_ROOT
const __filename = fileURLToPath(import.meta.url);
const FIXTURE_PATH = resolve(
    __filename,
    '..',
    '..',
    '..',
    '..',
    '..',
    '..',
    'tests',
    'fixtures',
    'cross-lang',
    'hcc-reverse-vectors.json',
);

// ─── Fixture types (Python Producer output structure) ─────────────────────────────

interface FixtureEntry {
    entryId: string;
    canonicalPayload: string;
    canonicalPayloadHash: string;
    previousHash: string;
    chainPosition: number;
    chainIdentity: { chainNamespace: string; tenantId?: string; auditClass?: string };
    timestamp: string;
    hccVersion: string;
}

interface FixtureVector {
    id: string;
    description: string;
    chainIdentity: { chainNamespace: string; tenantId?: string; auditClass?: string };
    entries: FixtureEntry[];
    expected_concat_preimage_hex_per_position: string[];
    expected_canonical_payload_hash_per_position: string[];
    expected_final_hash: string;
    expected_verify_outcome: 'PASS' | 'REJECT';
    expected_reject_error_substring?: string;
    expected_reject_error_code?: string;
    tamper_description?: string;
}

interface FixtureFile {
    version: string;
    generated_by: string;
    python_canonicalize_lib: string;
    python_hash_lib: string;
    hcc_version: string;
    preimage_order: string;
    vectors: FixtureVector[];
}

// ─── Fixture loading + entry conversion helpers ─────────────────────────────────────

function loadFixture(): FixtureFile {
    const raw = readFileSync(FIXTURE_PATH, 'utf-8');
    return JSON.parse(raw) as FixtureFile;
}

/**
 * fixtureEntryToHashChainEntry — fixture JSON dict -> TS HashChainEntry typed object
 *
 * TS verifyHashChain accepts the HashChainEntry interface; the fixture already carries all required fields
 * (the 8 fields map 1:1 to the TS interface). This helper does a type cast, not a conversion — field values are kept as-is,
 * with only a type assertion; nothing is mutated at runtime.
 */
function fixtureEntryToHashChainEntry(e: FixtureEntry): HashChainEntry {
    // Use a type assertion; field names + values are literally identical to the HashChainEntry interface
    return e as unknown as HashChainEntry;
}

/**
 * fixtureIdentityToChainIdentity — fixture chainIdentity dict -> TS ChainIdentity typed
 *
 * Contains only present fields (tenantId / auditClass are optional; a Python-side NotRequired field
 * does not appear in the JSON when absent); the TS interface defines them as optional too; this helper does a type cast.
 */
function fixtureIdentityToChainIdentity(d: {
    chainNamespace: string;
    tenantId?: string;
    auditClass?: string;
}): ChainIdentity {
    return {
        chainNamespace: d.chainNamespace as ChainNamespace,
        ...(d.tenantId !== undefined && { tenantId: d.tenantId }),
        ...(d.auditClass !== undefined && {
            auditClass: d.auditClass as 'L1' | 'L2' | 'L3',
        }),
    };
}

// ─── metadata verification ──────────────────────────────────────────────────────────

describe('cross-lang reverse fixture — Python Producer metadata', () => {
    it('should load version v0.2 and hcc_version 2.0.0 when fixture is read', () => {
        const fixture = loadFixture();
        expect(fixture.version).toBe('v0.2');
        expect(fixture.hcc_version).toBe('2.0.0');
    });

    it('should contain 7 vectors (RV1-RV5 PASS + RV6/RV7 NEGATIVE) when fixture is loaded', () => {
        const fixture = loadFixture();
        expect(fixture.vectors).toHaveLength(7);
        const ids = fixture.vectors.map((v) => v.id);
        expect(ids).toContain('RV1-py-genesis-only');
        expect(ids).toContain('RV2-py-three-entry-chain');
        expect(ids).toContain('RV3-py-five-entry-chain');
        expect(ids).toContain('RV4-py-japanese-emoji-payload');
        expect(ids).toContain('RV5-py-multi-field-identity');
        expect(ids).toContain('RV6-py-NEGATIVE-mixed-identity');
        expect(ids).toContain('RV7-py-NEGATIVE-tampered-hash');
    });

    it('should declare preimage_order matching TS Producer', () => {
        const fixture = loadFixture();
        expect(fixture.preimage_order).toContain(
            'canonicalPayloadBytes || chainIdentityJcsBytes',
        );
    });
});

// ─── PASS vectors (RV1-RV5) byte-exact cross-lang anchor verification ─────────────

describe('cross-lang reverse fixture — RV1-RV5 PASS byte-exact anchor', () => {
    it('should byte-exact match concat preimage per position when consuming Python fixture (RV1-RV5)', () => {
        const fixture = loadFixture();
        const failures: string[] = [];

        for (const v of fixture.vectors) {
            if (v.expected_verify_outcome !== 'PASS') continue;
            const identity = fixtureIdentityToChainIdentity(v.chainIdentity);
            const identityJcs = canonicalizeChainIdentity(identity);

            for (let i = 0; i < v.entries.length; i++) {
                const entry = v.entries[i]!;
                // TS recomputes the preimage (using the literal canonicalPayload from the Python fixture + the recomputed identity JCS)
                const preimage = concatPreimage(entry.canonicalPayload, identityJcs);
                const actualHex = Buffer.from(preimage).toString('hex');
                // A21: expected comes from the fixture (Python-produced); TS does not recompute expected
                const expectedHex =
                    v.expected_concat_preimage_hex_per_position[i]!;
                if (actualHex !== expectedHex) {
                    failures.push(
                        `  ${v.id} entry[${i}]:\n` +
                            `    expected = ${expectedHex}\n` +
                            `    actual   = ${actualHex}`,
                    );
                }
            }
        }

        expect(failures, `concat preimage diverged for ${failures.length} entries:\n${failures.join('\n')}`).toEqual([]);
    });

    it('should byte-exact match canonical payload hash per position when consuming Python fixture (RV1-RV5)', () => {
        const fixture = loadFixture();
        const failures: string[] = [];

        for (const v of fixture.vectors) {
            if (v.expected_verify_outcome !== 'PASS') continue;
            const identity = fixtureIdentityToChainIdentity(v.chainIdentity);
            const identityJcs = canonicalizeChainIdentity(identity);

            for (let i = 0; i < v.entries.length; i++) {
                const entry = v.entries[i]!;
                const preimage = concatPreimage(entry.canonicalPayload, identityJcs);
                const actualHash = computeCanonicalPayloadHashHex(preimage);
                // A21: expected comes from the fixture
                const expectedHash =
                    v.expected_canonical_payload_hash_per_position[i]!;
                if (actualHash !== expectedHash) {
                    failures.push(
                        `  ${v.id} entry[${i}]:\n` +
                            `    expected = ${expectedHash}\n` +
                            `    actual   = ${actualHash}`,
                    );
                }
                // In a PASS vector the stored canonicalPayloadHash should equal the recomputed value
                if (entry.canonicalPayloadHash !== expectedHash) {
                    failures.push(
                        `  ${v.id} entry[${i}] stored vs expected:\n` +
                            `    stored   = ${entry.canonicalPayloadHash}\n` +
                            `    expected = ${expectedHash}`,
                    );
                }
            }
        }

        expect(failures, `canonical payload hash diverged for ${failures.length} entries:\n${failures.join('\n')}`).toEqual([]);
    });

    it('should verify all PASS vectors when loading Python-generated fixture (RV1-RV5)', () => {
        const fixture = loadFixture();
        const failures: string[] = [];

        for (const v of fixture.vectors) {
            if (v.expected_verify_outcome !== 'PASS') continue;
            const entries = v.entries.map(fixtureEntryToHashChainEntry);
            const expectedIdentity = fixtureIdentityToChainIdentity(v.chainIdentity);

            try {
                // Run verifyHashChain (chain-level identity consistency + recursive hash + per-entry verify)
                verifyHashChain(entries, { expectedChainIdentity: expectedIdentity });
            } catch (exc) {
                const errMsg = exc instanceof Error ? exc.message : String(exc);
                failures.push(`  ${v.id}: verifyHashChain threw: ${errMsg}`);
            }
        }

        expect(failures, `verifyHashChain unexpectedly rejected ${failures.length} PASS vector(s):\n${failures.join('\n')}`).toEqual([]);
    });

    it('should verify previousHash recursive linkage for RV2-RV5 multi-entry chains', () => {
        const fixture = loadFixture();
        const failures: string[] = [];
        const GENESIS_ZERO = '0'.repeat(64);

        for (const v of fixture.vectors) {
            if (v.expected_verify_outcome !== 'PASS') continue;
            if (v.entries.length < 2) continue; // skip RV1 single-entry

            // Each entry[i].previousHash must equal entry[i-1].canonicalPayloadHash
            for (let i = 1; i < v.entries.length; i++) {
                const prevHashField = v.entries[i]!.previousHash;
                const prevCanonicalHash = v.entries[i - 1]!.canonicalPayloadHash;
                if (prevHashField !== prevCanonicalHash) {
                    failures.push(
                        `  ${v.id} entry[${i}].previousHash=${prevHashField} != ` +
                            `entries[${i - 1}].canonicalPayloadHash=${prevCanonicalHash}`,
                    );
                }
            }
            // genesis entry[0].previousHash must be 64 zeros
            if (v.entries[0]!.previousHash !== GENESIS_ZERO) {
                failures.push(
                    `  ${v.id} entry[0].previousHash != 64-zero sentinel: ${v.entries[0]!.previousHash}`,
                );
            }
        }

        expect(failures, `recursive hash linkage broken for ${failures.length} entries:\n${failures.join('\n')}`).toEqual([]);
    });

    it('should handle Japanese hiragana + katakana + emoji payload when consuming RV4', () => {
        // RV4 contains Japanese ひらがな + カタカナ + emoji (🦀 / 🐍 / 🌸);
        // verify that TS canonicalize npm and Python jcs/stdlib agree byte-for-byte on UTF-8 + field code-point sorting
        const fixture = loadFixture();
        const rv4 = fixture.vectors.find((v) => v.id === 'RV4-py-japanese-emoji-payload');
        expect(rv4).toBeDefined();
        const v = rv4!;

        const identity = fixtureIdentityToChainIdentity(v.chainIdentity);
        const identityJcs = canonicalizeChainIdentity(identity);

        for (let i = 0; i < v.entries.length; i++) {
            const entry = v.entries[i]!;
            // canonicalPayload contains ひらがな + カタカナ + emoji characters — must be UTF-8 encoded correctly
            const preimage = concatPreimage(entry.canonicalPayload, identityJcs);
            const expectedHex = v.expected_concat_preimage_hex_per_position[i]!;
            expect(
                Buffer.from(preimage).toString('hex'),
                `RV4 entry[${i}] preimage mismatch (Unicode UTF-8 cross-lang divergence?)`,
            ).toBe(expectedHex);

            const actualHash = computeCanonicalPayloadHashHex(preimage);
            const expectedHash = v.expected_canonical_payload_hash_per_position[i]!;
            expect(actualHash).toBe(expectedHash);
        }
    });
});

// ─── NEGATIVE vectors (RV6 mixed-identity + RV7 tampered hash) reject verification ─

describe('cross-lang reverse fixture — RV6 mixed-identity reject', () => {
    it('should reject mixed-identity chain when consuming Python negative fixture RV6', () => {
        const fixture = loadFixture();
        const rv6 = fixture.vectors.find((v) => v.id === 'RV6-py-NEGATIVE-mixed-identity');
        expect(rv6).toBeDefined();
        const v = rv6!;
        expect(v.expected_verify_outcome).toBe('REJECT');
        // The TS error code declared literally in the fixture (the Python Producer knows the TS-side naming)
        expect(v.expected_reject_error_code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');

        const entries = v.entries.map(fixtureEntryToHashChainEntry);

        // Without passing expectedChainIdentity — the chain-level identity consistency check
        // (entry[0] vs entry[1] with different chainIdentity) must also reject (TS L313-320)
        expect(() => verifyHashChain(entries)).toThrow(HashChainError);
        try {
            verifyHashChain(entries);
            // unreachable
            expect.fail('verifyHashChain should have thrown for RV6 mixed-identity');
        } catch (exc) {
            expect(exc).toBeInstanceOf(HashChainError);
            const hcErr = exc as HashChainError;
            expect(hcErr.code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');
            // Error message substring verification (defined literally in the fixture)
            const expectedSubstring = v.expected_reject_error_substring!;
            expect(
                hcErr.message,
                `RV6 expected error message containing "${expectedSubstring}", got: ${hcErr.message}`,
            ).toContain(expectedSubstring);
        }
    });

    it('should reject RV6 with scope isolation when expectedChainIdentity provided (audit-A scope)', () => {
        // Pass the audit-A scope as expected: entry[0] matches, entry[1] (audit-B) mismatches (mixed)
        const fixture = loadFixture();
        const v = fixture.vectors.find((vec) => vec.id === 'RV6-py-NEGATIVE-mixed-identity')!;
        const entries = v.entries.map(fixtureEntryToHashChainEntry);
        const expectedA = fixtureIdentityToChainIdentity(v.chainIdentity); // audit-A

        expect(() => verifyHashChain(entries, { expectedChainIdentity: expectedA })).toThrow(
            HashChainError,
        );
        try {
            verifyHashChain(entries, { expectedChainIdentity: expectedA });
            expect.fail('verifyHashChain should have thrown');
        } catch (exc) {
            const hcErr = exc as HashChainError;
            expect(hcErr.code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');
        }
    });
});

describe('cross-lang reverse fixture — RV7 tampered hash reject', () => {
    it('should reject tampered hash chain when consuming Python negative fixture RV7', () => {
        const fixture = loadFixture();
        const rv7 = fixture.vectors.find((v) => v.id === 'RV7-py-NEGATIVE-tampered-hash');
        expect(rv7).toBeDefined();
        const v = rv7!;
        expect(v.expected_verify_outcome).toBe('REJECT');
        expect(v.expected_reject_error_code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');

        const entries = v.entries.map(fixtureEntryToHashChainEntry);
        const expectedIdentity = fixtureIdentityToChainIdentity(v.chainIdentity);

        expect(() => verifyHashChain(entries, { expectedChainIdentity: expectedIdentity })).toThrow(
            HashChainError,
        );
        try {
            verifyHashChain(entries, { expectedChainIdentity: expectedIdentity });
            expect.fail('verifyHashChain should have thrown for RV7 tampered hash');
        } catch (exc) {
            expect(exc).toBeInstanceOf(HashChainError);
            const hcErr = exc as HashChainError;
            // RV7 has a single chainIdentity — the chain-level identity consistency check passes;
            // the hash recompute check fails -> HC_CHAIN_IDENTITY_PREIMAGE_FAILED
            expect(hcErr.code).toBe('HC_CHAIN_IDENTITY_PREIMAGE_FAILED');
            const expectedSubstring = v.expected_reject_error_substring!;
            expect(
                hcErr.message,
                `RV7 expected error message containing "${expectedSubstring}", got: ${hcErr.message}`,
            ).toContain(expectedSubstring);
        }
    });

    it('should compute preimage hex byte-exact for RV7 pristine value (pre-tamper)', () => {
        // RV7 entry[2].canonicalPayloadHash is the tampered, flipped value;
        // expected_canonical_payload_hash_per_position[2] is the original (pre-tamper) value.
        // TS recompute should equal the pre-tamper value (an anchor for preimage->hash algorithm correctness).
        const fixture = loadFixture();
        const v = fixture.vectors.find((vec) => vec.id === 'RV7-py-NEGATIVE-tampered-hash')!;
        const identity = fixtureIdentityToChainIdentity(v.chainIdentity);
        const identityJcs = canonicalizeChainIdentity(identity);

        const lastIdx = v.entries.length - 1;
        const lastEntry = v.entries[lastIdx]!;
        const preimage = concatPreimage(lastEntry.canonicalPayload, identityJcs);
        const actualHex = Buffer.from(preimage).toString('hex');
        // A21: expected_concat_preimage_hex comes from the fixture
        const expectedHex = v.expected_concat_preimage_hex_per_position[lastIdx]!;
        expect(actualHex).toBe(expectedHex);

        // The recomputed hash should equal the fixture's pre-tamper expected (i.e. the "correct value" other than entry[2].canonicalPayloadHash)
        const actualHash = computeCanonicalPayloadHashHex(preimage);
        const expectedHash = v.expected_canonical_payload_hash_per_position[lastIdx]!;
        expect(actualHash).toBe(expectedHash);

        // Verify stored (post-tamper) != expected (pre-tamper)
        expect(
            (lastEntry.canonicalPayloadHash as CanonicalPayloadHash) !==
                (expectedHash as CanonicalPayloadHash),
            'RV7 stored canonicalPayloadHash should differ from pre-tamper expected',
        ).toBe(true);

        // And the difference is exactly 1 character (flipped tamper_last_hash_char_index=-1, the last char)
        let diffCount = 0;
        for (let i = 0; i < lastEntry.canonicalPayloadHash.length; i++) {
            if (lastEntry.canonicalPayloadHash[i] !== expectedHash[i]) {
                diffCount++;
            }
        }
        expect(diffCount, `RV7 expected 1-char diff between stored and pre-tamper hash, got ${diffCount} diffs`).toBe(1);
    });
});
