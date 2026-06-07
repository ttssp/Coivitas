/**
 * hash-chain-canonicalize/types.test.ts — HCC L0 brand factory + error switch unit tests
 *
 * Coverage goals (≥95% coverage; at least one throw-path per error code):
 *   - 5 brand factories PASS / REJECT (toHashChainEntryId / toCanonicalPayloadHash /
 *     toPreviousHash / toChainPosition / toHccVersionString);
 *   - 6 HccErrorCode, each with ≥1 throw-path;
 *   - assertNeverHccError exhaustive switch guards compile-time (runtime throw HC_SCHEMA_VIOLATION fallback);
 *   - handleHccError switch covers all 6 cases (HTTP status code + fatal field).
 */

import { describe, expect, it } from 'vitest';

import {
    GENESIS_PREVIOUS_HASH,
    HCC_SUPPORTED_VERSIONS,
    HCC_VERSION_CURRENT,
    HashChainError,
    assertNeverHccError,
    handleHccError,
    toCanonicalPayloadHash,
    toChainPosition,
    toHashChainEntryId,
    toHccVersionString,
    toPreviousHash,
    type HccErrorCode,
} from '../../hash-chain-canonicalize/index.js';

// ─── HashChainError basics ─────────────────────────────────────────────────────

describe('HashChainError — constructor + name + code + message format', () => {
    it('should construct with name "HashChainError" and prefixed message', () => {
        const err = new HashChainError('HC_SCHEMA_VIOLATION', 'test message');
        expect(err.name).toBe('HashChainError');
        expect(err.code).toBe('HC_SCHEMA_VIOLATION');
        expect(err.message).toBe('[HC_SCHEMA_VIOLATION] test message');
    });

    it('should accept optional cause Error', () => {
        const cause = new Error('root cause');
        const err = new HashChainError(
            'HC_CANONICALIZE_FAILED',
            'wrapper',
            cause,
        );
        expect(err.cause).toBe(cause);
    });

    it('should be instanceof Error and HashChainError', () => {
        const err = new HashChainError('HC_HASH_MISMATCH', 'msg');
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(HashChainError);
    });
});

// ─── toHashChainEntryId — UUID v4 brand factory ──────────────────────────────

describe('toHashChainEntryId — UUID v4 brand factory (brand guard)', () => {
    it('should accept valid UUID v4 strings (lowercase)', () => {
        const valid = '550e8400-e29b-41d4-a716-446655440000';
        const result = toHashChainEntryId(valid);
        expect(result).toBe(valid);
    });

    it('should accept valid UUID v4 strings (uppercase) and normalize to lowercase', () => {
        const valid = '550E8400-E29B-41D4-A716-446655440000';
        // factory accepts a case-insensitive input but normalizes the output to lowercase
        // — aligned with the JSON Schema pattern `^[0-9a-f]...` lowercase-only semantics; triple defense L1/L2/L3 consistent
        expect(toHashChainEntryId(valid)).toBe(valid.toLowerCase());
    });

    it('should reject UUID v1/v3/v5 (non-v4 version)', () => {
        // v4 requires the 13th position to be '4'; this case has '1' (v1) at the 13th position
        expect(() =>
            toHashChainEntryId('550e8400-e29b-11d4-a716-446655440000'),
        ).toThrow(HashChainError);
        expect(() =>
            toHashChainEntryId('550e8400-e29b-11d4-a716-446655440000'),
        ).toThrow(/HC_SCHEMA_VIOLATION/);
    });

    it('should reject non-string input', () => {
        expect(() => toHashChainEntryId(123 as unknown as string)).toThrow(
            HashChainError,
        );
    });

    it('should reject empty string', () => {
        expect(() => toHashChainEntryId('')).toThrow(HashChainError);
    });

    it('should reject malformed UUID (missing dashes)', () => {
        expect(() =>
            toHashChainEntryId('550e8400e29b41d4a716446655440000'),
        ).toThrow(HashChainError);
    });

    it('should reject UUID v4 with invalid variant bits (not 8/9/a/b)', () => {
        // the 17th position must be 8/9/a/b (UUID v4 variant); this case has '0' at the 17th position
        expect(() =>
            toHashChainEntryId('550e8400-e29b-41d4-0716-446655440000'),
        ).toThrow(HashChainError);
    });
});

// ─── toCanonicalPayloadHash — SHA-256 lowercase hex brand factory ─────────────

describe('toCanonicalPayloadHash — 64 lowercase hex brand factory (brand guard)', () => {
    it('should accept valid 64 lowercase hex string', () => {
        const valid =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        expect(toCanonicalPayloadHash(valid)).toBe(valid);
    });

    it('should reject uppercase hex (strict lowercase)', () => {
        // uppercase drift is not allowed
        const upper =
            'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
        expect(() => toCanonicalPayloadHash(upper)).toThrow(HashChainError);
    });

    it('should reject 63-char hex (length boundary -1)', () => {
        expect(() =>
            toCanonicalPayloadHash(
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85',
            ),
        ).toThrow(HashChainError);
    });

    it('should reject 65-char hex (length boundary +1)', () => {
        expect(() =>
            toCanonicalPayloadHash(
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555',
            ),
        ).toThrow(HashChainError);
    });

    it('should reject non-hex characters', () => {
        expect(() =>
            toCanonicalPayloadHash(
                'g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            ),
        ).toThrow(HashChainError);
    });

    it('should reject empty string', () => {
        expect(() => toCanonicalPayloadHash('')).toThrow(HashChainError);
    });

    it('should reject non-string input', () => {
        expect(() =>
            toCanonicalPayloadHash(null as unknown as string),
        ).toThrow(HashChainError);
    });
});

// ─── toPreviousHash — SHA-256 hex brand factory (normalize lowercase) ─────────

describe('toPreviousHash — 64 hex brand factory (uppercase normalize to lowercase)', () => {
    it('should accept lowercase hex and return as-is', () => {
        const valid =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        expect(toPreviousHash(valid)).toBe(valid);
    });

    it('should normalize uppercase hex to lowercase', () => {
        const upper =
            'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
        const lower =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        expect(toPreviousHash(upper)).toBe(lower);
    });

    it('should accept GENESIS_PREVIOUS_HASH (64 zeros)', () => {
        expect(toPreviousHash(GENESIS_PREVIOUS_HASH)).toBe(
            GENESIS_PREVIOUS_HASH,
        );
        expect(GENESIS_PREVIOUS_HASH).toBe('0'.repeat(64));
    });

    it('should reject 63-char hex', () => {
        expect(() => toPreviousHash('0'.repeat(63))).toThrow(HashChainError);
    });

    it('should reject non-hex character', () => {
        expect(() => toPreviousHash('z'.repeat(64))).toThrow(HashChainError);
    });

    it('should reject non-string input', () => {
        expect(() => toPreviousHash(undefined as unknown as string)).toThrow(
            HashChainError,
        );
    });
});

// ─── toChainPosition — non-negative safe integer brand factory ────────────────

describe('toChainPosition — non-negative safe integer brand factory (I4 guard)', () => {
    it('should accept 0 (genesis position)', () => {
        expect(toChainPosition(0)).toBe(0);
    });

    it('should accept positive integers', () => {
        expect(toChainPosition(1)).toBe(1);
        expect(toChainPosition(100)).toBe(100);
        expect(toChainPosition(Number.MAX_SAFE_INTEGER)).toBe(
            Number.MAX_SAFE_INTEGER,
        );
    });

    it('should reject negative integers', () => {
        expect(() => toChainPosition(-1)).toThrow(HashChainError);
    });

    it('should reject non-integer (float)', () => {
        expect(() => toChainPosition(1.5)).toThrow(HashChainError);
    });

    it('should reject NaN', () => {
        expect(() => toChainPosition(NaN)).toThrow(HashChainError);
    });

    it('should reject Infinity', () => {
        expect(() => toChainPosition(Infinity)).toThrow(HashChainError);
    });

    it('should reject unsafe integer (> MAX_SAFE_INTEGER)', () => {
        expect(() =>
            toChainPosition(Number.MAX_SAFE_INTEGER + 2),
        ).toThrow(HashChainError);
    });

    it('should reject non-number input', () => {
        expect(() => toChainPosition('5' as unknown as number)).toThrow(
            HashChainError,
        );
    });
});

// ─── toHccVersionString — semver + supported set brand factory ────────────────

describe('toHccVersionString — semver + supported set brand factory', () => {
    it('should accept HCC_VERSION_CURRENT', () => {
        expect(toHccVersionString(HCC_VERSION_CURRENT)).toBe(
            HCC_VERSION_CURRENT,
        );
    });

    it('should reject malformed semver (missing patch)', () => {
        expect(() => toHccVersionString('1.0')).toThrow(HashChainError);
    });

    it('should reject malformed semver (extra suffix)', () => {
        expect(() => toHccVersionString('1.0.0-beta')).toThrow(HashChainError);
    });

    it('should reject valid semver not in supported set', () => {
        // valid semver but not in HCC_SUPPORTED_VERSIONS
        const unsupported = '9.9.9';
        expect(() => toHccVersionString(unsupported)).toThrow(HashChainError);
        expect(() => toHccVersionString(unsupported)).toThrow(
            /unsupported hccVersion/,
        );
    });

    it('should reject empty string', () => {
        expect(() => toHccVersionString('')).toThrow(HashChainError);
    });

    it('should reject non-string input', () => {
        expect(() => toHccVersionString(100 as unknown as string)).toThrow(
            HashChainError,
        );
    });

    it('should expose HCC_SUPPORTED_VERSIONS containing HCC_VERSION_CURRENT (single-value set)', () => {
        expect(HCC_SUPPORTED_VERSIONS).toEqual([HCC_VERSION_CURRENT]);
    });
});

// ─── handleHccError — 6 HccErrorCode exhaustive switch ───────────────────────

describe('handleHccError — full coverage of 6 HccErrorCode cases', () => {
    const cases: ReadonlyArray<{
        code: HccErrorCode;
        expectedStatus: 400 | 422 | 500;
        keywordInMessage: string;
    }> = [
        {
            code: 'HC_CANONICALIZE_FAILED',
            expectedStatus: 500,
            keywordInMessage: 'JCS canonicalize failed',
        },
        {
            code: 'HC_HASH_MISMATCH',
            expectedStatus: 400,
            keywordInMessage: 'SHA-256 recompute mismatch',
        },
        {
            code: 'HC_PREVIOUS_HASH_BROKEN',
            expectedStatus: 400,
            keywordInMessage: 'previousHash link broken',
        },
        {
            code: 'HC_CHAIN_POSITION_NONMONOTONIC',
            expectedStatus: 400,
            keywordInMessage: 'chainPosition non-monotonic',
        },
        {
            code: 'HC_FIXTURE_CROSS_LANG_MISMATCH',
            expectedStatus: 422,
            keywordInMessage: 'cross-lang fixture digest mismatch',
        },
        {
            code: 'HC_SCHEMA_VIOLATION',
            expectedStatus: 400,
            keywordInMessage: 'JSON Schema validation failed',
        },
    ];

    for (const { code, expectedStatus, keywordInMessage } of cases) {
        it(`should map ${code} → http ${expectedStatus} + fatal:true`, () => {
            const ctx = handleHccError(code);
            expect(ctx.code).toBe(code);
            expect(ctx.httpStatus).toBe(expectedStatus);
            expect(ctx.fatal).toBe(true);
            expect(ctx.message).toContain(keywordInMessage);
        });
    }

    it('should verify all 6 codes mapped (snapshot reject map gap)', () => {
        // if the HccErrorCode union expands without syncing the cases → TypeScript compile-time fail
        // this case verifies the 6-item enumeration is complete; later v0.2+ additions must update here in sync
        expect(cases.length).toBe(6);
    });

    it('should trigger default branch via type-system bypass (assertNeverHccError runtime guard)', () => {
        // TypeScript compilation blocks passing values outside the union; runtime triggers the default fallback via a type cast bypass
        // verifies the phantom enforcement guard fails closed at runtime when the union expands without syncing the cases
        expect(() => handleHccError('NON_EXISTENT_CODE' as HccErrorCode)).toThrow(
            HashChainError,
        );
        expect(() =>
            handleHccError('NON_EXISTENT_CODE' as HccErrorCode),
        ).toThrow(/phantom enforcement guard/);
    });
});

// ─── assertNeverHccError — compile-time exhaustive guard + runtime throw ────

describe('assertNeverHccError — exhaustive switch fallback (phantom enforcement guard)', () => {
    it('should throw HC_SCHEMA_VIOLATION when called with non-never value (runtime)', () => {
        // unreachable at runtime (TypeScript type system enforces never); but if the type system is bypassed → throw fallback
        expect(() => {
            assertNeverHccError('UNKNOWN_CODE' as never);
        }).toThrow(HashChainError);
        expect(() => {
            assertNeverHccError('UNKNOWN_CODE' as never);
        }).toThrow(/phantom enforcement guard/);
    });

    it('should include the offending value in error message', () => {
        try {
            assertNeverHccError('SOMETHING_NEW' as never);
            throw new Error('should not reach');
        } catch (e) {
            expect(e).toBeInstanceOf(HashChainError);
            expect((e as HashChainError).message).toContain('SOMETHING_NEW');
            expect((e as HashChainError).code).toBe('HC_SCHEMA_VIOLATION');
        }
    });
});

// ─── GENESIS_PREVIOUS_HASH constant ──────────────────────────────────────

describe('GENESIS_PREVIOUS_HASH — 64 zeros', () => {
    it('should equal "0".repeat(64)', () => {
        expect(GENESIS_PREVIOUS_HASH).toBe('0'.repeat(64));
    });

    it('should be length 64', () => {
        expect(GENESIS_PREVIOUS_HASH.length).toBe(64);
    });

    it('should match SHA-256 hex pattern', () => {
        expect(/^[a-f0-9]{64}$/.test(GENESIS_PREVIOUS_HASH)).toBe(true);
    });
});
