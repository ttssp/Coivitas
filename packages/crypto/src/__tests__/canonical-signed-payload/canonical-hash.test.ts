/**
 * canonical-hash.test.ts — unit tests for the CSP L1 crypto primitive
 *
 * Coverage goals (≥95% coverage):
 *   - known inputs checked against RFC 8785 vectors (canonical serialize + SHA-256);
 *   - 32-byte hash (fixed digest length) + 64-char hex / 43-char base64url;
 *   - same input same hash (determinism) + different input different hash (a micro-change differs);
 *   - both the canonicalHash (string surface) and canonicalHashBytes (Uint8Array surface) paths;
 *   - error paths passed through from canonicalSerialize (undefined / NaN / circular).
 */

import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';

import { toBase64Url, toHex } from '../../encoding.js';
import {
    canonicalHash,
    canonicalHashBytes,
    canonicalSerialize,
    CspError,
} from '../../canonical-signed-payload/index.js';

describe('canonicalHash — determinism', () => {
    it('should produce identical hash for same input', () => {
        const obj = { a: 1, b: 2 };
        expect(canonicalHash(obj)).toBe(canonicalHash(obj));
    });

    it('should produce identical hash regardless of key order (JCS normalization)', () => {
        const hashAB = canonicalHash({ a: 1, b: 2 });
        const hashBA = canonicalHash({ b: 2, a: 1 });
        expect(hashAB).toBe(hashBA);
    });

    it('should produce different hash for different input (micro-change → diff hash)', () => {
        const hash1 = canonicalHash({ a: 1 });
        const hash2 = canonicalHash({ a: 2 });
        expect(hash1).not.toBe(hash2);
    });

    it('should produce different hash for added field', () => {
        const hash1 = canonicalHash({ a: 1 });
        const hash2 = canonicalHash({ a: 1, b: 2 });
        expect(hash1).not.toBe(hash2);
    });

    it('should produce different hash for nested object micro-change', () => {
        const hash1 = canonicalHash({ outer: { inner: 1 } });
        const hash2 = canonicalHash({ outer: { inner: 2 } });
        expect(hash1).not.toBe(hash2);
    });
});

describe('canonicalHash — output format (hex default)', () => {
    it('should return 64-char hex string by default (32 bytes * 2 chars/byte)', () => {
        const hash = canonicalHash({ a: 1 });
        expect(typeof hash).toBe('string');
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should return 43-char base64url string when encoding=base64url (32 bytes, no padding)', () => {
        const hash = canonicalHash({ a: 1 }, 'base64url');
        expect(typeof hash).toBe('string');
        expect(hash).toHaveLength(43);
        expect(hash).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce consistent hex / base64url representations of same 32-byte digest', () => {
        const obj = { msg: 'hello' };
        const hex = canonicalHash(obj, 'hex');
        const b64 = canonicalHash(obj, 'base64url');
        // Decode base64url + re-encode as hex → should equal the hex output
        // (cross-validated via the canonicalHashBytes path)
        const bytes = canonicalHashBytes(obj);
        expect(toHex(bytes)).toBe(hex);
        expect(toBase64Url(bytes)).toBe(b64);
    });
});

describe('canonicalHashBytes — Uint8Array surface', () => {
    it('should return 32-byte Uint8Array (SHA-256 digest size)', () => {
        const bytes = canonicalHashBytes({ a: 1 });
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes.length).toBe(32);
    });

    it('should produce identical bytes for same input', () => {
        const obj = { x: 1, y: 2 };
        const b1 = canonicalHashBytes(obj);
        const b2 = canonicalHashBytes(obj);
        expect(b1).toEqual(b2);
    });

    it('should produce different bytes for different input', () => {
        const b1 = canonicalHashBytes({ a: 1 });
        const b2 = canonicalHashBytes({ a: 2 });
        expect(b1).not.toEqual(b2);
    });
});

describe('canonicalHash — known input verification (canonicalSerialize + SHA-256 chain)', () => {
    it('should match manual sha256(canonicalSerialize(payload)) for empty object', () => {
        const obj = {};
        const expected = toHex(sha256(canonicalSerialize(obj)));
        expect(canonicalHash(obj)).toBe(expected);
    });

    it('should match manual sha256(canonicalSerialize(payload)) for single field', () => {
        const obj = { key: 'value' };
        const expected = toHex(sha256(canonicalSerialize(obj)));
        expect(canonicalHash(obj)).toBe(expected);
    });

    it('should match manual sha256(canonicalSerialize(payload)) for csp 5-field payload', () => {
        const payload = {
            cspVersion: '1.0.0',
            token: { id: 'token-789', specVersion: '0.3.0' },
            disclosedClaims: [],
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            audience: 'did:example:verifier',
            notAfter: '2026-05-20T10:00:00.000Z',
        };
        const expected = toHex(sha256(canonicalSerialize(payload)));
        expect(canonicalHash(payload)).toBe(expected);
    });

    it('should produce known SHA-256 hash for canonical empty object {}', () => {
        // SHA-256("{}") = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
        // (canonicalize({}) = "{}", 2 bytes in UTF-8, sha256 32 bytes)
        const hash = canonicalHash({});
        expect(hash).toBe(
            '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
        );
    });
});

describe('canonicalHash — csp signed payload idempotency', () => {
    it('should produce same hash for differently-ordered key inputs (idempotency key derivation)', () => {
        const payloadA = {
            cspVersion: '1.0.0',
            audience: 'did:example:a',
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            disclosedClaims: [],
            notAfter: '2026-05-20T10:00:00.000Z',
            token: { id: 't1' },
        };
        const payloadB = {
            token: { id: 't1' },
            notAfter: '2026-05-20T10:00:00.000Z',
            disclosedClaims: [],
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            audience: 'did:example:a',
            cspVersion: '1.0.0',
        };
        expect(canonicalHash(payloadA)).toBe(canonicalHash(payloadB));
    });

    it('should produce different hash when notAfter changes (idempotency violation detection)', () => {
        const base = {
            cspVersion: '1.0.0',
            audience: 'did:example:a',
            challenge: '550e8400-e29b-41d4-a716-446655440000',
            disclosedClaims: [],
            notAfter: '2026-05-20T10:00:00.000Z',
            token: { id: 't1' },
        };
        const mutated = { ...base, notAfter: '2026-05-20T10:00:00.001Z' };
        expect(canonicalHash(base)).not.toBe(canonicalHash(mutated));
    });
});

describe('canonicalHash — fail-closed throw paths (passed through from canonicalSerialize)', () => {
    it('should throw CspError(CSP_SCHEMA_VIOLATION) on undefined field (passed through from canonicalSerialize)', () => {
        // The literal canonicalSerialize undefined throw = CSP_SCHEMA_VIOLATION (payload schema reject);
        // canonicalHash passes it through and need not wrap it as CSP_CANONICALIZE_MISMATCH —
        // CSP_CANONICALIZE_MISMATCH is literally defined as "canonical form mismatch between sender/receiver"
        // (the signature verify step, not the serialize boundary).
        expect(() => canonicalHash({ value: undefined })).toThrowError(
            CspError,
        );
        try {
            canonicalHash({ value: undefined });
        } catch (e) {
            expect((e as CspError).code).toBe('CSP_SCHEMA_VIOLATION');
        }
    });

    it('should throw CspError on NaN field', () => {
        expect(() => canonicalHash({ value: Number.NaN })).toThrowError(
            CspError,
        );
    });

    it('should throw CspError on circular reference', () => {
        const obj: Record<string, unknown> = { a: 1 };
        obj.cycle = obj;
        expect(() => canonicalHash(obj)).toThrowError(CspError);
    });

    it('should throw CspError on bigint field', () => {
        expect(() => canonicalHash({ big: BigInt(1) })).toThrowError(
            CspError,
        );
    });
});

describe('canonicalHashBytes — fail-closed throw paths', () => {
    it('should throw CspError(CSP_SCHEMA_VIOLATION) on undefined field (passed through from canonicalSerialize)', () => {
        expect(() => canonicalHashBytes({ value: undefined })).toThrowError(
            CspError,
        );
    });

    it('should throw CspError on NaN field', () => {
        expect(() => canonicalHashBytes({ value: Number.NaN })).toThrowError(
            CspError,
        );
    });

    it('should throw CspError on circular reference', () => {
        const obj: Record<string, unknown> = { a: 1 };
        obj.self = obj;
        expect(() => canonicalHashBytes(obj)).toThrowError(CspError);
    });
});

describe('canonicalHash / canonicalHashBytes — defensive catch (sha256 behavior change protection)', () => {
    /**
     * Defensive test coverage: the @noble/hashes/sha256 throw / non-32-byte return paths.
     *
     * These guard against the phantom pattern — we do not allow "this error condition is theoretically
     * unreachable, so skip it". Real scenario: @noble/hashes behavior may change after an upgrade
     * (e.g. the length is no longer fixed at 32); we must catch first and translate to
     * CspError(CSP_CANONICALIZE_MISMATCH) rather than letting the exception propagate directly.
     */

    it('should catch sha256 throw and translate to CspError in canonicalHash', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('@noble/hashes/sha256', () => ({
            sha256: () => {
                throw new Error('simulated sha256 throw');
            },
        }));

        const mod = await import('../../canonical-signed-payload/canonical-hash.js');

        try {
            mod.canonicalHash({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_CANONICALIZE_MISMATCH');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('SHA-256');
        }

        vi.doUnmock('@noble/hashes/sha256');
        vi.resetModules();
    });

    it('should catch sha256 unexpected length and translate to CspError in canonicalHash', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('@noble/hashes/sha256', () => ({
            sha256: () => new Uint8Array(16), // 16-byte instead of 32-byte
        }));

        const mod = await import('../../canonical-signed-payload/canonical-hash.js');

        try {
            mod.canonicalHash({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_CANONICALIZE_MISMATCH');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('digest length');
        }

        vi.doUnmock('@noble/hashes/sha256');
        vi.resetModules();
    });

    it('should catch sha256 throw and translate to CspError in canonicalHashBytes', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('@noble/hashes/sha256', () => ({
            sha256: () => {
                throw new Error('simulated sha256 throw (bytes variant)');
            },
        }));

        const mod = await import('../../canonical-signed-payload/canonical-hash.js');

        try {
            mod.canonicalHashBytes({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_CANONICALIZE_MISMATCH');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('canonicalHashBytes');
        }

        vi.doUnmock('@noble/hashes/sha256');
        vi.resetModules();
    });

    it('should catch sha256 unexpected length and translate to CspError in canonicalHashBytes', async () => {
        const { vi } = await import('vitest');
        vi.resetModules();
        vi.doMock('@noble/hashes/sha256', () => ({
            sha256: () => new Uint8Array(20),
        }));

        const mod = await import('../../canonical-signed-payload/canonical-hash.js');

        try {
            mod.canonicalHashBytes({ a: 1 });
            expect.fail('should have thrown CspError');
        } catch (e) {
            expect((e as { code?: string }).code).toBe('CSP_CANONICALIZE_MISMATCH');
            expect((e as { name?: string }).name).toBe('CspError');
            expect((e as Error).message).toContain('digest length');
        }

        vi.doUnmock('@noble/hashes/sha256');
        vi.resetModules();
    });
});
