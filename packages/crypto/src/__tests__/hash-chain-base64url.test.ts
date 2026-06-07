/**
 * hash-chain-base64url.test.ts
 * Dual-format compatibility verification
 *
 * Verification goals:
 * 1. hash()'s base64url output option works correctly, with bytes matching the hex output
 * 2. HashChain's default hex behavior is unaffected by base64url support (regression)
 * 3. A base64url-encoded hash decodes correctly via fromBase64Url and verifies byte equality
 * 4. detectEncoding correctly distinguishes hex from base64url hash output
 *
 * Constraints:
 * - Do not change HashChain default behavior (wire-format-freeze freezes prevHash as hex)
 * - Do not introduce base64url prevHash into HashChain (only done in the v0.2 migration)
 */

import { describe, expect, it } from 'vitest';

import {
    detectEncoding,
    fromBase64Url,
    fromHex,
    HashChain,
    hash,
} from '../index.js';

// Helper: create a test ActionRecord structure (aligned with wire-format-freeze)
function createRecord(id: number, prevHash: string | null) {
    return {
        id: `rec-${id.toString().padStart(3, '0')}`,
        action: `ACTION_${id}`,
        timestamp: `2026-04-02T00:00:0${id}Z`,
        prevHash,
    };
}

describe('hash() base64url output option', () => {
    it('should produce base64url output matching only base64url charset when encoding is base64url', () => {
        const result = hash('test-payload', 'base64url');
        // RFC 4648: base64url charset = [A-Za-z0-9_-], no padding
        expect(result).toMatch(/^[A-Za-z0-9_-]+$/);
        // SHA-256 output is a fixed 32 bytes; base64url without padding has length = ceil(32*4/3) = 43
        expect(result.length).toBe(43);
    });

    it('should produce identical bytes for hex and base64url outputs of same input', () => {
        const testCases = [
            'hello',
            'coivitas-v0.2',
            '',
            'prevHash is null for first record',
        ];

        for (const input of testCases) {
            const hexOut = hash(input, 'hex');
            const b64Out = hash(input, 'base64url');

            const bytesFromHex = fromHex(hexOut);
            const bytesFromB64 = fromBase64Url(b64Out);

            expect(bytesFromHex).toEqual(bytesFromB64);
            // hex is a fixed 64 chars, base64url a fixed 43 chars (SHA-256 32 bytes)
            expect(hexOut.length).toBe(64);
            expect(b64Out.length).toBe(43);
        }
    });

    it('should produce base64url output for Uint8Array input', () => {
        const input = new Uint8Array([0, 1, 2, 3, 255, 128, 64]);
        const hexOut = hash(input, 'hex');
        const b64Out = hash(input, 'base64url');

        const bytesFromHex = fromHex(hexOut);
        const bytesFromB64 = fromBase64Url(b64Out);

        expect(bytesFromHex).toEqual(bytesFromB64);
    });

    it('should return hex by default when encoding is omitted', () => {
        // Regression check: omitting the encoding parameter behaves the same as an explicit 'hex'
        const implicit = hash('default-check');
        const explicit = hash('default-check', 'hex');
        expect(implicit).toBe(explicit);
        expect(implicit.length).toBe(64);
    });
});

describe('detectEncoding recognizes hash output format', () => {
    it('should detect hex encoding for hash() hex output', () => {
        const hexHash = hash('detect-me', 'hex');
        expect(detectEncoding(hexHash)).toBe('hex');
    });

    it('should detect base64url encoding for hash() base64url output', () => {
        // Note: detectEncoding's heuristic prefers hex (all-hex chars + even length)
        // base64url's 43 chars is odd, so it is correctly classified as base64url
        const b64Hash = hash('detect-me', 'base64url');
        expect(detectEncoding(b64Hash)).toBe('base64url');
    });
});

describe('HashChain hex default behavior regression check', () => {
    it('should treat an empty chain as valid (hex mode)', () => {
        const chain = new HashChain();
        expect(chain.verify([])).toEqual({ valid: true, chainLength: 0 });
    });

    it('should append and verify records with hex prevHash (wire-format compliant)', () => {
        const chain = new HashChain();
        const records: Array<ReturnType<typeof createRecord>> = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 5; i++) {
            const record = createRecord(i, prevHash);
            prevHash = chain.append(record);
            records.push(record);

            // Verify each append returns a 64-char hex (the format frozen by wire-format-freeze)
            expect(prevHash).toMatch(/^[0-9a-f]{64}$/);
        }

        expect(chain.length).toBe(5);
        expect(chain.headHash).toBe(prevHash);
        expect(chain.verify(records)).toEqual({ valid: true, chainLength: 5 });
    });

    it('should detect broken chain when prevHash is corrupted', () => {
        const chain = new HashChain();
        const records: Array<ReturnType<typeof createRecord>> = [];
        let prevHash: string | null = null;

        for (let i = 0; i < 4; i++) {
            const record = createRecord(i, prevHash);
            prevHash = chain.append(record);
            records.push(record);
        }

        // Tamper with the prevHash of the 2nd record
        records[1] = {
            ...records[1]!,
            prevHash: records[1]!.prevHash,
            action: 'TAMPERED',
        };

        const result = chain.verify(records);
        expect(result.valid).toBe(false);
        expect(result.brokenAtIndex).toBe(2);
    });

    it('should reject invalid hex prevHash when appending', () => {
        const chain = new HashChain();
        // hash-chain's internal getPrevHash calls fromHex; a non-hex format throws CryptoError
        expect(() =>
            chain.append({ id: 'rec-1', prevHash: 'not-valid-hex!!!' }),
        ).toThrow();
    });
});

describe('base64url hash byte-level verification', () => {
    it('should round-trip base64url hash through fromBase64Url correctly', () => {
        const testInputs = ['record-001', 'agent-did-content', 'capability-token-payload'];

        for (const input of testInputs) {
            const b64Hash = hash(input, 'base64url');
            const decoded = fromBase64Url(b64Hash);

            // SHA-256 output is a fixed 32 bytes
            expect(decoded.length).toBe(32);

            // Byte-identical to the hex version
            const hexHash = hash(input, 'hex');
            expect(decoded).toEqual(fromHex(hexHash));
        }
    });

    it('should produce different base64url hashes for different inputs', () => {
        const h1 = hash('input-a', 'base64url');
        const h2 = hash('input-b', 'base64url');
        expect(h1).not.toBe(h2);
    });

    it('should verify that base64url SHA-256 of empty string matches known vector', () => {
        // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        const hexKnown =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        const b64Hash = hash('', 'base64url');
        const decoded = fromBase64Url(b64Hash);
        const fromKnownHex = fromHex(hexKnown);
        expect(decoded).toEqual(fromKnownHex);
    });
});

describe('v0.2 migration readiness verification', () => {
    it('should confirm hash() accepts encoding parameter without affecting default behavior', () => {
        // Key check: the encoding parameter is optional and defaults to hex when omitted (v0.1 behavior)
        const withDefault = hash('migration-test');
        const withHex = hash('migration-test', 'hex');
        const withB64 = hash('migration-test', 'base64url');

        expect(withDefault).toBe(withHex);
        expect(withDefault).not.toBe(withB64);

        // v0.1 hex format is 64 chars
        expect(withDefault.length).toBe(64);
        // v0.2 base64url format is 43 chars (32 bytes, no padding)
        expect(withB64.length).toBe(43);
    });

    it('should confirm that existing HashChain hex output is 64-char (wire-format compliant)', () => {
        const chain = new HashChain();
        const record = createRecord(0, null);
        const headHash = chain.append(record);

        // wire-format-freeze: paramsHash / prevHash are 64-char hex (32 bytes SHA-256)
        expect(headHash.length).toBe(64);
        expect(headHash).toMatch(/^[0-9a-f]{64}$/);
    });
});
