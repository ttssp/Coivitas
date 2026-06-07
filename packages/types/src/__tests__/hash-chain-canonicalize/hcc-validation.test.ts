/**
 * hash-chain-canonicalize/hcc-validation.test.ts — HCC L0 AJV strict-mode validate unit tests
 *
 * hcc v0.1 L0 schema
 *
 * Coverage goals (anti-phantom + third layer of the triple defense):
 *   - PASS: complete 7 fields + valid brand values;
 *   - REJECT: missing field / extra field (additionalProperties:false) / bad format / bad pattern /
 *     bad minimum / bad const "1.0.0";
 *   - AJV strict 5-flag interplay (strict / strictSchema / strictNumbers / strictTypes / validateFormats).
 */

import { describe, expect, it } from 'vitest';

import {
    HCC_VERSION_CURRENT,
    validateHashChainEntrySchema,
    type HashChainEntry,
} from '../../hash-chain-canonicalize/index.js';
import type {
    CanonicalPayloadHash,
    ChainPosition,
    HashChainEntryId,
    HccVersionString,
    PreviousHash,
} from '../../hash-chain-canonicalize/index.js';
import type { Timestamp } from '../../base.js';

const VALID_HASH =
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const VALID_PREV =
    '0000000000000000000000000000000000000000000000000000000000000000';
const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';

function makeValidEntry(): HashChainEntry {
    return {
        entryId: VALID_UUID as HashChainEntryId,
        canonicalPayload: '{"a":1}',
        canonicalPayloadHash: VALID_HASH as CanonicalPayloadHash,
        previousHash: VALID_PREV as PreviousHash,
        chainPosition: 0 as ChainPosition,
        chainIdentity: { chainNamespace: 'test' },
        timestamp: '2026-05-18T00:00:00.000Z' as Timestamp,
        hccVersion: HCC_VERSION_CURRENT as HccVersionString,
    };
}

describe('validateHashChainEntrySchema — PASS path', () => {
    it('should PASS valid full 7-field entry', () => {
        const result = validateHashChainEntrySchema(makeValidEntry());
        expect(result.valid).toBe(true);
    });

    it('should PASS entry with non-genesis previousHash (hash link)', () => {
        const entry = makeValidEntry();
        entry.previousHash = VALID_HASH as PreviousHash;
        entry.chainPosition = 1 as ChainPosition;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(true);
    });

    it('should PASS entry with chainPosition = MAX_SAFE_INTEGER (upper bound)', () => {
        const entry = makeValidEntry();
        entry.chainPosition = Number.MAX_SAFE_INTEGER as ChainPosition;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(true);
    });
});

describe('validateHashChainEntrySchema — REJECT missing field', () => {
    it('should REJECT entry missing entryId', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.entryId;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.errors.length).toBeGreaterThan(0);
        }
    });

    it('should REJECT entry missing canonicalPayload', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.canonicalPayload;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entry missing canonicalPayloadHash', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.canonicalPayloadHash;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entry missing previousHash', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.previousHash;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entry missing chainPosition', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.chainPosition;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entry missing timestamp', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.timestamp;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entry missing hccVersion', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.hccVersion;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entry missing chainIdentity (v0.2 mandatory 8th field)', () => {
        const entry = makeValidEntry() as Partial<HashChainEntry>;
        delete entry.chainIdentity;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });
});

describe('validateHashChainEntrySchema — REJECT additionalProperties (strict closed)', () => {
    it('should REJECT entry with extra field (additionalProperties:false)', () => {
        const entry: Record<string, unknown> = {
            ...makeValidEntry(),
            extraField: 'phantom',
        };
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });
});

describe('validateHashChainEntrySchema — REJECT bad format / pattern', () => {
    it('should REJECT non-UUID entryId', () => {
        const entry = makeValidEntry();
        (entry as { entryId: string }).entryId = 'not-a-uuid';
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT non-hex canonicalPayloadHash', () => {
        const entry = makeValidEntry();
        (entry as { canonicalPayloadHash: string }).canonicalPayloadHash =
            'z'.repeat(64);
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT uppercase hex canonicalPayloadHash (lowercase pattern enforce)', () => {
        const entry = makeValidEntry();
        (entry as { canonicalPayloadHash: string }).canonicalPayloadHash =
            VALID_HASH.toUpperCase();
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT non-hex previousHash', () => {
        const entry = makeValidEntry();
        (entry as { previousHash: string }).previousHash = 'g'.repeat(64);
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT chainPosition negative', () => {
        const entry = makeValidEntry();
        (entry as { chainPosition: number }).chainPosition = -1;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT chainPosition non-integer (1.5)', () => {
        const entry = makeValidEntry();
        (entry as { chainPosition: number }).chainPosition = 1.5;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT timestamp non-ISO 8601', () => {
        const entry = makeValidEntry();
        (entry as { timestamp: string }).timestamp = '2026/05/18';
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT hccVersion not in supported set (const enforce)', () => {
        const entry = makeValidEntry();
        // valid semver but not in HCC_SUPPORTED_VERSIONS
        (entry as { hccVersion: string }).hccVersion = '9.9.9';
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT hccVersion malformed semver', () => {
        const entry = makeValidEntry();
        (entry as { hccVersion: string }).hccVersion = '1.0';
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT canonicalPayload empty string (minLength 2)', () => {
        const entry = makeValidEntry();
        (entry as { canonicalPayload: string }).canonicalPayload = '';
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });
});

describe('validateHashChainEntrySchema — REJECT bad type (strictTypes)', () => {
    it('should REJECT chainPosition string', () => {
        const entry = makeValidEntry() as Record<string, unknown>;
        entry.chainPosition = '0';
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT entryId number', () => {
        const entry = makeValidEntry() as Record<string, unknown>;
        entry.entryId = 12345;
        const result = validateHashChainEntrySchema(entry);
        expect(result.valid).toBe(false);
    });

    it('should REJECT non-object input (null)', () => {
        const result = validateHashChainEntrySchema(null);
        expect(result.valid).toBe(false);
    });

    it('should REJECT non-object input (string)', () => {
        const result = validateHashChainEntrySchema('not-an-object');
        expect(result.valid).toBe(false);
    });

    it('should REJECT empty object', () => {
        const result = validateHashChainEntrySchema({});
        expect(result.valid).toBe(false);
    });
});
