/**
 * Unit tests for the ledger-anchor command
 *
 * Covered paths:
 * - Success path: runLedgerAnchor returns anchors + merkleRoot + chainValid
 * - Argument path: last=0 throws ProtocolError('INVALID_MESSAGE')
 * - Error path: an empty record set returns chainValid=true, anchors=[], merkleRoot=null
 *
 * Note: HashChain.verify() and generateProof() require prevHash to be null or
 * 64-char hex (32 bytes), so test records must use valid hex hash values.
 */

import { describe, expect, it, vi } from 'vitest';

import { ProtocolError } from '@coivitas/types';
import type { PersistedActionRecord } from '@coivitas/policy';
import type { DID, Timestamp } from '@coivitas/types';

import { runLedgerAnchor } from './ledger-anchor.js';

const AGENT: DID = 'did:agent:1111222233334444555566667777888899990000' as DID;

// 32-byte hex constant, used to build a valid hash chain (HashChain requires 64-char hex)
const HASH_1 = '1'.repeat(64);

function makeRecord(
    i: number,
    recordHash: string,
    previousRecordHash: string,
): PersistedActionRecord {
    return {
        recordId: `rec-${i.toString().padStart(3, '0')}`,
        agentDid: AGENT,
        principalDid: AGENT,
        actionType: 'TEST_ACTION',
        parametersSummary: null,
        authorizationRef: null,
        resultSummary: null,
        recordHash,
        previousRecordHash,
        actorSignature:
            `sig-actor-${i}` as PersistedActionRecord['actorSignature'],
        ledgerSignature:
            `sig-ledger-${i}` as PersistedActionRecord['ledgerSignature'],
        createdAt: `2026-05-0${i}T00:00:00.000Z` as Timestamp,
    };
}

describe('runLedgerAnchor', () => {
    it('should return empty result when no records are found', async () => {
        const queryRecords = vi.fn().mockResolvedValue({ records: [] });

        const result = await runLedgerAnchor({ last: 5 }, { queryRecords });

        expect(result.anchors).toHaveLength(0);
        expect(result.merkleRoot).toBeNull();
        expect(result.chainValid).toBe(true);
        expect(result.chainLength).toBe(0);
    });

    it('should return anchors with recordId, recordHash, createdAt fields', async () => {
        // single genesis record (previousRecordHash=''): HashChain.verify() prevHash=null,
        // matches the initial expectedPrevHash=null, so the chain is valid.
        const records = [makeRecord(1, HASH_1, '')];
        const queryRecords = vi.fn().mockResolvedValue({ records });

        const result = await runLedgerAnchor({ last: 1 }, { queryRecords });

        expect(result.anchors).toHaveLength(1);
        expect(result.anchors[0]).toMatchObject({
            recordId: 'rec-001',
            recordHash: HASH_1,
            previousRecordHash: '',
            createdAt: '2026-05-01T00:00:00.000Z',
        });
    });

    it('should return chainLength matching the number of records', async () => {
        const records = [makeRecord(1, HASH_1, '')];
        const queryRecords = vi.fn().mockResolvedValue({ records });

        const result = await runLedgerAnchor({ last: 1 }, { queryRecords });

        expect(result.chainLength).toBe(1);
    });

    it('should throw INVALID_MESSAGE when last is 0', async () => {
        await expect(runLedgerAnchor({ last: 0 }, {})).rejects.toThrow(
            ProtocolError,
        );

        await expect(runLedgerAnchor({ last: 0 }, {})).rejects.toMatchObject({
            code: 'INVALID_MESSAGE',
        });
    });

    it('should throw INVALID_MESSAGE when last is negative', async () => {
        await expect(runLedgerAnchor({ last: -1 }, {})).rejects.toMatchObject({
            code: 'INVALID_MESSAGE',
        });
    });

    it('should compute a non-null merkleRoot for a single record', async () => {
        const records = [makeRecord(1, HASH_1, '')];
        const queryRecords = vi.fn().mockResolvedValue({ records });

        const result = await runLedgerAnchor({ last: 1 }, { queryRecords });

        // Merkle root of 1 element = hash of that element
        expect(result.merkleRoot).not.toBeNull();
        expect(typeof result.merkleRoot).toBe('string');
    });

    // R1 medium regression: --last N must return the most recent N records (not the oldest N)
    it('should request order=desc and return anchors in chronological (oldest→newest) order for --last N', async () => {
        const HASH_2 = '2'.repeat(64);
        const HASH_3 = '3'.repeat(64);
        // The database actually holds 3 records (rec-001 oldest -> rec-002 -> rec-003 newest)
        // When calling --last 2, we expect [rec-002, rec-003] (the most recent 2), not [rec-001, rec-002]
        // queryRecords is called with order: 'desc', simulating the DB returning [rec-003, rec-002]
        const queryRecords = vi.fn().mockResolvedValue({
            records: [
                makeRecord(3, HASH_3, HASH_2), // newest (first under DESC)
                makeRecord(2, HASH_2, ''), // next newest
            ],
        });

        const result = await runLedgerAnchor({ last: 2 }, { queryRecords });

        // 1. the underlying query must be called with order: 'desc'
        expect(queryRecords).toHaveBeenCalledWith(
            expect.objectContaining({ limit: 2, order: 'desc' }),
        );
        // 2. the output must be in chronological order (oldest first), i.e. the reversed order
        expect(result.anchors).toHaveLength(2);
        expect(result.anchors[0]?.recordId).toBe('rec-002');
        expect(result.anchors[1]?.recordId).toBe('rec-003');
        // 3. anchors[1] is the newest (recordId rec-003 + recordHash HASH_3)
        expect(result.anchors[1]?.recordHash).toBe(HASH_3);
        expect(result.anchors[1]?.createdAt).toBe('2026-05-03T00:00:00.000Z');
        // 4. anchors[0] must not be the oldest record in the DB, rec-001 (guards against the "returns the oldest N" regression)
        expect(result.anchors[0]?.recordId).not.toBe('rec-001');
    });

    // Regression: a healthy multi-record chain must yield chainValid=true
    // Historical bug: HashChain.verify(records) re-canonicalized the entire PersistedActionRecord
    // (including recordHash/actorSignature/ledgerSignature), but the ledger's recordHash is computed from
    // the unsigned payload + previousRecordHash, which produced a false-negative chainValid=false on healthy chains.
    // The fix switched to verifyAnchorContinuity, which only continuity-checks recordHash <-> previousRecordHash.
    it('should report chainValid=true for a healthy 2-record chain (regression: F1)', async () => {
        const HASH_A = 'a'.repeat(64); // recordHash of the genesis record
        const HASH_B = 'b'.repeat(64); // recordHash of the second record
        // the second record's previousRecordHash must equal the first record's recordHash (chain continuity)
        const queryRecords = vi.fn().mockResolvedValue({
            records: [
                makeRecord(2, HASH_B, HASH_A), // first under DESC = newest (rec-002, prev=HASH_A)
                makeRecord(1, HASH_A, ''), // second under DESC = genesis (rec-001, prev='')
            ],
        });

        const result = await runLedgerAnchor({ last: 2 }, { queryRecords });

        expect(result.chainValid).toBe(true);
        expect(result.chainLength).toBe(2);
    });

    // Counterexample: a broken chain must yield chainValid=false
    it('should report chainValid=false when previousRecordHash does not match prior recordHash', async () => {
        const HASH_A = 'a'.repeat(64);
        const HASH_B = 'b'.repeat(64);
        const HASH_WRONG = 'f'.repeat(64);
        // the second record's previousRecordHash is deliberately wrong (!= HASH_A)
        const queryRecords = vi.fn().mockResolvedValue({
            records: [
                makeRecord(2, HASH_B, HASH_WRONG),
                makeRecord(1, HASH_A, ''),
            ],
        });

        const result = await runLedgerAnchor({ last: 2 }, { queryRecords });

        expect(result.chainValid).toBe(false);
        expect(result.chainLength).toBe(1); // record 1 (genesis) passes, record 2 breaks
    });

    // Regression: merkleRoot must be recomputable from anchors[].recordHash
    // Historical bug: HashChain.generateProof([{hash, prevHash}]) re-hashed each leaf once,
    // so the resulting root equalled hash({hash:..., prevHash:...}) rather than anchors[].recordHash itself.
    // The fix builds the Merkle tree directly from the anchors[].recordHash array, so callers can recompute it with the same algorithm.
    it('should compute merkleRoot directly from anchors[].recordHash (regression: F2 single)', async () => {
        const HASH_X = 'c'.repeat(64);
        const records = [makeRecord(1, HASH_X, '')];
        const queryRecords = vi.fn().mockResolvedValue({ records });

        const result = await runLedgerAnchor({ last: 1 }, { queryRecords });

        // single-leaf Merkle tree: root === recordHash itself (no re-hashing)
        expect(result.merkleRoot).toBe(HASH_X);
        expect(result.anchors[0]?.recordHash).toBe(HASH_X);
    });

    it('should compute merkleRoot deterministically for a 2-record chain (regression: F2 pair)', async () => {
        const HASH_A = 'a'.repeat(64);
        const HASH_B = 'b'.repeat(64);
        const queryRecords = vi.fn().mockResolvedValue({
            records: [
                makeRecord(2, HASH_B, HASH_A),
                makeRecord(1, HASH_A, ''),
            ],
        });

        const result = await runLedgerAnchor({ last: 2 }, { queryRecords });

        // expected: root = sha256(HASH_A_hex_string + HASH_B_hex_string)
        // callers can independently compute the same value (bound to the anchors[].recordHash array)
        expect(result.merkleRoot).not.toBeNull();
        expect(result.merkleRoot).toMatch(/^[a-f0-9]{64}$/);
        // counterexample: the root must not equal either leaf (2 nodes must be aggregated)
        expect(result.merkleRoot).not.toBe(HASH_A);
        expect(result.merkleRoot).not.toBe(HASH_B);
    });
});
