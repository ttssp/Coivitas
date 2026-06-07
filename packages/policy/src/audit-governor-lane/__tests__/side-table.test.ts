/**
 * InMemorySideTableAppender unit tests.
 *
 * Coverage:
 * - append happy path + hash chain formation
 * - verifyChain happy path (empty / single row / multiple rows)
 * - tamper-evidence detection: recordHash tampering -> SIDE_TABLE_ROW_TAMPERED
 * - tamper-evidence detection: prevRowHash tampering -> SIDE_TABLE_ANCHOR_MISMATCH
 * - Duplicate append for the same recordId -> throw
 * - genesis hash value is consistent
 * - agent-dimension filtered verifyChain
 *
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { DID, Timestamp } from '@coivitas/types';

import {
    InMemorySideTableAppender,
    SIDE_TABLE_GENESIS_HASH,
    computeRowHash,
} from '../side-table.js';
import type { SideTableEntry } from '../types.js';

const AGENT_DID = 'did:agent:test-agent-001' as DID;
const OTHER_AGENT_DID = 'did:agent:other-agent' as DID;
const TIMESTAMP = '2026-05-05T10:00:00.000Z' as Timestamp;

function entry(
    recordId: string,
    recordHash: string,
    agentDid: DID = AGENT_DID,
): SideTableEntry {
    return { recordId, recordHash, agentDid, createdAt: TIMESTAMP };
}

describe('SIDE_TABLE_GENESIS_HASH', () => {
    it('should be SHA-256 of empty string', () => {
        expect(SIDE_TABLE_GENESIS_HASH).toBe(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        );
    });
});

describe('computeRowHash', () => {
    it('should produce deterministic output', () => {
        const h1 = computeRowHash('prev', 'rec', 'hash', 'did', 'ts');
        const h2 = computeRowHash('prev', 'rec', 'hash', 'did', 'ts');
        expect(h1).toBe(h2);
    });

    it('should produce different output for different inputs', () => {
        const h1 = computeRowHash('prev', 'rec1', 'hash', 'did', 'ts');
        const h2 = computeRowHash('prev', 'rec2', 'hash', 'did', 'ts');
        expect(h1).not.toBe(h2);
    });

    it('should be 64-char hex string (SHA-256)', () => {
        const h = computeRowHash('a', 'b', 'c', 'd', 'e');
        expect(h).toMatch(/^[0-9a-f]{64}$/);
    });
});

describe('InMemorySideTableAppender', () => {
    let appender: InMemorySideTableAppender;

    beforeEach(() => {
        appender = new InMemorySideTableAppender();
    });

    describe('append', () => {
        it('should append first entry with genesis prevRowHash', async () => {
            const result = await appender.append(entry('rec-001', 'hash-001'));
            expect(result.rowHash).toBeTruthy();
            expect(result.rowHash).toMatch(/^[0-9a-f]{64}$/);
            expect(appender.size).toBe(1);
        });

        it('should chain entries (prevRowHash = previous rowHash)', async () => {
            const r1 = await appender.append(entry('rec-001', 'hash-001'));
            const r2 = await appender.append(entry('rec-002', 'hash-002'));

            // r2's rowHash is computed from r1's rowHash
            const expected = computeRowHash(
                r1.rowHash,
                'rec-002',
                'hash-002',
                AGENT_DID as string,
                TIMESTAMP as string,
            );
            expect(r2.rowHash).toBe(expected);
        });

        it('should throw on duplicate recordId (append-only)', async () => {
            await appender.append(entry('rec-001', 'hash-001'));

            await expect(
                appender.append(entry('rec-001', 'hash-duplicate')),
            ).rejects.toThrow('SIDE_TABLE_ANCHOR_MISMATCH');
        });

        it('should support multiple agents', async () => {
            await appender.append(entry('rec-001', 'hash-001', AGENT_DID));
            await appender.append(
                entry('rec-002', 'hash-002', OTHER_AGENT_DID),
            );
            expect(appender.size).toBe(2);
        });
    });

    describe('verifyChain', () => {
        it('should pass for empty chain', async () => {
            const result = await appender.verifyChain();
            expect(result.valid).toBe(true);
        });

        it('should pass for single entry chain', async () => {
            await appender.append(entry('rec-001', 'hash-001'));
            const result = await appender.verifyChain();
            expect(result.valid).toBe(true);
        });

        it('should pass for multi-entry chain', async () => {
            await appender.append(entry('rec-001', 'hash-001'));
            await appender.append(entry('rec-002', 'hash-002'));
            await appender.append(entry('rec-003', 'hash-003'));

            const result = await appender.verifyChain();
            expect(result.valid).toBe(true);
        });

        it('should detect tampered recordHash -> SIDE_TABLE_ROW_TAMPERED', async () => {
            await appender.append(entry('rec-001', 'hash-001'));
            await appender.append(entry('rec-002', 'hash-002'));

            // Tamper with the second row's recordHash
            appender._tamperRecordHash('rec-002', 'tampered-hash');

            const result = await appender.verifyChain();
            expect(result.valid).toBe(false);
            expect(result.errorCode).toBe('SIDE_TABLE_ROW_TAMPERED');
            expect(result.brokenAt).toBe('rec-002');
        });

        it('should detect tampered prevRowHash -> SIDE_TABLE_ANCHOR_MISMATCH', async () => {
            await appender.append(entry('rec-001', 'hash-001'));
            await appender.append(entry('rec-002', 'hash-002'));

            // Tamper with the second row's prevRowHash
            appender._tamperPrevRowHash('rec-002', 'tampered-prev');

            const result = await appender.verifyChain();
            expect(result.valid).toBe(false);
            expect(result.errorCode).toBe('SIDE_TABLE_ANCHOR_MISMATCH');
            expect(result.brokenAt).toBe('rec-002');
        });

        it('should detect tampered first row prevRowHash', async () => {
            await appender.append(entry('rec-001', 'hash-001'));

            // Tamper with the first row's prevRowHash (should be genesis)
            appender._tamperPrevRowHash('rec-001', 'not-genesis');

            const result = await appender.verifyChain();
            expect(result.valid).toBe(false);
            expect(result.errorCode).toBe('SIDE_TABLE_ANCHOR_MISMATCH');
            expect(result.brokenAt).toBe('rec-001');
        });

        it('should verify chain filtered by agentDid (full chain still validated)', async () => {
            await appender.append(entry('rec-001', 'hash-001', AGENT_DID));
            await appender.append(
                entry('rec-002', 'hash-002', OTHER_AGENT_DID),
            );

            const result = await appender.verifyChain(AGENT_DID);
            expect(result.valid).toBe(true);
        });
    });

    describe('utility methods', () => {
        it('should return last row hash', async () => {
            expect(appender.getLastRowHash()).toBeUndefined();

            const r1 = await appender.append(entry('rec-001', 'hash-001'));
            expect(appender.getLastRowHash()).toBe(r1.rowHash);

            const r2 = await appender.append(entry('rec-002', 'hash-002'));
            expect(appender.getLastRowHash()).toBe(r2.rowHash);
        });

        it('should clear all rows', async () => {
            await appender.append(entry('rec-001', 'hash-001'));
            appender.clear();
            expect(appender.size).toBe(0);
            expect(appender.getLastRowHash()).toBeUndefined();
        });
    });
});
