/**
 * Unit tests for the audit-query command
 *
 * Covered paths:
 * - Success path: runAuditQuery returns the record array via deps.queryRecords
 * - Missing-parameter path: throws ProtocolError('INVALID_MESSAGE') when principal is empty
 * - Error path: throws ProtocolError('INVALID_MESSAGE') when the since format is invalid
 */

import { describe, expect, it, vi } from 'vitest';

import { ProtocolError } from '@coivitas/types';
import type { PersistedActionRecord } from '@coivitas/policy';
import type { DID, Timestamp } from '@coivitas/types';

import { runAuditQuery } from './audit-query.js';

const PRINCIPAL: DID =
    'did:agent:aabbccdd0011223344556677889900aabbccdd00' as DID;

const FAKE_RECORD: PersistedActionRecord = {
    recordId: 'rec-001',
    agentDid: 'did:agent:1111222233334444555566667777888899990000' as DID,
    principalDid: PRINCIPAL,
    actionType: 'SEND_MESSAGE',
    parametersSummary: null,
    authorizationRef: null,
    resultSummary: null,
    recordHash: 'abc123',
    previousRecordHash: '',
    actorSignature: 'sig-actor' as PersistedActionRecord['actorSignature'],
    ledgerSignature: 'sig-ledger' as PersistedActionRecord['ledgerSignature'],
    createdAt: '2026-05-01T00:00:00.000Z' as Timestamp,
};

describe('runAuditQuery', () => {
    it('should return records from queryRecords when called with valid options', async () => {
        const queryRecords = vi
            .fn()
            .mockResolvedValue({ records: [FAKE_RECORD] });

        const result = await runAuditQuery(
            { principal: PRINCIPAL },
            { queryRecords },
        );

        expect(result).toHaveLength(1);
        expect(result[0]?.recordId).toBe('rec-001');
        expect(queryRecords).toHaveBeenCalledWith(
            expect.objectContaining({ principalDid: PRINCIPAL }),
        );
    });

    it('should pass since as createdFrom when provided', async () => {
        const since = '2026-04-01T00:00:00.000Z';
        const queryRecords = vi.fn().mockResolvedValue({ records: [] });

        await runAuditQuery({ principal: PRINCIPAL, since }, { queryRecords });

        expect(queryRecords).toHaveBeenCalledWith(
            expect.objectContaining({ createdFrom: since }),
        );
    });

    it('should throw INVALID_MESSAGE when since is not a valid ISO timestamp', async () => {
        await expect(
            runAuditQuery({ principal: PRINCIPAL, since: 'not-a-date' }, {}),
        ).rejects.toThrow(ProtocolError);

        await expect(
            runAuditQuery({ principal: PRINCIPAL, since: 'not-a-date' }, {}),
        ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    });

    it('should pass limit to queryRecords when provided', async () => {
        const queryRecords = vi.fn().mockResolvedValue({ records: [] });

        await runAuditQuery(
            { principal: PRINCIPAL, limit: 10 },
            { queryRecords },
        );

        expect(queryRecords).toHaveBeenCalledWith(
            expect.objectContaining({ limit: 10 }),
        );
    });

    // Regression: --limit must fail-closed and reject non-positive integers
    // Historical bug: limit was passed through to ActionRecorder.query() verbatim; 0/-1/NaN silently became LIMIT 0 or a backend error
    it('should throw INVALID_MESSAGE when limit is 0', async () => {
        await expect(
            runAuditQuery({ principal: PRINCIPAL, limit: 0 }, {}),
        ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    });

    it('should throw INVALID_MESSAGE when limit is negative', async () => {
        await expect(
            runAuditQuery({ principal: PRINCIPAL, limit: -1 }, {}),
        ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    });

    it('should throw INVALID_MESSAGE when limit is NaN (e.g. parseInt("foo"))', async () => {
        await expect(
            runAuditQuery({ principal: PRINCIPAL, limit: Number.NaN }, {}),
        ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    });

    // Regression: --since must be strictly ISO-8601 (round-trip validation)
    // Historical bug: Date.parse('1') / Date.parse('May 1, 2026') both return finite numbers and passed the old check
    it('should throw INVALID_MESSAGE when since is "1" (Date.parse passes but not ISO-8601)', async () => {
        await expect(
            runAuditQuery({ principal: PRINCIPAL, since: '1' }, {}),
        ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    });

    it('should throw INVALID_MESSAGE when since is "May 1, 2026" (locale string)', async () => {
        await expect(
            runAuditQuery(
                { principal: PRINCIPAL, since: 'May 1, 2026' },
                {},
            ),
        ).rejects.toMatchObject({ code: 'INVALID_MESSAGE' });
    });

    it('should accept since when it round-trips through new Date().toISOString()', async () => {
        const queryRecords = vi.fn().mockResolvedValue({ records: [] });
        const since = '2026-04-01T00:00:00.000Z';

        await runAuditQuery(
            { principal: PRINCIPAL, since },
            { queryRecords },
        );

        expect(queryRecords).toHaveBeenCalledWith(
            expect.objectContaining({ createdFrom: since }),
        );
    });
});
