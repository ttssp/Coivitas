/**
 * ap audit query — CLI command for querying audit records
 *
 * Purpose: query action records (PersistedActionRecord) by principal DID and time range.
 * Internally calls ActionRecorder.query() and outputs a JSON array.
 *
 */

import { Command } from 'commander';

import { ActionRecorder } from '@coivitas/policy';
import type { PersistedActionRecord } from '@coivitas/policy';
import type { DID, Timestamp } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import { createCliPool, printOutput } from '../runtime.js';

// ── Public types ──────────────────────────────────────────────────────────────────

export interface AuditQueryOptions {
    principal: string;
    since?: string;
    limit?: number;
}

export interface AuditQueryDeps {
    /** Injectable query function, so unit tests can bypass the database */
    queryRecords?: (filters: {
        principalDid: DID;
        createdFrom?: Timestamp;
        limit?: number;
    }) => Promise<{ records: PersistedActionRecord[] }>;
}

/**
 * Execution body (extracted for ease of unit testing)
 *
 * Execution order:
 * 1. Validate parameters (principal is required; since, if provided, must be valid ISO-8601)
 * 2. Create an ActionRecorder and call query()
 * 3. Output the records as JSON
 */
export async function runAuditQuery(
    options: AuditQueryOptions,
    deps: AuditQueryDeps = {},
): Promise<PersistedActionRecord[]> {
    const { principal, since, limit } = options;

    if (!principal) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            '--principal <DID> is required',
        );
    }

    // Strict ISO-8601 validation for since:
    // Date.parse is too permissive — non-ISO strings like "1" / "May 1, 2026" all pass. Here we require round-trip
    // consistency: `new Date(s).toISOString()` must equal the original value; otherwise treat it as invalid ISO-8601 (fail-closed).
    if (since !== undefined) {
        const parsed = Date.parse(since);
        const roundTrip = Number.isFinite(parsed)
            ? new Date(parsed).toISOString()
            : null;
        if (roundTrip !== since) {
            throw new ProtocolError(
                'INVALID_MESSAGE',
                `--since must be a valid ISO-8601 timestamp (e.g. 2026-04-01T00:00:00.000Z), got: ${since}`,
            );
        }
    }

    // Numeric validation for limit:
    // fail-closed contract consistent with ledger-anchor `--last`: must be a positive integer; an invalid value
    // must not be passed silently to PG (avoids LIMIT 0 / NaN turning into an empty result or a backend error).
    if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `--limit must be a positive integer, got: ${limit}`,
        );
    }

    if (deps.queryRecords) {
        const { records } = await deps.queryRecords({
            principalDid: principal as DID,
            createdFrom: since as Timestamp | undefined,
            limit: limit ?? undefined,
        });
        return records;
    }

    // Production path: requires DATABASE_URL + LEDGER_PRIVATE_KEY
    const ledgerPrivateKey = process.env.LEDGER_PRIVATE_KEY;
    if (!ledgerPrivateKey) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'LEDGER_PRIVATE_KEY is required for audit query.',
        );
    }

    const pool = createCliPool();
    try {
        const recorder = new ActionRecorder(pool, {
            kind: 'standard',
            ledgerPrivateKey,
        });
        const { records } = await recorder.query({
            principalDid: principal as DID,
            createdFrom: since as Timestamp | undefined,
            limit: limit ?? undefined,
        });
        return records;
    } finally {
        await pool.end();
    }
}

export const createAuditCommand = (): Command => {
    const command = new Command('audit').description('Audit record utilities.');

    command
        .command('query')
        .description('Query audit records for a principal DID.')
        .requiredOption(
            '--principal <DID>',
            'Principal DID to query records for.',
        )
        .option('--since <ISO>', 'ISO-8601 lower-bound timestamp (inclusive).')
        .option('--limit <N>', 'Maximum number of records to return.', parseInt)
        .action(async (options: AuditQueryOptions) => {
            const records = await runAuditQuery(options);
            printOutput(records, true);
        });

    return command;
};
