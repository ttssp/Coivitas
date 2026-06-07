/**
 * ledger anchor -- CLI command for exporting hash-chain anchors
 *
 * Purpose: query the most recent N action records, extract their hash-chain anchors, and optionally compute a Merkle root.
 * Under the hood it uses HashChain.generateProof() + ActionRecorder.query().
 *
 * Output formats:
 *   json: { anchors: [{ recordId, recordHash, createdAt }], merkleRoot: string }
 *   text: print anchor info line by line
 *
 */

import { Command } from 'commander';

import { hash } from '@coivitas/crypto';
import { ActionRecorder } from '@coivitas/policy';
import type { PersistedActionRecord } from '@coivitas/policy';
import type { DID } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import { createCliPool, printOutput } from '../runtime.js';

// ── Public types ──────────────────────────────────────────────────────────────────

export interface LedgerAnchorOptions {
    last: number;
    agentDid?: string;
    format?: 'json' | 'text';
}

export interface AnchorEntry {
    recordId: string;
    recordHash: string;
    previousRecordHash: string;
    createdAt: string;
}

export interface LedgerAnchorResult {
    anchors: AnchorEntry[];
    merkleRoot: string | null;
    chainValid: boolean;
    chainLength: number;
}

export interface LedgerAnchorDeps {
    /** Injectable query function, so unit tests can bypass the database*/
    queryRecords?: (filters: {
        agentDid?: DID;
        limit?: number;
        order?: 'asc' | 'desc';
    }) => Promise<{ records: PersistedActionRecord[] }>;
}

/**
 * Run chain-continuity verification directly off the anchors[].recordHash + previousRecordHash fields.
 *
 * HashChain.verify() cannot be used: it re-canonicalizes the entire PersistedActionRecord and
 * recomputes the hash, but on persistence the ledger's recordHash is produced by
 * computeRecordHash(unsignedPayload, previousRecordHash) in packages/policy/src/recorder/shared.ts --
 * it canonicalizes only the unsigned payload and never includes fields appended after persistence such
 * as recordHash / actorSignature / ledgerSignature. The two computation schemes produce different outputs,
 * so verify would always declare a healthy chain chainValid=false.
 *
 * Here we only verify "chain continuity" -- the previous record's recordHash must equal the next record's previousRecordHash;
 * this matches the contract in packages/policy/src/recorder/integrity-checker.ts. The internal integrity of
 * recordHash itself is already guaranteed by actorSignature/ledgerSignature at write time.
 *
 * @returns when valid=false, brokenAtIndex is the failing position (0 means a misaligned genesis position), expected is
 *   the prevHash that should appear at that position, and actual is the observed value; when valid=true, chainLength=records.length.
 */
function verifyAnchorContinuity(records: PersistedActionRecord[]): {
    valid: boolean;
    chainLength: number;
    brokenAtIndex?: number;
    expected?: string;
    actual?: string;
} {
    let expectedPrev = '';
    for (let i = 0; i < records.length; i += 1) {
        const r = records[i]!;
        if (r.previousRecordHash !== expectedPrev) {
            return {
                valid: false,
                chainLength: i,
                brokenAtIndex: i,
                expected: expectedPrev,
                actual: r.previousRecordHash,
            };
        }
        expectedPrev = r.recordHash;
    }
    return { valid: true, chainLength: records.length };
}

/**
 * Build a Merkle tree directly from anchors[].recordHash and return the root.
 *
 * HashChain.generateProof() is not reused: it re-canonicalizes+hashes the leaves (depending on
 * the whole record shape), so its root would never match the anchors[].recordHash array.
 * Here we treat recordHash as a "ready-made leaf", exactly matching the recordHash persisted by ActionRecorder,
 * so callers recomputing over anchors get the same result.
 *
 * Node-combination convention: same as hash-chain.ts L166-168 -- SHA-256 over the hex string text,
 * not over the raw bytes; on an odd node count, duplicate the last node (standard padding).
 */
function computeMerkleRootFromAnchors(anchors: AnchorEntry[]): string | null {
    if (anchors.length === 0) {
        return null;
    }
    if (anchors.length === 1) {
        return anchors[0]!.recordHash;
    }
    let layer: string[] = anchors.map((a) => a.recordHash);
    while (layer.length > 1) {
        if (layer.length % 2 !== 0) {
            layer.push(layer[layer.length - 1]!);
        }
        const next: string[] = [];
        for (let i = 0; i < layer.length; i += 2) {
            const combined = layer[i]! + layer[i + 1]!;
            next.push(hash(new TextEncoder().encode(combined)));
        }
        layer = next;
    }
    return layer[0]!;
}

/**
 * Execution body (extracted for unit testing)
 *
 * Implementation notes:
 * 1. Query with order: 'desc' to take the most recent N (the ledger head), matching `--last N` semantics
 * 2. Reverse the results back to chronological order (old -> new), so recomputation over anchors follows that order
 * 3. Use verifyAnchorContinuity to check chain continuity (does not call HashChain.verify; see the function docs)
 * 4. Use computeMerkleRootFromAnchors to compute the Merkle root directly over the recordHash array
 * 5. Return the anchors list + merkleRoot + chain verification result
 */
export async function runLedgerAnchor(
    options: LedgerAnchorOptions,
    deps: LedgerAnchorDeps = {},
): Promise<LedgerAnchorResult> {
    const { last, agentDid } = options;

    if (!Number.isInteger(last) || last < 1) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `--last must be a positive integer, got: ${last}`,
        );
    }

    let records: PersistedActionRecord[];

    if (deps.queryRecords) {
        const result = await deps.queryRecords({
            agentDid: agentDid as DID | undefined,
            limit: last,
            order: 'desc',
        });
        records = result.records;
    } else {
        const ledgerPrivateKey = process.env.LEDGER_PRIVATE_KEY;
        if (!ledgerPrivateKey) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'LEDGER_PRIVATE_KEY is required for ledger anchor.',
            );
        }
        const pool = createCliPool();
        try {
            const recorder = new ActionRecorder(pool, {
                kind: 'standard',
                ledgerPrivateKey,
            });
            const result = await recorder.query({
                agentDid: agentDid as DID | undefined,
                limit: last,
                order: 'desc',
            });
            records = result.records;
        } finally {
            await pool.end();
        }
    }

    // a DESC query returns [newest, ..., oldest]; the output semantics need chronological order, so reverse once
    records = records.slice().reverse();

    if (records.length === 0) {
        return {
            anchors: [],
            merkleRoot: null,
            chainValid: true,
            chainLength: 0,
        };
    }

    const anchors: AnchorEntry[] = records.map((r) => ({
        recordId: r.recordId,
        recordHash: r.recordHash,
        previousRecordHash: r.previousRecordHash,
        createdAt: r.createdAt,
    }));

    const verifyResult = verifyAnchorContinuity(records);
    const merkleRoot = computeMerkleRootFromAnchors(anchors);

    return {
        anchors,
        merkleRoot,
        chainValid: verifyResult.valid,
        chainLength: verifyResult.chainLength,
    };
}

export const createLedgerAnchorCommand = (): Command => {
    const command = new Command('anchor')
        .description(
            'Export hash-chain head anchors and Merkle root from the ledger.',
        )
        .requiredOption(
            '--last <N>',
            'Number of recent records to include.',
            parseInt,
        )
        .option('--agent-did <DID>', 'Filter by agent DID.')
        .option(
            '--format <fmt>',
            'Output format: json (default) or text.',
            'json',
        )
        .action(async (options: LedgerAnchorOptions) => {
            const result = await runLedgerAnchor(options);
            const asJson = (options.format ?? 'json') === 'json';
            if (asJson) {
                printOutput(result, true);
            } else {
                // text mode: print line by line
                for (const anchor of result.anchors) {
                    console.log(
                        `[${anchor.createdAt}] ${anchor.recordId} hash=${anchor.recordHash}`,
                    );
                }
                console.log(`merkle_root=${result.merkleRoot ?? 'n/a'}`);
                console.log(
                    `chain_valid=${result.chainValid} chain_length=${result.chainLength}`,
                );
            }
        });

    return command;
};
