/**
 * 028-hcc-v0.2-backward-compatibility.ts — hcc v0.2 backward-compatibility migration script
 *
 * Design intent:
 *   Migrate existing hcc v0.1 → v0.2 data (per-chain batch processing;
 *   backfill chain_identity_jcs + recompute canonical_payload_hash + previous_hash + upgrade hcc_version).
 *
 * Three-step run order (028a → 028b → 028c):
 *   Step A: 028a_hcc_v0.2_pre_backfill.sql — ADD COLUMN chain_identity_jcs TEXT (nullable)
 *   Step B: this script (028-hcc-v0.2-backward-compatibility.ts) — backfill chain_identity_jcs + recompute hashes
 *   Step C: 028c_hcc_v0.2_post_backfill.sql — SET NOT NULL + VALIDATE CHECK (NOT VALID lock split)
 *
 * Safety constraints:
 *   - In multi-tenant tables, chains must be partitioned by the (chain_namespace, tenant_id, audit_class) triple
 *   - No cross-chain mixing — the previousHash chained recompute is only valid within a single chain partition
 *   - IS NOT DISTINCT FROM null-safe equality — must match correctly when tenant_id / audit_class is NULL
 *   - keyset cursor (chain_position, entry_id) — a valid two-dimensional keyset; entry_id alone is not enough (skip risk)
 *   - Idempotent restart — already-committed entries (chain_identity_jcs IS NOT NULL AND hcc_version='2.0.0') are skipped automatically
 *
 * CLI usage:
 *   pnpm ts-node scripts/migrations/028-hcc-v0.2-backward-compatibility.ts [--dry-run]
 *   --dry-run: SELECT + recompute + diff log only; no UPDATE, no COMMIT (mandatory before production rollout)
 */

import { Pool, type PoolClient } from 'pg';
import {
    canonicalizeChainIdentity,
    concatPreimage,
    computeCanonicalPayloadHashHex,
    type ChainIdentityShape,
} from '@coivitas/crypto';

// ─── Interface definitions ───────────────────────────────────────────────────

/**
 * MigrationOptions — migration script configuration options
 *
 * Field semantics:
 *   - batchSize: number of entries committed per batch (default 1000)
 *   - dryRun: SELECT + recompute + diff log only; no UPDATE, no COMMIT
 *   - onProgress: progress callback fired after each batch commit (hook point for monitoring metrics)
 *   - batchTimeoutMs: per-batch timeout (ms; default 30000)
 *   - retryPerBatch: retry count per failed batch (default 3; exponential backoff)
 */
interface MigrationOptions {
    batchSize?: number;
    dryRun?: boolean;
    onProgress?: (progress: MigrationProgress) => void;
    batchTimeoutMs?: number;
    retryPerBatch?: number;
}

/**
 * MigrationProgress — snapshot of migration progress
 *
 * currentBatchFirstEntryId: crash recovery anchor (first entryId of the current batch)
 */
interface MigrationProgress {
    batchesProcessed: number;
    entriesProcessed: number;
    entriesFailed: number;
    batchesCommitted: number;
    currentBatchFirstEntryId: string | null;
}

/**
 * ChainPartitionKey — chain identity triple
 *
 * Design intent:
 *   - In multi-tenant tables, chains must be partitioned by the (chain_namespace, tenant_id, audit_class) triple
 *   - tenant_id / audit_class may be NULL — must use IS NOT DISTINCT FROM null-safe equality
 *   - A plain = against NULL returns NULL (not TRUE) → cross-chain data gets mixed up → irreversible chain-integrity corruption
 */
interface ChainPartitionKey {
    chain_namespace: string;
    tenant_id: string | null;
    audit_class: string | null;
}

/** Row type returned by selectNextBatch */
interface ChainEntryRow {
    entry_id: string;
    canonical_payload: string;
    canonical_payload_hash: string;
    previous_hash: string;
    chain_position: number;
    chain_namespace: string;
    tenant_id: string | null;
    audit_class: string | null;
}

// ─── main entrypoint ─────────────────────────────────────────────────────────

/**
 * migrateHccV01ToV02 — hcc v0.1 → v0.2 migration main entrypoint
 *
 * Execution order:
 *   Step 0: pre-check — count the total number of entries to migrate (union_total)
 *   Step 1: listMigrationChains — enumerate the chains to migrate by the (chain_namespace, tenant_id, audit_class) triple
 *   Step 2: per-chain keyset cursor batch processing
 *   Step 3: processBatchWithRetry — exponential backoff retry; idempotent restart
 */
export async function migrateHccV01ToV02(
    pool: Pool,
    opts: MigrationOptions = {},
): Promise<MigrationProgress> {
    const batchSize = opts.batchSize ?? 1000;
    const dryRun = opts.dryRun ?? false;
    const retryPerBatch = opts.retryPerBatch ?? 3;
    const progress: MigrationProgress = {
        batchesProcessed: 0,
        entriesProcessed: 0,
        entriesFailed: 0,
        batchesCommitted: 0,
        currentBatchFirstEntryId: null,
    };

    // Step 0: pre-check — count of chain_identity_jcs IS NULL rows + count of v0.1 hcc_version rows + union total
    // Note: chain_identity_jcs IS NULL and hcc_version = '1.0.0' may overlap (one row can satisfy both conditions)
    // totalEstimate uses union_total (aligned with the WHERE ... OR ... semantics of selectNextBatch)
    const preCheck = await pool.query<{
        null_jcs_count: string;
        v01_count: string;
        union_total: string;
    }>(
        `SELECT
            COUNT(*) FILTER (WHERE chain_identity_jcs IS NULL) AS null_jcs_count,
            COUNT(*) FILTER (WHERE hcc_version = '1.0.0') AS v01_count,
            COUNT(*) FILTER (WHERE chain_identity_jcs IS NULL OR hcc_version = '1.0.0') AS union_total
         FROM hash_chain_entries`,
    );

    const totalEstimate = parseInt(preCheck.rows[0]!.union_total, 10);
    console.log(
        `[Migration 028] pre-check: ${totalEstimate} entries to migrate (dryRun=${dryRun}, batchSize=${batchSize})`,
    );

    if (totalEstimate === 0) {
        console.log(
            `[Migration 028] no entries to migrate; migration script no-op`,
        );
        return progress;
    }

    // Step 1: chain-partition outer loop
    // CRITICAL: in multi-tenant tables, chains must be partitioned by chain identity
    // No cross-chain mixing — the previousHash chained recompute is only valid within a single chain
    const chains = await listMigrationChains(pool);
    console.log(
        `[Migration 028] discovered ${chains.length} distinct chains to migrate`,
    );

    for (const chain of chains) {
        console.log(
            `[Migration 028] processing chain (namespace=${chain.chain_namespace}, tenant_id=${chain.tenant_id ?? 'NULL'}, audit_class=${chain.audit_class ?? 'NULL'})`,
        );

        // Step 1.1: chain-internal keyset cursor (chain_position, entry_id) two-dimensional advance
        // within-chain ORDER BY chain_position ASC + entry_id ASC prevents skips
        let lastChainPosition: number | null = null;
        let lastEntryId: string | null = null;

        // keyset pagination idiom: break out via rows.length === 0 (no fixed upper bound)
        // eslint-disable-next-line no-constant-condition
        while (true) {
            // Step 1.2: SELECT next batch within chain (IS NOT DISTINCT FROM null-safe + keyset cursor)
            const rows = await selectNextBatch(
                pool,
                chain,
                lastChainPosition,
                lastEntryId,
                batchSize,
            );
            if (rows.length === 0) break;

            progress.currentBatchFirstEntryId = rows[0]!.entry_id;

            // Step 1.3: process batch with retry (idempotent — retrying the same batch never re-UPDATEs already-committed entries)
            const batchResult = await processBatchWithRetry(
                pool,
                chain,
                rows,
                retryPerBatch,
                dryRun,
            );
            progress.entriesProcessed += batchResult.entriesProcessed;
            progress.entriesFailed += batchResult.entriesFailed;
            progress.batchesProcessed++;
            if (!dryRun) progress.batchesCommitted++;

            // Step 1.4: progress callback (hook point for monitoring metrics)
            if (opts.onProgress) opts.onProgress({ ...progress });
            console.log(
                `[Migration 028] chain (${chain.chain_namespace}/${chain.tenant_id ?? 'NULL'}/${chain.audit_class ?? 'NULL'}) batch ${progress.batchesProcessed} done ` +
                    `(entries: ${batchResult.entriesProcessed} OK / ${batchResult.entriesFailed} fail; ` +
                    `total: ${progress.entriesProcessed}/${totalEstimate})`,
            );

            // Step 1.5: advance cursor — (chain_position, entry_id) two-dimensional keyset tuple
            const tail = rows[rows.length - 1]!;
            lastChainPosition = tail.chain_position;
            lastEntryId = tail.entry_id;
        }
    }

    console.log(
        `[Migration 028] migration complete: total ${progress.entriesProcessed} entries migrated ` +
            `(${progress.entriesFailed} failed; ${progress.batchesCommitted} batches committed)`,
    );

    // Step 2: post-backfill invariant
    // Background: processBatch does an independent BEGIN/COMMIT per batch; there is no outer overarching transaction.
    // A failure in a single chain/batch will throw and abort the migration, but batches already COMMITted before that
    // remain as v2 → a partial-backfill state.
    // Risk: if the caller ignores the exception / wrongly concludes completion after a restart and runs 028c
    // (SET NOT NULL + VALIDATE CHECK) on the partial state → the constraint is applied to incomplete data
    // (NOT NULL fails OR a broken chain goes undetected).
    // Guard: after completion, recompute union_total; non-zero → fail-closed throw, blocking the subsequent 028c DDL.
    // This explicitly marks "partial backfill" as a non-advanceable state (resumable: fix the failure cause and rerun
    // this script until union_total=0).
    // dryRun does not UPDATE, so union_total is necessarily non-zero; this invariant is therefore skipped.
    if (!dryRun) {
        const postCheck = await pool.query<{ union_total: string }>(
            `SELECT
                COUNT(*) FILTER (WHERE chain_identity_jcs IS NULL OR hcc_version = '1.0.0') AS union_total
             FROM hash_chain_entries`,
        );
        const remaining = parseInt(postCheck.rows[0]!.union_total, 10);
        if (remaining !== 0) {
            throw new Error(
                `[Migration 028] post-backfill invariant FAILED: ${remaining} entries still v0.1 ` +
                    `(chain_identity_jcs IS NULL OR hcc_version = '1.0.0'). ` +
                    `Partial-backfill state; do NOT run 028c (SET NOT NULL + VALIDATE CHECK). ` +
                    `Fix the failure cause and rerun this script until union_total=0 (the script is idempotent and skips rows already at v2).`,
            );
        }
        console.log(
            `[Migration 028] post-backfill invariant PASS: union_total=0; the 028c DDL can be run safely`,
        );
    }

    return progress;
}

// ─── helper functions ─────────────────────────────────────────────────────────

/**
 * listMigrationChains — list the distinct chain partitions to migrate
 *
 * SQL: SELECT DISTINCT (chain_namespace, tenant_id, audit_class) FROM hash_chain_entries
 *      WHERE hcc_version = '1.0.0' OR chain_identity_jcs IS NULL
 *      ORDER BY chain_namespace, tenant_id NULLS FIRST, audit_class NULLS FIRST
 *
 * ORDER BY makes the partition run order deterministic — the run order stays consistent across crash-recovery restarts (friendly)
 */
async function listMigrationChains(pool: Pool): Promise<ChainPartitionKey[]> {
    const result = await pool.query<ChainPartitionKey>(
        `SELECT DISTINCT chain_namespace, tenant_id, audit_class
           FROM hash_chain_entries
          WHERE hcc_version = '1.0.0' OR chain_identity_jcs IS NULL
          ORDER BY chain_namespace ASC,
                   tenant_id ASC NULLS FIRST,
                   audit_class ASC NULLS FIRST`,
    );
    return result.rows;
}

/**
 * selectNextBatch — within-chain keyset cursor pagination
 *
 * CRITICAL:
 *   - Old cursor: `entry_id > $1` ORDER BY (chain_position, entry_id) — not a valid keyset; risk of skipping rows
 *   - New cursor: WHERE chain identity full tuple match (IS NOT DISTINCT FROM null-safe)
 *               + keyset (chain_position, entry_id) > (lastChainPosition, lastEntryId)
 *               + ORDER BY chain_position ASC, entry_id ASC
 *   - Strictly ascending chain_position within the same chain partition keeps the previousHash chained-recompute anchor consistent
 *
 * Idempotent WHERE condition: (chain_identity_jcs IS NULL OR hcc_version = '1.0.0')
 *   - Already-committed entries (chain_identity_jcs IS NOT NULL AND hcc_version='2.0.0') are excluded from the SELECT automatically
 *   - selectNextBatch auto-resumes on crash-recovery restart — no manual checkpoint needed
 */
async function selectNextBatch(
    pool: Pool,
    chain: ChainPartitionKey,
    lastChainPosition: number | null,
    lastEntryId: string | null,
    batchSize: number,
): Promise<ChainEntryRow[]> {
    // chain identity predicate — IS NOT DISTINCT FROM null-safe
    // tenant_id NULL = NULL → IS NOT DISTINCT FROM returns TRUE (plain = returns NULL → row is missed)
    const baseParams: unknown[] = [
        chain.chain_namespace,
        chain.tenant_id,
        chain.audit_class,
    ];

    // keyset cursor — within-chain (chain_position, entry_id) two-dimensional tuple advance
    const isFirstBatch = lastChainPosition === null && lastEntryId === null;
    const cursorClause = isFirstBatch
        ? ''
        : `AND (chain_position, entry_id) > ($4, $5)`;
    const cursorParams: unknown[] = isFirstBatch
        ? []
        : [lastChainPosition, lastEntryId];

    const batchSizeIdx = baseParams.length + cursorParams.length + 1;
    const query = `
        SELECT entry_id, canonical_payload, canonical_payload_hash, previous_hash, chain_position,
               chain_namespace, tenant_id, audit_class
          FROM hash_chain_entries
         WHERE chain_namespace = $1
           AND tenant_id IS NOT DISTINCT FROM $2
           AND audit_class IS NOT DISTINCT FROM $3
           AND (hcc_version = '1.0.0' OR chain_identity_jcs IS NULL)
           ${cursorClause}
         ORDER BY chain_position ASC, entry_id ASC
         LIMIT $${batchSizeIdx}
    `;
    const params = [...baseParams, ...cursorParams, batchSize];
    const result = await pool.query<ChainEntryRow>(query, params);
    return result.rows;
}

/**
 * processBatchWithRetry — process batch with exponential backoff retry on transient failures
 *
 * Design intent:
 *   - retry on network / lock-timeout / deadlock (idempotent — re-UPDATEing an already-UPDATEd entry has no side effects)
 *   - non-retryable error (constraint violation / data corruption) → fail-closed propagate
 *   - wait 1000ms * attempt before each retry (exponential backoff; 1s → 2s → 3s)
 */
async function processBatchWithRetry(
    pool: Pool,
    chain: ChainPartitionKey,
    rows: ChainEntryRow[],
    retryPerBatch: number,
    dryRun: boolean,
): Promise<{ entriesProcessed: number; entriesFailed: number }> {
    let lastErr: Error | null = null;
    for (let attempt = 1; attempt <= retryPerBatch; attempt++) {
        try {
            return await processBatch(pool, chain, rows, dryRun);
        } catch (err) {
            lastErr = err as Error;
            console.warn(
                `[Migration 028] batch attempt ${attempt}/${retryPerBatch} failed: ${lastErr.message}`,
            );
            if (attempt < retryPerBatch) {
                // exponential backoff: 1s * attempt (1s, 2s, 3s, ...)
                await new Promise((r) => setTimeout(r, 1000 * attempt));
            }
        }
    }
    // Exceeded retryPerBatch attempts → fail-closed throw
    throw lastErr!;
}

/**
 * processBatch — atomic processing of a single batch (BEGIN/COMMIT)
 *
 * CRITICAL: previousHash chained recompute
 *   - The previousHash of the first entry in the current batch must be read from the DB (the recomputed hash committed by the previous batch)
 *   - If the previous batch fully failed → fetchPrevCommittedHash fail-closed throw → processBatch throw → retry
 *   - previousHash advances along the chain across entries within the batch: prevCanonicalPayloadHash = newCanonicalPayloadHashHex
 *
 * CRITICAL: fetchPrevCommittedHash must be passed the chain partition key
 *   - Prevents mixing up cross-chain anchors → the previousHash chain breaks irreversibly
 *
 * v0.2 preimage layout (payload first; identity second):
 *   SHA-256(canonicalPayloadBytes ‖ chainIdentityJcsBytes) — payload first; identity second
 *
 * Four-field synchronous update (no partial updates allowed):
 *   chain_identity_jcs + canonical_payload_hash + previous_hash + hcc_version='2.0.0'
 */
async function processBatch(
    pool: Pool,
    chain: ChainPartitionKey,
    rows: ChainEntryRow[],
    dryRun: boolean,
): Promise<{ entriesProcessed: number; entriesFailed: number }> {
    const client = await pool.connect();
    let entriesProcessed = 0;
    let entriesFailed = 0;

    try {
        if (!dryRun) await client.query('BEGIN');

        // Step 1: fetch the previousHash anchor of the batch's first entry (read the committed hash from the DB)
        // CRITICAL: pass chain — fetchPrevCommittedHash's WHERE does a full tuple match
        const firstEntry = rows[0]!;
        let prevCanonicalPayloadHash = await fetchPrevCommittedHash(
            client,
            chain,
            firstEntry,
        );

        // Step 2: process entries one by one (chain_position strictly ASC; previousHash chained recompute)
        for (const row of rows) {
            try {
                // Step 2.1: build the ChainIdentityShape (plain strings; no branded types; L0 types not yet upgraded)
                // tenantId / auditClass: a null DB value maps to undefined (RFC 8785 skips undefined fields)
                const chainIdentityShape: ChainIdentityShape = {
                    chainNamespace: row.chain_namespace,
                    ...(row.tenant_id != null
                        ? { tenantId: row.tenant_id }
                        : {}),
                    ...(row.audit_class != null
                        ? { auditClass: row.audit_class }
                        : {}),
                };

                // Step 2.2: canonicalize chainIdentity (RFC 8785 JCS; undefined fields skipped)
                const chainIdentityJcs =
                    canonicalizeChainIdentity(chainIdentityShape);

                // Step 2.3: recompute canonicalPayloadHash
                // v0.2 preimage = canonicalPayloadBytes ‖ chainIdentityJcsBytes (payload first; identity second)
                const preimage = concatPreimage(
                    row.canonical_payload,
                    chainIdentityJcs,
                );
                const newCanonicalPayloadHashHex =
                    computeCanonicalPayloadHashHex(preimage);

                if (dryRun) {
                    // dry-run: log the diff, no UPDATE
                    console.log(
                        `[Migration 028] [DRY-RUN] entry ${row.entry_id} (chain_position=${row.chain_position}):` +
                            `\n  old canonical_payload_hash: ${row.canonical_payload_hash}` +
                            `\n  new canonical_payload_hash: ${newCanonicalPayloadHashHex}` +
                            `\n  old previous_hash:          ${row.previous_hash}` +
                            `\n  new previous_hash:          ${prevCanonicalPayloadHash}` +
                            `\n  chainIdentityJcs:           ${chainIdentityJcs}`,
                    );
                } else {
                    // Step 2.4: UPDATE row — four-field synchronous update (no partial updates; sustains chain integrity)
                    // CRITICAL: previous_hash updated in lockstep (using prevCanonicalPayloadHash; the previous entry's recomputed hash)
                    await client.query(
                        `UPDATE hash_chain_entries
                         SET chain_identity_jcs     = $1,
                             canonical_payload_hash = $2,
                             previous_hash          = $3,
                             hcc_version            = '2.0.0'
                         WHERE entry_id = $4`,
                        [
                            chainIdentityJcs,
                            newCanonicalPayloadHashHex,
                            prevCanonicalPayloadHash,
                            row.entry_id,
                        ],
                    );
                }

                // Step 2.5: advance prevCanonicalPayloadHash (used as the next entry's previous_hash)
                prevCanonicalPayloadHash = newCanonicalPayloadHashHex;
                entriesProcessed++;
            } catch (entryErr) {
                const errMsg = (entryErr as Error).message;
                console.error(
                    `[Migration 028] entry ${row.entry_id} fail: ${errMsg}`,
                );
                entriesFailed++;

                // Any per-row failure must abort the whole batch (throw → batch ROLLBACK).
                // Old logic: on an entry-level error it did entriesFailed++ and continued to the next entry, but
                // prevCanonicalPayloadHash was not advanced past the failed row → the failed row was bypassed and
                // subsequent rows committed pointing at the hash before the failed row → broken chain (the post-backfill
                // SQL constraints do not validate linkage), and on rerun the already-v2 subsequent rows are skipped,
                // leaving the broken chain in place.
                // Fix: no more skip-and-continue; any per-row failure throws → triggers a batch-level ROLLBACK (see the
                // catch below), upholding the chain-integrity invariant "do not commit a successor as v2 until all its
                // predecessors are successfully rewritten".
                throw entryErr;
            }
        }

        if (!dryRun) await client.query('COMMIT');
        return { entriesProcessed, entriesFailed };
    } catch (batchErr) {
        if (!dryRun) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackErr) {
                // A failed ROLLBACK must not mask the original error — the original batchErr takes precedence on throw
                console.error(
                    `[Migration 028] ROLLBACK failed: ${(rollbackErr as Error).message}`,
                );
            }
        }
        throw batchErr;
    } finally {
        client.release();
    }
}

/**
 * fetchPrevCommittedHash — fetch the previousHash anchor of the batch's first entry
 *
 * Logic:
 *   - firstEntry.chain_position === 0 (genesis): return 64 zeros (GENESIS_PREVIOUS_HASH)
 *   - firstEntry.chain_position > 0: look up the committed hash at chain_position - 1 within the chain partition
 *   - previous entry hcc_version !== '2.0.0' → fail-closed throw
 *     (the previous batch is not committed; the previousHash chained recompute cannot be sustained)
 *
 * CRITICAL:
 *   - WHERE must include a chain identity full tuple match (chain_namespace = $X AND tenant_id IS NOT DISTINCT FROM $Y AND audit_class IS NOT DISTINCT FROM $Z)
 *   - The old SQL used only chain_position = $1 LIMIT 1 → in multi-tenant tables it fetches the wrong cross-chain anchor → irreversible chain-integrity corruption
 *   - IS NOT DISTINCT FROM = null-safe equality (PostgreSQL; matches correctly when tenant_id / audit_class is NULL)
 */
async function fetchPrevCommittedHash(
    client: PoolClient,
    chain: ChainPartitionKey,
    firstEntry: { chain_position: number },
): Promise<string> {
    // genesis entry (chain_position = 0) → previousHash = 64 zeros
    const GENESIS_PREVIOUS_HASH =
        '0000000000000000000000000000000000000000000000000000000000000000';
    if (firstEntry.chain_position === 0) {
        return GENESIS_PREVIOUS_HASH;
    }

    // Non-genesis — fetch the committed hash at chain_position - 1 within the chain partition
    const prevResult = await client.query<{
        canonical_payload_hash: string;
        hcc_version: string;
    }>(
        `SELECT canonical_payload_hash, hcc_version
           FROM hash_chain_entries
          WHERE chain_namespace = $1
            AND tenant_id IS NOT DISTINCT FROM $2
            AND audit_class IS NOT DISTINCT FROM $3
            AND chain_position = $4
          LIMIT 1`,
        [
            chain.chain_namespace,
            chain.tenant_id,
            chain.audit_class,
            firstEntry.chain_position - 1,
        ],
    );

    if (prevResult.rows.length === 0) {
        // previousHash anchor missing → fail-closed throw
        throw new Error(
            `previousHash anchor missing: chain (${chain.chain_namespace}/${chain.tenant_id ?? 'NULL'}/${chain.audit_class ?? 'NULL'}) chain_position ${firstEntry.chain_position - 1} not found`,
        );
    }

    const prev = prevResult.rows[0]!;
    if (prev.hcc_version !== '2.0.0') {
        // Previous entry not committed (still v0.1) → fail-closed throw → processBatchWithRetry retries
        throw new Error(
            `previousHash anchor in inconsistent state: chain_position ${firstEntry.chain_position - 1} hcc_version=${prev.hcc_version} (expected "2.0.0"; previous batch not committed)`,
        );
    }

    return prev.canonical_payload_hash;
}

// ─── CLI entrypoint ───────────────────────────────────────────────────────────

/**
 * CLI main — entrypoint for running the script directly
 *
 * Usage:
 *   pnpm ts-node scripts/migrations/028-hcc-v0.2-backward-compatibility.ts [--dry-run]
 *
 * Environment variables (aligned with db-setup.sh / db-migrate.sh):
 *   DATABASE_URL: PostgreSQL connection string (preferred)
 *   PGHOST / PGPORT / PGUSER / PGPASSWORD / PGDATABASE: individual connection parameters (when DATABASE_URL is absent)
 *
 * dry-run enforcement:
 *   --dry-run must be run first before any production rollout (mandatory)
 *   Production rollout verification order: dev --dry-run → staging --dry-run → staging real run → production real run
 */
async function main(): Promise<void> {
    const dryRun = process.argv.includes('--dry-run');

    if (dryRun) {
        console.log(
            `[Migration 028] DRY-RUN mode: SELECT + recompute + diff log only; no UPDATE, no COMMIT`,
        );
    } else {
        console.log(
            `[Migration 028] real migration mode: will update data in the hash_chain_entries table`,
        );
    }

    // Connection pool config — single worker, single pool (the migration script is not parallel; max=5 is sufficient)
    const pool = new Pool({
        connectionString: process.env['DATABASE_URL'],
        // When DATABASE_URL is absent, use individual parameters (the pg library reads PG* environment variables automatically)
        max: 5,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 10_000,
    });

    try {
        const progress = await migrateHccV01ToV02(pool, {
            batchSize: 1000,
            dryRun,
            retryPerBatch: 3,
            onProgress: (p) => {
                // monitoring callback — can hook into external metrics (Prometheus / OpenTelemetry)
                console.log(
                    `[Migration 028] [PROGRESS] batches=${p.batchesCommitted} entries=${p.entriesProcessed} failed=${p.entriesFailed}`,
                );
            },
        });

        console.log(`[Migration 028] final progress:`, progress);
        if (progress.entriesFailed > 0) {
            console.warn(
                `[Migration 028] WARNING: ${progress.entriesFailed} entries failed — review the logs before deciding whether to rerun`,
            );
            process.exit(1);
        }
        process.exit(0);
    } catch (err) {
        console.error(
            `[Migration 028] FATAL: migration aborted: ${(err as Error).message}`,
        );
        process.exit(1);
    } finally {
        await pool.end();
    }
}

// Determine whether this is being run directly (not imported)
// CommonJS: require.main === module
// ESM / ts-node: process.argv[1] contains this file's path
if (
    typeof require !== 'undefined' &&
    typeof module !== 'undefined' &&
    require.main === module
) {
    void main();
}
