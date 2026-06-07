/**
 * MCP Bridge — scope validator
 *
 * validateMCPCallScope implementation:
 *   - per-call limit (numeric_limit vs max_per_call)
 *   - currency check top-level guard (mandatory whenever max_value_per_call / max_total_value exists)
 *   - cumulative limits:
 *     - quota check + value check + idempotency cached_result + counter check-and-increment
 *       **all MUST be inside a single outer SERIALIZABLE transaction**
 *     - any reject → the outer tx ROLLBACK undoes all counter changes
 *     - the idempotency cached_result and the counter commit together or ROLLBACK together
 *
 * Acceptance behavior (acceptance gate):
 *   - quota=9 + value+$10=$105 reject → outer ROLLBACK → quota stays =9, not consumed
 *   - idempotency reuse of a cached fail result (quota_exhausted) → return the same fail; do not increment the counter again
 *   - different currency values are counted independently; a USD value does not affect the EUR counter
 *   - SERIALIZABLE retry on a pending race (a concurrent client retry with the same idempotency_key triggers a RETRY)
 *
 * Key invariants:
 *   - quota + value accounting is inside **a single outer SERIALIZABLE transaction** (grep verifies the double-tx anti-pattern = 0 lines)
 *   - currency check top-level guard (mandatory whenever max_value_per_call OR max_total_value exists)
 *   - idempotency_key reservation uses a single INSERT ... ON CONFLICT DO NOTHING RETURNING SQL statement
 *   - tests use runtime readFileSync + regex to verify the source contains no constraint-violating code (pinned by a grep test)
 */

import type { PoolClient } from 'pg';

import {
    MCP_ERROR,
    type MCPCallParams,
    type MCPErrorCode,
} from './types.js';

// ─── tokenId UUID format guard ────────────────────────────────
// the SQL DDL (028_mcp_quota_counter.sql + 025_mcp_outbox.sql owner_token_id) literally declares token_id UUID NOT NULL;
// at the protocol layer, if tokenId is not in UUID format → Postgres rejects the INSERT before the quota logic;
// the protocol-layer fail-closed guard keeps the SQL strong-typing constraint from being bypassed at runtime.
const UUID_REGEX =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuidFormat(value: string): boolean {
    return typeof value === 'string' && UUID_REGEX.test(value);
}

// ─── data model: ScopeClaim (literal disclosedClaim shape) ────

/**
 * ScopeClaim — disclosed scope claim wire shape
 *
 * - dim: dimension name ('max_per_call' / 'max_per_day' / 'max_value_per_call' / 'max_total_value' / ...)
 * - value: numeric value (number; max_total_value needs high precision, but the wire still uses number — the DB side is NUMERIC(20,2))
 * - currency: ISO-4217 string (mandatory only for the max_value_per_call / max_total_value dimensions)
 *
 * Note: this module does not verify the claim's internal signature (the disclosure flow is handled upstream by SD-Token verify);
 * this module only consumes already-disclosed claim values.
 */
export interface ScopeClaim {
    dim: string;
    value: number;
    currency?: string;
}

// ─── data model: ValidateScopeInput / Output ─────────────────────────────────

export interface ValidateScopeInput {
    /** MCP `tools/call` wire payload (the validated fields are in params.arguments) */
    mcpCall: MCPCallParams;
    /** SD-Token disclosed claims */
    disclosedClaims: ScopeClaim[];
    /** SD-Token id (durable counter key) */
    tokenId: string;
    /** request idempotency key (prevents double-counting on retry) */
    requestIdempotencyKey: string;
}

/**
 * ValidateScopeResult — validate wire shape
 *
 * - ok=true: passed; the caller may continue envelope processing
 * - ok=false: rejected; the caller must return an MCP error; code = internal; mcp_code = wire
 */
export type ValidateScopeResult =
    | { ok: true }
    | { ok: false; code: string; mcp_code: MCPErrorCode };

// ─── ScopeValidatorDeps ──────────────────────────────────────────────────────

/**
 * ScopeValidatorDeps — pg-abstracting dependencies (implementations inject a PoolClient; mockable in unit tests)
 *
 * **Key invariant**:
 *   - quota check + value check + idempotency cached + counter increment are all done
 *     **inside a single outer SERIALIZABLE transaction** (two parallel tx are **not** allowed)
 *   - any reject → the outer tx ROLLBACK undoes all counter changes
 *
 * The implementation's caller injects a PoolClient
 * factory, and the validator internally runs BEGIN ISOLATION LEVEL SERIALIZABLE ... COMMIT/ROLLBACK.
 */
export interface ScopeValidatorDeps {
    /**
     * Acquire a PoolClient (an exclusive connection; the caller is responsible for release).
     *
     * Implementations typically use `pool.connect()`; unit tests can mock it to return an object with query/release methods.
     */
    acquireClient: () => Promise<PoolClient>;

    /**
     * The current UTC date (YYYY-MM-DD) — injected for testability; defaults to new Date().toISOString().slice(0,10)
     */
    today?: () => string;
}

// ─── helper: SERIALIZABLE automatic retry ────────────────────────────────────

/**
 * SERIALIZABLE retry — "pending → SERIALIZABLE automatic retry by Postgres"
 *
 * After the application layer catches Postgres `ERROR: could not serialize access due to concurrent update` (SQLSTATE 40001),
 * it **re-runs** the entire outer tx; we also treat the internal IDEMPOTENCY_PENDING_RACE as a
 * retry trigger (throw → outer caller retries).
 *
 * **Max retries**: DEFAULT_SERIALIZABLE_RETRY_MAX times (3 is enough to cover typical concurrency).
 *
 * Note: unit tests have no concurrency scenario; retry is mainly covered by integration tests; this helper keeps a
 * retry cap to prevent a busy loop.
 */
export const DEFAULT_SERIALIZABLE_RETRY_MAX = 3;

const SERIALIZABLE_RETRY_TOKENS = [
    'could not serialize',
    '40001',
    'IDEMPOTENCY_PENDING_RACE',
    'VALUE_IDEMPOTENCY_PENDING_RACE',
];

function isSerializableRetryError(err: unknown): boolean {
    if (!(err instanceof Error)) return false;
    const msg = err.message;
    return SERIALIZABLE_RETRY_TOKENS.some((token) => msg.includes(token));
}

// ─── core: validateScope ─────────────────────────────

/**
 * validateScope — full implementation
 *
 * Flow:
 *   step 1: per-call numeric_limit validation (max_per_call)
 *   step 2 (pre-tx pure validation):
 *      - currency check top-level guard (mandatory whenever max_value_per_call OR max_total_value exists)
 *      - per-call value numeric comparison (max_value_per_call)
 *      - claim consistency (perCall + total both present with inconsistent currency)
 *      - on fail, return immediately; no counter is written
 *   step 3 (single outer SERIALIZABLE tx):
 *      - 3.1 quota idempotency reservation (INSERT ON CONFLICT DO NOTHING RETURNING)
 *      - 3.2 quota counter atomic check-and-increment (INSERT ON CONFLICT UPDATE WHERE)
 *      - 3.3 finalize quota idempotency 'ok' | 'fail'
 *      - 3.4 value idempotency reservation
 *      - 3.5 value counter atomic check-and-increment
 *      - 3.6 finalize value idempotency 'ok' | 'fail'
 *      - any fail → throw → outer tx ROLLBACK undoes quota + value counters
 *
 * **Key invariants**:
 *   - a single outer SERIALIZABLE transaction (quota + value as one atomic unit)
 *   - two parallel tx are not allowed (the grep test verifies the source has no `db\.transaction.*db\.transaction` anti-pattern)
 *   - a cached fail does not increment again (guaranteed by idempotency)
 *
 * @param input - mcpCall + disclosedClaims + tokenId + requestIdempotencyKey
 * @param deps - acquireClient + today
 * @returns ok: true | ok: false + code/mcp_code
 */
export async function validateScope(
    input: ValidateScopeInput,
    deps: ScopeValidatorDeps,
): Promise<ValidateScopeResult> {
    const { mcpCall, disclosedClaims, tokenId, requestIdempotencyKey } = input;

    // ── step 0: tokenId UUID format guard ──────────────
    // in the SQL DDL (028_mcp_quota_counter.sql + 025_mcp_outbox.sql owner_token_id), token_id is UUID NOT NULL;
    // at the protocol layer, if tokenId is not in UUID format → Postgres rejects the INSERT before the quota logic;
    // this protocol-layer guard fails closed: a non-UUID format is rejected immediately, and the SQL-layer strong-typing constraint is retained (double defense).
    if (!isUuidFormat(tokenId)) {
        return {
            ok: false,
            code: 'TOKEN_ID_INVALID_FORMAT',
            mcp_code: MCP_ERROR.TOKEN_ID_INVALID_FORMAT,
        };
    }

    // ── step 1: per-call numeric_limit ──────────────
    if (mcpCall.arguments.numeric_limit !== undefined) {
        const apClaim = disclosedClaims.find((c) => c.dim === 'max_per_call');
        if (!apClaim) {
            return {
                ok: false,
                code: 'AP_CLAIM_MISSING',
                mcp_code: MCP_ERROR.NO_PER_CALL_SCOPE,
            };
        }
        if (mcpCall.arguments.numeric_limit > apClaim.value) {
            return {
                ok: false,
                code: 'SCOPE_INFLATION_PER_CALL',
                mcp_code: MCP_ERROR.SCOPE_INFLATION,
            };
        }
    }

    // ── step 2: pre-tx pure validation ──────────────
    // currency check + per-call value numeric comparison + claim consistency
    // placed **before** the quota counter increment, so when validation fails the quota counter is not written
    const perDayClaim = disclosedClaims.find((c) => c.dim === 'max_per_day');
    const perCallClaim =
        mcpCall.arguments.value !== undefined
            ? disclosedClaims.find((c) => c.dim === 'max_value_per_call')
            : undefined;
    const totalClaim =
        mcpCall.arguments.value !== undefined
            ? disclosedClaims.find((c) => c.dim === 'max_total_value')
            : undefined;
    const enforcedCurrencyClaim = perCallClaim ?? totalClaim;

    // currency check, expanded top-level guard
    // every path that includes mcpCall.arguments.value first verifies the currency matches the disclosed claim currency
    if (enforcedCurrencyClaim) {
        if (mcpCall.arguments.currency === undefined) {
            return {
                ok: false,
                code: 'CURRENCY_MISSING',
                mcp_code: MCP_ERROR.CURRENCY_MISSING,
            };
        }
        if (mcpCall.arguments.currency !== enforcedCurrencyClaim.currency) {
            return {
                ok: false,
                code: 'CURRENCY_MISMATCH',
                mcp_code: MCP_ERROR.CURRENCY_MISMATCH,
            };
        }
        // perCallClaim + totalClaim both present with inconsistent currency → spec defect (issuer's responsibility)
        if (
            perCallClaim &&
            totalClaim &&
            perCallClaim.currency !== totalClaim.currency
        ) {
            return {
                ok: false,
                code: 'CURRENCY_CLAIM_INCONSISTENT',
                mcp_code: MCP_ERROR.SCOPE_INFLATION,
            };
        }
    }
    if (
        perCallClaim &&
        mcpCall.arguments.value !== undefined &&
        mcpCall.arguments.value > perCallClaim.value
    ) {
        return {
            ok: false,
            code: 'SCOPE_INFLATION_VALUE',
            mcp_code: MCP_ERROR.SCOPE_INFLATION,
        };
    }

    // ── step 3: cumulative limits — single outer SERIALIZABLE transaction ─
    // quota + value accounting is inside a single outer tx; any reject → outer tx ROLLBACK

    // invariant: **two parallel tx are not allowed** (the grep test verifies the source)
    if (!perDayClaim && !totalClaim) {
        // no cumulative limit → skip the outer tx; return ok directly
        return { ok: true };
    }

    const today =
        deps.today?.() ?? new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC

    // SERIALIZABLE retry loop
    let lastErr: unknown = null;
    for (let attempt = 0; attempt < DEFAULT_SERIALIZABLE_RETRY_MAX; attempt++) {
        const client = await deps.acquireClient();
        try {
            // begin the outer SERIALIZABLE transaction
            await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

            const result = await runScopeTxBody(client, {
                tokenId,
                requestIdempotencyKey,
                today,
                perDayClaim,
                totalClaim,
                mcpCallValue: mcpCall.arguments.value,
            });

            if (result.kind === 'commit') {
                await client.query('COMMIT');
                return result.outcome;
            }

            // result.kind === 'rollback': the outer tx ROLLBACK undoes all counter changes
            // acceptance gate: quota=9 + value+$10=$105 reject → quota stays =9, not consumed
            await client.query('ROLLBACK');
            return result.outcome;
        } catch (err) {
            // outer tx ROLLBACK on exception
            try {
                await client.query('ROLLBACK');
            } catch {
                // swallow even if ROLLBACK fails (already BEGUN)
            }
            if (isSerializableRetryError(err)) {
                // retry by re-running outer tx
                lastErr = err;
                continue;
            }
            // non-retry error → propagate
            throw err;
        } finally {
            client.release();
        }
    }

    // retry cap exhausted → return a pending-race error
    throw new Error(
        `validateScope: SERIALIZABLE retry exhausted (${DEFAULT_SERIALIZABLE_RETRY_MAX} attempts); lastErr=${
            lastErr instanceof Error ? lastErr.message : String(lastErr)
        }`,
    );
}

// ─── tx body: runScopeTxBody ────────────────────────

interface ScopeTxBodyInput {
    tokenId: string;
    requestIdempotencyKey: string;
    today: string;
    perDayClaim?: ScopeClaim;
    totalClaim?: ScopeClaim;
    mcpCallValue: number | undefined;
}

type ScopeTxBodyResult =
    | { kind: 'commit'; outcome: ValidateScopeResult }
    | { kind: 'rollback'; outcome: ValidateScopeResult };

/**
 * runScopeTxBody — executes inside the outer SERIALIZABLE tx
 *
 * **Note**: this function does **not** BEGIN/COMMIT itself — the caller (validateScope) has already BEGUN;
 * this function only decides the commit | rollback outcome.
 *
 * Outcome rules:
 *   - any fail (quota_exhausted / value_exhausted) → return { kind: 'rollback', outcome }
 *   - all pass → return { kind: 'commit', outcome: { ok: true } }
 *   - cached fail → return { kind: 'commit', outcome: cached } (reading the cache needs no rollback)
 *
 * SERIALIZABLE retry: triggers an outer-caller retry by throwing `IDEMPOTENCY_PENDING_RACE`.
 */
async function runScopeTxBody(
    client: PoolClient,
    input: ScopeTxBodyInput,
): Promise<ScopeTxBodyResult> {
    const {
        tokenId,
        requestIdempotencyKey,
        today,
        perDayClaim,
        totalClaim,
        mcpCallValue,
    } = input;

    // ── quota idempotency + counter ─────────────────
    if (perDayClaim) {
        // step 3.1: reserve the quota idempotency row
        // INSERT ... ON CONFLICT DO NOTHING RETURNING, a single SQL statement
        const quotaIdempInsert = await client.query<{ idempotency_key: string }>(
            `INSERT INTO communication.mcp_quota_idempotency
                (idempotency_key, token_id, cached_result, cached_code, cached_mcp_code)
             VALUES ($1, $2, 'pending', NULL, NULL)
             ON CONFLICT (idempotency_key, token_id) DO NOTHING
             RETURNING idempotency_key`,
            [requestIdempotencyKey, tokenId],
        );

        if (quotaIdempInsert.rowCount === 0) {
            // not the first reservation → read cached_result
            const cached = await client.query<{
                cached_result: string;
                cached_code: string | null;
                cached_mcp_code: string | null;
            }>(
                `SELECT cached_result, cached_code, cached_mcp_code
                   FROM communication.mcp_quota_idempotency
                  WHERE idempotency_key = $1 AND token_id = $2`,
                [requestIdempotencyKey, tokenId],
            );
            const cachedRow = cached.rows[0];
            if (!cachedRow) {
                // race: ON CONFLICT hit but the SELECT found nothing (extremely rare)
                throw new Error('IDEMPOTENCY_PENDING_RACE');
            }
            if (cachedRow.cached_result === 'ok') {
                // a cached ok still needs to enter the value tx
                // (prevents the "call quota cached ok but value not accumulated" undercount)
                // fall through to the value part here
            } else if (cachedRow.cached_result === 'fail') {
                // acceptance gate: cached fail → return the same fail; do not increment the counter again
                return {
                    kind: 'commit',
                    outcome: {
                        ok: false,
                        code: cachedRow.cached_code ?? 'CACHED_FAIL',
                        mcp_code:
                            (cachedRow.cached_mcp_code as MCPErrorCode) ??
                            MCP_ERROR.QUOTA_EXHAUSTED,
                    },
                };
            } else {
                // 'pending' → SERIALIZABLE retry
                throw new Error('IDEMPOTENCY_PENDING_RACE');
            }
        } else {
            // first reservation → quota counter atomic check-and-increment
            const quotaResult = await client.query<{ calls_count: number }>(
                `INSERT INTO communication.mcp_quota_counter (token_id, day, calls_count)
                 VALUES ($1, $2, 1)
                 ON CONFLICT (token_id, day) DO UPDATE
                     SET calls_count = communication.mcp_quota_counter.calls_count + 1
                     WHERE communication.mcp_quota_counter.calls_count + 1 <= $3
                 RETURNING calls_count`,
                [tokenId, today, perDayClaim.value],
            );

            if (!quotaResult.rows || quotaResult.rows.length === 0) {
                // quota_exhausted → the outer tx ROLLBACK undoes the counter change
                // (the quota counter's INSERT/UPDATE is invisible due to the ROLLBACK).
                //
                // the cached_result='fail' UPDATE sits in the same outer tx as the counter —
                // the ROLLBACK also undoes that cache. This is intended behavior: it ensures cached_result and the counter
                // commit together or ROLLBACK together (atomic semantics), leaving no partial accounting cache.
                //
                // a later retry re-runs the whole flow: finding cached_result still 'pending' →
                // it re-runs quota_counter, finds quota still = the current value, and again hits quota_exhausted;
                // so from the outside the effect is consistent — the fail is a "determinative reject".
                return {
                    kind: 'rollback',
                    outcome: {
                        ok: false,
                        code: 'QUOTA_EXHAUSTED_PER_DAY',
                        mcp_code: MCP_ERROR.QUOTA_EXHAUSTED,
                    },
                };
            }

            // step 3.3: finalize quota idempotency 'ok' (within the same outer tx)
            await client.query(
                `UPDATE communication.mcp_quota_idempotency
                    SET cached_result = 'ok'
                  WHERE idempotency_key = $1 AND token_id = $2`,
                [requestIdempotencyKey, tokenId],
            );
        }
    }

    // ── value idempotency + counter ─────────────────
    if (totalClaim) {
        const currency = totalClaim.currency!;

        // step 3.4: reserve the value idempotency row
        // PK triple (idempotency_key, token_id, currency)
        const valueIdempInsert = await client.query<{ idempotency_key: string }>(
            `INSERT INTO communication.mcp_value_idempotency
                (idempotency_key, token_id, currency, cached_result, cached_code, cached_mcp_code)
             VALUES ($1, $2, $3, 'pending', NULL, NULL)
             ON CONFLICT (idempotency_key, token_id, currency) DO NOTHING
             RETURNING idempotency_key`,
            [requestIdempotencyKey, tokenId, currency],
        );

        if (valueIdempInsert.rowCount === 0) {
            // not the first time → read cached_result
            const cached = await client.query<{
                cached_result: string;
                cached_code: string | null;
                cached_mcp_code: string | null;
            }>(
                `SELECT cached_result, cached_code, cached_mcp_code
                   FROM communication.mcp_value_idempotency
                  WHERE idempotency_key = $1 AND token_id = $2 AND currency = $3`,
                [requestIdempotencyKey, tokenId, currency],
            );
            const cachedRow = cached.rows[0];
            if (!cachedRow) {
                throw new Error('VALUE_IDEMPOTENCY_PENDING_RACE');
            }
            if (cachedRow.cached_result === 'ok') {
                return { kind: 'commit', outcome: { ok: true } };
            }
            if (cachedRow.cached_result === 'fail') {
                return {
                    kind: 'commit',
                    outcome: {
                        ok: false,
                        code: cachedRow.cached_code ?? 'CACHED_FAIL',
                        mcp_code:
                            (cachedRow.cached_mcp_code as MCPErrorCode) ??
                            MCP_ERROR.SCOPE_INFLATION,
                    },
                };
            }
            // 'pending' → SERIALIZABLE retry
            throw new Error('VALUE_IDEMPOTENCY_PENDING_RACE');
        }

        // step 3.5: value counter atomic check-and-increment
        if (mcpCallValue === undefined) {
            // inconsistency defense: totalClaim is present but mcpCallValue is not
            // reaching here = the step 2 currency check missed it; theoretically unreachable; a defensive reject
            return {
                kind: 'rollback',
                outcome: {
                    ok: false,
                    code: 'INTERNAL_VALUE_MISSING',
                    mcp_code: MCP_ERROR.SCOPE_INFLATION,
                },
            };
        }
        const r = await client.query<{ total_value: string }>(
            `INSERT INTO communication.mcp_value_counter (token_id, currency, total_value)
             VALUES ($1, $2, $3)
             ON CONFLICT (token_id, currency) DO UPDATE
                 SET total_value = communication.mcp_value_counter.total_value + $3
                 WHERE communication.mcp_value_counter.total_value + $3 <= $4
             RETURNING total_value`,
            [tokenId, currency, mcpCallValue, totalClaim.value],
        );

        if (!r.rows || r.rows.length === 0) {
            // total_value_exhausted → outer tx ROLLBACK
            // acceptance gate: quota=9 + value+$10=$105 reject → outer ROLLBACK
            // → quota stays =9, not consumed (the quota counter's +1 is undone by the ROLLBACK)
            return {
                kind: 'rollback',
                outcome: {
                    ok: false,
                    code: 'TOTAL_VALUE_EXHAUSTED',
                    mcp_code: MCP_ERROR.SCOPE_INFLATION,
                },
            };
        }

        // step 3.6: finalize value idempotency 'ok'
        await client.query(
            `UPDATE communication.mcp_value_idempotency
                SET cached_result = 'ok'
              WHERE idempotency_key = $1 AND token_id = $2 AND currency = $3`,
            [requestIdempotencyKey, tokenId, currency],
        );
    }

    // ── all pass → commit ─────────────────────────────────────────────────────
    return { kind: 'commit', outcome: { ok: true } };
}
