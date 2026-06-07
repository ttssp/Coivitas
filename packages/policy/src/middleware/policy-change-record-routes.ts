/**
 * policy-change-record-routes.ts — policy_change_records standalone read-path middleware.
 *
 * Design background:
 * PolicyChangeRecorder writes POLICY_CREATED/UPDATED/REVOKED into the standalone table
 * policy.policy_change_records. The ACTION_VOCABULARY allowlist in action-record-routes.ts
 * explicitly excludes POLICY_* types (correct behavior); but this causes
 * GET /records?action=POLICY_CREATED to return AUDIT_QUERY_MALFORMED, making audit data
 * "write-only, unreadable", which violates Pillar 3 "auditable behavior".
 *
 * Fix: add a standalone routes file without modifying the recorder/ directory; it lives in the
 * middleware/ directory alongside PolicyChangeRecorder, and callers can register it independently.
 *
 * Route: GET /policy-change-records
 * Query parameters: agentDid / principalDid / action / from / to / limit / cursor
 * action allowlist: POLICY_CREATED / POLICY_UPDATED / POLICY_REVOKED
 *
 * Security constraint:
 * An AuditAccessChecker must be provided at route registration (same pattern as
 * registerActionRecordRoutes). If omitted, a built-in deny-all checker serves as the fail-safe
 * default (every call is rejected), forcing callers to explicitly pass a real checker. Mounting
 * without authentication is never allowed in production.
 *
 * Related: Pillar 3 "auditable behavior"
 */

import { randomUUID } from 'node:crypto';

import type { Application, Request, Response } from 'express';

import type { DatabasePool } from '@coivitas/shared';
import type {
    AgentIdentityDocument,
    AuditAccessChecker,
    DID,
    VerifiedAuditRequest,
} from '@coivitas/types';
import {
    ACTION_POLICY_CREATED,
    ACTION_POLICY_REVOKED,
    ACTION_POLICY_UPDATED,
    type PolicyActionType,
    POLICY_ACTION_TYPES,
} from '@coivitas/types';

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** policy_change_records action allowlist (3 policy control-plane events). */
const POLICY_ACTION_WHITELIST = new Set<string>([
    ACTION_POLICY_CREATED,
    ACTION_POLICY_UPDATED,
    ACTION_POLICY_REVOKED,
]);

/** ISO 8601 UTC milliseconds format (consistent with action-record-routes). */
const ISO_8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Base64URL character set validation (cursor encode/decode). */
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/** Set of allowed query parameters (anti-injection, rejects unknown keys). */
const ALLOWED_QUERY_PARAMS = new Set([
    'agentDid',
    'principalDid',
    'action',
    'from',
    'to',
    'limit',
    'cursor',
]);

// ---------------------------------------------------------------------------
// cursor encode/decode (single-key id cursor, consistent with the writer hash chain ordering)
// ---------------------------------------------------------------------------

/**
 * Encode cursor: uses id only (consistent with the writer's ORDER BY id DESC ordering).
 * Format: Base64URL(id), where id is a BIGINT string.
 */
function encodeCursor(id: string | bigint): string {
    return Buffer.from(String(id), 'utf8').toString('base64url');
}

/**
 * Strictly decode cursor, fail-closed:
 * - non-Base64URL → { ok: false, reason }
 * - decoded content is non-numeric → { ok: false, reason }
 * - success → { ok: true, id: bigint }
 */
type DecodeCursorResult =
    | { ok: true; id: bigint }
    | { ok: false; reason: string };

function decodeCursor(cursor: string): DecodeCursorResult {
    if (!BASE64URL_RE.test(cursor)) {
        return { ok: false, reason: 'cursor is not valid Base64URL' };
    }
    let decoded: string;
    try {
        decoded = Buffer.from(cursor, 'base64url').toString('utf8');
    } catch {
        return { ok: false, reason: 'cursor Base64URL decode failed' };
    }
    // decoded should be a pure numeric string (BIGINT id)
    if (!/^\d+$/.test(decoded)) {
        return { ok: false, reason: 'cursor id segment is not a positive integer' };
    }
    let id: bigint;
    try {
        id = BigInt(decoded);
    } catch {
        return { ok: false, reason: 'cursor id segment overflow or invalid' };
    }
    return { ok: true, id };
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

function isValidIso8601(value: string): boolean {
    if (!ISO_8601_RE.test(value)) return false;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return false;
    return d.toISOString() === value;
}

function sendError(
    res: Response,
    status: number,
    code: string,
    detail: string,
): void {
    res.status(status).json({
        error: { code, detail, requestId: randomUUID() },
    });
}

// ---------------------------------------------------------------------------
// DB row type (policy.policy_change_records)
// ---------------------------------------------------------------------------

interface PolicyChangeRecordRow {
    id: string; // BIGINT, returned as string by pg
    record_id: string;
    agent_did: string;
    principal_did: string;
    action_type: string;
    params: Record<string, unknown>;
    row_hash: string;
    prev_row_hash: string;
    actor_signature: string;
    ledger_signature: string;
    created_at: string | Date;
}

// ---------------------------------------------------------------------------
// Query parameter parsing and validation
// ---------------------------------------------------------------------------

interface ParsedQueryParams {
    agentDid?: DID;
    principalDid?: DID;
    action?: PolicyActionType;
    from?: string;
    to?: string;
    limit: number;
    cursor?: string;
}

/**
 * Parse and validate the GET /policy-change-records query parameters.
 *
 * All parameters are optional; unknown keys return 400 POLICY_QUERY_MALFORMED (anti-injection).
 * limit defaults to 50, with an upper bound of 500.
 */
function parseQueryParams(
    raw: Record<string, unknown>,
    res: Response,
): ParsedQueryParams | null {
    // Unknown-parameter detection (anti-injection: reject any key not in the allowlist)
    for (const key of Object.keys(raw)) {
        if (!ALLOWED_QUERY_PARAMS.has(key)) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                `Unknown query parameter: ${key}`,
            );
            return null;
        }
    }

    // Empty/null/array value detection
    for (const [key, val] of Object.entries(raw)) {
        if (val === '' || val === 'null' || val === 'undefined') {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                `Empty/null value for ${key}`,
            );
            return null;
        }
        if (Array.isArray(val)) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                `Duplicate key: ${key}`,
            );
            return null;
        }
    }

    const out: ParsedQueryParams = { limit: 50 };

    // agentDid: must have the did:agent: prefix
    if (raw['agentDid'] !== undefined) {
        const v = raw['agentDid'] as string;
        if (!v.startsWith('did:agent:')) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                'agentDid must start with did:agent:',
            );
            return null;
        }
        out.agentDid = v as DID;
    }

    // principalDid: must have the did:key: prefix
    if (raw['principalDid'] !== undefined) {
        const v = raw['principalDid'] as string;
        if (!v.startsWith('did:key:')) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                'principalDid must start with did:key:',
            );
            return null;
        }
        out.principalDid = v as DID;
    }

    // action: only the three POLICY_* values are allowed
    if (raw['action'] !== undefined) {
        const v = raw['action'] as string;
        if (!POLICY_ACTION_WHITELIST.has(v)) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                `action must be one of: ${[...POLICY_ACTION_TYPES].join(', ')}`,
            );
            return null;
        }
        out.action = v as PolicyActionType;
    }

    // from / to: ISO 8601 UTC milliseconds
    for (const field of ['from', 'to'] as const) {
        if (raw[field] !== undefined) {
            const v = raw[field] as string;
            if (!isValidIso8601(v)) {
                sendError(
                    res,
                    400,
                    'POLICY_QUERY_MALFORMED',
                    `${field} must be ISO 8601 UTC with milliseconds (e.g. 2026-04-18T12:34:56.789Z)`,
                );
                return null;
            }
            out[field] = v;
        }
    }

    // limit: integer 1-500
    if (raw['limit'] !== undefined) {
        const n = Number(raw['limit']);
        if (!Number.isInteger(n) || n < 1 || n > 500) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                'limit must be an integer between 1 and 500',
            );
            return null;
        }
        out.limit = n;
    }

    // cursor: Base64URL format (decoded during the SQL processing stage)
    if (raw['cursor'] !== undefined) {
        const v = raw['cursor'] as string;
        if (!BASE64URL_RE.test(v)) {
            sendError(
                res,
                400,
                'POLICY_QUERY_MALFORMED',
                'cursor must be Base64URL encoded',
            );
            return null;
        }
        out.cursor = v;
    }

    return out;
}

// ---------------------------------------------------------------------------
// SQL query building (dynamic WHERE clause + cursor pagination)
// ---------------------------------------------------------------------------

interface BuildQueryResult {
    text: string;
    values: unknown[];
}

/**
 * Build the policy_change_records list query.
 *
 * Pagination strategy:
 * - ORDER BY id ASC (consistent with the hash chain linking order in the writer's writeWithinTransaction)
 * - The writer reads prev_row_hash using "ORDER BY id DESC LIMIT 1 FOR UPDATE", i.e. id is the chain order)
 * - Use a single-key id cursor rather than a (created_at, id) composite cursor, to avoid clock drift
 *   reordering the chain
 * - created_at is kept as a WHERE filter field (from/to time-range queries) and does not participate in ordering
 *
 * @param params - the parsed query parameters
 * @param cursorId - the decoded and validated cursor id (bigint); undefined means the first page
 */
function buildListQuery(
    params: ParsedQueryParams,
    cursorId?: bigint,
): BuildQueryResult {
    const conditions: string[] = [];
    const values: unknown[] = [];
    let idx = 1;

    if (params.agentDid !== undefined) {
        conditions.push(`agent_did = $${idx++}`);
        values.push(params.agentDid);
    }
    if (params.principalDid !== undefined) {
        conditions.push(`principal_did = $${idx++}`);
        values.push(params.principalDid);
    }
    if (params.action !== undefined) {
        conditions.push(`action_type = $${idx++}`);
        values.push(params.action);
    }
    if (params.from !== undefined) {
        // created_at is still used for time-range filtering (WHERE) and does not participate in ordering
        conditions.push(`created_at >= $${idx++}::timestamptz`);
        values.push(params.from);
    }
    if (params.to !== undefined) {
        conditions.push(`created_at < $${idx++}::timestamptz`);
        values.push(params.to);
    }

    // cursor pagination (single-key id cursor, consistent with the writer hash chain id sequence)
    if (cursorId !== undefined) {
        conditions.push(`id > $${idx++}::bigint`);
        values.push(cursorId);
    }

    const where =
        conditions.length > 0
            ? `WHERE ${conditions.join(' AND ')}`
            : '';

    // limit + 1 fetch: detect whether there is a next page
    values.push(params.limit + 1);
    const limitPlaceholder = `$${idx}`;

    // ORDER BY id ASC (consistent with the writer hash chain ordering, avoiding clock-drift reordering)
    const text = `
        SELECT id, record_id, agent_did, principal_did, action_type,
               params, row_hash, prev_row_hash, actor_signature, ledger_signature,
               created_at
        FROM policy.policy_change_records
        ${where}
        ORDER BY id ASC
        LIMIT ${limitPlaceholder}
    `;

    return { text, values };
}

// ---------------------------------------------------------------------------
// Response serialization
// ---------------------------------------------------------------------------

function toPublicRecord(row: PolicyChangeRecordRow): Record<string, unknown> {
    const createdAt =
        row.created_at instanceof Date
            ? row.created_at.toISOString()
            : String(row.created_at);

    return {
        recordId: row.record_id,
        agentDid: row.agent_did,
        principalDid: row.principal_did,
        actionType: row.action_type,
        params: row.params,
        rowHash: row.row_hash,
        prevRowHash: row.prev_row_hash,
        actorSignature: row.actor_signature,
        ledgerSignature: row.ledger_signature,
        createdAt,
    };
}

// ---------------------------------------------------------------------------
// Built-in deny-all checker (fail-safe default)
// ---------------------------------------------------------------------------

/**
 * deny-all AuditAccessChecker (fail-safe default).
 *
 * When the caller does not provide a real checker, every request is rejected with HTTP 403
 * AUDIT_FORBIDDEN. Purpose: force the caller to explicitly pass a real checker, avoiding mounting
 * without authentication (fail-closed). Production must pass a checker with subject-scope
 * constraints (same pattern as registerActionRecordRoutes).
 */
const DENY_ALL_CHECKER: AuditAccessChecker = {
    check: (_request) =>
        Promise.resolve({
            allowed: false,
            code: 'AUDIT_FORBIDDEN',
            reason:
                'PolicyChangeRecord routes require an explicit AuditAccessChecker. ' +
                'No checker was provided to registerPolicyChangeRecordRoutes — ' +
                'all access is denied by the built-in fail-safe default. ' +
                'Pass auditAccessChecker option to enable authenticated access.',
        }),
};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** registerPolicyChangeRecordRoutes registration options. */
export interface RegisterPolicyChangeRecordRoutesOptions {
    /** Postgres connection pool (injected by the caller, same pool as PolicyChangeRecorder). */
    dbPool: DatabasePool;
    /**
     * Audit access checker (security constraint).
     *
     * Same pattern as registerActionRecordRoutes: every read request must pass checker.check().
     * When omitted, the built-in deny-all fail-safe applies (all requests return 403
     * AUDIT_FORBIDDEN), forcing the caller to explicitly pass a real checker with subject-scope
     * constraints.
     *
     * Warning: this parameter must not be omitted in production.
     */
    auditAccessChecker?: AuditAccessChecker;
    /**
     * Identity resolver (security constraint).
     *
     * Injected by the caller; extracts the authenticated AgentIdentityDocument from the HTTP request.
     * In real deployments it is typically extracted from JWT middleware / request context.
     *
     * Returning null → fail-closed 403 AUDIT_FORBIDDEN (access is denied when identity cannot be resolved).
     *
     * When auditAccessChecker is the built-in DENY_ALL (no checker explicitly passed), this function
     * is not invoked (authorization is already rejected by deny-all before identity resolution).
     *
     * Note: if a real checker is passed but identityResolver is not, the handler can still fail
     * closed: the real checker errors out on its own when it receives resolvedIdentity=null, which is
     * preferable to an implicit TypeError crash. Production must pass both auditAccessChecker and
     * identityResolver.
     */
    identityResolver?: (req: Request) => Promise<AgentIdentityDocument | null>;
    /**
     * Route prefix (default '/policy-change-records').
     * Callers can pass a custom prefix to make it easy to mount under different sub-paths.
     */
    routePrefix?: string;
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

/**
 * Register the policy_change_records standalone read-path route.
 *
 * GET <routePrefix>
 *   - Query parameters (all optional): agentDid / principalDid / action / from / to / limit / cursor
 *   - action allowlist: POLICY_CREATED / POLICY_UPDATED / POLICY_REVOKED
 *   - Pagination: cursor-based, Base64URL(id)
 *   - Response: { records: [...], nextCursor?: string }
 *
 * Security constraints:
 * - auditAccessChecker must be provided (when omitted, the built-in deny-all returns 403
 *   AUDIT_FORBIDDEN for all requests)
 * - checker.check() runs before the DB query; SQL is only sent after it passes
 * - Same pattern as the registerActionRecordRoutes AuditAccessChecker
 * - The ACTION_VOCABULARY allowlist in action-record-routes.ts is unchanged (frozen)
 *
 * Note: the full SignedAuditQuery flow (X-Audit-* header signature verification + snapshot boundary)
 * is aligned with action-record-routes.ts and needs to be wired into createAuditAccessMiddleware in
 * a follow-up task. This path is the minimal security baseline: the checker.check() gate prevents
 * anonymous enumeration.
 *
 * Usage example:
 * ```ts
 * const recorder = new PolicyChangeRecorder(dbPool, ledgerKey);
 * registerActionRecordRoutes(app, { dbPool, identityRegistry, ledgerPublicKey });
 * registerPolicyChangeRecordRoutes(app, {
 *     dbPool,
 *     auditAccessChecker: myPolicyChangeChecker, // required! omitting = deny-all
 * });
 * ```
 */
export function registerPolicyChangeRecordRoutes(
    app: Application,
    options: RegisterPolicyChangeRecordRoutesOptions,
): void {
    const { dbPool } = options;
    const routePrefix = options.routePrefix ?? '/policy-change-records';

    // Pick the checker (defaults to the deny-all fail-safe)
    const checker: AuditAccessChecker =
        options.auditAccessChecker ?? DENY_ALL_CHECKER;

    app.get(routePrefix, async (req: Request, res: Response): Promise<void> => {
        try {
            // Authorization gate: run checker.check() before any DB query.
            // Build a real VerifiedAuditRequest so that real checkers such as
            // PrincipalAuditAccessChecker can normally dereference query.queryParams /
            // resolvedIdentity.principalDid, instead of passing null as unknown and causing a
            // TypeError → 500.

            // The full SignedAuditQuery signature-verification flow (X-Audit-* headers + snapshot
            // boundary) is wired into createAuditAccessMiddleware by a follow-up task.
            // This path serves as the minimal security baseline: the checker.check() gate prevents
            // anonymous enumeration.

            // Build steps:
            // 1. Get resolvedIdentity from identityResolver (caller-injected); null if not provided.
            // 2. Extract DIDs from the request headers x-audit-requester-did / x-audit-target-agent-did.
            // 3. Build AuditQueryParams from req.query (agentDid/principalDid are extracted here).
            // 4. Assemble a minimal VerifiedAuditRequest (lane='business') and pass it to the checker.

            // fail-closed rules:
            // - identityResolver returns null → 403 AUDIT_FORBIDDEN (identity cannot be resolved)
            // - deny-all checker (no auditAccessChecker passed) rejects directly, without calling identityResolver

            // Step 1: resolvedIdentity
            let resolvedIdentity: AgentIdentityDocument | null = null;
            if (options.identityResolver !== undefined) {
                resolvedIdentity = await options.identityResolver(req);
                if (resolvedIdentity === null) {
                    sendError(
                        res,
                        403,
                        'AUDIT_FORBIDDEN',
                        'Identity resolution returned null; access denied (fail-closed)',
                    );
                    return;
                }
            }

            // Step 2: extract DIDs from the request headers (empty string when missing; the checker makes the decision)
            const requesterDid = (
                req.headers['x-audit-requester-did'] as string | undefined ?? ''
            ) as import('@coivitas/types').DID;
            const targetAgentDid = (
                req.headers['x-audit-target-agent-did'] as string | undefined ?? ''
            ) as import('@coivitas/types').DID;

            // Step 3: build AuditQueryParams from req.query (extract only the fields supported by policy-change-records)
            const rawQuery = req.query as Record<string, string | undefined>;
            const queryParams: import('@coivitas/types').AuditQueryParams = {};
            if (rawQuery['agentDid'] !== undefined) {
                queryParams.agentDid = rawQuery['agentDid'] as import('@coivitas/types').DID;
            }
            if (rawQuery['principalDid'] !== undefined) {
                queryParams.principalDid = rawQuery['principalDid'] as import('@coivitas/types').DID;
            }

            // Step 4: assemble the minimal VerifiedAuditRequest
            // The signature field is filled with an empty string (this path does no signature
            // verification; full verification is done by the middleware wired in later)
            const verifiedAuditRequest: VerifiedAuditRequest = {
                lane: 'business',
                query: {
                    requesterDid,
                    targetAgentDid,
                    httpMethod: 'GET',
                    resourceBinding: { route: 'records.list', recordId: null },
                    queryParams,
                    timestamp: new Date().toISOString() as import('@coivitas/types').Timestamp,
                    signature: '' as import('@coivitas/types').Signature,
                },
                // If identityResolver is not provided, resolvedIdentity is null;
                // DENY_ALL_CHECKER rejects directly without reading this field; a real checker should
                // be used together with identityResolver.
                resolvedIdentity: resolvedIdentity as AgentIdentityDocument,
                identityStatus: 'active',
                verifiedAt: new Date().toISOString() as import('@coivitas/types').Timestamp,
            };

            const auditDecision = await checker.check(verifiedAuditRequest);
            if (!auditDecision.allowed) {
                sendError(res, 403, auditDecision.code, auditDecision.reason);
                return;
            }

            // Parse and validate the query parameters
            const params = parseQueryParams(
                req.query as Record<string, unknown>,
                res,
            );
            if (params === null) return; // an error response was already sent by parseQueryParams

            // fail-closed cursor decoding (strictly validated before sending the DB query)
            // The cursor string format has already been validated against BASE64URL_RE in
            // parseQueryParams; here we further validate the decoded content (whether it is a valid
            // bigint id) to prevent a Postgres CAST failure from producing a 500.
            let cursorId: bigint | undefined;
            if (params.cursor !== undefined) {
                const decoded = decodeCursor(params.cursor);
                if (!decoded.ok) {
                    sendError(
                        res,
                        400,
                        'POLICY_QUERY_MALFORMED',
                        `Invalid cursor: ${decoded.reason}`,
                    );
                    return;
                }
                cursorId = decoded.id;
            }

            // Build the SQL query (passing the decoded cursorId)
            const { text, values } = buildListQuery(params, cursorId);

            const result = await dbPool.query<PolicyChangeRecordRow>(
                text,
                values,
            );

            const rows = result.rows;

            // Determine whether there is a next page
            const hasMore = rows.length > params.limit;
            const pageRows = hasMore ? rows.slice(0, params.limit) : rows;

            // Build nextCursor (single-key id cursor, consistent with the writer hash chain ordering)
            let nextCursor: string | undefined;
            if (hasMore && pageRows.length > 0) {
                const last = pageRows[pageRows.length - 1]!;
                nextCursor = encodeCursor(last.id);
            }

            res.status(200).json({
                records: pageRows.map(toPublicRecord),
                ...(nextCursor !== undefined ? { nextCursor } : {}),
            });
        } catch (err) {
            // fail-closed: a DB query failure returns 500 (errors are not silently swallowed)
            const detail =
                err instanceof Error ? err.message : String(err);
            sendError(res, 500, 'INTERNAL_ERROR', detail);
        }
    });
}
