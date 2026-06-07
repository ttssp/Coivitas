import { randomUUID } from 'node:crypto';

import type { Application, NextFunction, Request, Response } from 'express';

import { canonicalize, detectEncoding, verify } from '@coivitas/crypto';
import {
    extractPublicKeyFromDIDKey,
    IdentityRegistry,
} from '@coivitas/identity';
import type { DatabasePool } from '@coivitas/shared';
import type { AgentIdentityDocument, DID, Hash } from '@coivitas/types';
import { ProtocolError, SESSION_GOVERNOR_DID } from '@coivitas/types';

import type {
    AuditAccessChecker,
    AuditQueryParams,
    AuditResourceBinding,
    AuditSnapshotBoundary,
    IdentityStoreForAudit,
    VerifiedAuditRequest,
    AuditIdentityResolution,
    AuditAccessDecision,
    ControlPlaneAuditResolution,
    ControlPlaneRequesterScope,
} from '../audit/types.js';
import { toTimestamp } from '../_shared/timestamp.js';
import type { PersistedActionRecord } from '../types.js';
import {
    buildUnsignedRecordPayload,
    computeRecordHash,
    verifyRecordSignature,
} from './shared.js';

// record_hash charset self-check: any character outside hex ∪ base64url is treated as
// DB data corruption. detectEncoding itself defaults illegal strings to 'base64url' without erroring,
// so a shape check is performed before the call to separate "integrity fault" from "normal encoding detection" semantics.
const RECORD_HASH_CHARSET_RE = /^[A-Za-z0-9_-]+$/;

// ── cursor wire format ─────────────────────────────────
// On the wire the cursor must be Base64URL; after decoding the structure is conventionally "${isoTimestamp}|${id}".
// Base64URL is compatible with the ordinary query-string charset (A-Z a-z 0-9 - _), so no further URL encoding is needed.
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function encodeCursor(timestamp: string, id: string | bigint): string {
    return Buffer.from(`${timestamp}|${id}`, 'utf8').toString('base64url');
}

function decodeCursor(cursor: string): { ts: string; id: string } | null {
    if (!BASE64URL_RE.test(cursor)) return null;
    let decoded: string;
    try {
        decoded = Buffer.from(cursor, 'base64url').toString('utf8');
    } catch {
        return null;
    }
    const pipeIdx = decoded.indexOf('|');
    if (pipeIdx <= 0 || pipeIdx === decoded.length - 1) return null;
    return { ts: decoded.slice(0, pipeIdx), id: decoded.slice(pipeIdx + 1) };
}

// ── internal DB row type (id is BIGINT) ─────────────────────────────────
// pg returns INT8 as a string by default to avoid JS Number precision loss; the code explicitly
// promotes with BigInt(row.id) where comparison/arithmetic is needed. No global setTypeParser is
// registered in packages/shared/database.ts, to avoid polluting communication/session-store's "BIGINT -> string" contract.
interface ActionRecordRowInternal {
    id: string;
    record_id: string;
    agent_did: string;
    principal_did: string;
    action_type: string;
    parameters_summary: Record<string, unknown> | null;
    authorization_ref: Record<string, unknown> | null;
    result_summary: Record<string, unknown> | null;
    record_hash: string;
    previous_record_hash: string;
    actor_signature: string;
    ledger_signature: string;
    delegation_depth: number | null;
    session_id: string | null;
    // The PG node driver returns a Date object for TIMESTAMPTZ by default; fromRow must normalize
    // with toTimestamp().
    created_at: string | Date;
}

// ── AuditHandlerContext (typed handler wrapper) ──────────────────
// Note: does not expose the raw req (prevents a handler from bypassing verifiedAudit to read unverified headers directly);
// compile-time enforcement that a handler can only access the verified context.
interface AuditHandlerContext {
    verifiedAudit: VerifiedAuditRequest;
    snapshotMaxId: bigint;
    prefetchedRecord?: ActionRecordRowInternal;
    /** record-not-found flag (set by the existence guard, consumed by the handler after auth)*/
    recordNotFound?: boolean;
    res: Response;
}

type AuditHandler = (ctx: AuditHandlerContext) => Promise<void>;

function auditHandler(fn: AuditHandler) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const verifiedAudit = res.locals[
                'verifiedAudit'
            ] as VerifiedAuditRequest;
            const snapshotMaxId = res.locals['snapshotMaxId'] as bigint;
            const prefetchedRecord = res.locals['prefetchedRecord'] as
                | ActionRecordRowInternal
                | undefined;
            const recordNotFound = res.locals['recordNotFound'] === true;
            await fn({
                verifiedAudit,
                snapshotMaxId,
                prefetchedRecord,
                recordNotFound,
                res,
            });
        } catch (err) {
            next(err);
        }
    };
}

// ── error-response helper ───────────────────────────────────────────────────────────
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

// ── UUID v4 regex ───────────────────────────────────────────────────────────
const UUID_V4_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── strict ISO 8601 validation ─────────────────────────────────────────────────────
// Attacker-controlled fields (X-Audit-Timestamp, X-Audit-Snapshot-HeadCreatedAt, the ts segment in cursor)
// must be validated explicitly before entering Date comparison and SQL, otherwise:
// - new Date("foo").getTime() === NaN, making time-window/ordering checks always false (bypasses the ±300s replay defense)
// - SQL `created_at = $1::timestamptz` throws 22007 -> next(err) -> 500 (should be 400)

// Contract: ISO 8601 UTC with millisecond precision; must be byte-for-byte equal to the DB-stored
// created_at after normalization via new Date(row).toISOString().
// Therefore: enforce UTC (trailing 'Z') + millisecond precision (.sss) + byte equivalence with toISOString().
// ±HH:MM offsets, missing milliseconds, lowercase z, etc. are all rejected.
const ISO_8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
function isValidIso8601(value: string): boolean {
    if (!ISO_8601_RE.test(value)) return false;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return false;
    // toISOString() byte equivalence: excludes cases like "2026-02-30T..." that are syntactically valid but have an invalid value
    return d.toISOString() === value;
}

// ── ACTION_VOCABULARY frozen values.
// Single source: packages/types/src/base.ts ACTION_VOCABULARY (includes v0.3.0 SESSION_SUPERSEDED);
// the audit lane extends the governor path on top of it.
import { ACTION_VOCABULARY as TYPES_ACTION_VOCABULARY } from '@coivitas/types';
// 6 frozen values (INQUIRY/QUOTE/CONFIRM/PUBLISH/RECORD/SESSION_SUPERSEDED).
// Control-plane policy-change actions (POLICY_CREATED/UPDATED/REVOKED) are written to a separate table policy_change_records,
// and do not enter this allow-list.
const ACTION_VOCABULARY = new Set<string>([...TYPES_ACTION_VOCABULARY]);

// ═══════════════════════════════════════════════════════════════════════════
// Default implementation: PrincipalAuditAccessChecker
// Serves the business lane only; the governor lane is handled by ControlPlaneAuditAccessChecker.
// ═══════════════════════════════════════════════════════════════════════════
export class PrincipalAuditAccessChecker implements AuditAccessChecker {
    public check(request: VerifiedAuditRequest): Promise<AuditAccessDecision> {
        // the union type enforces a lane type guard (guards against a broken type assertion)
        if (request.lane !== 'business') {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'PrincipalAuditAccessChecker invoked on non-business lane',
            });
        }

        const { query, resolvedIdentity } = request;

        if (resolvedIdentity.principalDid !== query.requesterDid) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'requester is not the principal of target agent',
            });
        }

        const qp = query.queryParams;
        if (
            qp.principalDid !== undefined &&
            qp.principalDid !== query.requesterDid
        ) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'principalDid filter must equal requester',
            });
        }

        if (qp.agentDid !== undefined && qp.agentDid !== query.targetAgentDid) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'queryParams.agentDid conflicts with targetAgentDid',
            });
        }

        return Promise.resolve({ allowed: true });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// v0.2 governor lane implementation: ControlPlaneAuditAccessChecker
// (minimal governor-lane subset + per-requester affected* subject scope)

// v0.1 historical vulnerability: the scope field was based on targetAgentDid, but the dispatcher
// requires targetAgentDid === SESSION_GOVERNOR_DID to enter the control-plane lane, which is equivalent to a flat
// allow-list — any allow-listed requester could still read the entire governor ledger on the governor lane.

// v0.2 revised design:
// - the scope field now uses the immutable-payload affectedAgentDid /
// affectedPrincipalDid of SESSION_SUPERSEDED (added as required fields)
// - the control-plane lane requires queryParams.affectedAgentDid to be declared explicitly (fail-closed)
// - the SQL predicate also binds parameters_summary->>'affectedAgentDid' (done inside makeHandleList)

// Protocol semantics: each control-plane requesterDid must be in the deployer-injected
// `ReadonlyMap<DID, ControlPlaneRequesterScope>`; the request's declared
// `queryParams.affectedAgentDid` must be within that requester's
// `scope.allowedAffectedAgentDids`. Optional: a principal-dimension constraint.

// Boundary goal: "what it can do / cannot do / within what boundary" —
// after per-requester affected-subject scope replaces the flat allow-list, an allow-listed DID no longer
// automatically reads the entire governor ledger; each requester may only read the affected* business subjects within its scope.

// fail-closed boundaries:
// - requester not in the Map -> AUDIT_FORBIDDEN (the allow-list, first gate)
// - queryParams.affectedAgentDid missing -> AUDIT_FORBIDDEN (subject must be declared explicitly)
// - scope.allowedAffectedAgentDids is an empty set -> any affected* -> reject
// - queryParams.affectedAgentDid not in scope.allowedAffectedAgentDids -> AUDIT_FORBIDDEN
// - the optional scope.allowedAffectedPrincipalDids is not undefined and queryParams is not in the set -> reject

// Metadata-driven quorum / role authorization uses the reserved
// extension anchor `ControlPlaneAuditResolution.metadata`.
// ═══════════════════════════════════════════════════════════════════════════
export class ControlPlaneAuditAccessChecker implements AuditAccessChecker {
    public constructor(
        private readonly allowedRequesterScopes: ReadonlyMap<
            DID,
            ControlPlaneRequesterScope
        >,
    ) {}

    public check(request: VerifiedAuditRequest): Promise<AuditAccessDecision> {
        if (request.lane !== 'control-plane') {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'ControlPlaneAuditAccessChecker invoked on non-control-plane lane',
            });
        }
        const scope = this.allowedRequesterScopes.get(
            request.query.requesterDid,
        );
        if (scope === undefined) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'requester is not in the control-plane allow-list',
            });
        }
        // If queryParams.agentDid is present it must equal targetAgentDid. Otherwise the signature binds A
        // while the server fetches data by B, causing a "signed target vs data target" drift: an attacker could use a single
        // legitimate signature to pull a ledger across agents (lateral privilege escalation). The principalDid dimension keeps
        // introspection freedom (cross-principal governance queries are intentional by design).
        if (
            request.query.queryParams.agentDid !== undefined &&
            request.query.queryParams.agentDid !== request.query.targetAgentDid
        ) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'queryParams.agentDid must equal targetAgentDid for control-plane lane',
            });
        }
        // v0.4: per-requester affected* subject scope validation
        //
        // Historical vulnerability: v0.2/v0.3 let the ledger.head route bypass
        // affected* validation, but the /audit/ledger/head handler returned the **global governor head** (any in-scope
        // requester could still observe out-of-scope governor activity) + the leaked headRecordId became an existence
        // oracle on /records/:id (even after v0.3 row-scope was added).
        //
        // v0.4 revision: ledger.head also enforces the affected* declaration + scope validation; the handler's SQL predicate
        // additionally pushes down parameters_summary->>'affectedAgentDid' = $2 so the head triple is "subject-scoped".
        // No out-of-scope governor record is visible — preventing the "out-of-scope head leak + recordId oracle" chain.
        const affectedAgentDid = request.query.queryParams.affectedAgentDid;
        if (affectedAgentDid === undefined) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'control-plane lane requires queryParams.affectedAgentDid (including ledger.head)',
            });
        }
        if (!scope.allowedAffectedAgentDids.has(affectedAgentDid)) {
            return Promise.resolve({
                allowed: false,
                code: 'AUDIT_FORBIDDEN',
                reason: 'queryParams.affectedAgentDid is not within the requester subject scope',
            });
        }
        if (scope.allowedAffectedPrincipalDids !== undefined) {
            const affectedPrincipalDid =
                request.query.queryParams.affectedPrincipalDid;
            if (
                affectedPrincipalDid === undefined ||
                !scope.allowedAffectedPrincipalDids.has(affectedPrincipalDid)
            ) {
                return Promise.resolve({
                    allowed: false,
                    code: 'AUDIT_FORBIDDEN',
                    reason: 'queryParams.affectedPrincipalDid is not within the requester subject scope',
                });
            }
        }
        return Promise.resolve({ allowed: true });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IdentityStoreForAudit adapter (wraps IdentityRegistry.queryForAudit)
// ═══════════════════════════════════════════════════════════════════════════
/**
 * v0.2 governor lane:
 * the control-plane DID resolution callback is injected by the deployer; returning null -> middleware fail-closed (404 IDENTITY_NOT_FOUND).
 */
export type ControlPlaneAuditResolver = (
    did: DID,
) => Promise<ControlPlaneAuditResolution | null>;

class RegistryAuditStore implements IdentityStoreForAudit {
    /**
     * resolveControlPlaneForAudit exists as a method only when controlPlaneResolver is injected at construction;
     * when not injected the method signature is absent (the IdentityStoreForAudit interface marks it optional),
     * letting the middleware dispatcher precisely distinguish the two fail-closed semantics:
     * "resolver not configured -> 403 control-plane lane disabled"
     * and "resolver configured but DID not registered -> 404 IDENTITY_NOT_FOUND".
     */
    public readonly resolveControlPlaneForAudit?: (
        did: DID,
    ) => Promise<ControlPlaneAuditResolution | null>;

    public constructor(
        private readonly registry: IdentityRegistry,
        // optional injection; when absent the governor lane takes the dispatcher fail-closed 403.
        controlPlaneResolver?: ControlPlaneAuditResolver,
    ) {
        if (controlPlaneResolver) {
            this.resolveControlPlaneForAudit = controlPlaneResolver;
        }
    }

    public async resolveForAudit(
        did: DID,
    ): Promise<AuditIdentityResolution | null> {
        const result = await this.registry.queryForAudit(did);
        if (!result) return null;
        return {
            document: result.document,
            status: result.status,
            verifiedAt:
                new Date().toISOString() as import('@coivitas/types').Timestamp,
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// queryParams normalization
// ═══════════════════════════════════════════════════════════════════════════
function parseQueryParams(
    raw: Record<string, unknown>,
    res: Response,
): AuditQueryParams | null {
    const allowed = new Set([
        'agent_did',
        'principal_did',
        'action',
        'session_id',
        'start',
        'end',
        'limit',
        'cursor',
        // v0.2: governor-lane subject-scope filter parameters. The control-plane lane
        // requires affected_agent_did to be declared explicitly (fail-closed); the business lane ignores this field.
        'affected_agent_did',
        'affected_principal_did',
    ]);

    for (const key of Object.keys(raw)) {
        if (!allowed.has(key)) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                `Unknown query parameter: ${key}`,
            );
            return null;
        }
    }

    const out: AuditQueryParams = {};

    for (const [key, raw2] of Object.entries(raw)) {
        if (raw2 === '' || raw2 === 'null' || raw2 === 'undefined') {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                `Empty/null value for ${key}`,
            );
            return null;
        }
        if (Array.isArray(raw2)) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                `Duplicate key: ${key}`,
            );
            return null;
        }
    }

    if (raw['agent_did'] !== undefined) {
        const v = raw['agent_did'] as string;
        // agent_did accepts did:agent: or SESSION_GOVERNOR_DID
        // governor-lane dispatch is decided by the middleware after signature verification based on targetAgentDid;
        // here only a prefix shape check is done (avoid did:wrong: / did:foo: and other malformed garbage input).
        if (!v.startsWith('did:agent:') && v !== SESSION_GOVERNOR_DID) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                'agent_did must start with did:agent: or be did:system:session-governor',
            );
            return null;
        }
        out.agentDid = v as DID;
    }

    if (raw['principal_did'] !== undefined) {
        const v = raw['principal_did'] as string;
        if (!v.startsWith('did:key:')) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                'principal_did must start with did:key:',
            );
            return null;
        }
        out.principalDid = v as DID;
    }

    if (raw['action'] !== undefined) {
        const v = raw['action'] as string;
        if (!ACTION_VOCABULARY.has(v)) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                `action must be one of: ${[...ACTION_VOCABULARY].join(', ')}`,
            );
            return null;
        }
        out.action = v as import('../audit/types.js').ActionVocabulary;
    }

    if (raw['session_id'] !== undefined) {
        const v = raw['session_id'] as string;
        if (!UUID_V4_RE.test(v)) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                'session_id must be UUID v4',
            );
            return null;
        }
        out.sessionId = v;
    }

    for (const field of ['start', 'end'] as const) {
        if (raw[field] !== undefined) {
            const v = raw[field] as string;
            // Uses the same strict UTC-millisecond validation as the header timestamp
            // (must be parseable by new Date() and round-trip-consistent under toISOString()).
            // The previous lax isNaN check accepted missing milliseconds / ±HH:MM offsets, so a client signing
            // the raw string would not match the server's normalized value -> a misleading 401 (should be 400).
            if (!isValidIso8601(v)) {
                sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    `${field} must be ISO 8601 UTC with milliseconds (e.g. 2026-04-18T12:34:56.789Z)`,
                );
                return null;
            }
            if (field === 'start')
                out.start = v as import('@coivitas/types').Timestamp;
            else out.end = v as import('@coivitas/types').Timestamp;
        }
    }

    if (raw['limit'] !== undefined) {
        const n = Number(raw['limit']);
        if (!Number.isInteger(n) || n < 1 || n > 500) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                'limit must be integer 1-500',
            );
            return null;
        }
        out.limit = n;
    }

    if (raw['cursor'] !== undefined) {
        out.cursor = raw['cursor'] as string;
    }

    // v0.2: parse the governor-lane subject-scope filter fields.
    // affectedAgentDid must have the did:agent: prefix;
    // affectedPrincipalDid must have the did:key: prefix. Neither field is forced to be provided explicitly on the
    // control-plane lane (the control-plane lane's mandatory constraint is done inside ControlPlaneAuditAccessChecker.check();
    // here only format validation is done to stop invalid input at the schema gate).
    if (raw['affected_agent_did'] !== undefined) {
        const v = raw['affected_agent_did'] as string;
        if (!v.startsWith('did:agent:')) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                'affected_agent_did must start with did:agent:',
            );
            return null;
        }
        out.affectedAgentDid = v as DID;
    }
    if (raw['affected_principal_did'] !== undefined) {
        const v = raw['affected_principal_did'] as string;
        if (!v.startsWith('did:key:')) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                'affected_principal_did must start with did:key:',
            );
            return null;
        }
        out.affectedPrincipalDid = v as DID;
    }

    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// recordExistenceGuard (precedes the records.get + records.verify routes only)
// ═══════════════════════════════════════════════════════════════════════════
function makeRecordExistenceGuard(dbPool: DatabasePool) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const recordId = Array.isArray(req.params['id'])
                ? req.params['id'][0]
                : req.params['id'];
            // format validation: a UUID v4 mismatch -> 400 AUDIT_QUERY_MALFORMED (not 404)
            // a format error is not existence-information leakage, so return 400 directly
            if (!recordId || !UUID_V4_RE.test(recordId)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    `Invalid record id format: ${recordId ?? ''}`,
                );
            }

            const result = await dbPool.query<ActionRecordRowInternal>(
                `SELECT id, record_id, agent_did, principal_did, action_type,
                        parameters_summary, authorization_ref, result_summary,
                        record_hash, previous_record_hash, actor_signature,
                        ledger_signature, delegation_depth, session_id, created_at
                 FROM policy.action_records
                 WHERE record_id = $1`,
                [recordId],
            );

            if (!result.rows[0]) {
                // Do not return 404 immediately (prevents a record oracle).
                // Set a flag so the auth middleware runs first, then the handler decides whether to 404.
                // An unauthenticated caller gets 401 regardless of whether the record exists.
                res.locals.recordNotFound = true;
                // Still set prefetchedRecord to a dummy so downstream middleware
                // does not crash reading undefined.agent_did (Step 3 dependency)
                res.locals.prefetchedRecord = {
                    id: '0',
                    record_id: recordId,
                    agent_did: 'did:agent:placeholder',
                    principal_did: 'did:key:placeholder',
                    action_type: 'UNKNOWN',
                    parameters_summary: null,
                    authorization_ref: null,
                    result_summary: null,
                    record_hash: '',
                    previous_record_hash: null,
                    actor_signature: '',
                    ledger_signature: '',
                    delegation_depth: 0,
                    session_id: null,
                    created_at: new Date().toISOString(),
                } as unknown as ActionRecordRowInternal;
                return next();
            }

            res.locals.prefetchedRecord = result.rows[0];
            next();
        } catch (err) {
            next(err);
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// audit middleware (14 steps)
// ═══════════════════════════════════════════════════════════════════════════
function makeAuditMiddleware(
    dbPool: DatabasePool,
    identityStore: IdentityStoreForAudit,
    checker: AuditAccessChecker,
    routeName: AuditResourceBinding['route'],
    /**
     * v0.2 governor lane:
     * the control-plane audit authorization checker. When absent the governor lane automatically fail-closes
     * (403 AUDIT_FORBIDDEN, reason='control-plane lane disabled').
     */
    controlPlaneChecker?: AuditAccessChecker,
) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // Step 1: assert the 5 required request headers + duplicate detection
            // Node concatenates multiple occurrences of a custom header into an "a, b" string by default (not an array),
            // so typeof === 'string' is always true -> the check is missed. Must use req.headersDistinct (Node 18.3+)
            // which returns string[] by occurrence count, allowing strict duplicate detection.
            const distinct = req.headersDistinct;
            const auditHeaderNames = [
                'x-audit-requester',
                'x-audit-signature',
                'x-audit-timestamp',
                'x-audit-snapshot-headcreatedat',
                'x-audit-snapshot-headrecordid',
                'x-audit-snapshot-headrecordhash',
            ] as const;
            for (const name of auditHeaderNames) {
                const arr = distinct[name];
                if (arr && arr.length > 1) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        `Duplicate header: ${name}`,
                    );
                }
            }

            const requesterDid = req.headers['x-audit-requester'];
            const signatureHex = req.headers['x-audit-signature'];
            const timestampStr = req.headers['x-audit-timestamp'];
            const headCreatedAt = req.headers['x-audit-snapshot-headcreatedat'];
            const headRecordId = req.headers['x-audit-snapshot-headrecordid'];
            const headRecordHash =
                req.headers['x-audit-snapshot-headrecordhash'];

            if (
                !requesterDid ||
                !signatureHex ||
                !timestampStr ||
                !headCreatedAt ||
                !headRecordId
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Missing required X-Audit-* headers',
                );
            }
            // fallback type guard: headersDistinct already prevents multi-values; this is only for TS narrowing
            if (
                typeof requesterDid !== 'string' ||
                typeof signatureHex !== 'string' ||
                typeof timestampStr !== 'string' ||
                typeof headCreatedAt !== 'string' ||
                typeof headRecordId !== 'string'
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Malformed X-Audit-* headers',
                );
            }

            // Step 1.5: attacker-controlled timestamps must first pass strict ISO 8601 validation
            // otherwise new Date("foo").getTime() === NaN, making all downstream time comparisons always false,
            // and both the ±300s replay window and the headCreatedAt<=timestamp ordering check can be bypassed;
            // it also converges the 500 caused by SQL 22007 (invalid_datetime_format) down to a 400.
            if (!isValidIso8601(timestampStr)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'X-Audit-Timestamp must be ISO 8601',
                );
            }
            if (!isValidIso8601(headCreatedAt)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'X-Audit-Snapshot-HeadCreatedAt must be ISO 8601',
                );
            }

            // Step 2: rebuild resourceBinding
            const rawParamId = req.params['id'];
            const recordId: string | null = Array.isArray(rawParamId)
                ? (rawParamId[0] ?? null)
                : (rawParamId ?? null);
            const resourceBinding: AuditResourceBinding =
                recordId !== null
                    ? {
                          route: routeName as 'records.get' | 'records.verify',
                          recordId,
                      }
                    : {
                          route: routeName as
                              | 'records.list'
                              | 'records.chain.verify',
                          recordId: null,
                      };

            // Step 3: extract targetAgentDid
            // when recordNotFound, read from the query param
            // (the dummy record's agent_did is a placeholder and cannot be used for signature verification)
            const recordNotFoundFlag = res.locals['recordNotFound'] === true;
            let targetAgentDid: DID;
            if (
                (routeName === 'records.get' ||
                    routeName === 'records.verify') &&
                !recordNotFoundFlag
            ) {
                // prefetchedRecord is guaranteed by recordExistenceGuard
                const prefetched = res.locals[
                    'prefetchedRecord'
                ] as ActionRecordRowInternal;
                targetAgentDid = prefetched.agent_did as DID;
            } else {
                const agentDidRaw = req.query['agent_did'];
                if (!agentDidRaw || typeof agentDidRaw !== 'string') {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'agent_did query parameter required',
                    );
                }
                // targetAgentDid accepts did:agent: or SESSION_GOVERNOR_DID
                if (
                    !agentDidRaw.startsWith('did:agent:') &&
                    agentDidRaw !== SESSION_GOVERNOR_DID
                ) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'agent_did must start with did:agent: or be did:system:session-governor',
                    );
                }
                targetAgentDid = agentDidRaw as DID;
            }

            // Step 4: normalize queryParams
            const queryParams = parseQueryParams(
                req.query as Record<string, unknown>,
                res,
            );
            if (!queryParams) return; // parseQueryParams already sent error

            // Step 5: snapshot boundary anchor query + snapshotMaxId
            if (!UUID_V4_RE.test(headRecordId)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                    'headRecordId must be UUID v4',
                );
            }

            const snapshotRow = await dbPool.query<{
                id: string;
                record_hash: string;
                // PG TIMESTAMPTZ → Date by default (not consumed in this block)
                created_at: string | Date;
            }>(
                `SELECT id, record_hash, created_at
                 FROM policy.action_records
                 WHERE record_id = $1
                   AND agent_did = $2
                   AND created_at = $3`,
                [headRecordId, targetAgentDid, headCreatedAt],
            );

            if (!snapshotRow.rows[0]) {
                return sendError(
                    res,
                    400,
                    'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                    'Snapshot anchor not found or does not belong to target agent',
                );
            }

            const snapshotRecord = snapshotRow.rows[0];

            if (
                headRecordHash &&
                typeof headRecordHash === 'string' &&
                headRecordHash !== snapshotRecord.record_hash
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                    'headRecordHash does not match stored record_hash',
                );
            }

            const snapshotMaxId = BigInt(snapshotRecord.id); // pg returns BIGSERIAL as string at runtime

            // ordering constraint: headCreatedAt <= timestamp
            if (
                new Date(headCreatedAt).getTime() >
                new Date(timestampStr).getTime()
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                    'headCreatedAt must be <= timestamp',
                );
            }

            // Step 6: construct snapshotBoundary
            const snapshotBoundary: AuditSnapshotBoundary = {
                headCreatedAt:
                    headCreatedAt as import('@coivitas/types').Timestamp,
                headRecordId,
                ...(headRecordHash && typeof headRecordHash === 'string'
                    ? { headRecordHash: headRecordHash as Hash }
                    : {}),
            };

            // Step 7 / SignedAuditQuery payload (without signature)
            const signaturePayload = {
                requesterDid: requesterDid as DID,
                targetAgentDid,
                httpMethod: 'GET' as const,
                resourceBinding,
                queryParams,
                snapshotBoundary,
                timestamp:
                    timestampStr as import('@coivitas/types').Timestamp,
            };

            // Step 8: timestamp window ±300s
            const skewMs = Math.abs(
                Date.now() - new Date(timestampStr).getTime(),
            );
            if (skewMs > 300_000) {
                return sendError(
                    res,
                    401,
                    'AUDIT_TIMESTAMP_SKEW',
                    'Request timestamp outside ±300s window',
                );
            }

            // Step 9: resolve the requesterDid public key
            let publicKeyHex: string;
            try {
                publicKeyHex = extractPublicKeyFromDIDKey(requesterDid as DID);
            } catch {
                return sendError(
                    res,
                    401,
                    'AUDIT_REQUESTER_UNKNOWN',
                    'Cannot decode requesterDid public key',
                );
            }

            // Step 10: Ed25519 signature verification
            const canonical = canonicalize(signaturePayload);
            const msgBytes = new TextEncoder().encode(canonical);
            const sigValid = verify(msgBytes, signatureHex, publicKeyHex);
            if (!sigValid) {
                return sendError(
                    res,
                    401,
                    'AUDIT_SIGNATURE_INVALID',
                    'Signature verification failed',
                );
            }

            // lane dispatcher
            // the governor is the target in audit (not the requester; the schema requesterDid is still didKey only),
            // so it dispatches to ControlPlaneAuditAccessChecker; everything else takes the v0.1 PrincipalAuditAccessChecker.
            const isControlPlaneLane =
                (targetAgentDid as string) === SESSION_GOVERNOR_DID;

            const signedQuery = {
                ...signaturePayload,
                signature:
                    signatureHex as import('@coivitas/types').Signature,
            };

            if (isControlPlaneLane) {
                // governor lane
                if (
                    !identityStore.resolveControlPlaneForAudit ||
                    !controlPlaneChecker
                ) {
                    return sendError(
                        res,
                        403,
                        'AUDIT_FORBIDDEN',
                        'control-plane lane disabled',
                    );
                }

                const cpResolution =
                    await identityStore.resolveControlPlaneForAudit(
                        targetAgentDid,
                    );
                if (!cpResolution) {
                    return sendError(
                        res,
                        404,
                        'IDENTITY_NOT_FOUND',
                        `Control-plane DID ${targetAgentDid} not registered`,
                    );
                }

                const verifiedAudit: VerifiedAuditRequest = {
                    lane: 'control-plane',
                    query: signedQuery,
                    resolution: cpResolution,
                    verifiedAt: cpResolution.verifiedAt,
                };
                res.locals.verifiedAudit = verifiedAudit;
                res.locals.snapshotMaxId = snapshotMaxId;

                const decision = await controlPlaneChecker.check(verifiedAudit);
                if (!decision.allowed) {
                    const statusCode =
                        decision.code === 'AUDIT_FORBIDDEN'
                            ? 403
                            : decision.code === 'AUDIT_QUERY_MALFORMED'
                              ? 400
                              : 500;
                    return sendError(
                        res,
                        statusCode,
                        decision.code,
                        decision.reason,
                    );
                }
                return next();
            }

            // business lane (the existing v0.1 path, zero regression)
            // Step 11: IdentityStoreForAudit.resolveForAudit(targetAgentDid) — business lane
            let resolution: AuditIdentityResolution | null;
            try {
                resolution =
                    await identityStore.resolveForAudit(targetAgentDid);
            } catch (err) {
                if (
                    err instanceof ProtocolError &&
                    err.code === 'BINDING_PROOF_INVALID'
                ) {
                    return sendError(
                        res,
                        401,
                        'AUDIT_IDENTITY_UNVERIFIED',
                        err.detail,
                    );
                }
                throw err;
            }

            if (!resolution) {
                return sendError(
                    res,
                    404,
                    'IDENTITY_NOT_FOUND',
                    `Agent ${targetAgentDid} not found`,
                );
            }

            // Step 12: construct VerifiedAuditRequest + mount res.locals
            const verifiedAudit: VerifiedAuditRequest = {
                lane: 'business',
                query: signedQuery,
                resolvedIdentity: resolution.document,
                identityStatus: resolution.status,
                verifiedAt: resolution.verifiedAt,
            };
            res.locals.verifiedAudit = verifiedAudit;
            res.locals.snapshotMaxId = snapshotMaxId;

            // Step 13: AuditAccessChecker.check
            const decision = await checker.check(verifiedAudit);
            if (!decision.allowed) {
                const statusCode =
                    decision.code === 'AUDIT_FORBIDDEN'
                        ? 403
                        : decision.code === 'AUDIT_QUERY_MALFORMED'
                          ? 400
                          : 500;
                return sendError(
                    res,
                    statusCode,
                    decision.code,
                    decision.reason,
                );
            }

            // Step 14: next()
            next();
        } catch (err) {
            next(err);
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// DB row -> PersistedActionRecord mapping (reuses the mapActionRecordRow logic from action-recorder.ts)
// ═══════════════════════════════════════════════════════════════════════════
function rowToRecord(
    row: ActionRecordRowInternal,
): PersistedActionRecord & { _internalId: bigint } {
    return {
        _internalId: BigInt(row.id),
        recordId: row.record_id,
        agentDid: row.agent_did as DID,
        principalDid: row.principal_did as DID,
        actionType: row.action_type,
        parametersSummary: row.parameters_summary,
        authorizationRef: row.authorization_ref,
        resultSummary: row.result_summary,
        recordHash: row.record_hash,
        previousRecordHash: row.previous_record_hash,
        actorSignature:
            row.actor_signature as import('@coivitas/types').Signature,
        ledgerSignature:
            row.ledger_signature as import('@coivitas/types').Signature,
        delegationDepth: row.delegation_depth ?? undefined,
        sessionId: row.session_id ?? undefined,
        createdAt: toTimestamp(row.created_at),
    };
}

// _internalId is not exposed in the external API: helper that strips it here
function toPublicRecord({
    _internalId: _id,
    ...pub
}: PersistedActionRecord & { _internalId: bigint }): PersistedActionRecord {
    void _id; // _internalId need not be exposed externally — intentionally discarded
    return pub;
}

// ═══════════════════════════════════════════════════════════════════════════
// Route Handlers
// ═══════════════════════════════════════════════════════════════════════════

// 05a: GET /records
function makeHandleList(dbPool: DatabasePool): AuditHandler {
    return async ({ verifiedAudit, snapshotMaxId, res }) => {
        const { queryParams, targetAgentDid } = verifiedAudit.query;
        const clauses: string[] = ['agent_did = $1', 'id <= $2'];
        const values: Array<string | number | bigint> = [
            targetAgentDid,
            snapshotMaxId,
        ];

        if (queryParams.principalDid) {
            values.push(queryParams.principalDid);
            clauses.push(`principal_did = $${values.length}`);
        }
        if (queryParams.action) {
            values.push(queryParams.action);
            clauses.push(`action_type = $${values.length}`);
        }
        if (queryParams.sessionId) {
            values.push(queryParams.sessionId);
            clauses.push(`session_id = $${values.length}`);
        }
        if (queryParams.start) {
            values.push(queryParams.start);
            clauses.push(`created_at >= $${values.length}`);
        }
        if (queryParams.end) {
            values.push(queryParams.end);
            clauses.push(`created_at <= $${values.length}`);
        }
        // v0.2: control-plane-lane subject-scope SQL predicate
        // Binds queryParams.affectedAgentDid / affectedPrincipalDid to the
        // immutable signed-payload fields inside the parameters_summary JSONB column, ensuring the scope boundary
        // is enforced at the SQL layer (not relying only on the checker's reject — preventing any later handler
        // on the control-plane path from bypassing scope and reading out-of-scope rows).
        if (queryParams.affectedAgentDid) {
            values.push(queryParams.affectedAgentDid);
            clauses.push(
                `parameters_summary->>'affectedAgentDid' = $${values.length}`,
            );
        }
        if (queryParams.affectedPrincipalDid) {
            values.push(queryParams.affectedPrincipalDid);
            clauses.push(
                `parameters_summary->>'affectedPrincipalDid' = $${values.length}`,
            );
        }
        if (queryParams.cursor) {
            // cursor is a Base64URL string with internal structure "${iso}|${id}".
            const decoded = decodeCursor(queryParams.cursor);
            if (!decoded) {
                sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Invalid cursor: not valid Base64URL or internal format',
                );
                return;
            }
            // After decoding, strictly validate the inner fields: ISO 8601 UTC milliseconds + a valid integer id.
            if (!isValidIso8601(decoded.ts)) {
                sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Invalid cursor: timestamp segment is not ISO 8601',
                );
                return;
            }
            let cursorId: bigint;
            try {
                cursorId = BigInt(decoded.id);
            } catch {
                sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Invalid cursor: id segment is not an integer',
                );
                return;
            }
            values.push(decoded.ts, cursorId);
            clauses.push(
                `(created_at, id) > ($${values.length - 1}::timestamptz, $${values.length})`,
            );
        }

        const limit = queryParams.limit ?? 100;
        values.push(limit + 1);

        const result = await dbPool.query<ActionRecordRowInternal>(
            `SELECT id, record_id, agent_did, principal_did, action_type,
                    parameters_summary, authorization_ref, result_summary,
                    record_hash, previous_record_hash, actor_signature,
                    ledger_signature, delegation_depth, session_id, created_at
             FROM policy.action_records
             WHERE ${clauses.join(' AND ')}
             ORDER BY created_at ASC, id ASC
             LIMIT $${values.length}`,
            values,
        );

        const hasMore = result.rows.length > limit;
        const pageRows = hasMore ? result.rows.slice(0, limit) : result.rows;
        const records = pageRows.map((r) => toPublicRecord(rowToRecord(r)));
        const lastRow = pageRows[pageRows.length - 1];
        const nextCursor =
            hasMore && lastRow
                ? encodeCursor(
                      new Date(lastRow.created_at).toISOString(),
                      lastRow.id,
                  )
                : undefined;

        res.status(200).json({ records, nextCursor });
    };
}

/**
 * Single-point row-level scope integrity invariant gate (v0.5).
 *
 * **The sole trusted row-level scope decision point.** Any surface that exposes a
 * PersistedActionRecord on the control-plane lane (list / get / verify / head / chain / future additions)
 * must be validated by this function first; writing a row-level field comparison at scattered points is not
 * allowed (except the SQL predicate, and the SQL must match this function's semantics).
 *
 * Recurrence trajectory of the same root cause (4 point patches have failed):
 *   - v0.1: the checker validated only queryParams, not row fields -> v0.2 added the list SQL predicate
 *   - v0.2: the list SQL was added but the get/verify/chain handlers did not validate the row -> v0.3 added assertControlPlaneRowScope
 *   - v0.3: head returned globally, bypassing row validation + the status-code difference acted as an existence oracle -> v0.4 added head SQL + normalized status codes
 *   - v0.4: head SQL filtered only affectedAgentDid and dropped affectedPrincipalDid -> v0.5 upgraded to a single-point gate
 *
 * v0.5 upgrade:
 *   - extracted recordVisibleToScope() as the single-point invariant gate
 *   - adding a ControlPlaneRequesterScope field catches all call sites of this function at compile time
 *   - a property-based conformance fixture forces coverage of every scope-field reject face × 5 surfaces
 *
 * **fail-closed semantics**:
 *   - applies to the control-plane lane only (business-lane calls should return true and not enter this function)
 *   - a record missing parameters_summary.affectedAgentDid (fallback for historical/corrupt data) -> not visible
 *   - parameters_summary.affectedAgentDid must equal query.affectedAgentDid
 *   - if query passes affectedPrincipalDid explicitly -> the record must equal it (a record missing the field is not allowed)
 *
 * Returns true = the record is visible within the current query scope; false = not visible (the caller should handle it as record-not-found).
 */
function recordVisibleToScope(
    record: { parametersSummary: Record<string, unknown> | null | undefined },
    queryParams: {
        affectedAgentDid?: string;
        affectedPrincipalDid?: string;
    },
): boolean {
    const params = record.parametersSummary;
    const recordAffectedAgentDid =
        params && typeof params['affectedAgentDid'] === 'string'
            ? params['affectedAgentDid']
            : undefined;
    if (
        queryParams.affectedAgentDid === undefined ||
        recordAffectedAgentDid === undefined ||
        recordAffectedAgentDid !== queryParams.affectedAgentDid
    ) {
        return false;
    }
    if (queryParams.affectedPrincipalDid !== undefined) {
        const recordAffectedPrincipalDid =
            params && typeof params['affectedPrincipalDid'] === 'string'
                ? params['affectedPrincipalDid']
                : undefined;
        if (
            recordAffectedPrincipalDid === undefined ||
            recordAffectedPrincipalDid !== queryParams.affectedPrincipalDid
        ) {
            return false;
        }
    }
    return true;
}

/**
 * Control-plane-lane row-level subject-scope validation (v0.5 — invoked internally by the single-point gate).
 *
 * Since v0.5: this function only does "control-plane lane gatekeeping + calling recordVisibleToScope + a uniform 404 response".
 * All row-level decision semantics are pushed down into recordVisibleToScope; adding a scope field requires no change to this function.
 *
 * Historical trajectory (archived in the recordVisibleToScope docs):
 *   - v0.3 status code 400 became an existence oracle -> v0.4 changed to 404
 *   - v0.4 row-level semantics were scattered, hitting the dropped field in head SQL -> v0.5 extracted the single-point gate
 *
 * Status-code contract (immutable): a control-plane row mismatch returns 404 NOT_FOUND (consistent with recordExistenceGuard,
 * to prevent an attacker from using the status-code difference as an existence oracle).
 *
 * Returns true -> the check passed; false -> sendError has been called and the caller should return directly.
 */
function assertControlPlaneRowScope(
    verifiedAudit: VerifiedAuditRequest,
    record: PersistedActionRecord & { _internalId: bigint },
    res: Response,
): boolean {
    if (verifiedAudit.lane !== 'control-plane') return true;
    const visible = recordVisibleToScope(
        {
            parametersSummary: record.parametersSummary as
                | Record<string, unknown>
                | null
                | undefined,
        },
        verifiedAudit.query.queryParams,
    );
    if (!visible) {
        sendError(res, 404, 'NOT_FOUND', `Record ${record.recordId} not found`);
        return false;
    }
    return true;
}

// 05b: GET /records/:id
function makeHandleGet(): AuditHandler {
    return ({
        verifiedAudit,
        snapshotMaxId,
        prefetchedRecord,
        recordNotFound,
        res,
    }) => {
        // deferred 404 — auth has passed, so it is now safe to return not-found
        if (recordNotFound) {
            sendError(res, 404, 'NOT_FOUND', 'Record not found');
            return Promise.resolve();
        }
        const record = rowToRecord(prefetchedRecord!);

        // secondary check: guard against a cross-agent recordId
        if (
            prefetchedRecord!.agent_did !== verifiedAudit.query.targetAgentDid
        ) {
            sendError(
                res,
                400,
                'AUDIT_RESOURCE_BINDING_MISMATCH',
                'Record does not belong to target agent',
            );
            return Promise.resolve();
        }

        // snapshot range check
        if (record._internalId > snapshotMaxId) {
            sendError(
                res,
                404,
                'NOT_FOUND',
                'Record exists but is outside snapshot boundary',
            );
            return Promise.resolve();
        }

        // v0.3: control-plane-lane row-level subject scope
        if (!assertControlPlaneRowScope(verifiedAudit, record, res)) {
            return Promise.resolve();
        }

        res.status(200).json(toPublicRecord(record));
        return Promise.resolve();
    };
}

/**
 * Port: fetch the document version history for an agent DID (version descending).
 *
 * Design rationale (historical actor_signature verification):
 *   The verify endpoint must be able to verify the actor_signature against the publicKey that was "valid at the
 *   record's creation moment". The agent may have rotated keys after the record was created; the current document's
 *   (verifiedAudit.resolvedIdentity) publicKey does not necessarily represent the agent's identity at the historical moment.
 *
 *   Abstracting this as a port rather than passing IdentityRegistry directly:
 *     1. decouples makeHandleVerify from the Registry implementation, making it easy to mock in unit tests;
 *     2. introduces no new SQL path and reuses IdentityRegistry.getDocumentHistory (registry.ts:207).
 *
 *   Implementation convention (consistent with IdentityRegistry.getDocumentHistory):
 *     - ordered by version descending (the most recent version is at [0]);
 *     - the current schema keeps only the most recent 2 versions (current + previous_document);
 *       history from earlier rotations has been overwritten and can no longer be resolved;
 *     - a non-key change (modifying capabilities/serviceEndpoints, etc.) also increments version
 *       and writes previous_document (registry.ts:174-201), so the updatedAt inside history
 *       cannot be used as a "key-era switch point" — see
 *       the design notes of collectActorPublicKeyCandidates.
 */
type AgentDocumentHistoryReader = (
    did: DID,
) => Promise<AgentIdentityDocument[]>;

/**
 * Collect the candidate set of publicKeys the agent may have held historically (deduplicated).
 *
 * Design notes (correcting the initial assumption):
 *   The initial version picked 1 public key by doc.updatedAt, assuming "updatedAt advances ⇔ publicKey changes".
 *   That assumption is wrong: IdentityRegistry.update also advances updatedAt and increments version on a non-key
 *   change (modifying capabilities / serviceEndpoints); after several ordinary updates the updatedAt of both
 *   [current, previous] is later than an early record.createdAt, causing a legitimate record from a never-rotated
 *   key to be falsely reported as having an invalid actor_signature.
 *
 *   Current strategy: include the publicKey + previousPublicKey of the current document + all versions in history
 *   into the candidate set, then have the caller deduplicate and try each in turn for verification.
 *
 *   Security argument: the candidate set only takes the agent identity fields from authoritative DB records; Ed25519
 *   unforgeability guarantees that "if some public key verifies, it must have been signed by the corresponding
 *   private key, and since that private key appears in this DID's identity history, the signature was legitimately
 *   produced by this agent at some point".
 *   Security is not relaxed; this only eliminates the false positives on legitimate records caused by "updatedAt misuse".
 */
function collectActorPublicKeyCandidates(
    currentDoc: AgentIdentityDocument,
    history: AgentIdentityDocument[],
): string[] {
    const seen = new Set<string>();
    const push = (key: string | undefined): void => {
        if (typeof key === 'string' && key.length > 0) seen.add(key);
    };
    push(currentDoc.publicKey);
    push(currentDoc.previousPublicKey);
    for (const doc of history) {
        push(doc.publicKey);
        push(doc.previousPublicKey);
    }
    return Array.from(seen);
}

/**
 * Single-record verification of a control-plane record (Step 5).
 *
 * Same logic as the makeHandleVerify business lane: verifies all three of record_hash + actor_signature +
 * ledger_signature. Differences:
 *   - the actor public key comes from ResolveControlPlanePublicKey (injected by the deployer) rather than
 *     getDocumentHistory (a control-plane DID has no IdentityRegistry document);
 *   - it does not maintain the "historical candidate public-key set" concept (the control-plane public key is authoritative from the deployment context).
 *
 * Reuses buildUnsignedRecordPayload + computeRecordHash + verifyRecordSignature
 * to guarantee the signature preimage shape is identical to IntegrityChecker.verifyIntegrity().
 */
async function verifyControlPlaneRecord(
    record: PersistedActionRecord & { _internalId: bigint },
    ledgerPublicKey: string,
    resolveControlPlanePublicKey: (did: DID) => Promise<string | null>,
    res: Response,
): Promise<void> {
    const payload = buildUnsignedRecordPayload({
        recordId: record.recordId,
        agentDid: record.agentDid,
        principalDid: record.principalDid,
        actionType: record.actionType,
        parametersSummary: record.parametersSummary,
        authorizationRef: record.authorizationRef,
        resultSummary: record.resultSummary,
        previousRecordHash: record.previousRecordHash,
        createdAt: record.createdAt,
        delegationDepth: record.delegationDepth,
        sessionId: record.sessionId,
    });
    /* v8 ignore start*/
    if (!RECORD_HASH_CHARSET_RE.test(record.recordHash)) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            `record ${record.recordId} has unrecognized record_hash encoding`,
        );
    }
    /* v8 ignore stop*/
    const outputEncoding = detectEncoding(record.recordHash);
    const expectedHash = computeRecordHash(
        payload,
        record.previousRecordHash,
        outputEncoding,
    );
    const checks: Array<{ name: string; valid: boolean; reason?: string }> = [];
    const hashValid = record.recordHash === expectedHash;
    checks.push({
        name: 'record_hash',
        valid: hashValid,
        ...(!hashValid
            ? { reason: 'computed hash does not match stored hash' }
            : {}),
    });

    const controlPlanePublicKey = await resolveControlPlanePublicKey(
        record.agentDid,
    );
    if (!controlPlanePublicKey) {
        checks.push({
            name: 'actor_signature',
            valid: false,
            reason: 'control-plane public key unavailable',
        });
    } else {
        const actorSigValid = verifyRecordSignature(
            payload,
            record.actorSignature,
            controlPlanePublicKey,
        );
        checks.push({
            name: 'actor_signature',
            valid: actorSigValid,
            ...(!actorSigValid ? { reason: 'actor signature invalid' } : {}),
        });
    }

    const ledgerSigValid = verifyRecordSignature(
        payload,
        record.ledgerSignature,
        ledgerPublicKey,
    );
    checks.push({
        name: 'ledger_signature',
        valid: ledgerSigValid,
        ...(!ledgerSigValid ? { reason: 'ledger signature invalid' } : {}),
    });

    const allValid = checks.every((c) => c.valid);
    res.status(200).json({ valid: allValid, checks });
}

// 05c: GET /records/:id/verify
// Step 5: the control-plane lane also takes the real signature-verification path.
// History (withdrawn): v0.1 simply 403'd the control-plane lane's verify, so a remote auditor could not verify
// governor record signatures —— "a closed hash chain guarantees tamper-resistance", but a valid chain and
// valid signatures are two independent matters; in a DB-compromise scenario the chain may still be valid while the
// signatures are forged (IntegrityChecker.check() already guarantees this; the audit lane should be consistent).
// v0.2: the control-plane lane accepts verify requests, reusing the same single-record verification
// logic as IntegrityChecker, with the governor public key resolved by ResolveControlPlanePublicKey (injected by the deployer).
function makeHandleVerify(
    ledgerPublicKey: string,
    getDocumentHistory: AgentDocumentHistoryReader,
    resolveControlPlanePublicKey?: (did: DID) => Promise<string | null>,
): AuditHandler {
    return async ({
        verifiedAudit,
        snapshotMaxId,
        prefetchedRecord,
        recordNotFound,
        res,
    }) => {
        // deferred 404 — auth has passed, so it is now safe to return not-found
        if (recordNotFound) {
            sendError(res, 404, 'NOT_FOUND', 'Record not found');
            return;
        }
        const record = rowToRecord(prefetchedRecord!);

        if (
            prefetchedRecord!.agent_did !== verifiedAudit.query.targetAgentDid
        ) {
            sendError(
                res,
                400,
                'AUDIT_RESOURCE_BINDING_MISMATCH',
                'Record does not belong to target agent',
            );
            return;
        }

        if (record._internalId > snapshotMaxId) {
            sendError(
                res,
                404,
                'NOT_FOUND',
                'Record exists but is outside snapshot boundary',
            );
            return;
        }

        // Step 5: the control-plane lane takes a dedicated verify path
        // - the actor public key comes from ResolveControlPlanePublicKey (the governor does not enter federated DID resolution)
        // - does not call getDocumentHistory (a control-plane DID has no IdentityRegistry document)
        // - still verifies all three of record_hash + actor_signature + ledger_signature
        if (verifiedAudit.lane !== 'business') {
            // fail-closed: when resolveControlPlanePublicKey is not injected, control-plane verify is unreachable
            if (typeof resolveControlPlanePublicKey !== 'function') {
                sendError(
                    res,
                    403,
                    'AUDIT_FORBIDDEN',
                    'control-plane lane verify requires resolveControlPlanePublicKey injection (use IntegrityChecker pattern)',
                );
                return;
            }
            // v0.3: row-level subject scope
            if (!assertControlPlaneRowScope(verifiedAudit, record, res)) {
                return;
            }
            await verifyControlPlaneRecord(
                record,
                ledgerPublicKey,
                resolveControlPlanePublicKey,
                res,
            );
            return;
        }

        const payload = buildUnsignedRecordPayload({
            recordId: record.recordId,
            agentDid: record.agentDid,
            principalDid: record.principalDid,
            actionType: record.actionType,
            parametersSummary: record.parametersSummary,
            authorizationRef: record.authorizationRef,
            resultSummary: record.resultSummary,
            previousRecordHash: record.previousRecordHash,
            createdAt: record.createdAt,
            delegationDepth: record.delegationDepth,
            sessionId: record.sessionId,
        });

        // encoding detection: reuses the canonical detectEncoding.
        // DB data corruption (a non-hex/base64url charset) = an unexpected server fault; leave it to the Express
        // error handler to return 5xx, and do not put it into the AuditAccessErrorCode contract.
        // Unreachable branch: ActionRecorder.record() writes are always constrained to hex/base64url (shared.ts),
        // so the fail-fast ProtocolError here is only a fallback defense against DB contamination.
        /* v8 ignore start*/
        if (!RECORD_HASH_CHARSET_RE.test(record.recordHash)) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                `record ${record.recordId} has unrecognized record_hash encoding`,
            );
        }
        /* v8 ignore stop*/
        const outputEncoding = detectEncoding(record.recordHash);
        const expectedHash = computeRecordHash(
            payload,
            record.previousRecordHash,
            outputEncoding,
        );

        const checks: Array<{ name: string; valid: boolean; reason?: string }> =
            [];

        const hashValid = record.recordHash === expectedHash;
        checks.push({
            name: 'record_hash',
            valid: hashValid,
            ...(!hashValid
                ? { reason: 'computed hash does not match stored hash' }
                : {}),
        });

        // Verify actor_signature against the candidate public-key set.
        // Candidate sources: the current document (resolvedIdentity) + all versions from getDocumentHistory,
        // also including each document's previousPublicKey (after rotation, current still holds a pointer to the prior key).
        // No longer picks 1 by doc.updatedAt — a non-key change also advances updatedAt (registry.ts:174-201),
        // which would falsely report a legitimate record from a never-rotated key as invalid.
        //
        // ── reason classification ───────────────────────
        // IdentityRegistry's current schema keeps only two versions (current + previous_document,
        // registry.ts:207-238); 3 or more rotations make the earliest key permanently disappear from the candidate set.
        // When the entire candidate set fails verification, `history.length >= 2` is already the "ceiling" the registry exposes
        // — meaning an earlier, already-overwritten legitimate key may exist. Within a 2-version-only window we cannot
        // distinguish "real forgery" from "history attrition", so the reason is split into two:
        // - history.length >= 2 -> reason='historical_key_unavailable'
        // (hints to the auditor "this may be an overwritten old key"; a full verification path is needed to tell them apart)
        // - history.length < 2 -> reason='actor signature invalid'
        // (the registry can fully cover at least the recent 2 versions, so a total failure leans toward a true mismatch)
        // Real cutoff-aware resolution (resolvePublicKeys + previousValidBefore) follows in a later
        // upgrade; the current implementation only removes the false-positive ambiguity in the reason.
        const history = await getDocumentHistory(record.agentDid);
        const candidates = collectActorPublicKeyCandidates(
            verifiedAudit.resolvedIdentity,
            history,
        );
        if (candidates.length === 0) {
            // extreme boundary: the DB identity has no publicKey at all; unreachable on the production path, only triggered by mock tests.
            checks.push({
                name: 'actor_signature',
                valid: false,
                reason: 'unable to resolve historical public key',
            });
        } else {
            const actorSigValid = candidates.some((publicKey) =>
                verifyRecordSignature(
                    payload,
                    record.actorSignature,
                    publicKey,
                ),
            );
            // On failure, classify the reason by history depth; on success, no reason is included.
            const failureReason =
                history.length >= 2
                    ? 'historical_key_unavailable'
                    : 'actor signature invalid';
            checks.push({
                name: 'actor_signature',
                valid: actorSigValid,
                ...(!actorSigValid ? { reason: failureReason } : {}),
            });
        }

        // ledger_signature is the only technical means to "prevent ledger-service forgery" and must be truly verified;
        // ledgerPublicKey is injected via registerActionRecordRoutes options (required).
        const ledgerSigValid = verifyRecordSignature(
            payload,
            record.ledgerSignature,
            ledgerPublicKey,
        );
        checks.push({
            name: 'ledger_signature',
            valid: ledgerSigValid,
            ...(!ledgerSigValid ? { reason: 'ledger signature invalid' } : {}),
        });

        const allValid = checks.every((c) => c.valid);
        res.status(200).json({ valid: allValid, checks });
    };
}

// 05d: GET /records/chain/verify
function makeHandleChainVerify(dbPool: DatabasePool): AuditHandler {
    return async ({ verifiedAudit, snapshotMaxId, res }) => {
        // v0.3:
        // chain.verify conceptually needs to traverse the entire governor chain to close the hash chain;
        // but the control-plane lane's per-requester subject scope restricts a requester
        // to reading only records within its affected* range — the two are fundamentally in conflict:
        // - enforcing the SQL predicate with affected* -> the "chain segment" semantics break (a discontinuous affected* would falsely report a broken chain)
        // - not enforcing it -> exposes recordCount/brokenAt to out-of-scope subjects
        // Choice: the control-plane lane simply disables chain.verify. Governor chain integrity
        // is done by the deployer's operations-side IntegrityChecker (already under the deployer's control within the trust boundary).
        // Cross-org evolution can open this up after redesigning the anchor semantics.
        if (verifiedAudit.lane !== 'business') {
            sendError(
                res,
                403,
                'AUDIT_FORBIDDEN',
                'control-plane lane does not support /records/chain/verify (subject scope vs full-chain semantics conflict; use IntegrityChecker for governor chain integrity)',
            );
            return;
        }

        const { queryParams, targetAgentDid } = verifiedAudit.query;

        // v0.5:
        // CLI ledger verify --chain --from already implements GenesisProbe detection: when --from is strictly later than
        // that agent's genesis record it rejects directly (packages/sdk/src/cli/commands/ledger.ts:162-186),
        // because IntegrityChecker hardcodes the `previousRecordHash=''` expectation for the first record,
        // so a non-genesis start point would falsely report a "previous_record_hash mismatch".
        // The remote API previously had no symmetric guard (a gap in the CLI/API symmetry); the CLI comment already
        // knew "the same restriction exists in GET /records/chain/verify" but did not fix it.
        // v0.5 fix: do the genesis probe symmetrically with the CLI; a non-genesis window start point -> 400 AUDIT_QUERY_MALFORMED.
        // Does not implement the "fetch the previous hash" branch (that is a breaking format change requiring a dedicated migration process;
        // here it is narrowed to a single option — an explicit 400 rejection).
        if (queryParams.start !== undefined) {
            // PG TIMESTAMPTZ → Date by default
            const genesisResult = await dbPool.query<{
                created_at: string | Date;
            }>(
                `SELECT created_at
                 FROM policy.action_records
                 WHERE agent_did = $1 AND id <= $2
                 ORDER BY id ASC
                 LIMIT 1`,
                [targetAgentDid, snapshotMaxId],
            );
            const genesisCreatedAt = genesisResult.rows[0]?.created_at;
            if (genesisCreatedAt !== undefined) {
                const genesisIso = new Date(genesisCreatedAt).toISOString();
                if (genesisIso < queryParams.start) {
                    sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        `start=${queryParams.start} is after the agent's genesis record (${genesisIso}); ` +
                            `non-genesis chain-segment verification not supported (parity with CLI ledger verify --chain --from). ` +
                            `Workaround: omit start to verify from genesis, or use end only.`,
                    );
                    return;
                }
            }
        }

        const clauses: string[] = ['agent_did = $1', 'id <= $2'];
        const values: Array<string | number | bigint> = [
            targetAgentDid,
            snapshotMaxId,
        ];

        if (queryParams.start) {
            values.push(queryParams.start);
            clauses.push(`created_at >= $${values.length}`);
        }
        if (queryParams.end) {
            values.push(queryParams.end);
            clauses.push(`created_at <= $${values.length}`);
        }

        // Hard cap of 10000 records, fetching 1 extra to detect overflow; if exceeded, return 400 asking to narrow the time window,
        // rather than silently truncating —— silent truncation would mislead the client into thinking the returned range was fully verified (an untrustworthy valid:true).
        // No limit semantics are defined for chain.verify, nor any truncated field,
        // so a registered error code (AUDIT_QUERY_MALFORMED) is used to surface the problem to the client.
        const CHAIN_VERIFY_MAX_RECORDS = 10_000;
        const result = await dbPool.query<ActionRecordRowInternal>(
            `SELECT id, record_id, agent_did, principal_did, action_type,
                    parameters_summary, authorization_ref, result_summary,
                    record_hash, previous_record_hash, actor_signature,
                    ledger_signature, delegation_depth, session_id, created_at
             FROM policy.action_records
             WHERE ${clauses.join(' AND ')}
             ORDER BY created_at ASC, id ASC
             LIMIT ${CHAIN_VERIFY_MAX_RECORDS + 1}`,
            values,
        );

        if (result.rows.length > CHAIN_VERIFY_MAX_RECORDS) {
            sendError(
                res,
                400,
                'AUDIT_QUERY_MALFORMED',
                `Chain verification window exceeds ${CHAIN_VERIFY_MAX_RECORDS} records; narrow via start/end`,
            );
            return;
        }

        const records = result.rows.map(rowToRecord);

        if (records.length === 0) {
            res.status(200).json({ valid: true, recordCount: 0 });
            return;
        }

        for (const [i, record] of records.entries()) {
            const expectedPrev = i === 0 ? '' : records[i - 1]!.recordHash;
            if (record.previousRecordHash !== expectedPrev) {
                res.status(200).json({
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'previous_record_hash mismatch',
                    recordCount: records.length,
                });
                return;
            }

            const payload = buildUnsignedRecordPayload({
                recordId: record.recordId,
                agentDid: record.agentDid,
                principalDid: record.principalDid,
                actionType: record.actionType,
                parametersSummary: record.parametersSummary,
                authorizationRef: record.authorizationRef,
                resultSummary: record.resultSummary,
                previousRecordHash: record.previousRecordHash,
                createdAt: record.createdAt,
                delegationDepth: record.delegationDepth,
                sessionId: record.sessionId,
            });
            // Unreachable branch: DB integrity defense, see the explanation of the same branch in makeHandleVerify.
            /* v8 ignore start*/
            if (!RECORD_HASH_CHARSET_RE.test(record.recordHash)) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `record ${record.recordId} has unrecognized record_hash encoding`,
                );
            }
            /* v8 ignore stop*/
            const outputEncoding = detectEncoding(record.recordHash);
            const expectedHash = computeRecordHash(
                payload,
                record.previousRecordHash,
                outputEncoding,
            );
            if (record.recordHash !== expectedHash) {
                res.status(200).json({
                    valid: false,
                    brokenAt: record.recordId,
                    reason: 'record_hash mismatch',
                    recordCount: records.length,
                });
                return;
            }
        }

        res.status(200).json({ valid: true, recordCount: records.length });
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /ledger/head (05f — unsigned auxiliary endpoint)

// Explicit convention: this endpoint does no rate-limiting; if throttling is needed, it is the responsibility of the
// reverse proxy or gateway layer (a later release may migrate this or upgrade it to a signed endpoint). Therefore no
// token-bucket is layered on within this process, to avoid deviating from the design convention and polluting the audit-route error-code contract.
// ═══════════════════════════════════════════════════════════════════════════
function registerLedgerHeadRoute(app: Application, dbPool: DatabasePool): void {
    app.get(
        '/ledger/head',
        async (req: Request, res: Response, next: NextFunction) => {
            try {
                const agentDid = req.query['agent_did'];
                if (!agentDid || typeof agentDid !== 'string') {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'agent_did query parameter required',
                    );
                }
                // The unsigned /ledger/head endpoint **explicitly rejects** the governor DID.
                // Historical lesson: an early version once added the governor DID to the /ledger/head allow-list ->
                // an anonymous caller could read the control-plane head (information leakage), which was later withdrawn.
                // After the withdrawal the prefix check still rejects the governor by default, but that is "coincidental";
                // an explicit 403 + a control-plane-specific reason is added here to make the boundary explicit.
                if (agentDid === SESSION_GOVERNOR_DID) {
                    return sendError(
                        res,
                        403,
                        'AUDIT_FORBIDDEN',
                        'control-plane head requires signed audit query (use GET /audit/ledger/head with X-Audit-* headers)',
                    );
                }
                if (!agentDid.startsWith('did:agent:')) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'agent_did must start with did:agent:',
                    );
                }

                const result = await dbPool.query<{
                    record_id: string;
                    // PG TIMESTAMPTZ → Date by default
                    created_at: string | Date;
                    record_hash: string;
                }>(
                    `SELECT record_id, created_at, record_hash
                 FROM policy.action_records
                 WHERE agent_did = $1
                 ORDER BY id DESC
                 LIMIT 1`,
                    [agentDid],
                );

                if (!result.rows[0]) {
                    return sendError(
                        res,
                        404,
                        'NOT_FOUND',
                        `No records found for agent ${agentDid}`,
                    );
                }

                const row = result.rows[0];
                res.status(200).json({
                    agentDid,
                    headRecordId: row.record_id,
                    headCreatedAt: new Date(row.created_at).toISOString(),
                    headRecordHash: row.record_hash,
                });
            } catch (err) {
                next(err);
            }
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// signed ledger.head endpoint — governor lane bootstrap
// ═══════════════════════════════════════════════════════════════════════════
// Background: after the unsigned /ledger/head 403's the governor, the audit middleware
// requires X-Audit-Snapshot-Head* headers, so a governor that does not know the head cannot construct its first
// legitimate audit request -> a bootstrap deadlock. This endpoint uses an Ed25519 signature over requesterDid +
// targetAgentDid + httpMethod + resourceBinding + queryParams + timestamp (**without**
// snapshotBoundary, because the head is its output not its input) to authorize the governor lane to read the head.
// ═══════════════════════════════════════════════════════════════════════════
function makeLedgerHeadAuditMiddleware(
    identityStore: IdentityStoreForAudit,
    controlPlaneChecker?: AuditAccessChecker,
) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // Step 1: assert the 4 required request headers (excluding the snapshot-boundary headers) + duplicate detection
            const distinct = req.headersDistinct;
            const auditHeaderNames = [
                'x-audit-requester',
                'x-audit-signature',
                'x-audit-timestamp',
            ] as const;
            for (const name of auditHeaderNames) {
                const arr = distinct[name];
                if (arr && arr.length > 1) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        `Duplicate header: ${name}`,
                    );
                }
            }

            const requesterDid = req.headers['x-audit-requester'];
            const signatureHex = req.headers['x-audit-signature'];
            const timestampStr = req.headers['x-audit-timestamp'];

            if (!requesterDid || !signatureHex || !timestampStr) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Missing required X-Audit-Requester / X-Audit-Signature / X-Audit-Timestamp headers',
                );
            }
            if (
                typeof requesterDid !== 'string' ||
                typeof signatureHex !== 'string' ||
                typeof timestampStr !== 'string'
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Malformed X-Audit-* headers',
                );
            }

            // Step 2: strict ISO 8601 validation
            if (!isValidIso8601(timestampStr)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'X-Audit-Timestamp must be ISO 8601',
                );
            }

            // Step 3: extract targetAgentDid (query string)
            const agentDidRaw = req.query['agent_did'];
            if (!agentDidRaw || typeof agentDidRaw !== 'string') {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'agent_did query parameter required',
                );
            }
            // The ledger.head endpoint is **governor-lane only** —— business agents use the unsigned
            // /ledger/head (the existing path).
            if (agentDidRaw !== SESSION_GOVERNOR_DID) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    '/audit/ledger/head requires agent_did=did:system:session-governor (business agents use unsigned /ledger/head)',
                );
            }
            const targetAgentDid = agentDidRaw as DID;

            // Step 4: normalize queryParams (only agent_did is meaningful; the other fields are ignored)
            const queryParams = parseQueryParams(
                req.query as Record<string, unknown>,
                res,
            );
            if (!queryParams) return;

            // Step 5: construct the SignedAuditQuery payload (without snapshotBoundary)
            const resourceBinding: AuditResourceBinding = {
                route: 'ledger.head',
                recordId: null,
            };
            const signaturePayload = {
                requesterDid: requesterDid as DID,
                targetAgentDid,
                httpMethod: 'GET' as const,
                resourceBinding,
                queryParams,
                timestamp:
                    timestampStr as import('@coivitas/types').Timestamp,
            };

            // Step 6: timestamp window ±300s
            const skewMs = Math.abs(
                Date.now() - new Date(timestampStr).getTime(),
            );
            if (skewMs > 300_000) {
                return sendError(
                    res,
                    401,
                    'AUDIT_TIMESTAMP_SKEW',
                    'Request timestamp outside ±300s window',
                );
            }

            // Step 7: resolve the requesterDid public key
            let publicKeyHex: string;
            try {
                publicKeyHex = extractPublicKeyFromDIDKey(requesterDid as DID);
            } catch {
                return sendError(
                    res,
                    401,
                    'AUDIT_REQUESTER_UNKNOWN',
                    'Cannot decode requesterDid public key',
                );
            }

            // Step 8: Ed25519 signature verification
            const canonical = canonicalize(signaturePayload);
            const msgBytes = new TextEncoder().encode(canonical);
            const sigValid = verify(msgBytes, signatureHex, publicKeyHex);
            if (!sigValid) {
                return sendError(
                    res,
                    401,
                    'AUDIT_SIGNATURE_INVALID',
                    'Signature verification failed',
                );
            }

            const signedQuery = {
                ...signaturePayload,
                signature:
                    signatureHex as import('@coivitas/types').Signature,
            };

            // Step 9: governor lane resolution + checker
            if (
                !identityStore.resolveControlPlaneForAudit ||
                !controlPlaneChecker
            ) {
                return sendError(
                    res,
                    403,
                    'AUDIT_FORBIDDEN',
                    'control-plane lane disabled',
                );
            }

            const cpResolution =
                await identityStore.resolveControlPlaneForAudit(targetAgentDid);
            if (!cpResolution) {
                return sendError(
                    res,
                    404,
                    'IDENTITY_NOT_FOUND',
                    `Control-plane DID ${targetAgentDid} not registered`,
                );
            }

            const verifiedAudit: VerifiedAuditRequest = {
                lane: 'control-plane',
                query: signedQuery,
                resolution: cpResolution,
                verifiedAt: cpResolution.verifiedAt,
            };
            res.locals.verifiedAudit = verifiedAudit;

            const decision = await controlPlaneChecker.check(verifiedAudit);
            if (!decision.allowed) {
                const statusCode =
                    decision.code === 'AUDIT_FORBIDDEN'
                        ? 403
                        : decision.code === 'AUDIT_QUERY_MALFORMED'
                          ? 400
                          : 500;
                return sendError(
                    res,
                    statusCode,
                    decision.code,
                    decision.reason,
                );
            }

            return next();
        } catch (err) {
            next(err);
        }
    };
}

// signed /audit/ledger/head handler: returns the subject-scoped governor head triple

// v0.5: head SQL must symmetrically cover
// all dimensions of ControlPlaneRequesterScope. v0.4 only filtered affectedAgentDid and dropped affectedPrincipalDid ->
// when the requester scope restricts the principal set, out-of-scope-principal governor records were still visible.

// v0.5 upgrade: double enforcement via the head SQL predicate + the recordVisibleToScope single-point invariant gate.
// When a ControlPlaneRequesterScope field is added, this SQL and recordVisibleToScope must be extended in lockstep
// (the property-based conformance fixture enforces symmetry — see control-plane-scope.property.test.ts).

// The middleware already ensures that on reaching this handler verifiedAudit.lane === 'control-plane' and
// queryParams.affectedAgentDid has passed scope validation (ControlPlaneAuditAccessChecker.check()
// no longer bypasses ledger.head as of v0.4).
function makeHandleSignedLedgerHead(dbPool: DatabasePool) {
    // bootstrap token TTL aligned with the signature window
    const BOOTSTRAP_TOKEN_TTL_MS = 300_000; // 300s

    // anchor cache prevents head drift across retries
    // key = requesterDid|affectedAgentDid|affectedPrincipalDid
    // value = { anchorId, expiresAt }
    // TTL = BOOTSTRAP_TOKEN_TTL_MS; cache eviction: lazy (expiry check on read)
    const anchorCache = new Map<
        string,
        { anchorId: string; expiresAt: number }
    >();

    function getOrCacheAnchor(cacheKey: string, freshAnchorId: string): string {
        const existing = anchorCache.get(cacheKey);
        if (existing && Date.now() < existing.expiresAt) {
            return existing.anchorId;
        }
        // lazily evict expired entries (cleaned once every 100 writes)
        if (anchorCache.size > 100) {
            const now = Date.now();
            for (const [k, v] of anchorCache) {
                if (now >= v.expiresAt) anchorCache.delete(k);
            }
        }
        anchorCache.set(cacheKey, {
            anchorId: freshAnchorId,
            expiresAt: Date.now() + BOOTSTRAP_TOKEN_TTL_MS,
        });
        return freshAnchorId;
    }

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const verifiedAudit = res.locals['verifiedAudit'] as
                | VerifiedAuditRequest
                | undefined;
            // defensive: a request that did not pass the middleware (calling the handler directly) -> 500 (unreachable, defense in depth only)
            /* v8 ignore start*/
            if (!verifiedAudit || verifiedAudit.lane !== 'control-plane') {
                return sendError(
                    res,
                    500,
                    'INTERNAL_ERROR',
                    'ledger.head reached without control-plane verifiedAudit',
                );
            }
            /* v8 ignore stop*/
            const affectedAgentDid =
                verifiedAudit.query.queryParams.affectedAgentDid;
            // The middleware guarantees affectedAgentDid is declared; a missing one means the middleware was bypassed — fail-closed
            if (typeof affectedAgentDid !== 'string') {
                return sendError(
                    res,
                    403,
                    'AUDIT_FORBIDDEN',
                    'control-plane ledger.head requires queryParams.affectedAgentDid',
                );
            }
            // v0.5: affectedPrincipalDid is symmetric with affectedAgentDid; if query passes it explicitly the SQL enforces it
            // (the checker already validated that query is within scope; here it additionally does row-level field binding — double defense)
            const affectedPrincipalDid =
                verifiedAudit.query.queryParams.affectedPrincipalDid;
            const clauses: string[] = [
                'agent_did = $1',
                `parameters_summary->>'affectedAgentDid' = $2`,
            ];
            const values: Array<string> = [
                SESSION_GOVERNOR_DID,
                affectedAgentDid,
            ];
            if (typeof affectedPrincipalDid === 'string') {
                values.push(affectedPrincipalDid);
                clauses.push(
                    `parameters_summary->>'affectedPrincipalDid' = $${values.length}`,
                );
            }

            // anchor cache prevents head drift across retries
            // cache key = requesterDid + affectedAgentDid + affectedPrincipalDid
            const requesterDid = verifiedAudit.query.requesterDid;
            const cacheKey = `${requesterDid}|${affectedAgentDid}|${affectedPrincipalDid ?? ''}`;

            // Step 1: obtain the anchor
            // Check the cache first: within the TTL reuse the same anchor, eliminating head drift across retries
            let anchorId: string | undefined;
            const cached = anchorCache.get(cacheKey);
            if (cached && Date.now() < cached.expiresAt) {
                anchorId = cached.anchorId;
            }

            if (!anchorId) {
                // cache miss: query MAX(id) to obtain a fresh anchor
                const anchorResult = await dbPool.query<{
                    anchor_id: string;
                }>(
                    `SELECT MAX(id)::text AS anchor_id
                     FROM policy.action_records
                     WHERE ${clauses.join(' AND ')}`,
                    values,
                );

                const freshAnchor = anchorResult.rows[0]?.anchor_id;
                if (!freshAnchor) {
                    return sendError(
                        res,
                        404,
                        'NOT_FOUND',
                        `No records found for governor in subject scope`,
                    );
                }
                anchorId = getOrCacheAnchor(cacheKey, freshAnchor);
            }

            // Step 2: anchor-bound head query
            // `id <= anchorId` replaces `LIMIT 1` — eliminates head-triple drift within the TTL
            values.push(anchorId);
            const headResult = await dbPool.query<{
                record_id: string;
                created_at: string | Date;
                record_hash: string;
            }>(
                `SELECT record_id, created_at, record_hash
                 FROM policy.action_records
                 WHERE ${clauses.join(' AND ')}
                   AND id <= $${values.length}
                 ORDER BY id DESC
                 LIMIT 1`,
                values,
            );

            // defensive: anchor exists but the head query returns no result (theoretically unreachable; the anchor comes from the same WHERE)
            /* v8 ignore start*/
            if (!headResult.rows[0]) {
                return sendError(
                    res,
                    404,
                    'NOT_FOUND',
                    `No records found for governor in subject scope (anchor=${anchorId})`,
                );
            }
            /* v8 ignore stop*/

            const row = headResult.rows[0];

            // do not emit an unsigned bootstrapToken
            // the token is required to contain a serverSignature (Ed25519); signing implementation is out of scope for now.
            // Until the signing infra is ready, do not send the client a security artifact it cannot verify.
            // The anchor-bound SQL predicate already eliminates the chain-growth oracle by itself.
            // Once a server signing key is wired in, construct and sign the LedgerHeadBootstrapToken here
            // and add it to the response (an optional bootstrapToken field).
            res.status(200).json({
                agentDid: SESSION_GOVERNOR_DID,
                headRecordId: row.record_id,
                headCreatedAt: new Date(row.created_at).toISOString(),
                headRecordHash: row.record_hash,
                // bootstrapToken: suppressed until server signing key available
            });
        } catch (err) {
            next(err);
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// test-only exports (for coverage purposes only, not part of the public API)
// ═══════════════════════════════════════════════════════════════════════════
export {
    makeHandleGet as __testing__makeHandleGet,
    makeHandleVerify as __testing__makeHandleVerify,
    // v0.5: the row-level scope single-point invariant gate
    // Exposed for the property-based conformance fixture (control-plane-scope.property.test.ts).
    // Mandatory constraint: the SQL/handler behavior of all 5 surfaces (list/get/verify/head/chain) must
    // match this function's return value (the property test's reject-face symmetry).
    recordVisibleToScope as __testing__recordVisibleToScope,
    // v0.5: expose the ledger.head + chain.verify handler factories for
    // the 5-surface SQL-predicate symmetry regression matrix (prevents the scope-dropped-field recurrence).
    // The 5-surface matrix does not go through the middleware signature-verification path (decoupled from makeBootstrapHeaders);
    // it directly mocks res.locals + calls the handler to inspect the SQL predicate construction.
    makeHandleSignedLedgerHead as __testing__makeHandleSignedLedgerHead,
    makeHandleChainVerify as __testing__makeHandleChainVerify,
};

// ═══════════════════════════════════════════════════════════════════════════
// Public API: registerActionRecordRoutes
// ═══════════════════════════════════════════════════════════════════════════
export interface RegisterActionRecordRoutesOptions {
    dbPool: DatabasePool;
    identityRegistry: IdentityRegistry;
    /**
     * Ledger public key (hex/base64url, same encoding as record.ledgerSignature).
     * /records/:id/verify and /records/chain/verify need it to truly verify ledger_signature;
     *  T4 makes ledger-signature verification the only technical means to "prevent ledger-service forgery", so it cannot be omitted.
     * Usually passed ActionRecorder.ledgerPublicKey (derived from LEDGER_PRIVATE_KEY at construction).
     */
    ledgerPublicKey: string;
    checker?: AuditAccessChecker;
    /**
     * v0.2 governor lane:
     * the control-plane audit authorization checker. When absent the governor lane automatically fail-closes
     * (403 AUDIT_FORBIDDEN, reason='control-plane lane disabled').
     */
    controlPlaneChecker?: AuditAccessChecker;
    /**
     * v0.2 governor lane:
     * the control-plane DID resolution callback. Injected by the deployer; returning null -> fail-closed (404 IDENTITY_NOT_FOUND).
     */
    controlPlaneResolver?: ControlPlaneAuditResolver;
    /**
     * Step 5:
     * the control-plane public-key resolver. When /records/:id/verify hits the control-plane lane,
     * this callback retrieves the actor public key (a governor DID does not enter federated DID resolution).
     * When absent -> the control-plane lane's verify route fail-closes 403 (signaling that injection is required).
     * The deployer should inject the same ResolveControlPlanePublicKey as IntegrityChecker.
     */
    resolveControlPlanePublicKey?: (did: DID) => Promise<string | null>;
}

export function registerActionRecordRoutes(
    app: Application,
    options: RegisterActionRecordRoutesOptions,
): void {
    const { dbPool, identityRegistry, ledgerPublicKey } = options;
    const identityStore = new RegistryAuditStore(
        identityRegistry,
        options.controlPlaneResolver,
    );
    const checker = options.checker ?? new PrincipalAuditAccessChecker();
    const controlPlaneChecker = options.controlPlaneChecker;
    const recordExistenceGuard = makeRecordExistenceGuard(dbPool);

    // Route registration order is strict: static paths before dynamic paths
    app.get(
        '/records',
        makeAuditMiddleware(
            dbPool,
            identityStore,
            checker,
            'records.list',
            controlPlaneChecker,
        ),
        auditHandler(makeHandleList(dbPool)),
    );

    // records/chain/verify must precede records/:id (prevents Express from parsing "chain" as :id)
    app.get(
        '/records/chain/verify',
        makeAuditMiddleware(
            dbPool,
            identityStore,
            checker,
            'records.chain.verify',
            controlPlaneChecker,
        ),
        auditHandler(makeHandleChainVerify(dbPool)),
    );

    // The getDocumentHistory port is bound to IdentityRegistry so the verify endpoint can resolve the agent
    // publicKey "at the record's creation moment" by record.createdAt (so historical records still verify correctly after rotation).
    const getDocumentHistory: AgentDocumentHistoryReader = (did) =>
        identityRegistry.getDocumentHistory(did);

    // The existence guard stays before auth (the middleware depends on prefetchedRecord)
    // but the guard no longer 404's record-not-found directly — instead it sets a flag + next().
    // After the auth middleware passes verification, the handler returns 404 based on the flag.
    // Effect: an unauthenticated caller gets 401 (auth failure) regardless of whether the record exists, eliminating the existence oracle.
    app.get(
        '/records/:id/verify',
        recordExistenceGuard,
        makeAuditMiddleware(
            dbPool,
            identityStore,
            checker,
            'records.verify',
            controlPlaneChecker,
        ),
        auditHandler(
            makeHandleVerify(
                ledgerPublicKey,
                getDocumentHistory,
                options.resolveControlPlanePublicKey,
            ),
        ),
    );

    app.get(
        '/records/:id',
        recordExistenceGuard,
        makeAuditMiddleware(
            dbPool,
            identityStore,
            checker,
            'records.get',
            controlPlaneChecker,
        ),
        auditHandler(makeHandleGet()),
    );

    // signed /audit/ledger/head:
    // the governor-lane bootstrap endpoint — independent of the /records* middleware, does not require snapshot-boundary
    // headers (the head is its output not its input); uses an Ed25519 signature to authorize the governor to read its own chain head.
    // Must be registered before the unsigned /ledger/head (a non-conflicting path, but it preserves the "signed-first" semantics).
    app.get(
        '/audit/ledger/head',
        makeLedgerHeadAuditMiddleware(identityStore, controlPlaneChecker),
        makeHandleSignedLedgerHead(dbPool),
    );

    // unsigned auxiliary endpoint
    registerLedgerHeadRoute(app, dbPool);
}
