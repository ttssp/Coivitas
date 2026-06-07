/**
 * audit-access-routes.ts — audit-access-model v0.2 business-lane middleware factory
 *
 * Scope: business lane only
 *
 * Relationship to action-record-routes.ts:
 *   - action-record-routes.ts: v0.1 middleware + route registration
 *   - this file: v0.2 business-lane auth middleware factory, for deployers to compose
 *     new DI parameters: nonceStore / delegatedKeyResolver / metaLedger
 *
 * Boundary constraints:
 *   - does not touch IntegrityChecker / ActionRecorder constructor parameters
 *   - does not touch governor lane logic (reuses the existing frozen baseline)
 *   - does not modify the registerActionRecordRoutes signature
 */

import { randomUUID } from 'node:crypto';

import type { NextFunction, Request, Response } from 'express';

import { canonicalize, detectEncoding, verify } from '@coivitas/crypto';
import { extractPublicKeyFromDIDKey } from '@coivitas/identity';
import type { DID, Hash, Timestamp } from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';

import type {
    AuditAccessChecker,
    AuditAccessErrorCode,
    AuditIdentityResolution,
    AuditQueryParams,
    AuditResourceBinding,
    AuditSnapshotBoundary,
    IdentityStoreForAudit,
    SignedAuditQuery,
    VerifiedAuditRequest,
} from '../audit/types.js';
import type { AuditMetaLedger, AuditMetaLedgerEvent } from './meta-ledger.js';
import type { AuditNonceStore } from './nonce-store.js';

// Re-export DI-related types so consumers need not import each submodule directly
export type { AuditNonceStore } from './nonce-store.js';
export type { AuditMetaLedger, AuditMetaLedgerEvent } from './meta-ledger.js';
export type { DelegatedAuditKeyResolver } from './delegated-key-resolver.js';

export { InMemoryAuditNonceStore } from './nonce-store.js';
export { NullDelegatedAuditKeyResolver } from './delegated-key-resolver.js';
export { NullAuditMetaLedger } from './meta-ledger.js';

// ── UUID v4 regex (kept consistent with action-record-routes.ts) ────────────────────
const UUID_V4_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── strict ISO 8601 validation (UTC millisecond precision, kept consistent with action-record-routes.ts) ──
const ISO_8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
function isValidIso8601(value: string): boolean {
    if (!ISO_8601_RE.test(value)) return false;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return false;
    return d.toISOString() === value;
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

// ── allowed proofType values (currently the only legal value) ────────────────────────────────────
const VALID_PROOF_TYPES = new Set(['Ed25519Signature2020']);

// ── AuditAccessErrorCode -> HTTP status code mapping ───────────────────────────────
function auditErrorToStatus(code: AuditAccessErrorCode): number {
    switch (code) {
        case 'AUDIT_FORBIDDEN':
            return 403;
        case 'AUDIT_QUERY_MALFORMED':
        case 'AUDIT_RESOURCE_BINDING_MISMATCH':
        case 'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED':
            return 400;
        case 'AUDIT_SIGNATURE_INVALID':
        case 'AUDIT_TIMESTAMP_SKEW':
        case 'AUDIT_REQUESTER_UNKNOWN':
        case 'AUDIT_IDENTITY_UNVERIFIED':
        case 'AUDIT_NONCE_REPLAY':
            return 401;
        default:
            return 500;
    }
}

// ── abstraction for makeAuditV2Middleware to read actionRecordReader (DB-free DI) ──
/**
 * Snapshot anchor query result interface.
 * Decouples the DB layer and allows tests to inject a mock.
 */
export interface SnapshotAnchorResult {
    /** The row's BIGSERIAL internal ID (string, to avoid JS Number precision loss)*/
    internalId: string;
    /** The record_hash stored in the DB*/
    recordHash: string;
    /** The created_at stored in the DB (ISO 8601)*/
    createdAt: string;
}

/**
 * agent identity resolution result (wrapped) — the verified audit identity.
 */
export interface ActionRecordReader {
    /**
     * Query the snapshot anchor by the headCreatedAt + headRecordId + targetAgentDid triple.
     * Returns null = the anchor does not exist or does not belong to the target agent.
     */
    findSnapshotAnchor(
        headRecordId: string,
        targetAgentDid: string,
        headCreatedAt: string,
    ): Promise<SnapshotAnchorResult | null>;
}

// ── DelegatedAuditKeyResolver interface (imported from types, re-exported here for test convenience) ──
import type { DelegatedAuditKeyResolver } from './delegated-key-resolver.js';

/**
 * createAuditAccessMiddleware factory options (v0.2 DI wiring)
 *
 */
export interface AuditAccessMiddlewareOptions {
    /** business-lane authorization checker (defaults to PrincipalAuditAccessChecker)*/
    checker: AuditAccessChecker;
    /** identity store (business lane uses resolveForAudit)*/
    identityStore: IdentityStoreForAudit;
    /** clock injection (for tests; defaults to Date.now)*/
    clock?: () => number;
    /** snapshot anchor query (abstracts the DB layer)*/
    actionRecordReader: ActionRecordReader;
    /** v0.2 nonce store (defaults to InMemoryAuditNonceStore)*/
    nonceStore: AuditNonceStore;
    /** v0.2 delegated audit key resolver (defaults to NullDelegatedAuditKeyResolver)*/
    delegatedKeyResolver: DelegatedAuditKeyResolver;
    /** v0.2 meta-ledger writer (defaults to NullAuditMetaLedger)*/
    metaLedger: AuditMetaLedger;
}

/**
 * Create the v0.2 audit access middleware (business lane only).
 *
 * Implements the 14 audit-access steps + the v0.2 incremental steps:
 *   - Step 1: assert required headers (v0.2 adds X-Audit-Nonce)
 *   - Step 6.5: nonce replay check (added in v0.2)
 *   - Step 7: signaturePayload includes v0.2 fields (only participate in canonicalize when defined)
 *   - Step 9: delegatedAuditKeyId delegated-public-key path
 *
 * v0.1 compatibility matrix:
 *   - v0.1 client (missing X-Audit-Nonce and X-Audit-Proof-Type): downgrade mode, functionally equivalent to v0.1
 *   - v0.2 client (X-Audit-Nonce or X-Audit-Proof-Type present): full v0.2 security guarantees
 *
 * Boundary: business lane only; governor lane / IntegrityChecker / ActionRecorder are not involved.
 *
 * @param routeName the AuditResourceBinding route name this middleware corresponds to
 * @param options v0.2 DI wiring options
 * @returns Express middleware
 *
 */
export function createAuditAccessMiddleware(
    routeName: AuditResourceBinding['route'],
    options: AuditAccessMiddlewareOptions,
) {
    const {
        checker,
        identityStore,
        clock = Date.now,
        actionRecordReader,
        nonceStore,
        delegatedKeyResolver,
        metaLedger,
    } = options;

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // ── Step 1: assert required headers + duplicate detection ────────────────────────
            // Node concatenates multiple occurrences of a custom header into an "a, b" string by default;
            // headersDistinct (Node 18.3+) returns string[] by occurrence count, allowing strict duplicate detection.
            const distinct = req.headersDistinct;

            // v0.2 new headers (including X-Audit-Nonce)
            const allAuditHeaders = [
                'x-audit-requester',
                'x-audit-signature',
                'x-audit-timestamp',
                'x-audit-snapshot-headcreatedat',
                'x-audit-snapshot-headrecordid',
                'x-audit-snapshot-headrecordhash',
                'x-audit-nonce',
                'x-audit-proof-type',
                'x-audit-delegated-key-id',
            ] as const;

            for (const name of allAuditHeaders) {
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
            const nonceHeader = req.headers['x-audit-nonce'];
            const proofTypeHeader = req.headers['x-audit-proof-type'];
            const delegatedKeyIdHeader =
                req.headers['x-audit-delegated-key-id'];

            // v0.2 client detection:
            // v0.2 = X-Audit-Nonce present OR X-Audit-Proof-Type present
            // v0.1 = both missing
            const isV2Client =
                nonceHeader !== undefined || proofTypeHeader !== undefined;

            // fail-closed when v0.2 indicators present without nonce
            // Rule (v0.2 requires nonce):
            // if any v0.2-only header (X-Audit-Proof-Type / X-Audit-Delegated-Key-Id) is present
            // but X-Audit-Nonce is missing, it must reject 400 AUDIT_QUERY_MALFORMED.
            // Before the fix: a missing nonce was still marked v0.2, silently skipping the AUDIT_NONCE_REPLAY
            // check -> a partially upgraded client appears to use v0.2 but actually loses replay protection
            if (
                nonceHeader === undefined &&
                (proofTypeHeader !== undefined ||
                    delegatedKeyIdHeader !== undefined)
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'X-Audit-Nonce is required when v0.2 headers (X-Audit-Proof-Type / X-Audit-Delegated-Key-Id) are present',
                );
            }

            // required headers (all client versions)
            if (!requesterDid || !signatureHex || !timestampStr) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'Missing required X-Audit-* headers (requester/signature/timestamp)',
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

            // the ledger.head route does not need snapshot headers; other routes do
            const needsSnapshotHeaders = routeName !== 'ledger.head';

            // snapshot headers (conditionally required)
            const headCreatedAtHeader =
                req.headers['x-audit-snapshot-headcreatedat'];
            const headRecordIdHeader =
                req.headers['x-audit-snapshot-headrecordid'];
            const headRecordHashHeader =
                req.headers['x-audit-snapshot-headrecordhash'];

            if (needsSnapshotHeaders) {
                if (!headCreatedAtHeader || !headRecordIdHeader) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'Missing required X-Audit-Snapshot-Head* headers',
                    );
                }
            }

            // type narrowing
            const headCreatedAt =
                typeof headCreatedAtHeader === 'string'
                    ? headCreatedAtHeader
                    : undefined;
            const headRecordId =
                typeof headRecordIdHeader === 'string'
                    ? headRecordIdHeader
                    : undefined;
            const headRecordHash =
                typeof headRecordHashHeader === 'string'
                    ? headRecordHashHeader
                    : undefined;

            // ── Step 1.5: timestamp format validation ───────────────────────────────────
            // Attacker-controlled fields must be strictly validated before entering Date comparison (to prevent bypassing the replay window)
            if (!isValidIso8601(timestampStr)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'X-Audit-Timestamp must be ISO 8601 UTC with milliseconds',
                );
            }
            if (headCreatedAt && !isValidIso8601(headCreatedAt)) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'X-Audit-Snapshot-HeadCreatedAt must be ISO 8601 UTC with milliseconds',
                );
            }

            // ── Step 2: rebuild resourceBinding ───────────────────────────────
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
                              | 'records.chain.verify'
                              | 'ledger.head',
                          recordId: null,
                      };

            // ── Step 3: extract targetAgentDid ────────────────────────────────
            // business lane: extracted from the query param (the route handler processes the record query after the middleware)
            const agentDidRaw = req.query['agent_did'];
            if (!agentDidRaw || typeof agentDidRaw !== 'string') {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'agent_did query parameter required',
                );
            }
            if (
                !agentDidRaw.startsWith('did:agent:') &&
                !agentDidRaw.startsWith('did:key:')
            ) {
                return sendError(
                    res,
                    400,
                    'AUDIT_QUERY_MALFORMED',
                    'agent_did must start with did:agent:',
                );
            }
            const targetAgentDid = agentDidRaw as DID;

            // ── Step 4: normalize queryParams ─────────────────────────────────
            // Extract the minimal queryParams here (business fields are parsed by the route handler)
            const queryParams: AuditQueryParams = {};
            const rawQuery = req.query as Record<string, unknown>;

            // Build the base queryParams from the query string (kept consistent with action-record-routes)
            if (typeof rawQuery['principal_did'] === 'string') {
                queryParams.principalDid = rawQuery['principal_did'] as DID;
            }
            if (typeof rawQuery['agent_did'] === 'string') {
                queryParams.agentDid = rawQuery['agent_did'] as DID;
            }
            if (typeof rawQuery['session_id'] === 'string') {
                queryParams.sessionId = rawQuery['session_id'];
            }
            if (typeof rawQuery['action'] === 'string') {
                queryParams.action = rawQuery[
                    'action'
                ] as import('../audit/types.js').ActionVocabulary;
            }
            if (
                typeof rawQuery['start'] === 'string' &&
                isValidIso8601(rawQuery['start'])
            ) {
                queryParams.start = rawQuery['start'] as Timestamp;
            }
            if (
                typeof rawQuery['end'] === 'string' &&
                isValidIso8601(rawQuery['end'])
            ) {
                queryParams.end = rawQuery['end'] as Timestamp;
            }
            if (rawQuery['limit'] !== undefined) {
                const n = Number(rawQuery['limit']);
                if (Number.isInteger(n) && n >= 1 && n <= 500) {
                    queryParams.limit = n;
                }
            }
            if (typeof rawQuery['cursor'] === 'string') {
                queryParams.cursor = rawQuery['cursor'];
            }

            // ── Step 5 & 6: snapshot boundary query (non-ledger.head routes) ────────
            let snapshotBoundary: AuditSnapshotBoundary | undefined;
            let snapshotMaxId: bigint | undefined;

            if (needsSnapshotHeaders && headRecordId && headCreatedAt) {
                if (!UUID_V4_RE.test(headRecordId)) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                        'headRecordId must be UUID v4',
                    );
                }

                const anchor = await actionRecordReader.findSnapshotAnchor(
                    headRecordId,
                    targetAgentDid,
                    headCreatedAt,
                );

                if (!anchor) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                        'Snapshot anchor not found or does not belong to target agent',
                    );
                }

                // headRecordHash consistency check (when the optional header is present)
                if (headRecordHash && headRecordHash !== anchor.recordHash) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED',
                        'headRecordHash does not match stored record_hash',
                    );
                }

                snapshotMaxId = BigInt(anchor.internalId);

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

                snapshotBoundary = {
                    headCreatedAt: headCreatedAt as Timestamp,
                    headRecordId,
                    ...(headRecordHash
                        ? { headRecordHash: headRecordHash as Hash }
                        : {}),
                };
            }

            // ── Step 6.5: v0.2 nonce format validation (v0.2 clients only) ──────────────

            // The original implementation placed the nonce's checkAndStore before signature/timestamp
            // verification -> an unauthenticated caller could consume valid UUIDs to trigger AUDIT_NONCE_REPLAY
            // and block real legitimate requests for the TTL duration -> a pre-auth DoS surface.

            // Order after the fix:
            // Step 6.5 (this block): format validation only (UUID v4), does not call checkAndStore
            // Step 8: timestamp skew
            // Step 10: signature verify
            // Step 10.1 (added): checkAndStore (consume the nonce) only after verification passes

            // Step 6.5:
            // If a nonce is present:
            // 1. format validation: UUID v4 -> failure 400 AUDIT_QUERY_MALFORMED (keeps the early fail-fast)
            // If no nonce is present (v0.1 client): skip
            let nonce: string | undefined;
            if (nonceHeader !== undefined) {
                if (typeof nonceHeader !== 'string') {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'X-Audit-Nonce must be a string',
                    );
                }
                if (!UUID_V4_RE.test(nonceHeader)) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'X-Audit-Nonce must be UUID v4',
                    );
                }
                nonce = nonceHeader;
            }

            // ── proofType parsing ───────────────────────────────────────────────
            let proofType: 'Ed25519Signature2020' | undefined;
            if (proofTypeHeader !== undefined) {
                if (
                    typeof proofTypeHeader !== 'string' ||
                    !VALID_PROOF_TYPES.has(proofTypeHeader)
                ) {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        `X-Audit-Proof-Type must be one of: ${[...VALID_PROOF_TYPES].join(', ')}`,
                    );
                }
                proofType = proofTypeHeader as 'Ed25519Signature2020';
            }

            // ── delegatedAuditKeyId parsing ─────────────────────────────────────
            let delegatedAuditKeyId: string | null | undefined;
            if (delegatedKeyIdHeader !== undefined) {
                if (typeof delegatedKeyIdHeader !== 'string') {
                    return sendError(
                        res,
                        400,
                        'AUDIT_QUERY_MALFORMED',
                        'X-Audit-Delegated-Key-Id must be a string',
                    );
                }
                delegatedAuditKeyId = delegatedKeyIdHeader || null;
            }

            // ── Step 7: build signaturePayload (v0.2 extension) ──────────────────
            // v0.2 new fields participate in canonicalize only when defined
            // Backward-compatibility invariant: a v0.1 client's undefined fields do not participate -> the signature result is equivalent to the v0.1 server
            const signaturePayload: Record<string, unknown> = {
                requesterDid: requesterDid as DID,
                targetAgentDid,
                httpMethod: 'GET' as const,
                resourceBinding,
                queryParams,
                timestamp: timestampStr as Timestamp,
            };

            // snapshotBoundary: present only when route !== 'ledger.head'
            if (snapshotBoundary !== undefined) {
                signaturePayload['snapshotBoundary'] = snapshotBoundary;
            }

            // v0.2 new fields: participate only when defined
            if (nonce !== undefined) {
                signaturePayload['nonce'] = nonce;
            }
            if (proofType !== undefined) {
                signaturePayload['proofType'] = proofType;
            }
            if (delegatedAuditKeyId !== undefined) {
                signaturePayload['delegatedAuditKeyId'] = delegatedAuditKeyId;
            }

            // ── Step 8: timestamp window ±300s ───────────────────────────────────
            const skewMs = Math.abs(clock() - new Date(timestampStr).getTime());
            if (skewMs > 300_000) {
                return sendError(
                    res,
                    401,
                    'AUDIT_TIMESTAMP_SKEW',
                    'Request timestamp outside ±300s window',
                );
            }

            // ── Step 9: public-key resolution (v0.2 extension: delegatedAuditKeyId path) ────
            // Step 9:
            // If delegatedAuditKeyId is non-null:
            // 1. delegatedKey = await delegatedAuditKeyResolver.resolve(keyId, targetAgentDid)
            // 2. delegatedKey === null -> 401 AUDIT_REQUESTER_UNKNOWN
            // 3. publicKey = decodeDidKey(delegatedKey.delegatedTo)
            // 4. verify delegatedKey.principalDid === query.requesterDid
            // Otherwise: publicKey = decodeDidKey(query.requesterDid) (v0.1 behavior unchanged)
            let publicKeyHex: string;
            if (
                delegatedAuditKeyId !== undefined &&
                delegatedAuditKeyId !== null
            ) {
                // delegated-key path
                const delegatedKey = await delegatedKeyResolver.resolve(
                    delegatedAuditKeyId,
                    targetAgentDid,
                );
                if (!delegatedKey) {
                    return sendError(
                        res,
                        401,
                        'AUDIT_REQUESTER_UNKNOWN',
                        'Delegated audit key not found, expired, or invalid',
                    );
                }
                // verify delegated-key ownership: principalDid must match requesterDid
                if (delegatedKey.principalDid !== requesterDid) {
                    return sendError(
                        res,
                        401,
                        'AUDIT_REQUESTER_UNKNOWN',
                        'Delegated audit key principal does not match requesterDid',
                    );
                }
                try {
                    publicKeyHex = extractPublicKeyFromDIDKey(
                        delegatedKey.delegatedTo,
                    );
                } catch {
                    return sendError(
                        res,
                        401,
                        'AUDIT_REQUESTER_UNKNOWN',
                        'Cannot decode delegated audit key public key',
                    );
                }
            } else {
                // v0.1 path: use the requesterDid public key
                try {
                    publicKeyHex = extractPublicKeyFromDIDKey(
                        requesterDid as DID,
                    );
                } catch {
                    return sendError(
                        res,
                        401,
                        'AUDIT_REQUESTER_UNKNOWN',
                        'Cannot decode requesterDid public key',
                    );
                }
            }

            // ── Step 10: Ed25519 signature verification ───────────────────────────────────────
            const canonical = canonicalize(signaturePayload);
            const msgBytes = new TextEncoder().encode(canonical);

            // signature format auto-detection (hex or base64url, compatible with both formats during the encoding transition)
            let sigBytes: string = signatureHex;
            try {
                const enc = detectEncoding(signatureHex);
                if (enc === 'base64url') {
                    // base64url -> hex conversion
                    const buf = Buffer.from(signatureHex, 'base64url');
                    sigBytes = buf.toString('hex');
                }
            } catch {
                // detectEncoding threw -> keep the original value and let verify handle it
            }

            const sigValid = verify(msgBytes, sigBytes, publicKeyHex);
            if (!sigValid) {
                return sendError(
                    res,
                    401,
                    'AUDIT_SIGNATURE_INVALID',
                    'Signature verification failed',
                );
            }

            // ── Step 10.1: nonce consumption ─────────

            // At this point timestamp + signature have all passed verification, so checkAndStore is safe:
            // - only an authenticated caller can make a nonce hit rollingNonceSet
            // - eliminates the pre-auth DoS surface (an unauthenticated UUID no longer consumes a nonce slot)

            // Step 10.1:
            // If a nonce is present (has passed Step 6.5 format validation + Step 10 signature verification):
            // 2. replay check: nonce in rollingNonceSet -> failure 401 AUDIT_NONCE_REPLAY
            // 3. store: rollingNonceSet.add(nonce, TTL=300s)
            if (nonce !== undefined) {
                const isReplay = await nonceStore.checkAndStore(nonce);
                if (isReplay) {
                    return sendError(
                        res,
                        401,
                        'AUDIT_NONCE_REPLAY',
                        `nonce ${nonce} has been used within replay window`,
                    );
                }
            }

            // ── Step 11: identity resolution (business lane only) ──────────────────────
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

            // ── Step 12: construct VerifiedAuditRequest + mount res.locals ────────
            const signedQuery: SignedAuditQuery = {
                requesterDid: requesterDid as DID,
                targetAgentDid,
                httpMethod: 'GET' as const,
                resourceBinding,
                queryParams,
                ...(snapshotBoundary !== undefined ? { snapshotBoundary } : {}),
                timestamp: timestampStr as Timestamp,
                signature:
                    signatureHex as import('@coivitas/types').Signature,
                ...(nonce !== undefined ? { nonce } : {}),
                ...(proofType !== undefined ? { proofType } : {}),
                ...(delegatedAuditKeyId !== undefined
                    ? { delegatedAuditKeyId }
                    : {}),
            };

            const verifiedAudit: VerifiedAuditRequest = {
                lane: 'business',
                query: signedQuery,
                resolvedIdentity: resolution.document,
                identityStatus: resolution.status,
                verifiedAt: resolution.verifiedAt,
            };

            res.locals['verifiedAudit'] = verifiedAudit;
            if (snapshotMaxId !== undefined) {
                res.locals['snapshotMaxId'] = snapshotMaxId;
            }

            // ── Step 13: AuditAccessChecker.check ───────────────────────────
            const decision = await checker.check(verifiedAudit);
            if (!decision.allowed) {
                const statusCode = auditErrorToStatus(decision.code);
                // meta-ledger: record the denied event (defaults to NullAuditMetaLedger no-op)
                await metaLedger.recordEvent({
                    requesterDid,
                    targetAgentDid,
                    route: resourceBinding.route,
                    decision: 'denied',
                    errorCode: decision.code,
                    timestamp: timestampStr,
                    ...(nonce !== undefined ? { nonce } : {}),
                } satisfies AuditMetaLedgerEvent);
                return sendError(
                    res,
                    statusCode,
                    decision.code,
                    decision.reason,
                );
            }

            // meta-ledger: record the allowed event (defaults to NullAuditMetaLedger no-op)
            await metaLedger.recordEvent({
                requesterDid,
                targetAgentDid,
                route: resourceBinding.route,
                decision: 'allowed',
                timestamp: timestampStr,
                ...(nonce !== undefined ? { nonce } : {}),
            } satisfies AuditMetaLedgerEvent);

            // v0.1 downgrade-mode log marker
            if (!isV2Client) {
                res.locals['auditClientVersion'] = 'v0.1-compat';
            } else {
                res.locals['auditClientVersion'] = 'v0.2';
            }

            // ── Step 14: next() ──────────────────────────────────────────────
            next();
        } catch (err) {
            next(err);
        }
    };
}
