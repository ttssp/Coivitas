/**
 * PostgresSessionStore — PostgreSQL persistence implementation of SessionStore
 *
 * Summary: every mutating operation executes revision = revision + 1 (the basis of the CAS fence).
 * Operations requiring transaction isolation (resume, supersedeAndCreate, cleanExpired) use BEGIN/COMMIT.
 * BIGINT -> string; TIMESTAMPTZ -> ISO string; JSONB -> string[].
 */

import type { Pool, PoolClient } from 'pg';
import { ProtocolError } from '@coivitas/types';
import type {
    Session,
    SessionStore,
    SessionCreateInput,
    SessionUpdatePatch,
    SessionResumeInput,
    SessionCleanResult,
    SessionListActiveFilter,
    CloseReason,
    EncryptionState,
} from './types.js';
import type { DID, Timestamp } from '@coivitas/types';

// ---------------------------------------------------------------------------
// DB row -> Session mapping
// ---------------------------------------------------------------------------

/**
 * Maps a raw row returned by pg into a Session object.
 * Notes:
 * - BIGINT revision is returned as a string by the pg driver (pg@8+); fall back to .toString()
 * - TIMESTAMPTZ is returned as a Date object; call .toISOString()
 * - JSONB negotiated_capabilities may already be parsed into an array by pg, or may still be a string
 */
function rowToSession(row: Record<string, unknown>): Session {
    // Extract a string from unknown: prefer toISOString for Date, and confirm string/number before coercing the rest
    const toIso = (v: unknown): string | null => {
        if (v == null) return null;
        if (v instanceof Date) return v.toISOString();
        if (typeof v === 'string' || typeof v === 'number') return String(v);
        return null;
    };
    const toIsoRequired = (v: unknown): string => {
        if (v instanceof Date) return v.toISOString();
        if (typeof v === 'string' && v.length > 0) return v;
        throw new Error(
            `rowToSession: required timestamp field is missing or invalid: ${String(v)}`,
        );
    };
    const toStr = (v: unknown): string => {
        if (typeof v === 'string' && v.length > 0) return v;
        throw new Error(
            `rowToSession: required string field is missing or invalid: ${String(v)}`,
        );
    };
    const toStrOrNull = (v: unknown): string | null => {
        if (v == null) return null;
        if (typeof v === 'string' || typeof v === 'number') return String(v);
        if (v instanceof Date) return v.toISOString();
        return null;
    };
    const toCaps = (v: unknown): string[] => {
        if (Array.isArray(v)) return v.map(String);
        if (typeof v === 'string') return JSON.parse(v) as string[];
        return [];
    };

    // encryption_state: when absent (old rows that predate migration 004), fall back to 'OFF'
    const encryptionStateRaw = row['encryption_state'];
    const encryptionState: EncryptionState =
        encryptionStateRaw === 'REQUIRED' ? 'REQUIRED' : 'OFF';

    return {
        sessionId: toStr(row['session_id']),
        initiatorDid: toStr(row['initiator_did']) as DID,
        responderDid: toStr(row['responder_did']) as DID,
        principalDid: toStr(row['principal_did']) as DID,
        capabilityTokenId: toStrOrNull(row['capability_token_id']),
        capabilityTokenFingerprint: toStrOrNull(
            row['capability_token_fingerprint'],
        ),
        state: toStr(row['state']) as Session['state'],
        negotiatedCapabilities: toCaps(row['negotiated_capabilities']),
        encryptionState,
        sessionKeyFingerprint: toStrOrNull(row['session_key_fingerprint']),
        rekeyCount: (() => {
            const rc = row['rekey_count'];
            if (typeof rc === 'number') return rc;
            if (typeof rc === 'string') return parseInt(rc, 10) || 0;
            return 0;
        })(),
        establishedAt: toIso(row['established_at']) as Timestamp | null,
        lastSeenAt: toIsoRequired(row['last_seen_at']) as Timestamp,
        lastAuthorizedAt: toIsoRequired(row['last_authorized_at']) as Timestamp,
        idleSince: toIso(row['idle_since']) as Timestamp | null,
        closedAt: toIso(row['closed_at']) as Timestamp | null,
        closeReason: toStrOrNull(row['close_reason']) as CloseReason | null,
        supersedesSessionId: toStrOrNull(row['supersedes_session_id']),
        didPairKey: toStr(row['did_pair_key']),
        createdAt: toIsoRequired(row['created_at']) as Timestamp,
        updatedAt: toIsoRequired(row['updated_at']) as Timestamp,
        // BIGINT is already returned as a string by pg@8+; fall back to toStr
        revision: toStr(row['revision']),
    };
}

// ---------------------------------------------------------------------------
// Diagnostic helper: query the current state to determine the correct error code
// ---------------------------------------------------------------------------

async function diagnoseNotFound(
    client: Pool | PoolClient,
    sessionId: string,
): Promise<never> {
    const res = await client.query<Record<string, unknown>>(
        'SELECT state FROM communication.sessions WHERE session_id = $1',
        [sessionId],
    );
    if (res.rows.length === 0) {
        throw new ProtocolError(
            'SESSION_NOT_FOUND',
            `session ${sessionId} does not exist`,
        );
    }
    const state = String(res.rows[0]!['state']);
    if (state === 'CLOSED') {
        throw new ProtocolError('SESSION_CLOSED', `session ${sessionId} is closed`);
    }
    throw new ProtocolError(
        'SESSION_STATE_INVALID',
        `session ${sessionId} state ${state} does not match expectation`,
    );
}

// ---------------------------------------------------------------------------
// PostgresSessionStore
// ---------------------------------------------------------------------------

export class PostgresSessionStore implements SessionStore {
    constructor(private readonly pool: Pool) {}

    // -----------------------------------------------------------------------
    // create
    // -----------------------------------------------------------------------

    async create(input: SessionCreateInput): Promise<Session> {
        const isActive = input.initialState === 'ACTIVE';
        // established_at: NOW() when ACTIVE, NULL when CREATED
        // Use a CASE expression to avoid passing the literal string 'NOW()' as a parameter

        // Encryption-state consistency check (aligned with chk_sessions_encryption_state_consistency)
        const encState: EncryptionState = input.encryptionState ?? 'OFF';
        if (encState === 'OFF' && input.sessionKeyFingerprint !== undefined) {
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                'sessionKeyFingerprint must not be provided when encryptionState=OFF',
            );
        }
        const fingerprint =
            encState === 'REQUIRED'
                ? (input.sessionKeyFingerprint ?? null)
                : null;

        const res = await this.pool.query<Record<string, unknown>>(
            `INSERT INTO communication.sessions (
                session_id, initiator_did, responder_did, principal_did,
                capability_token_id, capability_token_fingerprint,
                state, negotiated_capabilities,
                encryption_state, session_key_fingerprint, rekey_count,
                established_at, last_seen_at, last_authorized_at,
                supersedes_session_id
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6,
                $7, $8::jsonb,
                $9, $10, 0,
                CASE WHEN $11::boolean THEN NOW() ELSE NULL END,
                NOW(), NOW(),
                $12
            ) RETURNING *`,
            [
                input.sessionId,
                input.initiatorDid,
                input.responderDid,
                input.principalDid,
                input.capabilityTokenId ?? null,
                input.capabilityTokenFingerprint ?? null,
                isActive ? 'ACTIVE' : 'CREATED',
                JSON.stringify(input.negotiatedCapabilities ?? []),
                encState, // $9 encryption_state
                fingerprint, // $10 session_key_fingerprint
                isActive, // $11 boolean -> established_at = NOW() or NULL
                input.supersedesSessionId ?? null,
            ],
        );
        return rowToSession(res.rows[0]!);
    }

    // -----------------------------------------------------------------------
    // get
    // -----------------------------------------------------------------------

    async get(sessionId: string): Promise<Session | null> {
        const res = await this.pool.query<Record<string, unknown>>(
            'SELECT * FROM communication.sessions WHERE session_id = $1',
            [sessionId],
        );
        if (res.rows.length === 0) return null;
        return rowToSession(res.rows[0]!);
    }

    // -----------------------------------------------------------------------
    // update
    // -----------------------------------------------------------------------

    async update(
        sessionId: string,
        patch: SessionUpdatePatch,
    ): Promise<Session> {
        // idle_since may be explicitly set to NULL, so an extra boolean flags whether to write it
        const hasIdleSince = Object.prototype.hasOwnProperty.call(
            patch,
            'idleSince',
        );
        // session_key_fingerprint may also be explicitly set to NULL
        const hasFingerprint = Object.prototype.hasOwnProperty.call(
            patch,
            'sessionKeyFingerprint',
        );

        const res = await this.pool.query<Record<string, unknown>>(
            `UPDATE communication.sessions
             SET state                  = COALESCE($2, state),
                 negotiated_capabilities= COALESCE($3::jsonb, negotiated_capabilities),
                 established_at         = COALESCE($4::timestamptz, established_at),
                 last_seen_at           = COALESCE($5::timestamptz, last_seen_at),
                 last_authorized_at     = COALESCE($6::timestamptz, last_authorized_at),
                 idle_since             = CASE WHEN $7::boolean THEN $8::timestamptz ELSE idle_since END,
                 closed_at              = COALESCE($9::timestamptz, closed_at),
                 close_reason           = COALESCE($10, close_reason),
                 session_key_fingerprint= CASE WHEN $11::boolean THEN $12 ELSE session_key_fingerprint END,
                 rekey_count            = COALESCE($13::integer, rekey_count),
                 updated_at             = NOW(),
                 revision               = revision + 1
             WHERE session_id = $1 AND state <> 'CLOSED'
             RETURNING *`,
            [
                sessionId,
                patch.state ?? null,
                patch.negotiatedCapabilities !== undefined
                    ? JSON.stringify(patch.negotiatedCapabilities)
                    : null,
                patch.establishedAt ?? null,
                patch.lastSeenAt ?? null,
                patch.lastAuthorizedAt ?? null,
                hasIdleSince, // $7 boolean trigger
                patch.idleSince ?? null, // $8 actual value (may be NULL)
                patch.closedAt ?? null,
                patch.closeReason ?? null,
                hasFingerprint, // $11 boolean trigger
                patch.sessionKeyFingerprint ?? null, // $12 actual value (may be NULL)
                patch.rekeyCount ?? null, // $13 rekey_count
            ],
        );

        if (res.rows.length === 0) {
            await diagnoseNotFound(this.pool, sessionId);
        }
        return rowToSession(res.rows[0]!);
    }

    // -----------------------------------------------------------------------
    // resume — perform the IDLE -> ACTIVE transition within a transaction
    // -----------------------------------------------------------------------

    async resume(input: SessionResumeInput): Promise<Session> {
        const client = await this.pool.connect();
        let committed = false;
        try {
            await client.query('BEGIN');

            // Row-level lock: prevent concurrent resume races
            const selRes = await client.query<Record<string, unknown>>(
                'SELECT * FROM communication.sessions WHERE session_id = $1 FOR UPDATE',
                [input.sessionId],
            );
            if (selRes.rows.length === 0) {
                await client.query('ROLLBACK');
                committed = true;
                throw new ProtocolError(
                    'SESSION_NOT_FOUND',
                    `session ${input.sessionId} does not exist`,
                );
            }

            const row = selRes.rows[0]!;
            const state = String(row['state']);

            if (state === 'CLOSED') {
                await client.query('ROLLBACK');
                committed = true;
                throw new ProtocolError('SESSION_CLOSED', 'session is closed');
            }
            if (state !== 'IDLE') {
                await client.query('ROLLBACK');
                committed = true;
                throw new ProtocolError(
                    'SESSION_STATE_INVALID',
                    `resume is only permitted on IDLE sessions, current state: ${state}`,
                );
            }

            // DID validation
            if (
                String(row['initiator_did']) !== input.expectedInitiatorDid ||
                String(row['responder_did']) !== input.expectedResponderDid
            ) {
                await client.query('ROLLBACK');
                committed = true;
                throw new ProtocolError(
                    'SESSION_DID_MISMATCH',
                    'DID tuple does not match',
                );
            }

            // Token binding validation (optional); use rowToSession-mapped values for null-safe comparison
            if (input.expectedCapabilityTokenId !== undefined) {
                const session = rowToSession(row);
                const tokenOk =
                    session.capabilityTokenId ===
                        input.expectedCapabilityTokenId &&
                    session.capabilityTokenFingerprint ===
                        (input.expectedCapabilityTokenFingerprint ?? null);
                if (!tokenOk) {
                    await client.query('ROLLBACK');
                    committed = true;
                    throw new ProtocolError(
                        'SESSION_TOKEN_MISMATCH',
                        'Token binding does not match',
                    );
                }
            }

            // Expiry check
            const nowMs = input.now
                ? new Date(input.now).getTime()
                : Date.now();
            const idleSinceRaw = row['idle_since'];
            if (idleSinceRaw != null) {
                const idleSinceMs =
                    idleSinceRaw instanceof Date
                        ? idleSinceRaw.getTime()
                        : typeof idleSinceRaw === 'string'
                          ? new Date(idleSinceRaw).getTime()
                          : 0;
                if (nowMs - idleSinceMs > input.idleHardMs) {
                    // Mark as CLOSED and commit, then throw
                    const nowTs = new Date(nowMs).toISOString();
                    await client.query(
                        `UPDATE communication.sessions
                         SET state='CLOSED', closed_at=$2::timestamptz, close_reason='IDLE_TIMEOUT',
                             idle_since=NULL, updated_at=$2::timestamptz, revision=revision+1
                         WHERE session_id=$1`,
                        [input.sessionId, nowTs],
                    );
                    await client.query('COMMIT');
                    committed = true;
                    throw new ProtocolError(
                        'SESSION_IDLE_EXPIRED',
                        'IDLE session exceeded the hard timeout',
                    );
                }
            }

            // Restore to ACTIVE
            const existingEstablished = row['established_at'];
            const updRes = await client.query<Record<string, unknown>>(
                `UPDATE communication.sessions
                 SET state='ACTIVE',
                     idle_since=NULL,
                     negotiated_capabilities=$2::jsonb,
                     last_seen_at=NOW(),
                     last_authorized_at=NOW(),
                     established_at=COALESCE($3::timestamptz, established_at),
                     updated_at=NOW(),
                     revision=revision+1
                 WHERE session_id=$1
                 RETURNING *`,
                [
                    input.sessionId,
                    JSON.stringify(input.negotiatedCapabilities),
                    existingEstablished == null
                        ? new Date(nowMs).toISOString()
                        : null,
                ],
            );

            await client.query('COMMIT');
            committed = true;
            return rowToSession(updRes.rows[0]!);
        } catch (err) {
            if (!committed) {
                try {
                    await client.query('ROLLBACK');
                } catch {
                    /* ignore */
                }
            }
            throw err;
        } finally {
            client.release();
        }
    }

    // -----------------------------------------------------------------------
    // supersedeAndCreate — atomically close the old session and create a new one
    // -----------------------------------------------------------------------

    async supersedeAndCreate(params: {
        oldSessionId: string;
        fallbackCloseReason: CloseReason;
        newCreateInput: SessionCreateInput;
        now?: Timestamp;
    }): Promise<Session> {
        const client = await this.pool.connect();
        let committed = false;
        try {
            await client.query('BEGIN');

            const nowTs = params.now ?? new Date().toISOString();

            // Close the old session (skipped if already CLOSED, idempotent)
            await client.query(
                `UPDATE communication.sessions
                 SET state='CLOSED', closed_at=$2::timestamptz, close_reason=$3,
                     idle_since=NULL, updated_at=$2::timestamptz, revision=revision+1
                 WHERE session_id=$1 AND state <> 'CLOSED'`,
                [params.oldSessionId, nowTs, params.fallbackCloseReason],
            );

            // Create the new session
            // Use NOW() (the DB clock), consistent with create(), to avoid passing established_at from the app clock
            const input = {
                ...params.newCreateInput,
                supersedesSessionId: params.oldSessionId,
            };
            const isActive = input.initialState === 'ACTIVE';

            // Encryption-state consistency check (consistent with create())
            const encState: EncryptionState = input.encryptionState ?? 'OFF';
            if (
                encState === 'OFF' &&
                input.sessionKeyFingerprint !== undefined
            ) {
                await client.query('ROLLBACK');
                committed = true;
                throw new ProtocolError(
                    'SESSION_STATE_INVALID',
                    'sessionKeyFingerprint must not be provided when encryptionState=OFF',
                );
            }
            const fingerprint =
                encState === 'REQUIRED'
                    ? (input.sessionKeyFingerprint ?? null)
                    : null;

            const insertRes = await client.query<Record<string, unknown>>(
                `INSERT INTO communication.sessions (
                    session_id, initiator_did, responder_did, principal_did,
                    capability_token_id, capability_token_fingerprint,
                    state, negotiated_capabilities,
                    encryption_state, session_key_fingerprint, rekey_count,
                    established_at, last_seen_at, last_authorized_at,
                    supersedes_session_id
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6,
                    $7, $8::jsonb,
                    $9, $10, 0,
                    CASE WHEN $11::boolean THEN NOW() ELSE NULL END,
                    NOW(), NOW(),
                    $12
                ) RETURNING *`,
                [
                    input.sessionId,
                    input.initiatorDid,
                    input.responderDid,
                    input.principalDid,
                    input.capabilityTokenId ?? null,
                    input.capabilityTokenFingerprint ?? null,
                    isActive ? 'ACTIVE' : 'CREATED',
                    JSON.stringify(input.negotiatedCapabilities ?? []),
                    encState, // $9 encryption_state
                    fingerprint, // $10 session_key_fingerprint
                    isActive, // $11 boolean -> established_at = NOW() or NULL
                    input.supersedesSessionId,
                ],
            );

            await client.query('COMMIT');
            committed = true;
            return rowToSession(insertRes.rows[0]!);
        } catch (err) {
            // Roll back uniformly in the outer catch to avoid confusing state semantics once committed=true
            if (!committed) {
                try {
                    await client.query('ROLLBACK');
                } catch {
                    /* ignore */
                }
            }
            if (
                typeof err === 'object' &&
                err !== null &&
                'code' in err &&
                (err as { code: string }).code === '23505'
            ) {
                throw new ProtocolError(
                    'HANDSHAKE_REJECTED',
                    'an active session already exists for this DID pair',
                );
            }
            throw err;
        } finally {
            client.release();
        }
    }

    // -----------------------------------------------------------------------
    // claimForDispatch — atomic claim (validates DID, token, state)
    // -----------------------------------------------------------------------

    async claimForDispatch(params: {
        sessionId: string;
        senderDid: DID;
        selfDid: DID;
        expectedCapabilityTokenId?: string;
        expectedCapabilityTokenFingerprint?: string;
        now?: Timestamp;
    }): Promise<Session> {
        const res = await this.pool.query<Record<string, unknown>>(
            `UPDATE communication.sessions
             SET last_seen_at = NOW(),
                 updated_at   = NOW(),
                 revision     = revision + 1
             WHERE session_id = $1
               AND state = 'ACTIVE'
               AND (
                   (initiator_did = $2 AND responder_did = $3)
                   OR
                   (responder_did = $2 AND initiator_did = $3)
               )
               AND capability_token_id IS NOT DISTINCT FROM $4
               AND capability_token_fingerprint IS NOT DISTINCT FROM $5
             RETURNING *`,
            [
                params.sessionId,
                params.senderDid,
                params.selfDid,
                params.expectedCapabilityTokenId ?? null,
                params.expectedCapabilityTokenFingerprint ?? null,
            ],
        );

        if (res.rows.length === 0) {
            // Diagnosis: narrow down the error code
            const diagRes = await this.pool.query<Record<string, unknown>>(
                'SELECT * FROM communication.sessions WHERE session_id = $1',
                [params.sessionId],
            );
            if (diagRes.rows.length === 0) {
                throw new ProtocolError(
                    'SESSION_NOT_FOUND',
                    `session ${params.sessionId} does not exist`,
                );
            }
            const row = diagRes.rows[0]!;
            const state = String(row['state']);
            if (state === 'CLOSED') {
                throw new ProtocolError('SESSION_CLOSED', 'session is closed');
            }
            if (state !== 'ACTIVE') {
                throw new ProtocolError(
                    'SESSION_STATE_INVALID',
                    `session state ${state} is not ACTIVE`,
                );
            }
            // DID mismatch
            const didMatch =
                (String(row['initiator_did']) === params.senderDid &&
                    String(row['responder_did']) === params.selfDid) ||
                (String(row['responder_did']) === params.senderDid &&
                    String(row['initiator_did']) === params.selfDid);
            if (!didMatch) {
                throw new ProtocolError(
                    'SESSION_DID_MISMATCH',
                    'DID tuple does not match',
                );
            }
            // Token mismatch
            throw new ProtocolError(
                'SESSION_TOKEN_MISMATCH',
                'Token binding does not match',
            );
        }

        return rowToSession(res.rows[0]!);
    }

    // -----------------------------------------------------------------------
    // markAuthorized — CAS fencing (revision must match exactly)
    // -----------------------------------------------------------------------

    async markAuthorized(params: {
        sessionId: string;
        expectedRevision: string;
        now?: Timestamp;
    }): Promise<Session> {
        const res = await this.pool.query<Record<string, unknown>>(
            `UPDATE communication.sessions
             SET last_authorized_at = NOW(),
                 updated_at         = NOW(),
                 revision           = revision + 1
             WHERE session_id = $1
               AND state = 'ACTIVE'
               AND revision = $2::bigint
             RETURNING *`,
            [params.sessionId, params.expectedRevision],
        );

        if (res.rows.length === 0) {
            // Diagnosis: SESSION_NOT_FOUND / SESSION_CLOSED / SESSION_STATE_INVALID (including CAS failure)
            const diagRes = await this.pool.query<Record<string, unknown>>(
                'SELECT state, revision FROM communication.sessions WHERE session_id = $1',
                [params.sessionId],
            );
            if (diagRes.rows.length === 0) {
                throw new ProtocolError(
                    'SESSION_NOT_FOUND',
                    `session ${params.sessionId} does not exist`,
                );
            }
            const state = String(diagRes.rows[0]!['state']);
            if (state === 'CLOSED') {
                throw new ProtocolError('SESSION_CLOSED', 'session is closed');
            }
            // Wrong state or revision mismatch -> SESSION_STATE_INVALID
            const rawRev = diagRes.rows[0]!['revision'];
            const actualRevision =
                typeof rawRev === 'string' || typeof rawRev === 'number'
                    ? String(rawRev)
                    : '?';
            throw new ProtocolError(
                'SESSION_STATE_INVALID',
                `CAS failure or state not ACTIVE: state=${state}, expectedRevision=${params.expectedRevision}, actual=${actualRevision}`,
            );
        }

        return rowToSession(res.rows[0]!);
    }

    // -----------------------------------------------------------------------
    // closeByToken
    // -----------------------------------------------------------------------

    async closeByToken(params: {
        tokenId: string;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]> {
        const reason = params.reason ?? 'REVOKED_TOKEN';
        const res = await this.pool.query<Record<string, unknown>>(
            `UPDATE communication.sessions
             SET state        = 'CLOSED',
                 closed_at    = NOW(),
                 close_reason = $2,
                 idle_since   = NULL,
                 updated_at   = NOW(),
                 revision     = revision + 1
             WHERE capability_token_id = $1
               AND state IN ('CREATED', 'ACTIVE', 'IDLE')
             RETURNING session_id`,
            [params.tokenId, reason],
        );
        return res.rows.map((r) => String(r['session_id']));
    }

    // -----------------------------------------------------------------------
    // closeByPrincipal
    // -----------------------------------------------------------------------

    async closeByPrincipal(params: {
        principalDid: DID;
        reason?: CloseReason;
        now?: Timestamp;
    }): Promise<string[]> {
        const reason = params.reason ?? 'REVOKED_TOKEN';
        const res = await this.pool.query<Record<string, unknown>>(
            `UPDATE communication.sessions
             SET state        = 'CLOSED',
                 closed_at    = NOW(),
                 close_reason = $2,
                 idle_since   = NULL,
                 updated_at   = NOW(),
                 revision     = revision + 1
             WHERE principal_did = $1
               AND state IN ('CREATED', 'ACTIVE', 'IDLE')
             RETURNING session_id`,
            [params.principalDid, reason],
        );
        return res.rows.map((r) => String(r['session_id']));
    }

    // -----------------------------------------------------------------------
    // listActive
    // -----------------------------------------------------------------------

    async listActive(filter?: SessionListActiveFilter): Promise<Session[]> {
        const states = filter?.states ?? ['ACTIVE'];
        const res = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM communication.sessions
             WHERE state = ANY($1::text[])
               AND ($2::text IS NULL OR initiator_did = $2)
               AND ($3::text IS NULL OR responder_did = $3)
             ORDER BY last_seen_at DESC
             LIMIT $4`,
            [
                states,
                filter?.initiatorDid ?? null,
                filter?.responderDid ?? null,
                filter?.limit ?? 1000,
            ],
        );
        return res.rows.map(rowToSession);
    }

    // -----------------------------------------------------------------------
    // cleanExpired — three-pass cleanup (single transaction)
    // -----------------------------------------------------------------------

    async cleanExpired(params: {
        createdTimeoutMs: number;
        idleSoftMs: number;
        idleHardMs: number;
        now?: Timestamp;
    }): Promise<SessionCleanResult> {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');

            // Pass 1: CREATED -> CLOSED (handshake timeout)
            const r1 = await client.query<Record<string, unknown>>(
                `UPDATE communication.sessions
                 SET state='CLOSED', close_reason='HANDSHAKE_REJECTED',
                     closed_at=NOW(), updated_at=NOW(), revision=revision+1
                 WHERE state='CREATED'
                   AND created_at < NOW() - make_interval(secs => $1::double precision / 1000.0)
                 RETURNING session_id`,
                [params.createdTimeoutMs],
            );

            // Pass 2: ACTIVE -> IDLE (soft timeout)
            const r2 = await client.query<Record<string, unknown>>(
                `UPDATE communication.sessions
                 SET state='IDLE', idle_since=NOW(), updated_at=NOW(), revision=revision+1
                 WHERE state='ACTIVE'
                   AND last_authorized_at < NOW() - make_interval(secs => $1::double precision / 1000.0)
                 RETURNING session_id`,
                [params.idleSoftMs],
            );

            // Pass 3: IDLE -> CLOSED (hard timeout)
            const r3 = await client.query<Record<string, unknown>>(
                `UPDATE communication.sessions
                 SET state='CLOSED', close_reason='IDLE_TIMEOUT',
                     closed_at=NOW(), idle_since=NULL, updated_at=NOW(), revision=revision+1
                 WHERE state='IDLE'
                   AND idle_since < NOW() - make_interval(secs => $1::double precision / 1000.0)
                 RETURNING session_id`,
                [params.idleHardMs],
            );

            await client.query('COMMIT');
            return {
                markedStale: r1.rowCount ?? 0,
                markedIdle: r2.rowCount ?? 0,
                markedClosed: r3.rowCount ?? 0,
            };
        } catch (err) {
            try {
                await client.query('ROLLBACK');
            } catch {
                /* ignore */
            }
            throw err;
        } finally {
            client.release();
        }
    }
}
