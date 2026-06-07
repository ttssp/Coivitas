/**
 * encryption-meta-session — encryption session-dimension aggregation (Approach C side data)
 *
 * Design points (Approach C):
 *   - Encryption metadata is carried via the encryption_state field of the session-persistence table
 *   - No new fields are added to ActionRecord (no pollution of the hash chain)
 *   - No changes to IntegrityChecker / ActionRecorder constructor parameters
 *   - No calls to ControlPlaneAuditAccessChecker / governor lane routing (firewall)
 *
 * Architecture constraints (L3 must not import L4):
 *   - Injected via the EncryptionSessionMetaStore interface, with the communication-layer implementation provided by the L5 SDK
 *   - L3 defines equivalent types internally (not imported from @coivitas/communication)
 *
 * Carrier location: the encryption_state field of the session-persistence table (already
 *   implemented by communication/sql/004-add-encryption-state.sql; this file provides the L3 query aggregation layer).
 */

// ─────────────────────────────────────────────────────────────────────────────
// Type definitions (semantically equivalent to EncryptionState in communication/src/session/types.ts,
// but L3 does not pull in an L4 dependency, so they are declared independently here)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Session-level encryption state (aligned with the communication.sessions.encryption_state DB enum)
 *
 * OFF = E2E encryption not enabled (legacy semantics or a non-encrypted handshake negotiation result)
 * REQUIRED = E2E-encrypted session (handshake negotiation result REQUIRED; see the E2E encryption spec)
 */
export type SessionEncryptionState = 'OFF' | 'REQUIRED';

/**
 * Encryption session-dimension aggregation record
 *
 * Returned by EncryptionSessionMetaStore.getBySessionId();
 * may be attached to an audit query response; does not enter the ActionRecord hash chain.
 */
export interface EncryptionSessionMeta {
    /** Unique session identifier */
    sessionId: string;
    /** Encryption state */
    encryptionState: SessionEncryptionState;
    /** Current-generation session key fingerprint (64-char hex); null when OFF */
    sessionKeyFingerprint: string | null;
    /** Cumulative in-place re-handshake count; 0 when OFF */
    rekeyCount: number;
}

/**
 * Encryption-dimension aggregation result (per-DID-pair level)
 *
 * Summarizes the encryption distribution across all sessions between a given DID pair:
 *   - encryptedCount: number of sessions with encryptionState='REQUIRED'
 *   - totalCount: total number of sessions
 *   - encryptedRatio: encryption ratio (0.0 ~ 1.0)
 */
export interface EncryptionSessionAggregation {
    initiatorDid: string;
    responderDid: string;
    encryptedCount: number;
    totalCount: number;
    encryptedRatio: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Store interface (defined on the L3 side; the L5 SDK injects the implementation; typically delegates to SessionStore.listActive)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Session encryption metadata store interface used by the L3 policy layer.
 *
 * Injection point: at the L5/SDK layer the deployer adapts the communication package's SessionStore to this interface,
 * then injects it into EncryptionSessionMetaService.
 *
 * Implementation: InMemoryEncryptionSessionMetaStore (for tests) or
 * delegating to PostgresSessionStore (injected via an adapter).
 */
export interface EncryptionSessionMetaStore {
    /**
     * Query a single encryption metadata record by sessionId.
     *
     * @returns the meta record; null if the session does not exist
     */
    getBySessionId(sessionId: string): Promise<EncryptionSessionMeta | null>;

    /**
     * Query the list of encryption metadata for all sessions between a given DID pair.
     *
     * @param initiatorDid initiator DID
     * @param responderDid responder DID
     * @returns the metadata list sorted ascending by session creation time
     */
    listByDidPair(
        initiatorDid: string,
        responderDid: string,
    ): Promise<EncryptionSessionMeta[]>;
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemory test implementation (replaced by a PostgresSessionStore adapter in production)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * InMemoryEncryptionSessionMetaStore — in-memory implementation for test/development environments.
 *
 * Production deployments should inject PostgresEncryptionSessionMetaStoreAdapter (delegating to postgres-store.ts).
 * The Postgres adapter is not yet implemented (the InMemory test implementation already covers the acceptance criteria).
 */
export class InMemoryEncryptionSessionMetaStore
    implements EncryptionSessionMetaStore
{
    /** key: sessionId */
    private readonly records = new Map<string, EncryptionSessionMeta>();

    /**
     * Write or update a single session encryption metadata record (test helper method; in the production layer the communication package writes it)
     */
    public upsert(meta: EncryptionSessionMeta): void {
        this.records.set(meta.sessionId, { ...meta });
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    public async getBySessionId(
        sessionId: string,
    ): Promise<EncryptionSessionMeta | null> {
        return this.records.get(sessionId) ?? null;
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    public async listByDidPair(
        initiatorDid: string,
        responderDid: string,
    ): Promise<EncryptionSessionMeta[]> {
        return [...this.records.values()].filter(
            (m) => m.sessionId.startsWith(`${initiatorDid}:${responderDid}:`),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service layer
// ─────────────────────────────────────────────────────────────────────────────

/**
 * EncryptionSessionMetaService — encryption session-dimension aggregation service (Approach C implementation)
 *
 * Responsibilities:
 *   1. Query encryption metadata by sessionId (attached to an audit query response)
 *   2. Aggregate the encryption distribution by DID pair (audit monitoring dashboard / audit report)
 *   3. Determine whether a given session is an encrypted session
 *
 * Firewall constraints:
 *   - No ControlPlaneAuditAccessChecker calls
 *   - No governor lane routing
 *   - No extension of IntegrityChecker / ActionRecorder constructor parameters
 *   - No new ActionRecord fields (no change to the hash chain)
 */
export class EncryptionSessionMetaService {
    constructor(private readonly store: EncryptionSessionMetaStore) {}

    /**
     * Query the encryption metadata of a single session.
     *
     * Purpose: attach the encryption state to an audit query response (the combined Approach B + C scenario).
     *
     * @returns the metadata; null if the session does not exist or the data source has no record
     */
    public async getSessionMeta(
        sessionId: string,
    ): Promise<EncryptionSessionMeta | null> {
        return this.store.getBySessionId(sessionId);
    }

    /**
     * Determine whether a given session is an E2E-encrypted session.
     *
     * @returns true = encryptionState='REQUIRED'; false = 'OFF' or the session does not exist
     */
    public async isEncryptedSession(sessionId: string): Promise<boolean> {
        const meta = await this.store.getBySessionId(sessionId);
        return meta?.encryptionState === 'REQUIRED';
    }

    /**
     * Aggregate the encryption distribution by DID pair (the main logic of Approach C session-dimension aggregation).
     *
     * Computes, across all sessions between initiatorDid ↔ responderDid:
     *   - encrypted session count / total count / ratio
     *
     * @param initiatorDid initiator DID
     * @param responderDid responder DID
     * @returns the aggregation result; encryptedRatio=0 when totalCount=0
     */
    public async aggregateByDidPair(
        initiatorDid: string,
        responderDid: string,
    ): Promise<EncryptionSessionAggregation> {
        const sessions = await this.store.listByDidPair(
            initiatorDid,
            responderDid,
        );

        const totalCount = sessions.length;
        const encryptedCount = sessions.filter(
            (s) => s.encryptionState === 'REQUIRED',
        ).length;

        return {
            initiatorDid,
            responderDid,
            encryptedCount,
            totalCount,
            encryptedRatio: totalCount === 0 ? 0 : encryptedCount / totalCount,
        };
    }
}
