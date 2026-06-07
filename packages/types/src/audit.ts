// Audit query access model types (L3).
// Fully independent of the RuntimeGuard CapabilityToken authorization chain (read vs write authorization are orthogonal).
// v0.2 governor lane strict restriction: requesterDid is still did:key only; in audit the governor acts as the target, not the requester.

// Field names/types are frozen.
// v0.2 new fields: nonce / proofType / delegatedAuditKeyId
// v0.2 new types: AuditProofType / DelegatedAuditKey / DelegatedAuditKeyResolver /
// AuditAccessV02Header / AuditEventRecord

import { ACTION_VOCABULARY } from './base.js';
import type { DID, Hash, Signature, Timestamp } from './base.js';
import type { AgentIdentityDocument } from './identity.js';

// ActionVocabulary: synced from a single source in base.ts (including the v0.3.0 new SESSION_SUPERSEDED).
// Historically this file hard-coded a 5-member union; it was later switched to a single-source import to avoid dual sources of truth.
export type ActionVocabulary = (typeof ACTION_VOCABULARY)[number];

// Audit query parameters (read filters, aligned with the HTTP query string fields).
// v0.2 revision:
// Added the affectedAgentDid / affectedPrincipalDid filter fields — used for the governor lane's
// per-requester subject scope check. The dispatcher requires targetAgentDid === governor
// to enter the control-plane lane; the old target-bound scope degenerated into a flat allow-list;
// the new design uses the affected* fields of the SESSION_SUPERSEDED immutable payload (already
// required fields of sessionSupersededParams) for the scope check + SQL predicate.
export interface AuditQueryParams {
    agentDid?: DID;
    principalDid?: DID;
    action?: ActionVocabulary;
    sessionId?: string;
    start?: Timestamp;
    end?: Timestamp;
    limit?: number;
    cursor?: string;
    /** v0.2: governor lane subject scope filter field*/
    affectedAgentDid?: DID;
    /** v0.2: governor lane subject scope filter field*/
    affectedPrincipalDid?: DID;
}

// Resource binding: binds the signature to a specific HTTP resource, preventing cross-endpoint/cross-record replay.
// Added 'ledger.head' clause:
// for governor lane bootstrap — does not require the X-Audit-Snapshot-Head* headers
// (head is its output, not its input), authorizing via an Ed25519 signature over requesterDid + targetAgentDid +
// timestamp. Fix point: after governor /ledger/head was changed to 403 there was no head
// discovery path → the audit middleware enforcing the snapshot boundary formed a bootstrap deadlock.
export type AuditResourceBinding =
    | { route: 'records.list'; recordId: null }
    | { route: 'records.get'; recordId: string }
    | { route: 'records.verify'; recordId: string }
    | { route: 'records.chain.verify'; recordId: null }
    | { route: 'ledger.head'; recordId: null };

// Snapshot boundary: anchors a specific position in an agent's chain using a (created_at, record_id) tuple.
export interface AuditSnapshotBoundary {
    headCreatedAt: Timestamp;
    headRecordId: string;
    headRecordHash?: Hash;
}

// SignedAuditQuery — a signature-verified audit query (v0.2 extension: +3 optional fields).
// GET only; resourceBinding is rebuilt by the server from the actual HTTP request and participates in signature verification.
// snapshotBoundary changed to optional —
// - when resourceBinding.route ∈ {'records.list','records.get','records.verify','records.chain.verify'},
//   snapshotBoundary must be present (the middleware enforces the X-Audit-Snapshot-Head* headers)
// - when resourceBinding.route === 'ledger.head', snapshotBoundary must be absent
//   (head is the output of the ledger.head endpoint, not its input; this is the governor lane bootstrap fix)
// The schema enforces this conditional branch with if/then; TypeScript guarantees it jointly with optional fields + runtime
// per-route validation.

// v0.2 new fields:
// - nonce: UUID v4, eliminates stateful replay within the window
// - proofType: signature algorithm identifier (sole valid value 'Ed25519Signature2020')
// - delegatedAuditKeyId: delegated audit key ID
// v0.1 compatibility: all three fields are optional; when undefined they are handled with v0.1 semantics.
// v0.2 signature payload: undefined fields do not participate in canonicalize (backward compatible).
/**
 * @breaking no (v0.1 compatible: the three new fields are optional)
 */
export interface SignedAuditQuery {
    // --- v0.1 inherited fields (8) ---
    requesterDid: DID;
    targetAgentDid: DID;
    httpMethod: 'GET';
    resourceBinding: AuditResourceBinding;
    queryParams: AuditQueryParams;
    snapshotBoundary?: AuditSnapshotBoundary;
    timestamp: Timestamp;
    signature: Signature;

    // --- v0.2 new fields (3) ---
    /**
     * Unique random value (UUID v4), eliminates stateful replay within the window.
     * v0.1 compatibility: when undefined the server does not perform the nonce replay check.
     *
     */
    nonce?: string;

    /**
     * Signature algorithm identifier. Sole valid value = 'Ed25519Signature2020'.
     * v0.1 compatibility: when undefined it is implicitly treated as Ed25519.
     *
     */
    proofType?: AuditProofType;

    /**
     * Delegated audit key ID. When non-null it changes the source of the signature-verification public key.
     * v0.1 compatibility: when undefined/null the requesterDid public key is used.
     *
     */
    delegatedAuditKeyId?: string | null;
}

// v0.2 governor lane: control-plane audit identity resolution result.
// Mutually exclusive with AuditIdentityResolution: the governor DID has no BindingProof / publicKeys / principalDid,
// and does not reuse AgentIdentityDocument fields (compile-time guarantee of lane isolation).
export interface ControlPlaneAuditResolution {
    /** control-plane DID (sole valid value at the current stage = SESSION_GOVERNOR_DID)*/
    did: DID;
    /** "governance-plane identity metadata" injected by the deployer; the protocol level does not constrain its structure.
     *  Anchor point for the metadata-driven quorum/role authorization extension.
*/
    metadata: Readonly<Record<string, unknown>>;
    verifiedAt: Timestamp;
}

// v0.2: per-requester subject scope.

// Historical vulnerability: the original design did the scope check based on targetAgentDid.
// But the dispatcher requires targetAgentDid === SESSION_GOVERNOR_DID to enter the
// control-plane lane, so a scope check using targetAgentDid is equivalent to the old flat allow-list (any allow-listed
// requester still reads the full governor ledger in the governor lane).

// v0.2 revised design: the scope field switches to the affectedAgentDid /
// affectedPrincipalDid of the SESSION_SUPERSEDED immutable payload (now required), and requires the control-plane lane
// to explicitly provide the queryParams.affectedAgentDid filter parameter (fail-closed).

// Authorization boundary semantics: "what can be done / what cannot be done / within what boundary" —
// each control-plane requester DID may only read the set of affected* DIDs within its scope.

// fail-closed boundaries:
// - allowedAffectedAgentDids is the empty set → any request → AUDIT_FORBIDDEN
// - queryParams.affectedAgentDid missing → AUDIT_FORBIDDEN (forces explicit subject declaration)
// - queryParams.affectedAgentDid not in scope.allowedAffectedAgentDids → AUDIT_FORBIDDEN
// - allowedAffectedPrincipalDids is not undefined and queryParams.affectedPrincipalDid
//   is not in the set → AUDIT_FORBIDDEN (the principal dimension is optional; undefined = unconstrained)

// Minimal usable scope; the metadata-driven quorum/role extension uses the metadata anchor.
export interface ControlPlaneRequesterScope {
    /** this requester may only read governor records for these affectedAgentDids; empty set = reject*/
    readonly allowedAffectedAgentDids: ReadonlySet<DID>;
    /** optional principal-dimension constraint; undefined = the principalDid dimension is unconstrained*/
    readonly allowedAffectedPrincipalDids?: ReadonlySet<DID>;
}

// VerifiedAuditRequest — union type (fixes the earlier broken type assertion problem).
// Passed to the handler after the middleware verifies the signature + parses; the handler must do a lane type guard first before it can access identity / resolution.
export type VerifiedAuditRequest =
    | {
          readonly lane: 'business';
          readonly query: SignedAuditQuery;
          readonly resolvedIdentity: AgentIdentityDocument;
          readonly identityStatus: 'active' | 'suspended' | 'deactivated';
          readonly verifiedAt: Timestamp;
      }
    | {
          readonly lane: 'control-plane';
          readonly query: SignedAuditQuery;
          readonly resolution: ControlPlaneAuditResolution;
          readonly verifiedAt: Timestamp;
      };

export type AuditAccessErrorCode =
    | 'AUDIT_SIGNATURE_INVALID'
    | 'AUDIT_TIMESTAMP_SKEW'
    | 'AUDIT_REQUESTER_UNKNOWN'
    | 'AUDIT_FORBIDDEN'
    | 'AUDIT_QUERY_MALFORMED'
    | 'AUDIT_RESOURCE_BINDING_MISMATCH'
    | 'AUDIT_SNAPSHOT_BOUNDARY_VIOLATED'
    | 'AUDIT_IDENTITY_UNVERIFIED'
    // v0.2 new: nonce replay rejection
    | 'AUDIT_NONCE_REPLAY';

export type AuditAccessDecision =
    | { allowed: true }
    | { allowed: false; code: AuditAccessErrorCode; reason: string };

// AuditAccessChecker — L3 internal interface (does not enter the envelope / token wire path).
export interface AuditAccessChecker {
    check(request: VerifiedAuditRequest): Promise<AuditAccessDecision>;
}

// IdentityStoreForAudit — audit-specific identity resolution.
// Differences from regular resolve:
// 1. returns deactivated-status documents (principal audit requirement)
// 2. must perform triple binding validation (params.did === row.did === document.id + verifyAgentIdentityDocument(document))
// 3. the returned document must be the original copy from persistent storage; remote or cached unsigned versions are not accepted
export interface AuditIdentityResolution {
    document: AgentIdentityDocument;
    status: 'active' | 'suspended' | 'deactivated';
    verifiedAt: Timestamp;
}

export interface IdentityStoreForAudit {
    /** v0.1 business lane: DID resolution for principal-only audit.*/
    resolveForAudit(did: DID): Promise<AuditIdentityResolution | null>;

    /**
     * v0.2 governor lane: control-plane DID resolution.
     *
     * Called only when the audit middleware dispatches to the governor lane per `targetAgentDid === SESSION_GOVERNOR_DID`.
     * Returning null → fail-closed (404 IDENTITY_NOT_FOUND).
     *
     * Optional member (zero regression for v0.1 callers; a deployer that has not implemented it naturally fail-closes on the governor path).
     */
    resolveControlPlaneForAudit?(
        did: DID,
    ): Promise<ControlPlaneAuditResolution | null>;
}

// ---------------------------------------------------------------------------
// v0.2 signature algorithm enum
// ---------------------------------------------------------------------------

/**
 * Audit query signature algorithm enum
 *
 * Sole valid value: 'Ed25519Signature2020'.
 * Reserved extension values: 'EcdsaSecp256k1Signature2019' | 'BbsBlsSignature2020'
 * (reserved only, not implemented).
 *
 * @frozen frozen
 */
export type AuditProofType = 'Ed25519Signature2020';

// ---------------------------------------------------------------------------
// DelegatedAuditKey — delegated audit key
// ---------------------------------------------------------------------------

/**
 * Delegated audit key
 *
 * A restricted audit-permission key issued by the principal to an auditor/service account.
 * Signature canonicalization: canonicalize(omit(delegatedAuditKey, 'signature')) -> Ed25519 sign by principalDid.
 *
 * @breaking no (new type)
 * @frozen frozen
 */
export interface DelegatedAuditKey {
    /** Unique identifier (UUID v4), generated by the principal at issuance time.*/
    id: string;

    /** Issuer DID (did:key, principal).*/
    principalDid: DID;

    /** DID of the subject granted audit rights (did:key, auditor/service account).*/
    delegatedTo: DID;

    /**
     * Optional: restricts the auditable subset of agents.
     * undefined / empty array = all agents under the principal can be audited.
     */
    scopeAgentDids?: DID[];

    /** Key expiry time (ISO 8601 UTC).*/
    expiresAt: Timestamp;

    /** The principal's Ed25519 signature over this structure (with the signature field removed).*/
    signature: Signature;
}

// ---------------------------------------------------------------------------
// DelegatedAuditKeyResolver — delegated key resolver
// ---------------------------------------------------------------------------

/**
 * Delegated audit key resolver interface
 *
 * The implementation must:
 *   1. look up the key by id
 *   2. verify the key.principalDid signature (canonicalize + Ed25519 verify)
 *   3. check key.expiresAt >= now
 *   4. check that key.principalDid is the principal of targetAgentDid (cross-reference identity)
 *   5. if scopeAgentDids is non-empty, check that targetAgentDid is in the list
 * Any failure returns null (fail-closed).
 *
 * Default implementation: NullDelegatedAuditKeyResolver (always returns null).
 *
 * @frozen frozen
 */
export interface DelegatedAuditKeyResolver {
    resolve(
        keyId: string,
        targetAgentDid: DID,
    ): Promise<DelegatedAuditKey | null>;
}

// ---------------------------------------------------------------------------
// AuditAccessV02Header — v0.2 HTTP request header mapping
// ---------------------------------------------------------------------------

/**
 * v0.2 complete audit request header mapping
 *
 * v0.1 inherited 3 required + 3 conditionally required + v0.2 new 1 required (X-Audit-Nonce) + 2 optional.
 * Maps to the SignedAuditQuery v0.2 fields.
 *
 * @breaking no (v0.1 clients apply the downgrade rules within the tri-state coexistence window)
 * @frozen frozen
 */
export interface AuditAccessV02Header {
    // --- v0.1 inherited ---
    /** X-Audit-Requester -> query.requesterDid*/
    'X-Audit-Requester': string;
    /** X-Audit-Signature -> query.signature*/
    'X-Audit-Signature': string;
    /** X-Audit-Timestamp -> query.timestamp*/
    'X-Audit-Timestamp': string;
    /** X-Audit-Snapshot-HeadCreatedAt -> query.snapshotBoundary.headCreatedAt (conditionally required)*/
    'X-Audit-Snapshot-HeadCreatedAt'?: string;
    /** X-Audit-Snapshot-HeadRecordId -> query.snapshotBoundary.headRecordId (conditionally required)*/
    'X-Audit-Snapshot-HeadRecordId'?: string;
    /** X-Audit-Snapshot-HeadRecordHash -> query.snapshotBoundary.headRecordHash (optional)*/
    'X-Audit-Snapshot-HeadRecordHash'?: string;

    // --- v0.2 new ---
    /** X-Audit-Nonce -> query.nonce (required in v0.2; not enforced in v0.1 downgrade mode)*/
    'X-Audit-Nonce': string;
    /** X-Audit-Proof-Type -> query.proofType (optional)*/
    'X-Audit-Proof-Type'?: string;
    /** X-Audit-Delegated-Key-Id -> query.delegatedAuditKeyId (optional)*/
    'X-Audit-Delegated-Key-Id'?: string;
}

// ---------------------------------------------------------------------------
// AuditEventRecord — meta-ledger interface reservation
// ---------------------------------------------------------------------------

/**
 * Audit event record (reserved meta-ledger interface)
 *
 * "Auditing the audit": records the operation log of audit queries themselves.
 * Only the interface is defined; it is not implemented (deferred to a later release).
 *
 * @breaking no (new type, not yet implemented)
 * @frozen only the type is frozen; the evaluator implementation is deferred to a later release
 */
export interface AuditEventRecord {
    /** Unique event ID (UUID v4)*/
    readonly id: string;

    /** Event type*/
    readonly eventType:
        | 'AUDIT_QUERY'
        | 'AUDIT_KEY_ISSUED'
        | 'AUDIT_KEY_REVOKED';

    /** Actor DID (requesterDid or principalDid)*/
    readonly actorDid: DID;

    /** The audited targetAgentDid*/
    readonly targetAgentDid: DID;

    /** Event occurrence time (ISO 8601 UTC)*/
    readonly timestamp: Timestamp;

    /** Associated SignedAuditQuery.nonce (for AUDIT_QUERY events) or DelegatedAuditKey.id*/
    readonly correlationId?: string;

    /** Event outcome*/
    readonly outcome: 'ALLOWED' | 'DENIED';

    /** Deny reason (filled in when outcome='DENIED')*/
    readonly denyReason?: AuditAccessErrorCode;

    /** Hash of the previous record in the meta-ledger hash chain*/
    readonly prevHash: Hash | null;

    /** meta-ledger signature*/
    readonly signature: Signature;
}

// ---------------------------------------------------------------------------
// LedgerHeadBootstrapToken — replay defense
// ---------------------------------------------------------------------------

/**
 * LedgerHeadBootstrapToken — a server-side immutable token that anchors the head position.
 *
 * The server generates this token after the signature is verified:
 *   1. query the current latest record MAX(id) as anchorId
 *   2. construct token = { anchorId, anchorHash, issuedAt, expiresAt }
 *   3. sign the token (server signing key)
 *   4. the handler constrains the query boundary with `WHERE id <= token.anchorId`
 *
 * The token does not participate in the client signaturePayload (the client does not hold the token info to sign;
 * the token is server-generated, the client cannot forge it).
 *
 * @breaking no (new type, does not change the existing signature protocol)
 */
export interface LedgerHeadBootstrapToken {
    /** the maximum record ID anchored by the server (BigInt sequence-number string)*/
    readonly anchorId: string;

    /** the record_hash of the record corresponding to anchorId (used for tamper-evidence)*/
    readonly anchorHash: string;

    /** token issuance time (ISO 8601 UTC)*/
    readonly issuedAt: Timestamp;

    /** token expiry time (issuedAt + 300s, aligned with the signature TTL)*/
    readonly expiresAt: Timestamp;

    /** the server's Ed25519 signature over canonicalize({ anchorId, anchorHash, issuedAt, expiresAt })*/
    readonly serverSignature: Signature;
}
