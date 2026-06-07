/**
 * EnvelopeLedger interface definition
 *
 * Field names/types are frozen.
 *
 * EnvelopeLedger is the evolutionary replacement for idempotencyCache:
 *   - idempotencyCache provides envelope-level idempotency (in-memory Map<envelopeId, boolean> only)
 *   - EnvelopeLedger provides atomic claim/finalize + cross-trust-domain cumulative settle
 *
 * idempotencyCache and EnvelopeLedger coexist short-term; idempotencyCache will be removed later.
 *
 * This file does not touch the internals of IntegrityChecker / ActionRecorder.
 *
 * Key constraints: auditable, tamper-proof, three-state coexistence.
 *
 * Impact of the 12 invariants:
 *   - Inv 9: timing of the sender Receipt write (claim must happen before send)
 *   - Inv 10: handshake/business specVersion boundary (the ledger does not constrain it)
 */

import type { DID, Hash, Signature, Timestamp } from './base.js';

// ---------------------------------------------------------------------------
// EnvelopeClaim — envelope claim state
// ---------------------------------------------------------------------------

/**
 * Envelope claim state enum
 *
 * @frozen frozen
 */
export type EnvelopeClaimState = 'CLAIMED' | 'FINALIZED' | 'RELEASED';

/**
 * Envelope claim record
 *
 * Represents the claim state of an envelopeId in the ledger.
 * CLAIMED -> FINALIZED (business execution succeeded) or CLAIMED -> RELEASED (timeout/failure reclaim).
 *
 * @frozen frozen
 */
export interface EnvelopeClaim {
    /** unique envelope ID (from NegotiationEnvelope.id)*/
    readonly envelopeId: string;

    /** claiming agent DID*/
    readonly claimedByAgentDid: DID;

    /** claiming party session ID*/
    readonly sessionId: string;

    /** current state*/
    readonly state: EnvelopeClaimState;

    /** claim time*/
    readonly claimedAt: Timestamp;

    /** finalization time (filled in when FINALIZED or RELEASED)*/
    readonly finalizedAt: Timestamp | null;

    /** associated ActionRecord ID (filled in when FINALIZED)*/
    readonly actionRecordId: string | null;

    /** hash chain previous-record hash*/
    readonly prevHash: Hash | null;

    /** signature (Ed25519, over the canonicalized payload of the claim record)*/
    readonly signature: Signature;
}

// ---------------------------------------------------------------------------
// EnvelopeLedger — envelope ledger interface
// ---------------------------------------------------------------------------

/**
 * Envelope ledger interface
 *
 * The evolutionary replacement for idempotencyCache.
 * Provides atomic claim/finalize semantics, guaranteeing each envelopeId is processed at most once.
 *
 * @breaking N/A (new interface, during the idempotencyCache coexistence period)
 * @frozen frozen
 */
export interface EnvelopeLedger {
    /**
     * Atomically claim an envelope
     *
     * Idempotent: a repeated claim of the same envelopeId returns the existing claim (does not throw).
     * A different agent/session claiming the same envelopeId -> returns null (fail-closed).
     *
     * @param params claim parameters
     * @returns the claim record (on success) or null (already claimed by another party)
     */
    claim(params: {
        envelopeId: string;
        agentDid: DID;
        sessionId: string;
        now?: Timestamp;
    }): Promise<EnvelopeClaim | null>;

    /**
     * Finalize envelope processing
     *
     * claim -> FINALIZED: business execution succeeded, associated with an ActionRecord.
     * Only the CLAIMED state can be finalized; other states throw INTERNAL_ERROR.
     *
     * @param params finalize parameters
     * @returns the updated claim record
     */
    finalize(params: {
        envelopeId: string;
        actionRecordId: string;
        now?: Timestamp;
    }): Promise<EnvelopeClaim>;

    /**
     * Release an envelope claim
     *
     * claim -> RELEASED: timeout or business failure, releases the claim allowance.
     * Only the CLAIMED state can be released; other states throw INTERNAL_ERROR.
     *
     * @param params release parameters
     * @returns the updated claim record
     */
    release(params: {
        envelopeId: string;
        reason: string;
        now?: Timestamp;
    }): Promise<EnvelopeClaim>;

    /**
     * Query envelope claim state
     *
     * @param envelopeId envelope ID
     * @returns the claim record or null (not claimed)
     */
    lookup(envelopeId: string): Promise<EnvelopeClaim | null>;

    /**
     * Clean up expired CLAIMED records
     *
     * Transitions records that remain CLAIMED beyond timeoutMs to RELEASED.
     *
     * @param params cleanup parameters
     * @returns the number of released records
     */
    cleanExpired(params: {
        timeoutMs: number;
        now?: Timestamp;
    }): Promise<number>;
}
