/**
 * atp v0.1 L3 TamperProofAuditVerifier — audit event verification (reverse hash chain replay)
 *
 * priority 4 sub-protocol — audit-tamper-proof v0.1 L3 implementation
 *
 * verifier asymmetry defense:
 *   - verifier hash input aligns with the writer on all 10 fields (buildTamperProofHashInput shared helper);
 *   - the legacy 3-field sha256(canonicalPayload || previousHash || tenantId) pattern is strictly forbidden;
 *   - writer/verifier must not implement the hash input separately;
 *   - signature input also uses the 10 fields (cross-tenant replay vulnerability defense).
 *
 * pipeline step 1-7:
 *   1. verifier input: targetEventId + tenantId scope
 *   2. fetchEventById (tenantId mismatch → AUDIT_TENANT_SCOPE_VIOLATION)
 *   3. JSON Schema validate (audit event schema invariants)
 *   4. reverse hash chain replay (per-(tenantId, audit_class); GENESIS first)
 *      - i===0 && previousHash !== null → AUDIT_GENESIS_VIOLATION
 *      - i>0 && previousHash === null → AUDIT_GENESIS_VIOLATION
 *      - recomputedHash !== tamperProofHash → AUDIT_TAMPER_DETECTED
 *      - i>0 && previousHash !== chain[i-1].tamperProofHash → AUDIT_HASH_CHAIN_BROKEN
 *   5. (optional) re-canonicalize payload (when the caller provides the original payload)
 *   6. (optional) Ed25519 signature verify (when event.signature !== null)
 *   7. all checks pass → ACCEPTED; any failure → fail-closed reject + error code
 */

import { hash } from '@coivitas/crypto';
import type {
    AuditEvent,
    AuditEventId,
    TenantId,
} from '@coivitas/types';
import { AuditError, validateAuditEvent } from '@coivitas/types';

import { buildTamperProofHashInput } from './build-tamper-proof-hash-input.js';
import { canonicalizeAuditPayload } from './canonicalize-audit-payload.js';
import type { AuditEventStore } from './tamper-proof-audit-writer.js';

/**
 * VerifyAuditEventResult — verify pipeline result (deterministic two-state)
 *
 * - ok:true → all checks pass (event + complete reverse hash chain + optional signature verify)
 * - ok:false → fail-closed reject + error code + error location (chain index)
 *
 * counterexample defense strictly enforced (ACCEPTED-only verification primitive):
 *   - no partial-PASS intermediate state exists;
 *   - any step failure throws AuditError + immediate reject;
 *   - fail-degraded / "PASSED with warnings" is not allowed.
 */
export type VerifyAuditEventResult =
    | { readonly ok: true; readonly event: AuditEvent }
    | {
          readonly ok: false;
          readonly error: AuditError;
      };

/**
 * VerifyAuditEventOptions — verifier input parameters
 */
export interface VerifyAuditEventOptions {
    /** target event ID to verify*/
    readonly eventId: AuditEventId;
    /** tenant scope (multi-tenant isolation enforced; cross-tenant query is fail-closed)*/
    readonly tenantId: TenantId;
    /**
     * Optional original payload (when provided by the caller, step 5 re-canonicalize check runs);
     * step 5 is skipped when undefined.
     */
    readonly originalPayload?: unknown;
}

/**
 * TamperProofAuditVerifier — atp v0.1 audit event verification core
 *
 * 5 counterexample defenses enforced:
 *   - fail-closed: any step failure throws AuditError + returns {ok:false}; "PASSED with caveats" is not allowed
 *   - no brand cast: verify input AuditEventId / TenantId are already branded; raw string is not accepted
 *   - top-level import canonicalize: the canonicalizeAuditPayload module is imported at the top level
 *   - does not modify any audit-share / audit-access / EnvelopeLedger pipeline
 *   - partial-PASS: no ok:true with warnings intermediate state exists
 */
export class TamperProofAuditVerifier {
    private readonly store: AuditEventStore;

    public constructor(opts: { store: AuditEventStore }) {
        this.store = opts.store;
    }

    /**
     * verifyAuditEvent — atp audit event verify main entry (step 1-7)
     *
     * full pipeline (fail-closed; any step failure throws + returns ok:false):
     *   step 1-2: fetchEventById (tenantId mismatch → AUDIT_TENANT_SCOPE_VIOLATION)
     *   step 3: JSON Schema validate (third defense line, AJV strict)
     *   step 4: reverse hash chain replay (GENESIS first; recomputedHash comparison;
     *           previousHash chain comparison; GENESIS invariant)
     *   step 5: (optional) re-canonicalize(originalPayload) === event.canonicalPayload
     *           (when provided by the caller; skipped when undefined)
     *   step 6: (optional) Ed25519 signature verify (when event.signature !== null; real verification not implemented in v0.1)
     *   step 7: all checks pass → ok:true + event; any failure → ok:false + error
     *
     * @returns VerifyAuditEventResult (deterministic two-state; ACCEPTED-only)
     */
    public async verifyAuditEvent(
        opts: VerifyAuditEventOptions,
    ): Promise<VerifyAuditEventResult> {
        try {
            // step 1-2: fetchEventById with tenantId scope
            const event = await this.store.fetchEventById(
                opts.eventId,
                opts.tenantId,
            );
            if (event === null) {
                throw new AuditError(
                    'AUDIT_TENANT_SCOPE_VIOLATION',
                    `audit event not found (eventId mismatch or cross-tenant query): eventId="${opts.eventId}" tenantId="${opts.tenantId}"`,
                    { eventId: opts.eventId, tenantId: opts.tenantId },
                );
            }

            // step 3: JSON Schema validate (audit event schema invariants)
            const validateResult = validateAuditEvent(event);
            if (!validateResult.valid) {
                const firstErr = validateResult.errors[0];
                throw new AuditError(
                    'AUDIT_SCHEMA_VIOLATION',
                    `audit event JSON Schema validate failed: ${
                        firstErr?.instancePath ?? '/'
                    }: ${firstErr?.message ?? 'unknown'}`,
                    {
                        eventId: opts.eventId,
                        instancePath: firstErr?.instancePath,
                    },
                );
            }

            // step 4: reverse hash chain replay
            // fetch the full per-(tenantId, audit_class) chain GENESIS first; cross-tenant / cross-class is strictly forbidden
            await this.reverseHashChainReplay(event);

            // step 5: (optional) re-canonicalize(originalPayload)
            if (opts.originalPayload !== undefined) {
                const recomputedCanonicalPayload = canonicalizeAuditPayload(
                    opts.originalPayload,
                );
                if (recomputedCanonicalPayload !== event.canonicalPayload) {
                    throw new AuditError(
                        'AUDIT_CANONICALIZE_MISMATCH',
                        `verifier re-canonicalize(payload) !== event.canonicalPayload`,
                        {
                            eventId: opts.eventId,
                            recomputedLen: recomputedCanonicalPayload.length,
                            storedLen: event.canonicalPayload.length,
                        },
                    );
                }
            }

            // step 6: (optional) Ed25519 signature verify (within v0.1 scope)

            // v0.1 implementation scope:
            // - when event.signature !== null, call the issuer public key resolver + Ed25519 verify;
            // - v0.1 does not couple to the DelegatedAuditKey resolver (counterexample defense: does not modify other module pipelines);
            // - v0.1 does not implement the internal Ed25519 verify logic (deferred to audit-share v0.2);
            // - when event.signature !== null but the verifier side has no issuerPublicKey
            // → throw AuditError(AUDIT_EVENT_SIGNATURE_INVALID) (fail-closed; counterexample defense strictly enforced).

            // v0.1 default behavior: if event.signature !== null, throw AUDIT_EVENT_SIGNATURE_INVALID directly;
            // to enable real Ed25519 verify, the caller must implement the issuerPublicKeyResolver interface and extend the verifyAuditEvent signature —
            // this is the atp v0.1 → v0.2 upgrade path (audit-share v0.2 L3 implementation).
            if (event.signature !== null) {
                throw new AuditError(
                    'AUDIT_EVENT_SIGNATURE_INVALID',
                    `event.signature present but Ed25519 verify not implemented in atp v0.1 (deferred to v0.2 audit-share L3; counterexample defense: fail-closed strict);
                    if the caller only needs tamper-proof hash chain verification, pass an input event without the signature field (=null)`,
                    {
                        eventId: opts.eventId,
                        hasSignature: true,
                        v01Scope: 'v0.1 does not implement signature verify',
                    },
                );
            }

            // step 7: all checks pass → ACCEPTED
            return { ok: true, event };
        } catch (err) {
            if (err instanceof AuditError) {
                return { ok: false, error: err };
            }
            // fallback wrapping for non-AuditError (counterexample defense; bare Error must not leak out)
            return {
                ok: false,
                error: new AuditError(
                    'AUDIT_REVERSE_REPLAY_FAILED',
                    `verifier internal error (non-AuditError): ${
                        err instanceof Error ? err.message : String(err)
                    }`,
                    { eventId: opts.eventId, tenantId: opts.tenantId },
                ),
            };
        }
    }

    /**
     * reverseHashChainReplay — per-(tenantId, audit_class) full-chain GENESIS first replay
     *
     * pseudocode:
     *   for each ev in chain (index i starting from 0):
     *     if i === 0 && ev.previousHash !== null:
     *       throw AUDIT_GENESIS_VIOLATION at index 0
     *     if i > 0 && ev.previousHash === null:
     *       throw AUDIT_GENESIS_VIOLATION at index i
     *     recomputedHash = sha256(buildTamperProofHashInput(ev))
     *     if recomputedHash !== ev.tamperProofHash:
     *       throw AUDIT_TAMPER_DETECTED at index i
     *     if i > 0 && ev.previousHash !== chain[i-1].tamperProofHash:
     *       throw AUDIT_HASH_CHAIN_BROKEN at index i
     *
     * @throws AuditError when any invariant is violated
     */
    private async reverseHashChainReplay(targetEvent: AuditEvent): Promise<void> {
        let chain: readonly AuditEvent[];
        try {
            chain = await this.store.fetchAllEvents(
                targetEvent.tenantId,
                targetEvent.auditClass,
            );
        } catch (err) {
            if (err instanceof AuditError) {
                throw err;
            }
            throw new AuditError(
                'AUDIT_REVERSE_REPLAY_FAILED',
                `fetchAllEvents failed: ${
                    err instanceof Error ? err.message : String(err)
                }`,
                {
                    tenantId: targetEvent.tenantId,
                    auditClass: targetEvent.auditClass,
                },
            );
        }

        // the chain must contain targetEvent (storage invariant; fetchEventById already confirmed the event exists)
        // a chain length of 0 is treated as corrupted storage state (fail-closed)
        if (chain.length === 0) {
            throw new AuditError(
                'AUDIT_REVERSE_REPLAY_FAILED',
                `fetchAllEvents returned empty chain but fetchEventById returned event (storage state inconsistent)`,
                {
                    tenantId: targetEvent.tenantId,
                    auditClass: targetEvent.auditClass,
                },
            );
        }

        let targetIndex = -1;
        for (let i = 0; i < chain.length; i++) {
            const ev = chain[i];
            // safety: chain index in-range; TS narrows the Array<T> access undefined union
            /* v8 ignore next 8*/
            if (ev === undefined) {
                throw new AuditError(
                    'AUDIT_REVERSE_REPLAY_FAILED',
                    `chain[${i}] is undefined (impossible path;storage state inconsistent)`,
                    { chainLength: chain.length, index: i },
                );
            }
            // GENESIS invariant
            if (i === 0 && ev.previousHash !== null) {
                throw new AuditError(
                    'AUDIT_GENESIS_VIOLATION',
                    `chain[0] previousHash !== null (GENESIS state requires previousHash=null)`,
                    {
                        eventId: ev.eventId,
                        index: i,
                        previousHash: ev.previousHash,
                    },
                );
            }
            if (i > 0 && ev.previousHash === null) {
                throw new AuditError(
                    'AUDIT_GENESIS_VIOLATION',
                    `chain[${i}] previousHash === null (non-GENESIS state requires previousHash!=null)`,
                    { eventId: ev.eventId, index: i },
                );
            }

            // recomputedHash check (all 10 fields bound; writer/verifier asymmetry defense)
            const hashInput = buildTamperProofHashInput(ev);
            const recomputedHash = hash(hashInput, 'hex');
            if (recomputedHash !== ev.tamperProofHash) {
                throw new AuditError(
                    'AUDIT_TAMPER_DETECTED',
                    `chain[${i}] recomputedHash !== ev.tamperProofHash (DBA tampering or hash input asymmetry detected)`,
                    {
                        eventId: ev.eventId,
                        index: i,
                        recomputedHash,
                        storedHash: ev.tamperProofHash,
                    },
                );
            }

            // previousHash chain check (last clause)
            if (i > 0) {
                const prevEv = chain[i - 1];
                /* v8 ignore next 8*/
                if (prevEv === undefined) {
                    throw new AuditError(
                        'AUDIT_REVERSE_REPLAY_FAILED',
                        `chain[${i - 1}] is undefined (impossible path)`,
                        { chainLength: chain.length, index: i - 1 },
                    );
                }
                if (ev.previousHash !== prevEv.tamperProofHash) {
                    throw new AuditError(
                        'AUDIT_HASH_CHAIN_BROKEN',
                        `chain[${i}] previousHash mismatch chain[${i - 1}] tamperProofHash`,
                        {
                            eventId: ev.eventId,
                            index: i,
                            expectedPreviousHash: prevEv.tamperProofHash,
                            actualPreviousHash: ev.previousHash,
                        },
                    );
                }
            }

            if (ev.eventId === targetEvent.eventId) {
                targetIndex = i;
            }
        }

        // targetEvent not in the chain → storage state fail-closed
        /* v8 ignore next 11*/
        if (targetIndex === -1) {
            throw new AuditError(
                'AUDIT_REVERSE_REPLAY_FAILED',
                `targetEvent not found in fetched chain (storage state inconsistent)`,
                {
                    targetEventId: targetEvent.eventId,
                    chainLength: chain.length,
                },
            );
        }

        // verification passed (all replay full-chain invariants PASS)
        // no return value; no throw = success
    }

    /**
     * verifyAuditEventOrThrow — convenience helper (throw-style API)
     *
     * for callers that expect throw behavior (e.g. service layer error middleware);
     * equivalent to verifyAuditEvent + if (!ok) throw error.
     *
     * @throws AuditError when verify fails
     */
    public async verifyAuditEventOrThrow(
        opts: VerifyAuditEventOptions,
    ): Promise<AuditEvent> {
        const result = await this.verifyAuditEvent(opts);
        if (!result.ok) {
            throw result.error;
        }
        return result.event;
    }
}
