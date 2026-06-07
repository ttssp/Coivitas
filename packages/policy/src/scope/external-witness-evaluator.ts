/**
 * ExternalWitnessEvaluator — stub (fail-closed)
 *
 * Design context: a DSL extension point.
 *   external_witness/consensus_meter land only the type and interface; the evaluator
 *   implementation is deferred to a later release.
 *
 * Security constraint (fail-closed):
 *   evaluate() throws MetricSourceNotImplemented, ensuring "not implemented = authorization denied",
 *   never accidentally letting through an unverified witness attestation.
 *
 * Future implementation plan:
 *   - Actual attestation validation logic (witnessSource HTTP request, signature verification)
 *   - quorum decision (consensus_meter path)
 *   - EnvelopeLedger witness log write
 */

import type { EvaluatorFn } from '../guard/scope-evaluator.js';
import type { ScopeEvaluator } from '../guard/scope-evaluator.js';

// ─────────────────────────────────────────────────────────────────────────────
// Error class: for L3 internal use only (not a ProtocolErrorCode enum value).
// The error-code reuse strategy applies: this carries "not implemented" semantics and is not a
// SCOPE_EXCEEDED runtime subtype; once the full evaluator is implemented this class will no longer be thrown.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Error thrown when a Metric Source evaluator is not implemented.
 *
 * Extends Error (not ProtocolError) to avoid introducing a new ProtocolErrorCode enum value
 * (principle: don't add an enum value if you can avoid it).
 * A caller that catches this error should treat it as "authorization denied" and record reason='not implemented'.
 */
export class MetricSourceNotImplemented extends Error {
    public override readonly name = 'MetricSourceNotImplemented';

    public constructor(source: string) {
        super(
            `ExternalWitnessEvaluator: metric source "${source}" is not implemented. ` +
                `Fail-closed: authorization denied until attestation validation is implemented.`,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExternalWitnessEvaluator interface (schema definition)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ExternalWitnessEvaluator configuration interface.
 *
 * This is the schema definition for the current stub stage; the full implementation
 * extends this interface with the parameters needed for attestation validation, without
 * introducing a breaking change.
 */
export interface ExternalWitnessEvaluator {
    /**
     * Source identifier of the external witness service (e.g. 'https://witness.example.com/attest').
     * The full implementation will use this to issue the attestation request.
     */
    witnessSource: string;

    /**
     * Optional: the key ID (DID Key reference) used to verify the witness signature.
     * The full implementation uses this field to load the public key and verify the attestation signature.
     */
    witnessKeyId?: string;

    /**
     * Optional: the drift window for accepting the witness timestamp (in seconds, default 60).
     * The full implementation prevents replay attacks: an attestation outside the window is rejected.
     */
    witnessTimestampWindow?: number;

    /**
     * Scope type identifier, fixed to 'external_witness'.
     * Aligned with the MeterFieldRef.source tri-state enum.
     */
    readonly type: 'external_witness';
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory: createExternalWitnessEvaluator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Creates an ExternalWitnessEvaluator plugin instance (stub).
 *
 * The return value contains:
 * - evaluatorConfig: a read-only configuration object conforming to the ExternalWitnessEvaluator interface.
 * - evaluatorFn: an EvaluatorFn that can be injected into ScopeEvaluator (fail-closed).
 *
 * fail-closed semantics:
 *   Before the full implementation, evaluatorFn **always** throws MetricSourceNotImplemented.
 *   Any Token carrying an external_witness scope is denied authorization,
 *   ensuring unverified witness information is never used in authorization decisions.
 *
 * @param config evaluator configuration parameters
 * @returns a tuple of the configuration object + EvaluatorFn
 */
export function createExternalWitnessEvaluator(
    config: Omit<ExternalWitnessEvaluator, 'type'>,
): { evaluatorConfig: ExternalWitnessEvaluator; evaluatorFn: EvaluatorFn } {
    // Config validation: witnessSource must not be empty.
    if (!config.witnessSource || config.witnessSource.trim().length === 0) {
        throw new Error(
            'createExternalWitnessEvaluator: witnessSource must be a non-empty string',
        );
    }

    const evaluatorConfig: ExternalWitnessEvaluator = {
        type: 'external_witness',
        witnessSource: config.witnessSource,
        witnessKeyId: config.witnessKeyId,
        witnessTimestampWindow: config.witnessTimestampWindow,
    };

    /**
     * EvaluatorFn (fail-closed stub)
     *
     * Returns { allowed: false } rather than throwing, ensuring ScopeEvaluator.evaluateAll
     * can aggregate the denial result normally and have RuntimeGuard / Orchestrator's REJECTED
     * handling path write the ledger (not throwing avoids bypassing the fail-closed path, where an
     * upstream catch would treat it as INTERNAL_ERROR).
     *
     * The deny reason must not leak witnessSource — it would be passed through to the
     * AUTHORIZATION_INSUFFICIENT error message and the persisted REJECTED ActionRecord,
     * letting any caller learn the internal URL / credential parameters by triggering the fail-closed path.
     * Keep the public message generic; route the specific witnessSource to server-side logs/telemetry.
     *
     * When implementing the full evaluator, replace this function body with:
     * 1. Issue an attestation request to witnessSource.
     * 2. Verify the response signature with witnessKeyId.
     * 3. Check that the attestation timestamp is within witnessTimestampWindow.
     * 4. Return a ScopeEvaluationResult based on the verification result.
     */
    const evaluatorFn: EvaluatorFn = (_scope, _params, _now, _tracker) => {
        return Promise.resolve({
            allowed: false,
            reason: 'external_witness: METRIC_SOURCE_NOT_IMPLEMENTED (stub fail-closed)',
        });
    };

    return { evaluatorConfig, evaluatorFn };
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration helper: registerExternalWitnessEvaluator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Registers an ExternalWitnessEvaluator on the given ScopeEvaluator instance.
 *
 * Compatible with the registerScopeEvaluator API (scope-evaluator.ts);
 * also compatible with the ScopeEvaluatorRegistry (once the registry lands, callers can
 * switch to globalScopeEvaluatorRegistry.register() and pass evaluatorFn directly).
 *
 * After registration, any request that uses this ScopeEvaluator to evaluate an external_witness Scope
 * will receive a MetricSourceNotImplemented error (fail-closed).
 *
 * @param scopeEvaluator the target ScopeEvaluator instance
 * @param config evaluator configuration parameters
 * @returns the registered evaluatorConfig (convenient for test assertions)
 */
export function registerExternalWitnessEvaluator(
    scopeEvaluator: ScopeEvaluator,
    config: Omit<ExternalWitnessEvaluator, 'type'>,
): ExternalWitnessEvaluator {
    const { evaluatorConfig, evaluatorFn } =
        createExternalWitnessEvaluator(config);
    scopeEvaluator.registerScopeEvaluator('external_witness', evaluatorFn);
    return evaluatorConfig;
}
