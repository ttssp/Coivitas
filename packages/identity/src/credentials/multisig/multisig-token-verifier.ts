/**
 * multisig-token-verifier — Multisig L2 identity primitive (verifier-side verify pipeline)
 *
 * Full verifier-side pipeline (8 steps):
 *   1. Verifier receives the MultisigToken + request context (incl. verifier.expectedAudience)
 *   2. Verifier issues a challenge (UUID v4; issuance time recorded; stateless)
 *      -> inherits the csp v0.1 verifier-side bind reverse semantics
 *   3. Verifier sends challenge + verifier.expectedAudience to the holder
 *   4. Holder reassembles the CanonicalSignedPayload (csp v0.1 step 4)
 *   5. Holder JCS-canonicalizes csp -> signedBytes
 *   6. Holder returns {csp, MultisigToken}
 *   7. Verifier-side validation flow:
 *      7.1. JSON Schema validate (MultisigToken) -> I_ms_ver + I1-I4 + I6 + I8 field completeness
 *      7.2. csp v0.1 step 8 validation sub-flow -> 5-field invariants + I9 challenge anti-replay
 *      7.3. Merkle inclusion validation (I3 + I4)
 *      7.4. verify each signature (signers[i].signature Ed25519 verify)
 *      7.5. quorum sufficiency (I7)
 *      7.6. signer duplicate detection (I2)
 *      7.7. quorum rule (all signers equally weighted; role does not participate in weighting)
 *   8. All pass -> ACCEPTED; any failure -> fail-closed reject + error code
 *
 * MVP vs production scope:
 *   This L2 verifier implementation:
 *     - step 1-6: provided by the caller (challenge issue + csp reassembly happen caller-side; this verifier receives token + opts)
 *     - step 7.1-7.7: implemented by this verifier (main flow chains into L1 verifyMultisigProof)
 *     - step 8: returns the verify result
 *   Production deployment must add:
 *     - cross-process persistence of the challenge cache (Redis / PostgreSQL; a production-deployment constraint)
 *     - revocation list query (delegation chain primitive)
 *
 * Anti-phantom defenses:
 *   - Top-level import of verifyMultisigProof / canonicalSerialize (no in-body require);
 *   - challenge is mandatorily bound verifier-side (the caller may not skip challenge validation);
 *   - audience compared by strict equality (no startsWith / wildcard allowed);
 *   - notAfter checked for strict expiry (incl. minWindow);
 *   - no stub default success / partial-PASS allowed (strict);
 *   - signer duplicate detection + Merkle inclusion + Ed25519 verify all fail-closed throw.
 */

import {
    canonicalSerialize,
    MultisigError,
    type MultisigTokenLike,
    verifyMultisigProof,
    type VerifyMultisigProofResult,
} from '@coivitas/crypto';

/**
 * VerifyMultisigTokenOptions — verifier-side verify pipeline options
 *
 * Required fields:
 *   - expectedAudience: verifier-side expected audience (DID or https URL; strict equality)
 *   - expectedChallenge: the challenge issued verifier-side in step 2 (UUID v4; first-contact replay defense)
 *
 * Optional fields:
 *   - now: current time (defaults to new Date(); spec I5 notAfter validation)
 *   - minValidityWindowMs: minimum validity window (defaults to 1000ms; spec I5 anti-clock-skew)
 *   - enforceFullSchema: whether to enable L0 AJV schema validate (defaults to true; step 7.1)
 */
export interface VerifyMultisigTokenOptions {
    /** verifier-side expected audience (DID or https URL; compared by strict equality)*/
    expectedAudience: string;
    /** the challenge issued verifier-side in step 2 (UUID v4; C1 first-contact replay defense)*/
    expectedChallenge: string;
    /** current time (defaults to new Date())*/
    now?: Date;
    /** notAfter minimum validity window (defaults to 1000ms; anti-clock-skew)*/
    minValidityWindowMs?: number;
    /** whether to enable L0 AJV schema validate (defaults to true; step 7.1 fail-closed)*/
    enforceFullSchema?: boolean;
}

/**
 * VerifyMultisigTokenResult — verifier-side verify pipeline result
 *
 * Does not return a { valid: false } type — auth/verification primitives have strict fail-closed semantics;
 * every verify failure must throw MultisigError with one of the
 * 14 error codes (consumers must handle via try/catch; no silent skip allowed).
 *
 * The validCount + threshold return values are consumed for audit / observability (logging + metrics);
 * they do not participate in the verify-pass decision (when this function returns, quorum is necessarily met, validCount >= threshold).
 */
export interface VerifyMultisigTokenResult {
    valid: true;
    /** number of signers that passed Ed25519 verify (sufficient; >= threshold)*/
    validCount: number;
    /** configured threshold (n; the n in n-of-m)*/
    threshold: number;
}

/**
 * verifyMultisigToken — full Multisig token verify pipeline (L2 verifier main entry point)
 *
 * Implements verifier-side steps 7-8 (step 7.1-7.7 + step 8);
 * steps 1-6 are the caller's responsibility (challenge issue + csp reassembly; this verifier receives token + opts).
 *
 * Call order:
 *   1. step 7.1: L0 AJV schema validate (when enforceFullSchema = true)
 *   2. step 7.2: csp 5-field invariant validation (challenge / audience / notAfter)
 *      - csp.challenge === opts.expectedChallenge -> MULTISIG_CHALLENGE_INVALID (if unequal)
 *      - csp.audience === opts.expectedAudience -> MULTISIG_SCHEMA_VIOLATION (if unequal)
 *      - csp.notAfter > now + minWindow -> MULTISIG_SCHEMA_VIOLATION (if expired)
 *   3. step 7.3-7.7: delegate to L1 verifyMultisigProof (Merkle inclusion + Ed25519 verify + quorum)
 *
 * @param token Multisig token (caller should guarantee it passed the L0 createMultisigToken factory)
 * @param opts verifier-side verify pipeline options (expectedAudience + expectedChallenge required)
 * @returns { valid: true, validCount, threshold } — verify passed
 * @throws MultisigError with one of 14 codes (fail-closed)
 */
export function verifyMultisigToken(
    token: MultisigTokenLike,
    opts: VerifyMultisigTokenOptions,
): VerifyMultisigTokenResult {
    // step 0: validate required opts fields
    if (
        typeof opts.expectedAudience !== 'string' ||
        opts.expectedAudience.length === 0
    ) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            'verifyMultisigToken: opts.expectedAudience must be non-empty string',
        );
    }
    if (
        typeof opts.expectedChallenge !== 'string' ||
        opts.expectedChallenge.length === 0
    ) {
        throw new MultisigError(
            'MULTISIG_CHALLENGE_INVALID',
            'verifyMultisigToken: opts.expectedChallenge must be non-empty string (C1 first-contact replay defense; verifier must issue a challenge)',
        );
    }

    const now = opts.now ?? new Date();
    const minValidityWindowMs = opts.minValidityWindowMs ?? 1000;
    const enforceFullSchema = opts.enforceFullSchema ?? true;

    // step 7.2: csp 5-field invariant validation (challenge / audience / notAfter)
    // Note: this verifier does the csp validation before L1 verifyMultisigProof,
    // to keep a multisig with no challenge bind out of the Merkle inclusion stage (fail-fast)
    if (!token.csp || typeof token.csp !== 'object') {
        throw new MultisigError(
            'MULTISIG_TOKEN_INCOMPLETE',
            'verifyMultisigToken: token.csp is null or not object',
        );
    }
    const cspChallenge = token.csp['challenge'];
    if (typeof cspChallenge !== 'string') {
        throw new MultisigError(
            'MULTISIG_CHALLENGE_INVALID',
            `verifyMultisigToken: csp.challenge must be string (got ${typeof cspChallenge})`,
        );
    }
    if (cspChallenge !== opts.expectedChallenge) {
        throw new MultisigError(
            'MULTISIG_CHALLENGE_INVALID',
            `verifyMultisigToken: csp.challenge !== verifier-issued challenge (got "${cspChallenge}", expected "${opts.expectedChallenge}"; first-contact replay defense)`,
        );
    }

    const cspAudience = token.csp['audience'];
    if (typeof cspAudience !== 'string') {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `verifyMultisigToken: csp.audience must be string (got ${typeof cspAudience})`,
        );
    }
    if (cspAudience !== opts.expectedAudience) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `verifyMultisigToken: csp.audience !== verifier expected audience (got "${cspAudience}", expected "${opts.expectedAudience}"; must match exactly)`,
        );
    }

    const cspNotAfter = token.csp['notAfter'];
    if (typeof cspNotAfter !== 'string') {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `verifyMultisigToken: csp.notAfter must be string (got ${typeof cspNotAfter})`,
        );
    }
    const notAfterDate = new Date(cspNotAfter);
    if (Number.isNaN(notAfterDate.getTime())) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `verifyMultisigToken: csp.notAfter is not parseable Date (got "${cspNotAfter}")`,
        );
    }
    if (notAfterDate.getTime() <= now.getTime() + minValidityWindowMs) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `verifyMultisigToken: csp.notAfter expired (notAfter=${cspNotAfter}, now=${now.toISOString()}, minWindow=${minValidityWindowMs}ms; stale-replay defense)`,
        );
    }

    // step 7.3-7.7: delegate to L1 verifyMultisigProof (Merkle inclusion + Ed25519 verify + quorum)
    // L1 internally covers step 7.1 (L0 schema validate; enforceFullSchema = true) + step 7.6 (signer duplicate detection)
    // + step 7.7 (quorum rule; role does not participate in weighting)
    let cspSignedBytes: Uint8Array;
    try {
        // token.csp is CanonicalSignedPayload | Record<string, unknown> (MultisigTokenLike interface);
        // the brand -> record broadening cast is legal (after csp gains a brand, narrowing remains compatible here)
        cspSignedBytes = canonicalSerialize(
            token.csp as Record<string, unknown>,
        );
    } catch (error) {
        throw new MultisigError(
            'MULTISIG_SCHEMA_VIOLATION',
            `verifyMultisigToken: canonicalSerialize(token.csp) FAIL: ${error instanceof Error ? error.message : String(error)}`,
            error instanceof Error ? error : undefined,
        );
    }

    const l1Result: VerifyMultisigProofResult = verifyMultisigProof(token, {
        enforceFullSchema,
        cspSignedBytes,
    });

    // step 8: all pass -> ACCEPTED
    return {
        valid: true,
        validCount: l1Result.validCount,
        threshold: l1Result.threshold,
    };
}
