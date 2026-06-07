/**
 * verifySignature — CSP L1 crypto primitive
 *
 * Implements: csp v0.1 L1 crypto
 *    error codes (6-code MVP set) + first-contact replay defense +
 *    canonicalize consistency + type-layer defense
 *
 * Algorithm (MVP L1 surface; L2 identity sd-capability-token-verifier calls this function):
 *   1. canonicalSerialize(payload) → recomputedBytes (RFC 8785 JCS; UTF-8);
 *   2. Ed25519 verify(recomputedBytes, signature, publicKey) → boolean;
 *   3. (optional) opts checks expectedAudience / expectedChallenge / notAfterWindow;
 *   4. fail-closed: any invariant violation throws CspError + one of the 6-code MVP error codes.
 *
 * MVP L1 surface vs L2 verify pipeline:
 *   This L1 verifySignature is the cryptographic primitive (canonicalize + Ed25519 verify
 *   + basic semantic checks); it does not own the full 9-step verify pipeline of step 8 (the
 *   latter is implemented by L2 sd-capability-token-verifier; it calls this L1 function and adds
 *   token signature verify + token expiresAt check + revocation query + delegation chain
 *   decay checks).
 *
 * Anti-phantom defense:
 *   - top-level import of canonicalSerialize / ed25519 (no in-body require);
 *   - every code in the 6-code CspErrorCode has a throw-path (physically enforced to prevent
 *     phantom recurrence);
 *   - assertNever exhaustive switch fallback (compile-time failure if the union expands without
 *     synchronized coverage);
 *   - no stub default success / silent return true allowed (auth/verification primitive is strict).
 */

import { ed25519 } from '@noble/curves/ed25519';

import { validateCspPayload } from '@coivitas/types';

import { detectEncoding, fromBase64Url, fromHex } from '../encoding.js';

import { canonicalSerialize } from './canonical-serialize.js';
import { assertNever, CspError, type CspErrorCode } from './types.js';

/**
 * verifySignature parameters — payload + signature + publicKey + optional semantic checks
 *
 * payload: full csp signed payload object (containing cspVersion + token + disclosedClaims +
 *   challenge + audience + notAfter; CanonicalSignedPayload interface);
 *   the verify side uses canonicalSerialize to reconstruct signedBytes and checks canonicalize
 *   consistency (spec I7).
 *
 * signature: Ed25519 signature (hex 64-byte / base64url 86-char; reuses the existing signature
 *   format convention in packages/crypto/src/signing.ts; consistent with wire-format-freeze).
 *
 * publicKey: Ed25519 public key (hex 32-byte / base64url 43-char; reuses the existing convention).
 *
 * opts: optional semantic checks (enabled on demand; each one independently fail-closed throws
 *   one of the 6-code MVP error codes)
 *   - expectedAudience: if provided, checks payload.audience === expectedAudience (spec I4);
 *   - expectedChallenge: if provided, checks payload.challenge === expectedChallenge (spec I3 +
 *     first-contact replay inverse semantics; verifier-side issued challenge enforces binding);
 *   - now: if provided, checks payload.notAfter > now + minWindow (spec I5);
 *   - minWindowMs: defaults to 1000 (1s) to guard against clock skew (spec I5 literal minWindow default);
 *   - requireMandatoryFields: if true (default true), checks the 5/4 mandatory fields + cspVersion (spec I6).
 */
export interface VerifySignatureOptions {
    expectedAudience?: string;
    expectedChallenge?: string;
    now?: Date;
    minWindowMs?: number;
    requireMandatoryFields?: boolean;
    /**
     * Enables the full L0 AJV schema validate (validateCspPayload) as the step 0 fail-closed entry.
     *
     * A caller invoking L1 verifySignature directly must not be able to bypass
     * the L0 schema third line of defense; default = true enforces the fail-closed contract; when the
     * L2 pipeline has already validated on its own, it may explicitly pass false to skip (avoiding
     * the cost of redundant validation; but L2 must itself guarantee the L0 validate has run).
     *
     * Design rationale:
     * - "Malformed token fields can bypass CSP schema if consumers call L1 verify directly"
     *   - the verify pipeline's 1st + 3rd lines of defense (schema validate + Ed25519 verify) must be enabled together
     *   - fail-closed reject by default — opt-out must be explicit (default true)
     */
    enforceFullSchema?: boolean;
}

/**
 * verifySignature return value — returns { valid: true } when verify passes; throws CspError otherwise
 *
 * Does not return a { valid: false } type — auth/verification primitives have strict fail-closed
 * semantics (design principle 5); every verify failure must throw + error code +
 * literal message description (the consumer must handle it with try/catch; no silent skip allowed).
 */
export interface VerifySignatureResult {
    valid: true;
}

/**
 * Mandatory field check — invariants I1/I6
 *
 * mode A: 4 mandatory fields (token + challenge + audience + notAfter) + cspVersion + disclosedClaims = [];
 * mode B: 5 mandatory fields (mode A's 4 fields + non-empty disclosedClaims) + cspVersion.
 *
 * This L1 primitive simplifies:
 *   - checks that the 5 fields + cspVersion are all present (key-in-payload check);
 *   - does not distinguish mode A/B (the spec requires disclosedClaims = [] in mode A; here
 *     disclosedClaims only needs to be an array, an empty array is valid);
 *   - the mode A/B distinction is left to the L2 sd-capability-token-verifier implementation.
 */
function assertMandatoryFields(payload: Record<string, unknown>): void {
    const required = [
        'cspVersion',
        'token',
        'disclosedClaims',
        'challenge',
        'audience',
        'notAfter',
    ] as const;

    for (const field of required) {
        if (!(field in payload)) {
            throw new CspError(
                'CSP_SCHEMA_VIOLATION',
                `verifySignature: csp signed payload missing mandatory field '${field}' (5 mandatory fields + cspVersion metadata required).`,
            );
        }
    }

    // disclosedClaims must be an array (mode A: empty array is valid; mode B: non-empty array)
    if (!Array.isArray(payload.disclosedClaims)) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            'verifySignature: csp signed payload field disclosedClaims must be array (mode A = [] / mode B ⊆ token.capabilities derived claim set).',
        );
    }

    // token must be a non-null object (spec I1)
    if (
        payload.token === null ||
        payload.token === undefined ||
        typeof payload.token !== 'object'
    ) {
        throw new CspError(
            'CSP_TOKEN_MISSING',
            'verifySignature: csp signed payload field token must be non-null object.',
        );
    }
}

/**
 * Signature format check + decode → Uint8Array
 *
 * Reuses the packages/crypto/src/signing.ts:assertSignature pattern (hex 128-char OR base64url
 * 86-char; must be 64-byte after decode; invalid format throws CspError CSP_SIGNATURE_INVALID).
 */
function assertSignature(signature: string): Uint8Array {
    let signatureBytes: Uint8Array;

    try {
        const encoding = detectEncoding(signature);
        signatureBytes =
            encoding === 'hex' ? fromHex(signature) : fromBase64Url(signature);
    } catch (error) {
        throw new CspError(
            'CSP_SIGNATURE_INVALID',
            'verifySignature: signature must be valid hex or base64url encoded string (Ed25519 64-byte).',
            error instanceof Error ? error : undefined,
        );
    }

    if (signatureBytes.length !== 64) {
        throw new CspError(
            'CSP_SIGNATURE_INVALID',
            `verifySignature: signature decode length unexpected (got ${signatureBytes.length}; expected 64).`,
        );
    }

    return signatureBytes;
}

/**
 * Public key format check + decode → Uint8Array
 *
 * Reuses the packages/crypto/src/signing.ts:assertPublicKey pattern (hex 64-char OR base64url
 * 43-char; must be 32-byte after decode; invalid format throws CspError CSP_SIGNATURE_INVALID).
 *
 * Note: public key format errors also map to CSP_SIGNATURE_INVALID (signature primitive surface
 * error; no new error code CSP_INVALID_PUBLIC_KEY is introduced — 6-code MVP set constraint).
 */
function assertPublicKey(publicKey: string): Uint8Array {
    let publicKeyBytes: Uint8Array;

    try {
        const encoding = detectEncoding(publicKey);
        publicKeyBytes =
            encoding === 'hex' ? fromHex(publicKey) : fromBase64Url(publicKey);
    } catch (error) {
        throw new CspError(
            'CSP_SIGNATURE_INVALID',
            'verifySignature: publicKey must be valid hex or base64url encoded string (Ed25519 32-byte).',
            error instanceof Error ? error : undefined,
        );
    }

    if (publicKeyBytes.length !== 32) {
        throw new CspError(
            'CSP_SIGNATURE_INVALID',
            `verifySignature: publicKey decode length unexpected (got ${publicKeyBytes.length}; expected 32).`,
        );
    }

    return publicKeyBytes;
}

/**
 * ISO 8601 strict validation pattern (I5 + JSON Schema format "date-time")
 *
 * Strictly matches the RFC 3339 date-time format (YYYY-MM-DDTHH:MM:SS[.fff]Z or ±HH:MM timezone);
 * rejects any string that V8 Date would loosely parse (e.g. '9601' parsed as year-only).
 * This strictly enforces the literal "ISO 8601 UTC" requirement of I5.
 */
const ISO_8601_STRICT_PATTERN =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * notAfter ISO 8601 check + expiry check (spec I5)
 *
 * Algorithm:
 *   - ISO_8601_STRICT_PATTERN strict match (rejects the V8 Date loose-parse path);
 *   - new Date(notAfter) parse; NaN → CSP_SCHEMA_VIOLATION;
 *   - notAfter ≤ now + minWindow → CSP_PAYLOAD_EXPIRED (fail-closed; guards against stale replay).
 *
 * Guarding against the V8 Date loose-parse path (anti-phantom):
 *   - V8 `new Date('not-iso-8601')` parses '8601' as year-only → yields a far-future Date (NaN expected);
 *   - the ISO 8601 strict pattern must be pre-checked to reject invalid formats; otherwise verify
 *     silently passes a stale replay.
 */
function assertNotAfter(
    notAfter: string,
    now: Date,
    minWindowMs: number,
): void {
    if (!ISO_8601_STRICT_PATTERN.test(notAfter)) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `verifySignature: notAfter field is not valid ISO 8601 timestamp (got '${notAfter}'; JSON Schema format 'date-time' + RFC 3339 strict pattern).`,
        );
    }

    const notAfterDate = new Date(notAfter);

    if (Number.isNaN(notAfterDate.getTime())) {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `verifySignature: notAfter field is not parseable Date (got '${notAfter}'; JSON Schema format 'date-time').`,
        );
    }

    const threshold = now.getTime() + minWindowMs;
    if (notAfterDate.getTime() <= threshold) {
        throw new CspError(
            'CSP_PAYLOAD_EXPIRED',
            `verifySignature: csp signed payload notAfter expired (notAfter=${notAfter}; now=${now.toISOString()}; minWindow=${minWindowMs}ms).`,
        );
    }
}

/**
 * audience check (spec I4)
 *
 * Algorithm: strict equality comparison (===); literally "no startsWith / match / wildcard allowed".
 */
function assertAudience(
    payloadAudience: unknown,
    expectedAudience: string,
): void {
    if (typeof payloadAudience !== 'string') {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `verifySignature: audience field must be string (got ${typeof payloadAudience}; CspAudience brand type).`,
        );
    }

    if (payloadAudience !== expectedAudience) {
        throw new CspError(
            'CSP_AUDIENCE_MISMATCH',
            `verifySignature: audience mismatch (payload='${payloadAudience}'; expected='${expectedAudience}'; must match exactly).`,
        );
    }
}

/**
 * challenge check (spec I3 + first-contact replay inverse semantics)
 *
 * Algorithm: strict equality comparison (===); literally "verifier-side issue + bind challenge".
 * The verifier side issues a fresh UUID v4 challenge before the verify pipeline entry → passes it to
 * the holder → the holder reassembles the csp signed payload containing the challenge → the verifier
 * side checks payload.challenge === the step 2 issued value (must be equal to pass). An attacker
 * carrying a historical challenge → fails.
 */
function assertChallenge(
    payloadChallenge: unknown,
    expectedChallenge: string,
): void {
    if (typeof payloadChallenge !== 'string') {
        throw new CspError(
            'CSP_SCHEMA_VIOLATION',
            `verifySignature: challenge field must be string (got ${typeof payloadChallenge}; UuidV4String brand type).`,
        );
    }

    if (payloadChallenge !== expectedChallenge) {
        throw new CspError(
            'CSP_CHALLENGE_INVALID',
            `verifySignature: challenge mismatch (payload='${payloadChallenge}'; expected='${expectedChallenge}'; first-contact replay defense).`,
        );
    }
}

/**
 * verifySignature — CSP signed payload Ed25519 signature verify + optional semantic checks
 *
 * @param payload full csp signed payload object (containing the 5 fields + cspVersion metadata).
 * @param signature Ed25519 signature (hex 64-byte / base64url 86-char).
 * @param publicKey Ed25519 public key (hex 32-byte / base64url 43-char).
 * @param opts optional semantic checks (expectedAudience / expectedChallenge / now / minWindowMs /
 *   requireMandatoryFields); each, when enabled, independently fail-closed throws one of the 6-code MVP error codes.
 * @returns { valid: true } — verify passes; on failure throws CspError + error code.
 * @throws CspError + one of the 6-code MVP error codes:
 *   - CSP_SCHEMA_VIOLATION: one of the 5 fields missing / disclosedClaims not an array / notAfter not ISO 8601 /
 *     audience/challenge not a string / propagated from canonicalSerialize;
 *   - CSP_SIGNATURE_INVALID: signature format error / public key format error / Ed25519 verify FAIL;
 *   - CSP_PAYLOAD_EXPIRED: notAfter ≤ now + minWindow;
 *   - CSP_AUDIENCE_MISMATCH: payload.audience !== expectedAudience (when opts enabled);
 *   - CSP_CHALLENGE_INVALID: payload.challenge !== expectedChallenge (when opts enabled);
 *   - CSP_TOKEN_MISSING: payload.token is not an object / null / undefined.
 */
export function verifySignature(
    payload: Record<string, unknown>,
    signature: string,
    publicKey: string,
    opts: VerifySignatureOptions = {},
): VerifySignatureResult {
    const {
        expectedAudience,
        expectedChallenge,
        now,
        minWindowMs = 1000,
        requireMandatoryFields = true,
        enforceFullSchema = true,
    } = opts;

    // step 0: full L0 AJV schema validate
    // fail-closed by default to prevent a caller using the L1 entry directly from bypassing the schema
    // third line of defense; the L2 pipeline may opt out (explicit false)
    if (enforceFullSchema) {
        const schemaResult = validateCspPayload(payload);
        if (!schemaResult.valid) {
            const firstError = schemaResult.errors[0];
            const errorPath = firstError?.instancePath ?? '(root)';
            const errorMsg = firstError?.message ?? 'unknown schema violation';
            throw new CspError(
                'CSP_SCHEMA_VIOLATION',
                `verifySignature step 0: L0 AJV schema validate FAIL at ${errorPath}: ${errorMsg} (fail-closed: callers invoking L1 verify directly must still satisfy the CSP schema).`,
            );
        }
    }

    // step 1: mandatory field check (spec I1 + I6 + I2 token + disclosedClaims primitive type)
    if (requireMandatoryFields) {
        assertMandatoryFields(payload);
    }

    // step 2: signature format + public key format check
    const signatureBytes = assertSignature(signature);
    const publicKeyBytes = assertPublicKey(publicKey);

    // step 3: canonicalSerialize → recomputedBytes (step 8.2 + I7)
    const recomputedBytes = canonicalSerialize(payload);

    // step 4: Ed25519 verify (step 8.3)
    let signatureValid: boolean;
    try {
        signatureValid = ed25519.verify(
            signatureBytes,
            recomputedBytes,
            publicKeyBytes,
        );
    } catch (error) {
        throw new CspError(
            'CSP_SIGNATURE_INVALID',
            'verifySignature: Ed25519 verify threw (signature/publicKey/canonicalBytes corrupted).',
            error instanceof Error ? error : undefined,
        );
    }

    if (!signatureValid) {
        throw new CspError(
            'CSP_SIGNATURE_INVALID',
            'verifySignature: Ed25519 verify FAIL (signature does not match canonicalSerialize(payload) under publicKey).',
        );
    }

    // step 5: notAfter expiry check (when opts.now enabled; spec I5)
    if (now !== undefined) {
        if (typeof payload.notAfter !== 'string') {
            throw new CspError(
                'CSP_SCHEMA_VIOLATION',
                `verifySignature: notAfter field must be string (got ${typeof payload.notAfter}).`,
            );
        }
        assertNotAfter(payload.notAfter, now, minWindowMs);
    }

    // step 6: audience strict equality comparison (when opts.expectedAudience enabled; spec I4)
    if (expectedAudience !== undefined) {
        assertAudience(payload.audience, expectedAudience);
    }

    // step 7: challenge strict equality comparison (when opts.expectedChallenge enabled; spec I3)
    if (expectedChallenge !== undefined) {
        assertChallenge(payload.challenge, expectedChallenge);
    }

    // step 8: all passed → ACCEPTED
    return { valid: true };
}

/**
 * mapCspErrorCodeToMessage — phantom-guard exhaustive switch
 *
 * Purpose: every CspErrorCode must have a literal message mapping; if the union expands without a
 * synchronized case → assertNever compile-time failure. This function is mainly used by upper-layer
 * logging / debugging / error-catch routing; it does not participate in the main verify flow (the
 * main verify flow throws CspError directly with a message).
 *
 * Anti-phantom design (physically enforced):
 *   - 6 cases, one literal mapping per code;
 *   - default → assertNever (TypeScript compile-time exhaustive guard);
 *   - if the 6-code union later expands → this function fails at compile time → forcing developers
 *     to update the switch in sync (no silent skip allowed).
 */
export function mapCspErrorCodeToMessage(code: CspErrorCode): string {
    switch (code) {
        case 'CSP_SCHEMA_VIOLATION':
            return 'csp signed payload schema / structure / canonicalize invariant violated';
        case 'CSP_CANONICALIZE_MISMATCH':
            return 'csp canonical hash mismatch / canonicalize SHA-256 failed';
        case 'CSP_SIGNATURE_INVALID':
            return 'csp signed payload Ed25519 signature verify FAIL';
        case 'CSP_PAYLOAD_EXPIRED':
            return 'csp signed payload notAfter expired';
        case 'CSP_AUDIENCE_MISMATCH':
            return 'csp signed payload audience !== verifier.expectedAudience';
        case 'CSP_CHALLENGE_INVALID':
            return 'csp signed payload challenge !== verifier-issued challenge';
        case 'CSP_TOKEN_MISSING':
            return 'csp signed payload token is null / undefined / not object';
        case 'CSP_PAYLOAD_INCOMPLETE':
            return 'csp signed payload missing mandatory field';
        case 'CSP_TOKEN_VERSION_UNSUPPORTED':
            return 'csp token.specVersion not in supported enum';
        case 'CSP_DISCLOSURE_INVALID':
            return 'csp disclosedClaims invalid (mode B selective disclosure)';
        case 'CSP_CHALLENGE_EXPIRED':
            return 'csp challenge nonce expired (verifier-side challenge ttl)';
        case 'CSP_REVOCATION_QUERY_UNAVAILABLE':
            return 'csp token.revocationUrl query failed (token revocation check)';
        case 'CSP_VERSION_UNSUPPORTED':
            return 'csp cspVersion not supported (version negotiation)';
        default:
            return assertNever(code);
    }
}
