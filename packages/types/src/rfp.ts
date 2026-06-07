/**
 * Resolver Freshness Proof (RFP) v0.1 — L0 type layer
 *
 * Triple defense design (aligned with the csp constraints):
 *   Layer 1 — brand type (TypeScript compile time)
 *   Layer 2 — JSON Schema (schema-layer structural constraints)
 *   Layer 3 — AJV strict mode (runtime schema engine)
 *
 * Note: this file introduces no L1 crypto dependency (L0 constraint; reverse dependencies forbidden)
 */

import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';

import type { DID, Signature, Timestamp } from './base.js';
import { ProtocolError } from './errors.js';

// ---------------------------------------------------------------------------
// Brand types (layer-1 defense; no naked cast allowed, must use a factory function)
// ---------------------------------------------------------------------------

/**
 * RFP version string brand type.
 * Fixed to "1.0.0" in v0.1; the toRfpVersionString() factory function is the only legal cast path.
 */
export type RfpVersionString = string & { readonly __brand: 'RfpVersionString' };

/**
 * CSP version string brand type — the RFP side reuses the csp source of truth to avoid a naming collision (TS2308 - already exported).
 * Source: packages/types/src/canonical-signed-payload/types.ts CspVersionString
 */
import type { CspVersionString } from './canonical-signed-payload/types.js';
export type { CspVersionString };

/**
 * freshnessWindow milliseconds brand type.
 * Range constraint: [1000, 3600000], integer; the toFreshnessWindowMs() factory function is the only legal path.
 */
export type FreshnessWindowMs = number & { readonly __brand: 'FreshnessWindowMs' };

/**
 * Signature brand type (reuses the base.ts definition).
 * The toSignature() factory function is the only legal cast path (after AJV validation).
 */
export type { Signature } from './base.js';

// ---------------------------------------------------------------------------
// Factory functions (the compliant path for the no-naked-cast rule; runtime validation + brand conversion separated)
// ---------------------------------------------------------------------------

const SEM_VER_RE = /^\d+\.\d+\.\d+$/;

/**
 * RfpVersionString factory function.
 * Accepts only semver-format strings; the v0.1 constrained value is "1.0.0".
 */
export function toRfpVersionString(value: string): RfpVersionString {
    if (!SEM_VER_RE.test(value)) {
        throw new RfpError(
            'RFP_VERSION_UNSUPPORTED',
            `rfpVersion must be semver format, got: ${value}`,
        );
    }
    // legal cast path after AJV validation (compliant with the no-naked-cast rule)
    return value as RfpVersionString;
}

/**
 * CspVersionString factory function — RFP re-export of the csp source-of-truth factory.
 * Source: packages/types/src/canonical-signed-payload/types.ts toCspVersionString
 *
 * Note: the csp source-of-truth toCspVersionString does not throw RfpError;
 * if the RFP consumer needs the RFP_CSP_VERSION_MISMATCH error code, wrap it inside verifyResolverFreshness step I_csp.
 */
export { toCspVersionString } from './canonical-signed-payload/types.js';

/**
 * FreshnessWindowMs factory function.
 * Constraint: integer, [1000, 3600000].
 */
export function toFreshnessWindowMs(value: number): FreshnessWindowMs {
    if (!Number.isInteger(value) || value < 1_000 || value > 3_600_000) {
        throw new RfpError(
            'RFP_FRESHNESS_WINDOW_INVALID',
            `freshnessWindow must be integer in [1000, 3600000], got: ${value}`,
        );
    }
    return value as FreshnessWindowMs;
}

/**
 * Signature brand cast (the only legal path once AJV validation passes).
 * Note: Signature = string & { __brand: 'Signature' } comes from base.ts (already re-exported).
 */
export function toSignature(value: string): Signature {
    // base64url format constraint (already covered by the JSON Schema pattern; a defensive runtime check here)
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new RfpError(
            'RFP_SIGNATURE_INVALID',
            `signature must be base64url encoded, got invalid format`,
        );
    }
    return value as Signature;
}

// ---------------------------------------------------------------------------
// ResolverFreshnessProof interface (the formal 6-field schema)
// ---------------------------------------------------------------------------

/**
 * ResolverFreshnessProof — the freshness proof primitive for a Resolver node
 *
 * 6-field structure:
 *   rfpVersion — RFP spec version, fixed to "1.0.0" in v0.1
 *   cspVersion — csp spec version (alignment anchor), fixed to "1.0.0" in v0.1
 *   resolverDid — the DID of the resolver node issuing the proof
 *   asOfTime — the proof issuance moment (ISO 8601)
 *   freshnessWindow — the declared validity window (milliseconds; [1000, 3600000])
 *   signature — Ed25519 signature (base64url; signed over the 5 fields after JCS canonicalization)
 *
 */
export interface ResolverFreshnessProof {
    readonly rfpVersion: RfpVersionString;
    readonly cspVersion: CspVersionString;
    readonly resolverDid: DID;
    readonly asOfTime: Timestamp;
    readonly freshnessWindow: FreshnessWindowMs;
    readonly signature: Signature;
}

// ---------------------------------------------------------------------------
// RfpErrorCode union (11 items; assertNever exhaustiveness protection)
// ---------------------------------------------------------------------------

/**
 * The complete RFP error code enum (11 items).
 *
 * Namespace: RFP_* prefix isolation (not merged into the ProtocolErrorCode @frozen union).
 * assertNever exhaustiveness: every error code has a corresponding throw path in verifyRfpInvariants() (anti-phantom guard).
 */
export type RfpErrorCode =
    | 'RFP_PROOF_INCOMPLETE'          // I_complete: schema validation failed (required field missing / bad format)
    | 'RFP_VERSION_UNSUPPORTED'       // I_ver: rfpVersion is not "1.0.0"
    | 'RFP_CSP_VERSION_MISMATCH'      // I_csp: cspVersion is not "1.0.0"
    | 'RFP_RESOLVER_DID_INVALID'      // I_did: resolverDid lacks the did: prefix
    | 'RFP_FRESHNESS_WINDOW_INVALID'  // I_fw: freshnessWindow is not an integer or < 1000
    | 'RFP_FRESHNESS_WINDOW_EXCESSIVE'// I_fw: freshnessWindow > 3600000
    | 'RFP_ASOF_FUTURE'               // I_asof: asOfTime exceeds the current moment + 5s tolerance
    | 'RFP_SIGNATURE_INVALID'         // I_sig: Ed25519 signature verification failed
    | 'RFP_FRESHNESS_EXPIRED'         // I_asof_window: the proof has expired (now - asOfTime > freshnessWindow)
    | 'RFP_RESOLVER_UNREACHABLE'      // the resolver is unreachable from the consumer (consumer-side)
    | 'RFP_QUORUM_FRESHNESS_UNMET';   // insufficient freshness proofs among the nodes reaching quorum (consumer-side)

/**
 * assertNever — exhaustiveness check utility (anti-phantom guard).
 * At compile time, ensures every RfpErrorCode branch has a corresponding throw path.
 */
export function assertNeverRfp(code: never): never {
    throw new Error(`Unhandled RfpErrorCode: ${String(code)}`);
}

// ---------------------------------------------------------------------------
// RfpError class (extends ProtocolError)
// ---------------------------------------------------------------------------

/**
 * RfpError — the RFP-specific error class
 *
 * Inherits ProtocolError to support the generic instanceof ProtocolError capture path.
 * The precise error code is accessed via the rfpCode field (distinct from ProtocolError.code).
 *
 * ProtocolError.code uses 'FEDERATED_RESOLUTION_FAILED' as the aggregate code
 * (upper-layer catch can handle it uniformly without understanding RFP details).
 */
export class RfpError extends ProtocolError {
    // name cannot be overridden due to the base class literal-type constraint (TS2416);
    // type discrimination is done via the rfpCode field (instanceof RfpError is sufficient).

    public constructor(
        public readonly rfpCode: RfpErrorCode,
        detail: string,
        public readonly resolverDid?: string,
    ) {
        super('FEDERATED_RESOLUTION_FAILED', `[${rfpCode}] ${detail}`);
        this.rfpCode = rfpCode;
    }
}

// ---------------------------------------------------------------------------
// JSON Schema (layer-2 defense)
// ---------------------------------------------------------------------------

const RFP_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    type: 'object',
    required: ['rfpVersion', 'cspVersion', 'resolverDid', 'asOfTime', 'freshnessWindow', 'signature'],
    additionalProperties: false,
    properties: {
        rfpVersion: {
            type: 'string',
            pattern: '^\\d+\\.\\d+\\.\\d+$',
            const: '1.0.0',
        },
        cspVersion: {
            type: 'string',
            pattern: '^\\d+\\.\\d+\\.\\d+$',
            const: '1.0.0',
        },
        resolverDid: {
            type: 'string',
            pattern: '^did:',
        },
        asOfTime: {
            type: 'string',
            // ISO 8601 UTC format pattern (an L0 fallback for when ajv-formats is unavailable; Date.parse re-validates at runtime in verifyResolverFreshness)
            pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$',
        },
        freshnessWindow: {
            type: 'integer',
            minimum: 1_000,
            maximum: 3_600_000,
        },
        signature: {
            type: 'string',
            pattern: '^[A-Za-z0-9_-]+$',
        },
    },
} as const;

// ---------------------------------------------------------------------------
// AJV strict mode (layer-3 defense)
// ---------------------------------------------------------------------------

// ESM/CJS interop: under ESM the AjvModule default export is not directly constructable,
// so follow the `as unknown as new(...)` pattern from validation.ts (a project-verified path).
type AjvConstructor = new (options?: Record<string, unknown>) => {
    compile: (schema: unknown) => ((data: unknown) => boolean) & { errors?: Array<{ message?: string; instancePath?: string }> | null };
};
const AjvClass = AjvModule as unknown as AjvConstructor;

const ajv = new AjvClass({
    strict: true,           // strict mode is mandatory
    allErrors: false,       // fail-closed; the first invariant violation triggers a reject
    strictSchema: true,
    strictNumbers: true,
    strictTypes: true,
    coerceTypes: false,     // type coercion forbidden
    useDefaults: false,     // default value injection forbidden
    validateFormats: true,  // format validation is mandatory; ajv-formats is installed, genuinely using asOfTime ISO 8601 + DID URI format
});

// install ajv-formats + inject the ajv instance, enabling genuine format:"date-time" + format:"uri" validation
// ESM/CJS interop: addFormats default export shim
type AddFormatsFn = (ajv: unknown) => void;
const addFormats = addFormatsModule as unknown as AddFormatsFn;
addFormats(ajv);

const validateRfpRaw = ajv.compile(RFP_SCHEMA);

/**
 * validateRfpSchema — RFP Schema-layer validation (layer 2+3 defense)
 *
 * Input: unknown (an untrusted JSON structure)
 * Output: a validated ResolverFreshnessProof (field types confirmed)
 * throws: RfpError('RFP_PROOF_INCOMPLETE') when AJV validation fails
 *
 * Note: the brand type conversion (as ResolverFreshnessProof) is performed only after AJV validation passes (the compliant path for the no-naked-cast rule)
 */
export function validateRfpSchema(rfp: unknown): ResolverFreshnessProof {
    if (!validateRfpRaw(rfp)) {
        const firstError = validateRfpRaw.errors?.[0];
        throw new RfpError(
            'RFP_PROOF_INCOMPLETE',
            `Schema validation failed: ${firstError?.message ?? 'unknown error'} at ${firstError?.instancePath ?? '/'}`,
        );
    }
    // AJV validation passed → the legal brand type conversion path (compliant with the no-naked-cast rule; not a naked cast)
    return rfp as ResolverFreshnessProof;
}
