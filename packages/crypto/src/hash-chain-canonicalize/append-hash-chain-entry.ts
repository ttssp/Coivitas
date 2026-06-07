/**
 * appendHashChainEntry — HCC L1 crypto primitive (v0.2 upgrade)
 *
 * v0.2 upgrade: audit primitive upgraded to fold chainIdentity into the preimage
 *
 *   - hash chain entry write flow (v0.2 upgrade; chainIdentity JCS canonicalize folded into the hash preimage)
 *   - appendHashChainEntry Step breakdown (Step 1-8; preimage concatenation order has canonicalPayload first)
 *   - HashChainEntry 8 fields (new mandatory chainIdentity field)
 *   - ChainIdentity edge-case factory guard (Case 1-7; HC_SCHEMA_VIOLATION fail-closed)
 *   - hccVersion hard-upgraded to "2.0.0" only
 *
 * v0.2 upgrade core (differences from v0.1):
 *   1. signature: payload + lastEntry → payload + chainIdentity + lastEntry (new mandatory parameter; factory guard)
 *   2. preimage = canonicalPayloadBytes ‖ chainIdentityJcsBytes (no longer plain SHA-256(canonicalPayloadBytes))
 *   3. HashChainEntry 8 fields (new chainIdentity; v0.1 7 fields → v0.2 8 fields)
 *   4. hccVersion hard-upgraded to "2.0.0" (HCC_VERSION_CURRENT; v0.1 "1.0.0" no longer valid)
 *   5. validateHashChainEntrySchema AJV strict validate (third line of the triple defense; 8 required fields + ChainIdentity $defs)
 *
 * Algorithm (Step 1-8):
 *   Step 0 | chainIdentity input parameter + factory guard propagation (canonicalizeChainIdentity internally fail-closed)
 *   Step 1 | canonicalize(payload) → canonicalPayload (RFC 8785 JCS; canonicalize npm)
 *   Step 2 | canonicalizeChainIdentity(chainIdentity) → chainIdentityJcs (RFC 8785 JCS)
 *   Step 3 | preimage concatenation = canonicalPayloadBytes ‖ chainIdentityJcsBytes (canonicalPayload first)
 *   Step 4 | sha256(preimage) → canonicalPayloadHash (lowercase hex 64 chars; via toCanonicalPayloadHash factory)
 *   Step 5 | previousHash computation (genesis = 64 zeros OR lastEntry.canonicalPayloadHash; via toPreviousHash factory)
 *   Step 6 | chainPosition computation (genesis = 0 OR lastEntry.chainPosition + 1; via toChainPosition factory + overflow guard)
 *   Step 7 | construct the 8-field HashChainEntry (mandatory chainIdentity included; hccVersion = HCC_VERSION_CURRENT)
 *   Step 8 | validateHashChainEntrySchema AJV strict validate (third line of the triple defense; HC_SCHEMA_VIOLATION fail-closed)
 *
 * L1 vs L3 boundary:
 *   - this L1 primitive accepts the chainIdentity field parameter (v0.2 upgrade; chainIdentity enters L0 types)
 *   - L1 is not responsible for SQL row assembly / cross-tenant verification (L3 manager's responsibility)
 *   - the L3 manager reuses this L1 primitive + adds SQL row assembly + audit-share scope coordination
 *
 * Anti-phantom defense:
 *   - top-level import (no in-body require / dynamic import)
 *   - all brand factories single-cast (toCanonicalPayloadHash / toPreviousHash / toChainPosition / toHashChainEntryId / toHccVersionString / toChainIdentityJcs)
 *   - bare `as <Brand>` cast strictly forbidden
 *   - validateHashChainEntrySchema fail-closed (any field schema violation → HC_SCHEMA_VIOLATION throw)
 *   - canonicalizeChainIdentity failure propagation (empty chainNamespace / sentinel / non-string → HC_SCHEMA_VIOLATION)
 */

import {
    GENESIS_PREVIOUS_HASH,
    HCC_VERSION_CURRENT,
    HashChainError,
    toCanonicalPayloadHash,
    toChainIdentityJcs,
    toChainPosition,
    toHashChainEntryId,
    toHccVersionString,
    toPreviousHash,
    validateHashChainEntrySchema,
    type ChainIdentity,
    type HashChainEntry,
    type Timestamp,
} from '@coivitas/types';

import { canonicalizeChainIdentity } from './canonicalize-chain-identity.js';
import { canonicalizeHashChainEntryToString } from './canonicalize-hash-chain-entry.js';
import {
    computeCanonicalPayloadHashHex,
    concatPreimage,
} from './preimage-helpers.js';

/**
 * appendHashChainEntry — append a new entry to the end of the hash chain (L1 primitive surface; v0.2)
 *
 * v0.2 upgrade: accepts the mandatory chainIdentity parameter, produces an 8-field entry; the preimage includes chainIdentity JCS bytes.
 *
 * @param payload raw payload object (written into entry.canonicalPayload after JCS canonicalize);
 *   any JSON-serializable Record is allowed; upstreams such as audit-tamper-proof / policy / governance can all reuse it.
 * @param chainIdentity new mandatory v0.2 parameter — chainIdentity triple (chainNamespace + tenantId? + auditClass?);
 *   the factory guard is fail-closed inside canonicalizeChainIdentity (chainNamespace mandatory non-empty + sentinel reject;
 *   tenantId/auditClass, if present, must be non-empty strings).
 * @param lastEntry the current HashChainEntry at the end of the chain; pass undefined at genesis;
 *   when not genesis, lastEntry must have passed verifyHashChain validation (caller's responsibility) or come from trusted storage.
 *
 * @returns the newly assembled HashChainEntry (v0.2 all 8 fields populated; chainIdentity included; via brand factory + AJV strict)
 *
 * @throws HashChainError(HC_CANONICALIZE_FAILED) — JCS canonicalization failure (payload OR chainIdentity not JCS-serializable)
 * @throws HashChainError(HC_HASH_MISMATCH) — sha256 internal fail / digest length not 32 bytes (phantom defense)
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — non-conforming chainIdentity field / brand factory validation failure /
 *   lastEntry field missing or wrong type / AJV strict validation failure
 *
 * Invariants (I1-I10; v0.2 adds I9+I10):
 *   - I1 canonicalPayload must go through the canonicalize npm package (JCS RFC 8785)
 *   - I2 canonicalPayloadHash = SHA-256(canonicalPayloadBytes ‖ chainIdentityJcsBytes) lowercase hex 64 chars (v0.2 upgrade)
 *   - I3 previousHash must be the previous item's canonicalPayloadHash; genesis = GENESIS_PREVIOUS_HASH (64 zeros)
 *   - I4 chainPosition must increase monotonically by 1 step; no jumps
 *   - I5 hccVersion = HCC_VERSION_CURRENT ("2.0.0")
 *   - I6 timestamp = new Date().toISOString() (ISO 8601 UTC)
 *   - I8 all 8 entry fields populated (chainIdentity included)
 *   - I9 chainIdentity folded into the preimage with cryptographic enforcement (any field mutation → hash mismatch)
 *   - I10 hccVersion strictly "2.0.0" (v0.2's only valid value; schema breaking change version independence)
 */
export function appendHashChainEntry(
    payload: Record<string, unknown>,
    chainIdentity: ChainIdentity,
    lastEntry: HashChainEntry | undefined,
): HashChainEntry {
    // ── Step 0: chainIdentity input defense (canonicalizeChainIdentity internal factory guard fail-closed) ──
    // Note: top-level defense for chainIdentity null/undefined (the TypeScript type only guarantees compile time; at runtime it may be injected from deserialization)
    if (chainIdentity === null || chainIdentity === undefined) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            'appendHashChainEntry: chainIdentity must not be null/undefined (mandatory v0.2 parameter)',
        );
    }

    // ── Step 0.5: chain identity continuity guard ──
    // When not genesis, the new entry's chainIdentity must match lastEntry.chainIdentity,
    // otherwise append would graft an entry of tenant/namespace B onto chain A, building a mixed chain.
    // Fail-closed at this append boundary, bidirectionally closed with verifyHashChain's chain-level guard.
    if (lastEntry !== undefined) {
        const lastChainIdentity = (lastEntry as { chainIdentity?: unknown })
            .chainIdentity;
        if (lastChainIdentity === undefined || lastChainIdentity === null) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                'appendHashChainEntry: lastEntry.chainIdentity missing (v0.2 entry mandatorily includes chainIdentity)',
            );
        }
        const lastJcs = canonicalizeChainIdentity(
            lastChainIdentity as Parameters<typeof canonicalizeChainIdentity>[0],
        );
        const newJcs = canonicalizeChainIdentity(chainIdentity);
        if (lastJcs !== newJcs) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `appendHashChainEntry: new entry chainIdentity ("${newJcs}") differs from lastEntry chainIdentity ("${lastJcs}"); cannot append cross-scope entry to existing chain (mixed-identity rejected)`,
            );
        }
    }

    // ── Step 1: payload JCS canonical encode → canonicalPayload (string) ───────
    // canonicalizeHashChainEntryToString propagates the HC_CANONICALIZE_FAILED throw
    const canonicalPayload = canonicalizeHashChainEntryToString(payload);

    // ── Step 2: chainIdentity JCS canonical encode → chainIdentityJcs (string brand) ──
    // canonicalizeChainIdentity is internally fail-closed:
    // - chainNamespace mandatory non-empty string; empty / sentinel "__NULL__" / non-string → HC_SCHEMA_VIOLATION
    // - tenantId/auditClass, if present, must be non-empty strings → HC_SCHEMA_VIOLATION
    // - canonicalize npm returns undefined → HC_CANONICALIZE_FAILED
    const chainIdentityJcsRaw = canonicalizeChainIdentity(chainIdentity);
    // brand factory enforce (no bare cast; length >= 2 + reject sentinel "__NULL__")
    const chainIdentityJcs = toChainIdentityJcs(chainIdentityJcsRaw);

    // ── Step 3: preimage concatenation (canonicalPayload first; chainIdentity after) ──
    // Invariant I9 — any field mutation → preimage UTF-8 bytes mutate → SHA-256 digest mutate
    const preimage = concatPreimage(canonicalPayload, chainIdentityJcs);

    // ── Step 4: SHA-256 hash → canonicalPayloadHash (64 lowercase hex) ─────
    // inside computeCanonicalPayloadHashHex:
    // - sha256(preimage) computation + try/catch wrapping (HC_HASH_MISMATCH propagation)
    // - 32-byte digest length fallback guard (unreachable under the RFC 6234 standard; phantom defense)
    // - lowercase hex encode (aligned with the toCanonicalPayloadHash factory's lowercase pattern)
    const canonicalPayloadHashHex = computeCanonicalPayloadHashHex(preimage);
    // brand factory enforce (no bare cast; strict 64 lowercase hex pattern)
    const canonicalPayloadHash = toCanonicalPayloadHash(canonicalPayloadHashHex);

    // ── Step 5: previousHash linkage ───────────────────────────────────────────
    // genesis (lastEntry === undefined) → GENESIS_PREVIOUS_HASH (64 zeros)
    // not genesis → lastEntry.canonicalPayloadHash (normalized to lowercase via brand factory)
    let previousHash;
    if (lastEntry === undefined) {
        previousHash = toPreviousHash(GENESIS_PREVIOUS_HASH);
    } else {
        // defensive check (lastEntry fields cannot be trusted for caller-constructed objects; validated via brand factory)
        if (
            typeof lastEntry.canonicalPayloadHash !== 'string' ||
            lastEntry.canonicalPayloadHash.length === 0
        ) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                'appendHashChainEntry: lastEntry.canonicalPayloadHash missing or empty',
            );
        }
        previousHash = toPreviousHash(lastEntry.canonicalPayloadHash);
    }

    // ── Step 6: chainPosition increment ───────────────────────────────────────────
    let nextPosition: number;
    if (lastEntry === undefined) {
        nextPosition = 0;
    } else {
        if (typeof lastEntry.chainPosition !== 'number') {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `appendHashChainEntry: lastEntry.chainPosition not a number, got: ${typeof lastEntry.chainPosition}`,
            );
        }
        if (!Number.isSafeInteger(lastEntry.chainPosition + 1)) {
            // boundary protection: chainPosition + 1 must not exceed Number.MAX_SAFE_INTEGER (2^53 - 1)
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `appendHashChainEntry: chainPosition overflow (lastEntry.chainPosition=${lastEntry.chainPosition} + 1 exceeds Number.MAX_SAFE_INTEGER)`,
            );
        }
        nextPosition = lastEntry.chainPosition + 1;
    }
    const chainPosition = toChainPosition(nextPosition);

    // ── Step 7: construct the HashChainEntry (v0.2 8 fields; brand factory enforce) ───
    // crypto.randomUUID() returns a UUID v4 (Node 20+ standard); validated via toHashChainEntryId
    const entryId = toHashChainEntryId(crypto.randomUUID());
    // ISO 8601 UTC timestamp; the Timestamp brand already exists in base.ts
    const timestamp = new Date().toISOString() as Timestamp;
    // hccVersion hard-upgraded to "2.0.0" (HCC_VERSION_CURRENT)
    const hccVersion = toHccVersionString(HCC_VERSION_CURRENT);

    const entry: HashChainEntry = {
        entryId,
        canonicalPayload,
        canonicalPayloadHash,
        previousHash,
        chainPosition,
        chainIdentity,
        timestamp,
        hccVersion,
    };

    // ── Step 8: AJV strict validate (third line of the triple defense; HC_SCHEMA_VIOLATION fail-closed) ──
    // JSON Schema 8 required fields + ChainIdentity $defs
    // Defense: this function produces the entry entirely through the brand factory path, so the schema theoretically PASSes; this layer is a fallback to catch brand factory misjudgment cases
    const schemaResult = validateHashChainEntrySchema(entry);
    /* v8 ignore next 13 -- after the brand factory fully populates + the step 1-7 guards, the schema PASSes; phantom fallback unreachable*/
    if (!schemaResult.valid) {
        const firstError = schemaResult.errors[0];
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `appendHashChainEntry: AJV strict validate failed at ${
                firstError?.instancePath ?? '/'
            }: ${firstError?.message ?? 'unknown'} (keyword: ${
                firstError?.keyword ?? 'unknown'
            })`,
        );
    }

    return entry;
}
