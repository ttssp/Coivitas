/**
 * verifyHashChain — HCC L1 crypto primitive (v0.2 upgrade)
 *
 *   - hash chain verification flow (v0.2 upgrade; chainIdentity preimage is directly in the cryptographic-enforce scope)
 *   - verifyHashChain step refinement (Step 0-3.3)
 *   - verifyHashChain helper functions (assertCanonicalPayloadHashConsistent /
 *     recomputeCanonicalPayloadHash)
 *   - Design principle: fail-closed enforced; any verification failure → throw HC_*
 *   - security properties I1-I10 (v0.2 added I9+I10)
 *   - hccVersion strictly "2.0.0" only
 *
 * v0.2 upgrade core (difference from v0.1):
 *   1. Step 0 added — assertCanonicalPayloadHashConsistent(entry, i) runs the full
 *      recomputeCanonicalPayloadHash pipeline (canonicalizeChainIdentity + concatPreimage + computeCanonicalPayloadHashHex);
 *      replacing the v0.1 step-4 path that only re-hashed sha256(canonicalPayloadBytes).
 *   2. Mutating any entry's chainIdentity field → JCS canonicalize output mutates → preimage mutates →
 *      SHA-256 digest differs → throw HC_HASH_MISMATCH (HC_HASH_MISMATCH is used here to keep the
 *      error-code semantics consistent with v0.1 verify-hash-chain; assertCanonicalPayloadHashConsistent currently throws
 *      HC_HASH_MISMATCH internally, see the verify-helpers.ts comments)
 *   3. Step 2.3 added — hccVersion strictly "2.0.0" literal-equality verify; on mismatch → throw
 *      HC_CHAIN_IDENTITY_SCHEMA_BREAKING (I10)
 *
 * Algorithm ( Step 0-3 ):
 *   Step 0 | entries.length === 0 → return (empty chain is valid; NO-OP)
 *   Step 1 | genesis entry check — entries[0].chainPosition === 0 + entries[0].previousHash === 64 zeros
 *   Step 2 | sequential traversal i = 1 to entries.length - 1:
 *              Step 2.1 | schema validate (HC_SCHEMA_VIOLATION; requires chainIdentity + hccVersion const "2.0.0")
 *              Step 2.2 | chainPosition monotonic — entries[i].chainPosition === entries[i-1].chainPosition + 1
 *              Step 2.3 | previousHash linking — entries[i].previousHash === entries[i-1].canonicalPayloadHash
 *              Step 2.4 | hccVersion strictly "2.0.0" (HC_CHAIN_IDENTITY_SCHEMA_BREAKING; I10)
 *   Step 3 | chainIdentity preimage cryptographic enforce over all entries —
 *              forEach entries: assertCanonicalPayloadHashConsistent(entry, i) literal-equality verify
 *              tampering with any entry's chainIdentity OR canonicalPayload → throw HC_HASH_MISMATCH
 *
 * Verification-order rationale:
 *   schema (precondition) → chainPosition monotonic (structure) → previousHash linking (linkage) → hccVersion consistent (version) →
 *   chainIdentity preimage cryptographic enforce (data; most expensive).
 *   The chainIdentity preimage recompute runs only after the first 4 steps pass → saves hash computation on the reject path.
 *
 * L1 scope:
 *   - this L1 primitive only verifies hash-chain primitive properties (chainPosition monotonic + previousHash linking +
 *     chainIdentity preimage cryptographic enforce + schema invariant);
 *   - accepts a v0.2 8-field entries array (chainIdentity required);
 *   - chain scope verification (cross-tenant / cross-namespace) is pushed to the upstream audit-share L3 manager;
 *   - caller responsibility: query by scope, then pass in a same-scope entries array.
 *
 * Robustness defenses:
 *   - top-level import (no in-function require/dynamic import);
 *   - fail-closed throw enforced (no silent return false / partial-PASS / WARNING-only);
 *   - empty array (entries.length === 0) → return directly (NO-OP; empty chain is a valid state);
 *   - active invocation required (no stub default success; crypto verification primitive is strict);
 *   - assertCanonicalPayloadHashConsistent does an internal literal-equality verify (recomputed === stored); any mismatch throws.
 */

import {
    GENESIS_PREVIOUS_HASH,
    HCC_VERSION_CURRENT,
    HashChainError,
    validateHashChainEntrySchema,
    type HashChainEntry,
} from '@coivitas/types';

import { canonicalizeChainIdentity } from './canonicalize-chain-identity.js';
import { assertCanonicalPayloadHashConsistent } from './verify-helpers.js';

/**
 * VerifyHashChainOptions — optional verifyHashChain scope/checkpoint guards
 *
 * Security root cause:
 *   Before this, v0.2 verifyHashChain only re-hashed each entry using its own chainIdentity + checked previousHash linking;
 *   it took no expected chain identity and required no external checkpoint. This allowed two classes of bypass:
 *     (1) a mixed-chainIdentity chain A→B (B.previousHash points to A, each hash individually correct) passes verification → identity-rebinding
 *         (breaks cross-tenant/audit-scope isolation)
 *     (2) empty array / suffix deletion / full deletion return success (the remaining prefix is internally consistent) → deletion/truncation tampering goes undetected
 *
 * Fix (must be passed for audit/ledger scenarios):
 *   - expectedChainIdentity: assert all entries share the same chainIdentity (canonical JCS literal equality)
 *   - checkpoint: an externally trusted anchor (expected non-empty + last chainPosition + head/tail hash + count)
 */
export interface VerifyHashChainOptions {
    /**
     * Expected chainIdentity (audit/ledger scope-isolation guard).
     * When passed: each entry's chainIdentity canonical JCS must be literally equal to this value; any mismatch → throw.
     * When omitted: degrades to the old v0.2 behavior (intra-chain consistency only, no scope guard) — for non-security-sensitive self-consistency checks only.
     */
    readonly expectedChainIdentity?: {
        readonly chainNamespace: string;
        readonly tenantId?: string;
        readonly auditClass?: string;
    };
    /**
     * Externally trusted checkpoint (deletion/truncation guard).
     * When passed, assertions are made per field; any mismatch → throw. audit/ledger verification must pass this to detect deletion tampering.
     */
    readonly checkpoint?: {
        /** Require a non-empty chain (empty array → throw; prevents "delete all rows" being judged legal)*/
        readonly requireNonEmpty?: boolean;
        /** Expected total entry count (literally equal to entries.length; prevents truncation/insertion)*/
        readonly expectedEntryCount?: number;
        /** Expected last chainPosition (prevents tail truncation)*/
        readonly expectedLastChainPosition?: number;
        /** Expected last canonicalPayloadHash (external head/tail anchor; prevents tail truncation)*/
        readonly expectedLastCanonicalPayloadHash?: string;
    };
}

/**
 * verifyHashChain — hash-chain integrity verification (sequential traversal; fail-closed; v0.2)
 *
 * v0.2 upgrade: chainIdentity preimage is directly cryptographically enforced — tampering with any chainIdentity OR
 * canonicalPayload → recomputed hash ≠ stored hash → throw HC_HASH_MISMATCH.
 *
 * @param entries HashChainEntry array sorted ascending by chainPosition (v0.2 8 fields; includes chainIdentity);
 *   genesis must be at the entries[0] position (chainPosition = 0 + previousHash = GENESIS_PREVIOUS_HASH);
 *   empty array (length === 0) returns directly (empty chain is a valid state; does not throw).
 *
 * @throws HashChainError(HC_SCHEMA_VIOLATION) — schema validation failed (missing field / bad format / bad brand / chainIdentity non-conformant)
 * @throws HashChainError(HC_CHAIN_POSITION_NONMONOTONIC) — chainPosition gap / duplicate / not equal to i
 * @throws HashChainError(HC_PREVIOUS_HASH_BROKEN) — previousHash linkage broken (a middle entry was deleted/tampered/inserted)
 * @throws HashChainError(HC_CHAIN_IDENTITY_SCHEMA_BREAKING) — hccVersion is not "2.0.0" (the only legal v0.2 value)
 * @throws HashChainError(HC_HASH_MISMATCH) — recomputed canonicalPayloadHash ≠ stored
 *   (chainIdentity OR canonicalPayload tampering; v0.2 upgrade enforces cryptographically in scope directly;
 *   assertCanonicalPayloadHashConsistent currently throws HC_HASH_MISMATCH internally, see the verify-helpers.ts comments)
 *
 * Invariant guards:
 *   - I1 canonicalize exclusive (assertCanonicalPayloadHashConsistent reuses the write-path algorithm in its internal recompute)
 *   - I2 SHA-256(canonicalPayloadBytes ‖ chainIdentityJcsBytes) === stored canonicalPayloadHash (v0.2 upgraded preimage)
 *   - I3 previousHash integrity: entries[i].previousHash === entries[i-1].canonicalPayloadHash
 *   - I4 chainPosition monotonic: entries[i].chainPosition === entries[i-1].chainPosition + 1
 *   - I5 hccVersion = HCC_VERSION_CURRENT ("2.0.0") — schema const guard + Step 2.4 explicit verify
 *   - I7 fail-closed enforced: any failure throws; does not return false and does not swallow errors
 *   - I9 chainIdentity enters the preimage cryptographic enforce — guarded by Step 3 assertCanonicalPayloadHashConsistent
 *   - I10 hccVersion strictly "2.0.0" — double-layered Step 2.4 literal-equality verify + schema const guard
 */
export function verifyHashChain(
    entries: readonly HashChainEntry[],
    options?: VerifyHashChainOptions,
): void {
    // ── Step -1: checkpoint requireNonEmpty / count guard (deletion detection) ──
    // Runs before the empty-chain return — otherwise "delete all rows" would be judged legal at Step 0
    const checkpoint = options?.checkpoint;
    if (checkpoint?.requireNonEmpty === true && entries.length === 0) {
        throw new HashChainError(
            'HC_PREVIOUS_HASH_BROKEN',
            'verifyHashChain: checkpoint.requireNonEmpty asserted but entries is empty (possible deletion of entire chain)',
        );
    }
    if (
        checkpoint?.expectedEntryCount !== undefined &&
        entries.length !== checkpoint.expectedEntryCount
    ) {
        throw new HashChainError(
            'HC_PREVIOUS_HASH_BROKEN',
            `verifyHashChain: checkpoint.expectedEntryCount (${checkpoint.expectedEntryCount}) !== actual entries.length (${entries.length}) (possible truncation/insertion)`,
        );
    }

    // ── Step 0: empty chain edge case (valid; NO-OP return) ─────────────────────
    if (entries.length === 0) {
        // empty chain is a valid state (no entry to verify); return directly
        // Note: checkpoint.requireNonEmpty was already guarded at Step -1
        return;
    }

    // ── Step 1: genesis entry check (entries[0] must be the genesis) ───────────────
    // Do the genesis check before the loop — distinguishes the chainPosition 0 + previousHash GENESIS dual invariants
    // Note: entries[0] necessarily exists (the length >= 1 check above passed)
    const genesis = entries[0]!;
    if (genesis === undefined || genesis === null) {
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            'verifyHashChain: entries[0] is null or undefined',
        );
    }

    // genesis schema validate (requires chainIdentity + hccVersion const "2.0.0")
    const genesisSchemaResult = validateHashChainEntrySchema(genesis);
    if (!genesisSchemaResult.valid) {
        const firstError = genesisSchemaResult.errors[0];
        throw new HashChainError(
            'HC_SCHEMA_VIOLATION',
            `verifyHashChain: entries[0] schema violation at ${firstError?.instancePath ?? '/'}: ${firstError?.message ?? 'unknown'} (keyword: ${firstError?.keyword ?? 'unknown'})`,
        );
    }

    // genesis chainPosition === 0 (I4 invariant; HC_CHAIN_POSITION_NONMONOTONIC)
    if ((genesis.chainPosition as unknown as number) !== 0) {
        throw new HashChainError(
            'HC_CHAIN_POSITION_NONMONOTONIC',
            `verifyHashChain: entries[0].chainPosition must be 0 (genesis), got ${genesis.chainPosition}`,
        );
    }

    // genesis previousHash === GENESIS_PREVIOUS_HASH (I3 invariant; HC_PREVIOUS_HASH_BROKEN)
    if ((genesis.previousHash as string) !== GENESIS_PREVIOUS_HASH) {
        throw new HashChainError(
            'HC_PREVIOUS_HASH_BROKEN',
            `verifyHashChain: entries[0].previousHash must be 64 zeros (genesis), got "${genesis.previousHash}"`,
        );
    }

    // genesis hccVersion === "2.0.0" (I10 invariant; the only legal v0.2 value)
    // Note: schema const "2.0.0" already guards this; the explicit verify here is a fallback + error-code refinement (HC_CHAIN_IDENTITY_SCHEMA_BREAKING)
    if ((genesis.hccVersion as string) !== HCC_VERSION_CURRENT) {
        throw new HashChainError(
            'HC_CHAIN_IDENTITY_SCHEMA_BREAKING',
            `verifyHashChain: entries[0].hccVersion must be "${HCC_VERSION_CURRENT}" (the only legal v0.2 value), got "${genesis.hccVersion}"`,
        );
    }

    // ── Step 2: sequential traversal i = 1 to entries.length - 1 (chain link + monotonic) ──
    for (let i = 1; i < entries.length; i++) {
        const current = entries[i];
        const previous = entries[i - 1];

        // Defensive null/undefined check (the TypeScript type is only a compile-time guarantee; at runtime the caller may pass null)
        if (current === undefined || current === null) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `verifyHashChain: entries[${i}] is null or undefined`,
            );
        }
        // previous necessarily exists (i >= 1; i - 1 >= 0; loop bound i < length)
        /* v8 ignore next 6 -- TypeScript noUncheckedIndexedAccess defensive fallback; the loop bound guarantees i-1 exists*/
        if (previous === undefined || previous === null) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `verifyHashChain: entries[${i - 1}] is null or undefined (loop boundary phantom)`,
            );
        }

        // ── Step 2.1: schema validate (requires chainIdentity + hccVersion const) ──
        const schemaResult = validateHashChainEntrySchema(current);
        if (!schemaResult.valid) {
            const firstError = schemaResult.errors[0];
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `verifyHashChain: entries[${i}] schema violation at ${firstError?.instancePath ?? '/'}: ${firstError?.message ?? 'unknown'} (keyword: ${firstError?.keyword ?? 'unknown'})`,
            );
        }

        // ── Step 2.2: chainPosition monotonic — entries[i].chainPosition === entries[i-1].chainPosition + 1 ──
        if (
            (current.chainPosition as unknown as number) !==
            (previous.chainPosition as unknown as number) + 1
        ) {
            throw new HashChainError(
                'HC_CHAIN_POSITION_NONMONOTONIC',
                `verifyHashChain: entries[${i}].chainPosition (${current.chainPosition}) must equal entries[${i - 1}].chainPosition (${previous.chainPosition}) + 1`,
            );
        }

        // ── Step 2.3: previousHash linking — entries[i].previousHash === entries[i-1].canonicalPayloadHash ──
        if (
            (current.previousHash as string) !==
            (previous.canonicalPayloadHash as string)
        ) {
            throw new HashChainError(
                'HC_PREVIOUS_HASH_BROKEN',
                `verifyHashChain: entries[${i}].previousHash ("${current.previousHash}") must equal entries[${i - 1}].canonicalPayloadHash ("${previous.canonicalPayloadHash}")`,
            );
        }

        // ── Step 2.4: hccVersion strictly "2.0.0" (I10 invariant; HC_CHAIN_IDENTITY_SCHEMA_BREAKING) ──
        // Note: schema const "2.0.0" already guards this; the explicit verify here is a fallback + error-code refinement
        if ((current.hccVersion as string) !== HCC_VERSION_CURRENT) {
            throw new HashChainError(
                'HC_CHAIN_IDENTITY_SCHEMA_BREAKING',
                `verifyHashChain: entries[${i}].hccVersion must be "${HCC_VERSION_CURRENT}" (the only legal v0.2 value), got "${current.hccVersion}"`,
            );
        }
    }

    // ── Step 3: chainIdentity preimage cryptographic enforce over all entries + chain identity consistency ──
    // forEach entries: assertCanonicalPayloadHashConsistent(entry, i) literal-equality verify
    // tampering with any entry's chainIdentity OR canonicalPayload → recomputed hash ≠ stored → throw
    // (v0.2 upgrade core — replaces the v0.1 step-4 path that only re-hashed sha256(canonicalPayloadBytes))
    // Note: this layer runs only after the prior steps 1-2 all pass — saves hash computation on the reject path

    // chain identity consistency is elevated to a chain-level invariant:
    // assert per entry that every entry's chainIdentity canonical JCS is literally identical (unique within the chain),
    // and, when options.expectedChainIdentity is passed, assert it equals that expected value (scope-isolation guard).
    // Prevents a mixed chain A→B (B belongs to another tenant/namespace but B.previousHash points to A) being judged legal.
    const expectedJcs =
        options?.expectedChainIdentity !== undefined
            ? canonicalizeChainIdentity(options.expectedChainIdentity)
            : undefined;
    let firstChainIdentityJcs: string | undefined;
    for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        /* v8 ignore next 6 -- loop bound 0 <= i < length; defensive fallback, unreachable*/
        if (entry === undefined || entry === null) {
            throw new HashChainError(
                'HC_SCHEMA_VIOLATION',
                `verifyHashChain: entries[${i}] is null or undefined (Step 3 phantom)`,
            );
        }
        // assertCanonicalPayloadHashConsistent pass-through:
        // - canonicalizeChainIdentity failure → HC_SCHEMA_VIOLATION (chainIdentity non-conformant)
        // - canonicalizeChainIdentity failure → HC_CANONICALIZE_FAILED (canonicalize npm returns undefined)
        // - canonicalPayload not canonical → HC_CHAIN_IDENTITY_PREIMAGE_FAILED
        // - literal-inequality verify → HC_CHAIN_IDENTITY_PREIMAGE_FAILED (chainIdentity OR canonicalPayload tampering)
        assertCanonicalPayloadHashConsistent(entry, i);

        // chain identity consistency — this entry's chainIdentity canonical JCS
        const thisJcs = canonicalizeChainIdentity(entry.chainIdentity);
        if (firstChainIdentityJcs === undefined) {
            firstChainIdentityJcs = thisJcs;
        } else if (thisJcs !== firstChainIdentityJcs) {
            throw new HashChainError(
                'HC_CHAIN_IDENTITY_PREIMAGE_FAILED',
                `verifyHashChain: entries[${i}].chainIdentity ("${thisJcs}") differs from chain's first chainIdentity ("${firstChainIdentityJcs}"); mixed-identity chain rejected (cross-scope identity-rebinding)`,
            );
        }
        if (expectedJcs !== undefined && thisJcs !== expectedJcs) {
            throw new HashChainError(
                'HC_CHAIN_IDENTITY_PREIMAGE_FAILED',
                `verifyHashChain: entries[${i}].chainIdentity ("${thisJcs}") does not match expectedChainIdentity ("${expectedJcs}"); scope isolation enforced`,
            );
        }
    }

    // ── Step 4: checkpoint tail guard (truncation detection) ──
    // On a non-empty chain, assert the last entry's chainPosition / canonicalPayloadHash matches the externally trusted anchor.
    // Prevents "suffix deletion" being judged legal (the remaining prefix is internally consistent but the tail has been truncated).
    if (checkpoint !== undefined) {
        const last = entries[entries.length - 1]!;
        if (
            checkpoint.expectedLastChainPosition !== undefined &&
            (last.chainPosition as unknown as number) !==
                checkpoint.expectedLastChainPosition
        ) {
            throw new HashChainError(
                'HC_PREVIOUS_HASH_BROKEN',
                `verifyHashChain: checkpoint.expectedLastChainPosition (${checkpoint.expectedLastChainPosition}) !== actual last chainPosition (${last.chainPosition}) (possible tail truncation)`,
            );
        }
        if (
            checkpoint.expectedLastCanonicalPayloadHash !== undefined &&
            (last.canonicalPayloadHash as string) !==
                checkpoint.expectedLastCanonicalPayloadHash
        ) {
            throw new HashChainError(
                'HC_PREVIOUS_HASH_BROKEN',
                `verifyHashChain: checkpoint.expectedLastCanonicalPayloadHash mismatch (possible tail truncation/rewrite)`,
            );
        }
    }
}
