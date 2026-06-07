/**
 * AuditShareManager — L3 audit-share v0.2 manager
 *
 * L3 schema enforce is mandatory.
 *
 * 11-step verifyAuditRequest algorithm:
 *   Step 0: caller responsibility, procedural (procedural is acknowledged in the alpha phase)
 *   Step 1: schema validate (AJV strict 4 flag; 3rd layer of the triple defense)
 *   Step 2: csp v0.1 5-field invariant verify (audience/notAfter/challenge/disclosedClaims/version)
 *   Step 3: fetch AuditShareDelegatedKey by request.token
 *   Step 4: verifyAuditShareDelegatedKey (5-step fail-closed)
 *   Step 5: key.delegatedTo === request.requesterDid (strict equality)
 *   Step 6: verify request.requesterSignature (Ed25519)
 *   Step 7: scope verify (toAuditShareScope factory re-verify)
 *   Step 8: multi-tenant isolation cross-check (atp v0.1 linkage)
 *   Step 9: fetchByChainIdentity (SQL WHERE procedural scope enforce)
 *   Step 10: verifyHashChain (hcc v0.1 primitive)
 *   Step 11: selective disclosure projection (return result)
 *
 * Every step is fail-closed (an auth primitive only accepts results that pass verification):
 *   fail-degraded / fail-open / partial-PASS / stub success are not allowed;
 *   any step that fails throws a fatal AuditShareError;
 *   skipping across steps is not allowed (even if a prior step fails it must throw,
 *   never return verifyResult.ok = false and proceed to the next step).
 *
 * Namespace isolation:
 *   every throw uses AuditShareError + an AUDIT_SHARE_* code; no collision with the
 *   csp / atp / hcc / tb namespaces.
 *
 * schema enforce (same pattern as da v0.1 / ccr v0.1):
 *   step 1 schema validate must call validateAuditShareRequestSchema (defense-in-depth);
 *   L3 does not rely on the caller-side schema guard; fail-closed throw AUDIT_SHARE_SCHEMA_INVALID.
 */

import { canonicalize, verify as verifyEd25519 } from '@coivitas/crypto';
import {
    verifyAuditShareDelegatedKey,
    type AuditShareDelegatedKey,
    type AuditShareResolvePublicKeyFn,
} from '@coivitas/identity';
import {
    AUDIT_EVENT_FIELDS,
    AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS,
    AUDIT_SHARE_VERSION_1_0_0,
    AuditShareError,
    toAuditShareScope,
    validateAuditShareRequestSchema,
    type AuditShareEventPayload as AuditEvent,
    type AuditEventField,
    type AuditKeyId,
    type AuditShareEntryWithWitness,
    type AuditShareScope,
    type AuditShareVerifiedRequest,
    type AuditShareVerifyResult,
    type DID,
    type AuditShareHashChainEntry as HashChainEntry,
    type Timestamp,
} from '@coivitas/types';

// ─── Port interfaces (DI; every method has an active invocation to guard against dead port methods) ─────

/**
 * AuditShareDelegatedKeyStore — AuditShareDelegatedKey data-source port
 *
 * step 3 data source: the managed_service.delegated_audit_keys table.
 *
 * Guard against dead port methods:
 *   - the fetch method has an active invocation in step 3 (verifyAuditRequest)
 */
export interface AuditShareDelegatedKeyStore {
    /**
     * Look up an AuditShareDelegatedKey by auditKeyId
     *
     * @param token = AuditKeyId (request.token; called in step 3)
     * @returns AuditShareDelegatedKey or null (fail-closed: null → AUDIT_SHARE_TOKEN_INVALID)
     */
    fetch(token: AuditKeyId): Promise<AuditShareDelegatedKey | null>;
}

/**
 * TenantAuditSharePolicyStore — multi-tenant isolation policy data-source port (step 8)
 *
 * step 8 data source: the managed_service.tenant_audit_share_policy table
 * (atp v0.1 multi-tenant isolation mandatory cross-check).
 *
 * Guard against dead port methods:
 *   - the isAllowed method has an active invocation in step 8
 */
export interface TenantAuditSharePolicyStore {
    /**
     * Check whether the delegator (principal DID) is authorized to access tenantId + auditClass
     *
     * @returns true if authorized; false → AUDIT_SHARE_CROSS_TENANT_REJECT (fail-closed)
     */
    isAllowed(
        principalDid: DID,
        tenantId: string,
        auditClass: 'L1' | 'L2' | 'L3',
    ): Promise<boolean>;
}

/**
 * AuditEventStore — atp v0.1 audit event data source + hcc v0.1 hash chain entries port
 *
 * step 9 fetchByChainIdentity(scope):
 *   SELECT * FROM hash_chain_entries
 *   WHERE tenant_id = $1 AND audit_class = $2
 *     AND chain_namespace = COALESCE($3, chain_namespace)
 *   ORDER BY chain_position ASC
 *
 * procedural scope enforce (v0.1 baseline; later versions may upgrade to hcc v0.2 cryptographic).
 *
 * Guard against dead port methods:
 *   - fetchByChainIdentity has an active invocation in step 9
 *   - fetchAuditEvents has an active invocation in step 11 (prelude to selective disclosure projection)
 */
export interface AuditEventStore {
    /**
     * Fetch hash chain entries by scope (SQL WHERE procedural enforce)
     *
     * @returns HashChainEntry[] (ascending chainPosition); an empty array is valid (no matching entries)
     */
    fetchByChainIdentity(
        scope: AuditShareScope,
    ): Promise<readonly HashChainEntry[]>;

    /**
     * Fetch the audit events corresponding to the given hash chain entries
     *
     * Called after fetchByChainIdentity; fetches the audit events in a single batch to
     * avoid multiple round-trips.
     *
     * @returns AuditEvent[] (one-to-one with entries; equal length)
     */
    fetchAuditEvents(
        entries: readonly HashChainEntry[],
    ): Promise<readonly AuditEvent[]>;
}

/**
 * HashChainVerifier — hcc v0.1 verifyHashChain primitive port (step 10)
 *
 * step 10 verifyHashChain(entries):
 *   monotonic chainPosition + previousHash linkage + canonicalPayloadHash recomputation
 *   fail (any HC_* error) → AUDIT_SHARE_HASH_CHAIN_INVALID
 *
 * The hcc v0.1 primitive is implemented independently; this port only injects the verify
 * interface (this module does not implement the internal logic of the hcc primitive).
 *
 * Guard against dead port methods:
 *   - verify has an active invocation in step 10
 */
export interface HashChainVerifier {
    /**
     * Verify the integrity of the hash chain entries
     *
     * @returns true if it passes; false → AUDIT_SHARE_HASH_CHAIN_INVALID
     */
    verify(
        entries: readonly HashChainEntry[],
    ): Promise<{ valid: true } | { valid: false; reason: string }>;
}

// ─── ChallengeStore (verifier-side one-time challenge) ───────────────────────────────────────

/**
 * ChallengeStore — verifier-side issued challenges (step 2 one-time nonce)
 *
 * On every verify-pipeline entry the verifier issues a fresh UUID v4 challenge and records it
 * in this store; step 2 checks that request.challenge is in the issued set (single use,
 * removed once verified).
 *
 * The alpha phase accepts an in-memory implementation (a caller-injected persistent version is
 * an optional upgrade); this port interface constrains the two actions issue + consume
 * (one-time nonce to prevent replay).
 *
 * Guard against dead port methods:
 *   - consume has an active invocation in step 2 (verifyAuditRequest)
 */
export interface ChallengeStore {
    /**
     * Check the existence of a challenge (without consuming it)
     *
     * Active invocation in Step 2; returns whether the challenge has been issued and not yet
     * consumed; does not burn the nonce (avoids the case where an attacker uses an invalid
     * signature to trigger a nonce burn).
     *
     * @returns true if it exists; false → AUDIT_SHARE_CHALLENGE_INVALID
     */
    check(challenge: string): Promise<boolean>;

    /**
     * Check and consume a challenge (one-time nonce; prevents replay)
     *
     * The consume action is placed after Step 6 (requester signature verify);
     * this ensures an invalid signature does not burn a legitimate challenge.
     *
     * @returns true if it passes (challenge has been issued and not yet consumed);
     *          false → AUDIT_SHARE_CHALLENGE_INVALID
     */
    consume(challenge: string): Promise<boolean>;
}

// ─── AuditShareManager (L3 main class) ──────────────────────────────────────────

/**
 * AuditShareManagerDeps — DI container
 *
 * 5 ports:
 *   - resolvePublicKey — public-key resolution for Steps 1+6
 *   - delegatedAuditKeyStore — AuditShareDelegatedKey lookup for Step 3
 *   - tenantPolicyStore — multi-tenant isolation cross-check for Step 8
 *   - auditEventStore — hash chain entries + audit events for Steps 9+11
 *   - hashChainVerifier — hcc v0.1 verifyHashChain primitive for Step 10
 *   - challengeStore — challenge consume for Step 2 (one-time nonce)
 */
export interface AuditShareManagerDeps {
    readonly resolvePublicKey: AuditShareResolvePublicKeyFn;
    readonly delegatedAuditKeyStore: AuditShareDelegatedKeyStore;
    readonly tenantPolicyStore: TenantAuditSharePolicyStore;
    readonly auditEventStore: AuditEventStore;
    readonly hashChainVerifier: HashChainVerifier;
    readonly challengeStore: ChallengeStore;
}

/**
 * AuditShareManager — L3 audit-share v0.2 manager main class
 *
 * 11-step verifyAuditRequest algorithm;
 * fetchByChainIdentity delegates to the AuditEventStore port (procedural scope enforce).
 *
 * Namespace isolation:
 *   every throw uses AuditShareError + an AUDIT_SHARE_* code;
 *   no collision with the csp / atp / hcc / tb / da / sr namespaces.
 */
export class AuditShareManager {
    private readonly deps: AuditShareManagerDeps;

    constructor(deps: AuditShareManagerDeps) {
        this.deps = deps;
    }

    /**
     * fetchByChainIdentity — L3 manager fetch by scope
     *
     * Passes through to the AuditEventStore port (procedural SQL WHERE scope enforce);
     * does not perform schema validate / scope re-verify at this layer (left to the
     * verifyAuditRequest step 9 call).
     *
     * @param scope AuditShareScope brand (guarded by the toAuditShareScope factory; brand
     *              casting is forbidden)
     * @returns HashChainEntry[] (ascending chainPosition)
     */
    public async fetchByChainIdentity(
        scope: AuditShareScope,
    ): Promise<readonly HashChainEntry[]> {
        return this.deps.auditEventStore.fetchByChainIdentity(scope);
    }

    /**
     * verifyAuditRequest — 11-step fail-closed verify
     *
     * @param request AuditShareVerifiedRequest
     * @param expectedAudience target domain DID (the verifier-side expected audience; step 2 audience check)
     * @param now current-moment Timestamp (injected by the caller; enforced in steps 2+4)
     * @returns AuditShareVerifyResult.ok = true (entries + auditEvents);
     *          on failure it does not return ok = false but throws a fatal AuditShareError
     * @throws AuditShareError fail-closed (any of the 11 steps failing); fully covers all 14 AUDIT_SHARE_* codes
     */
    public async verifyAuditRequest(
        request: AuditShareVerifiedRequest,
        expectedAudience: DID,
        now: Timestamp,
    ): Promise<AuditShareVerifyResult> {
        // ───────────────────────────────────────────────────────────────
        // Step 0: caller responsibility, procedural
        // ───────────────────────────────────────────────────────────────
        // The caller's transport/SDK-layer cryptographic primitive (mTLS / JWT / OAuth2 → DID mapping)
        // is outside the audit-share v0.2 sub-protocol scope — the alpha phase accepts a weak procedural constraint.
        // Once sdk v0.2 is integrated in a later version it switches to cryptographic enforce.
        // This step performs no enforce action (procedural is acknowledged); proceed to step 1.

        // ───────────────────────────────────────────────────────────────
        // Step 1: AJV schema validate (defense-in-depth 3rd layer)
        // ───────────────────────────────────────────────────────────────
        const schemaResult = validateAuditShareRequestSchema(request);
        if (!schemaResult.valid) {
            const firstErr = schemaResult.errors[0];
            throw new AuditShareError(
                'AUDIT_SHARE_SCHEMA_INVALID',
                `schema validate fail at ${firstErr?.instancePath ?? '/'}: ${firstErr?.message ?? 'unknown'}`,
                'step-1-schema-validate',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 2: csp v0.1 5-field invariant verify
        // ───────────────────────────────────────────────────────────────
        // 2a: auditShareVersion === '1.0.0' (factory equivalence; already enforced by the schema const)
        // defense-in-depth 4th layer (factory + schema + L3 step 2a triple); the schema const "1.0.0"
        // already rejects all non-1.0.0 values; this step is only a schema-bypass fallback (unreachable in practice)
        /* v8 ignore next 7*/
        if (request.auditShareVersion !== AUDIT_SHARE_VERSION_1_0_0) {
            throw new AuditShareError(
                'AUDIT_SHARE_VERSION_UNSUPPORTED',
                `auditShareVersion "${request.auditShareVersion}" not in supported set`,
                'step-2-version',
            );
        }

        // 2b: every disclosedClaims entry belongs to the AuditEventField enum (defense-in-depth; already enforced by the schema)
        // the schema enum already rejects non-AuditEventField values; this loop is a schema-bypass fallback (unreachable in practice)
        const validClaims: ReadonlySet<string> = new Set(AUDIT_EVENT_FIELDS);
        for (const claim of request.disclosedClaims) {
            /* v8 ignore next 7*/
            if (!validClaims.has(claim)) {
                throw new AuditShareError(
                    'AUDIT_SHARE_DISCLOSED_CLAIMS_INVALID',
                    `disclosedClaims contains non-AuditEventField value: "${String(claim)}"`,
                    'step-2-disclosed-claims',
                );
            }
        }

        // 2c: audience === expectedAudience (strict equality; prevents hijack)
        if (request.audience !== expectedAudience) {
            throw new AuditShareError(
                'AUDIT_SHARE_AUDIENCE_MISMATCH',
                `request.audience "${request.audience}" !== expectedAudience "${expectedAudience}"`,
                'step-2-audience',
            );
        }

        // 2d: notAfter > now + minWindow (prevents stale replay)
        const notAfterMs = Date.parse(request.notAfter);
        const nowMs = Date.parse(now);
        if (Number.isNaN(notAfterMs) || Number.isNaN(nowMs)) {
            throw new AuditShareError(
                'AUDIT_SHARE_NOT_AFTER_EXPIRED',
                `notAfter or now not valid ISO 8601 (notAfter="${request.notAfter}", now="${now}")`,
                'step-2-not-after-format',
            );
        }
        if (notAfterMs <= nowMs + AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS) {
            throw new AuditShareError(
                'AUDIT_SHARE_NOT_AFTER_EXPIRED',
                `notAfter "${request.notAfter}" not > now + ${AUDIT_SHARE_MIN_VALIDITY_WINDOW_MS}ms (now="${now}")`,
                'step-2-not-after-window',
            );
        }

        // 2e: challenge ∈ verifier-issued set (one-time nonce to prevent replay)
        //
        // step 2 only checks existence (does not consume); the real consume is moved to step 6
        // (after requester signature verify), ensuring an invalid signature does not burn a legitimate
        // challenge (avoids an attacker burning the nonce).
        const challengeExists = await this.deps.challengeStore.check(
            request.challenge,
        );
        if (!challengeExists) {
            throw new AuditShareError(
                'AUDIT_SHARE_CHALLENGE_INVALID',
                `challenge "${request.challenge}" not in verifier-issued set (or already consumed)`,
                'step-2-challenge-check',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 3: fetch AuditShareDelegatedKey by request.token
        // ───────────────────────────────────────────────────────────────
        const delegatedAuditKey = await this.deps.delegatedAuditKeyStore.fetch(
            request.token,
        );
        if (delegatedAuditKey === null || delegatedAuditKey === undefined) {
            throw new AuditShareError(
                'AUDIT_SHARE_TOKEN_INVALID',
                `AuditShareDelegatedKey not found (token="${request.token}")`,
                'step-3-fetch',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 4: verifyAuditShareDelegatedKey 5-step fail-closed
        // ───────────────────────────────────────────────────────────────
        // verifyAuditShareDelegatedKey throws AuditShareError internally; it is passed straight
        // through to the caller (not caught and re-wrapped, preserving the original code +
        // invariant context).
        await verifyAuditShareDelegatedKey(
            delegatedAuditKey,
            this.deps.resolvePublicKey,
            now,
        );

        // ───────────────────────────────────────────────────────────────
        // Step 5: key.delegatedTo === request.requesterDid
        // ───────────────────────────────────────────────────────────────
        if (delegatedAuditKey.delegatedTo !== request.requesterDid) {
            throw new AuditShareError(
                'AUDIT_SHARE_DELEGATOR_AUDIENCE_MISMATCH',
                `key.delegatedTo "${delegatedAuditKey.delegatedTo}" !== request.requesterDid "${request.requesterDid}"`,
                'step-5-delegator-audience',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 6: verify request.requesterSignature (Ed25519)
        // ───────────────────────────────────────────────────────────────
        // canonicalPayload = canonicalize({ ...request, requesterSignature: undefined })
        // publicKey = await resolvePublicKey(request.requesterDid)
        // verifyEd25519(canonicalPayload, request.requesterSignature, publicKey)
        const requesterPublicKey = await this.deps.resolvePublicKey(
            request.requesterDid,
        );
        if (
            requesterPublicKey === null ||
            requesterPublicKey === undefined ||
            requesterPublicKey.length === 0
        ) {
            throw new AuditShareError(
                'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
                `unknown requester DID: "${request.requesterDid}" (resolvePublicKey returned null)`,
                'step-6-resolve-requester-public-key',
            );
        }

        // Construct the canonical payload (excluding requesterSignature)
        const requestPayloadObj: Record<string, unknown> = {
            auditShareVersion: request.auditShareVersion,
            token: request.token,
            disclosedClaims: [...request.disclosedClaims],
            challenge: request.challenge,
            audience: request.audience,
            notAfter: request.notAfter,
            requestedScope: this.canonicalScopeObject(request.requestedScope),
            requesterDid: request.requesterDid,
        };
        const canonicalPayloadStr = canonicalize(requestPayloadObj);
        const payloadBytes = new TextEncoder().encode(canonicalPayloadStr);

        let requesterSigValid: boolean;
        try {
            requesterSigValid = verifyEd25519(
                payloadBytes,
                request.requesterSignature,
                requesterPublicKey,
            );
        } catch (err) {
            throw new AuditShareError(
                'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
                `Ed25519 verify threw: ${err instanceof Error ? err.message : String(err)}`,
                'step-6-ed25519-verify',
            );
        }
        if (!requesterSigValid) {
            throw new AuditShareError(
                'AUDIT_SHARE_REQUESTER_SIGNATURE_INVALID',
                'Ed25519 verify fail (requesterSignature does not match canonicalized request payload)',
                'step-6-ed25519-verify',
            );
        }

        // challenge consumption relocation:
        // the challenge consume is placed in step 6 (after requester signature verify); this ensures
        // an invalid signature does not burn a legitimate challenge; step 2 only checks existence (does not burn)
        const challengeConsumed = await this.deps.challengeStore.consume(
            request.challenge,
        );
        if (!challengeConsumed) {
            throw new AuditShareError(
                'AUDIT_SHARE_CHALLENGE_INVALID',
                `challenge "${request.challenge}" race-condition consumed by concurrent request`,
                'step-6-challenge-consume-race',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 7: scope re-verify (toAuditShareScope factory re-verify)
        // ───────────────────────────────────────────────────────────────
        // the factory is already enforced on the caller side; here we type-narrow + re-verify non-sentinel (defense-in-depth)
        let verifiedScope: AuditShareScope;
        try {
            verifiedScope = toAuditShareScope({
                tenantId: request.requestedScope.tenantId,
                auditClass: request.requestedScope.auditClass,
                ...(request.requestedScope.chainNamespace !== undefined && {
                    chainNamespace: request.requestedScope.chainNamespace,
                }),
            });
        } catch (err) {
            // toAuditShareScope throws AuditShareError AUDIT_SHARE_SCOPE_INVALID; passed straight through
            // defense-in-depth: the schema already rejects illegal scopes; this catch only handles the extreme schema-bypass case
            /* v8 ignore next 9*/
            if (err instanceof AuditShareError) {
                throw err;
            }
            throw new AuditShareError(
                'AUDIT_SHARE_SCOPE_INVALID',
                `scope factory threw: ${err instanceof Error ? err.message : String(err)}`,
                'step-7-scope-re-verify',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 8: multi-tenant isolation cross-check (atp v0.1 linkage)
        // ───────────────────────────────────────────────────────────────

        // scope expansion defense:
        // if the delegated key is not bound to a scope, the requester controls requestedScope → cross-tenant
        // reads beyond the delegator's intent. Therefore it is mandatory to verify that the
        // DelegatedAuditKey.scope ↔ request.requestedScope fields match:
        // key.scope.tenantId === request.requestedScope.tenantId AND
        // key.scope.auditClass === request.requestedScope.auditClass (chainNamespace likewise if defined)
        const keyScope = delegatedAuditKey.scope;
        if (keyScope.tenantId !== verifiedScope.tenantId) {
            throw new AuditShareError(
                'AUDIT_SHARE_CROSS_TENANT_REJECT',
                `DelegatedAuditKey.scope.tenantId "${keyScope.tenantId}" !== request.requestedScope.tenantId "${verifiedScope.tenantId}" (scope expansion fail-closed reject)`,
                'step-8-key-scope-tenant-binding',
            );
        }
        if (keyScope.auditClass !== verifiedScope.auditClass) {
            throw new AuditShareError(
                'AUDIT_SHARE_CROSS_TENANT_REJECT',
                `DelegatedAuditKey.scope.auditClass "${keyScope.auditClass}" !== request.requestedScope.auditClass "${verifiedScope.auditClass}" (scope expansion fail-closed reject)`,
                'step-8-key-scope-class-binding',
            );
        }
        if (
            keyScope.chainNamespace !== undefined &&
            keyScope.chainNamespace !== verifiedScope.chainNamespace
        ) {
            throw new AuditShareError(
                'AUDIT_SHARE_CROSS_TENANT_REJECT',
                `DelegatedAuditKey.scope.chainNamespace "${keyScope.chainNamespace}" !== request.requestedScope.chainNamespace "${verifiedScope.chainNamespace}" (scope expansion fail-closed reject)`,
                'step-8-key-scope-namespace-binding',
            );
        }

        const tenantAllowed = await this.deps.tenantPolicyStore.isAllowed(
            delegatedAuditKey.delegatedFrom,
            verifiedScope.tenantId,
            verifiedScope.auditClass,
        );
        if (!tenantAllowed) {
            throw new AuditShareError(
                'AUDIT_SHARE_CROSS_TENANT_REJECT',
                `delegator "${delegatedAuditKey.delegatedFrom}" not authorized for tenantId="${verifiedScope.tenantId}" auditClass="${verifiedScope.auditClass}"`,
                'step-8-multi-tenant',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 9: fetchByChainIdentity (procedural scope enforce)
        // ───────────────────────────────────────────────────────────────
        const entries = await this.fetchByChainIdentity(verifiedScope);

        // ───────────────────────────────────────────────────────────────
        // Step 10: verifyHashChain (hcc v0.1 primitive)
        // ───────────────────────────────────────────────────────────────
        const chainResult = await this.deps.hashChainVerifier.verify(entries);
        if (!chainResult.valid) {
            throw new AuditShareError(
                'AUDIT_SHARE_HASH_CHAIN_INVALID',
                `hash chain verify fail: ${chainResult.reason}`,
                'step-10-hash-chain',
            );
        }

        // ───────────────────────────────────────────────────────────────
        // Step 11: selective disclosure projection
        // ───────────────────────────────────────────────────────────────

        // selective disclosure leak defense:
        // if step 11 fetchAuditEvents returns full events while disclosedClaims is not actually projected,
        // cross-domain callers would obtain unauthorized fields (actorDid/targetAgentDid/tenantId/signatures, etc.)
        // therefore it is mandatory to go through the project() projection, returning only the disclosedClaims subset
        const fullAuditEvents =
            await this.deps.auditEventStore.fetchAuditEvents(entries);
        const projectedAuditEvents = fullAuditEvents.map((event) =>
            this.project(event, request.disclosedClaims),
        );

        return {
            ok: true,
            entries,
            auditEvents: projectedAuditEvents,
        };
    }

    /**
     * project — selective disclosure projection
     *
     * Public method (the caller may invoke this projection independently after verifyAuditRequest);
     * also used internally by buildWithWitness.
     *
     * @param event a single AuditEvent
     * @param disclosedClaims the subset of fields to project
     * @returns Partial<AuditEvent> (contains only the disclosedClaims subset of fields)
     */
    public project(
        event: AuditEvent,
        disclosedClaims: readonly AuditEventField[],
    ): Partial<AuditEvent> {
        const projected: Partial<AuditEvent> = {};
        for (const field of disclosedClaims) {
            // only project when the event has the field (avoids undefined entering the result)
            if (Object.prototype.hasOwnProperty.call(event, field)) {
                const value = (event as unknown as Record<string, unknown>)[
                    field
                ];
                if (value !== undefined) {
                    (projected as unknown as Record<string, unknown>)[field] =
                        value;
                }
            }
        }
        return projected;
    }

    /**
     * buildEntriesWithWitness — AuditShareEntryWithWitness wrapper layer
     *
     * Given entries + auditEvents + disclosedClaims, assembles AuditShareEntryWithWitness[]
     * (the caller can use this result for subsequent cross-domain chain-hop verify).
     *
     * Does not modify the 7 fields of the hcc v0.1 HashChainEntry.
     */
    public buildEntriesWithWitness(
        entries: readonly HashChainEntry[],
        auditEvents: readonly AuditEvent[],
        disclosedClaims: readonly AuditEventField[],
    ): readonly AuditShareEntryWithWitness[] {
        if (entries.length !== auditEvents.length) {
            throw new AuditShareError(
                'AUDIT_SHARE_HASH_CHAIN_INVALID',
                `entries.length (${entries.length}) !== auditEvents.length (${auditEvents.length})`,
                'build-with-witness-length-mismatch',
            );
        }
        const result: AuditShareEntryWithWitness[] = [];
        for (let i = 0; i < entries.length; i += 1) {
            const entry = entries[i]!;
            const event = auditEvents[i]!;
            const disclosedFields = this.project(event, disclosedClaims);
            // the witness field is optional; the manager does not sign the witness internally (left to the caller / a later version upgrade)
            result.push({
                entry,
                auditEvent: event,
                disclosedFields,
            });
        }
        return result;
    }

    /**
     * canonicalScopeObject — construct a canonical scope object for the signing payload (private helper)
     *
     * Removes the __brand symbol; keeps only the wire-layer fields (tenantId / auditClass / chainNamespace).
     */
    private canonicalScopeObject(
        scope: AuditShareScope,
    ): Record<string, unknown> {
        const obj: Record<string, unknown> = {
            tenantId: scope.tenantId,
            auditClass: scope.auditClass,
        };
        if (scope.chainNamespace !== undefined) {
            obj.chainNamespace = scope.chainNamespace;
        }
        return obj;
    }
}
