import { randomUUID } from 'node:crypto';

import type {
    AgentIdentityDocument,
    CapabilityToken,
    CumulativeLimitScope,
    DelegationChainValidationResult,
    DID,
    DiscoveryService,
    FederatedResolver,
    MeterFieldRef,
    NegotiationEnvelope,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';
import { ProtocolError } from '@coivitas/types';
import { verify } from '@coivitas/crypto';
import {
    createCapabilityTokenPayload,
    verifyCapabilityToken,
} from '@coivitas/identity';
import {
    computeWindowStart,
    METER_FIELD_REGISTRY,
    ScopeEvaluator,
} from '@coivitas/policy';
import type { PolicyRecorder } from '@coivitas/policy';
import {
    buildAuthorizationInsufficientEnvelope,
    buildEnvelope,
    buildIdentityVerificationFailedEnvelope,
    buildInternalErrorEnvelope,
    buildInvalidEnvelopeEnvelope,
    parseEnvelope,
    verifyEnvelope,
    // Mandatory L3/L4 boundary wrapper (production path).
    // businessHandler may internally descend into a sub-protocol entry (audit-share, hcc, settlement-retry, etc.);
    // any sub-protocol L0 error thrown up to the L5 orchestrator boundary must be unwrapped to a ProtocolError,
    // preventing CrError/HashChainError/AuditShareError/AuditError/SrError/DaError from escaping the L5 boundary.
    wrapSubProtocolBoundary,
} from '@coivitas/communication';
import type { Transport } from '@coivitas/communication';
import type { PolicyEngine } from '@coivitas/policy';

/**
 * Orchestrator — the L5 orchestration assembly.
 *
 * Integration points:
 *  - DiscoveryService: exposed to the orchestration layer as an injection point (not on the handleEnvelope path).
 *  - FederatedResolver: replaces the single resolvePublicKey; falls back to the legacy callback when not injected.
 *  - Delegation chain validation: resolve the Token from capabilityTokenRef and call DelegationChainValidator.
 *  - Scope extension: transparently handled at step4 by PolicyEngine → RuntimeGuard → ScopeEvaluator.
 *
 * **Known gaps (must not be ignored)**: several structural gaps remain (ROTATING dual-key / a true
 * EnvelopeLedger / landing the delegationDepth schema / cross-trust-domain settle authority, etc.).
 * These gaps affect this file's port signatures; assess their constraints before extending.
 */
export interface OrchestratorConfig {
    agentDid: DID;
    agentPrivateKey: string;
    principalDid: DID;
    policyEngine: Pick<PolicyEngine, 'executeWithPolicy'>;
    transport: Transport;
    businessHandler: BusinessHandler;
    verbose?: boolean;

    /**
     * Clock injection port — used for the issuedAt/expiresAt time-window check of
     * the step3.5 sender leaf token. Defaults to `new Date().toISOString()`.
     *
     * It must be injected in tests and offline-replay scenarios, otherwise the wall-clock
     * would falsely flag a "token generated at a past instant" as expired even when within
     * the spec-allowed window (integration-test bug H-01: the original implementation called
     * `new Date()` directly inside verifyCapability, ignoring the `now` clock injected by
     * downstream ports such as RuntimeGuard; once real runtime clock drift crosses into
     * 2026-04-22, every test token issued 2026-04-21 and expiring 2026-04-22T10Z would be
     * falsely flagged as expired — at odds with the test intent).
     *
     * Injection is not required on the production path; but if the Orchestrator's node depends
     * on an external clock (e.g. central NTP correction latency), it is recommended to route the
     * service clock uniformly through this port.
     */
    now?: () => Timestamp;

    /**
     * Discovery service (AgentCard publish/query).
     * Not used on the handleEnvelope path; called by the orchestration layer.
     * Placed on Config rather than BusinessHandlerContext: discovery is an orchestration responsibility,
     * and the business handler should only see "requests that have passed identity + authorization".
     */
    discoveryService?: DiscoveryService;

    /**
     * Federated resolver (the preferred path).
     * Recommended; takes priority over the legacy resolvePublicKey.
     * **Note**: mutually exclusive with `resolvePublicKey` — injecting both throws at construction time
     * to avoid path ambiguity in staged-rollout scenarios.
     */
    federatedResolver?: FederatedResolver;

    /**
     * Managed-service DID resolution client (optional injection point).
     *
     * Once injected, DID-document resolution inside the orchestrator (the federatedResolver path) is
     * proxied through the ManagedServiceClient — it calls the managed service first and automatically
     * falls back to federatedResolver on 5xx/network errors/timeouts (handled internally by ManagedServiceClient).
     *
     * Usage constraints:
     * - When managedServiceClient and federatedResolver are both injected, managedServiceClient's
     *   fallbackResolver must be consistent with federatedResolver (the caller guarantees this), otherwise resolution behavior is unpredictable.
     * - Injecting managedServiceClient alone (without federatedResolver) has no effect —
     *   the orchestrator still requires one of federatedResolver / resolvePublicKey / resolveAgentDocument to be present.
     *   In that case, wrap managedServiceClient.resolveDid as resolveAgentDocument and inject it.
     * - Not injected (default) = use the federatedResolver path directly, with behavior unchanged.
     */
    managedServiceClient?: import('./managed-service-client.js').ManagedServiceClient;

    /**
     * Public-key resolution callback (legacy single-source path).
     * **Mutually exclusive with `federatedResolver`**. Use cases: single-source resolution.
     * When production needs caching, wrap the cache inside the `FederatedResolver` implementation rather than
     * splitting into two resolution paths at L5.
     */
    resolvePublicKey?: (did: DID) => Promise<string | null>;

    /**
     * Dual-key resolution port (ROTATING path).
     * **Takes priority over resolvePublicKey**.
     *
     * Once injected, the orchestrator leaf signature + chain-validator wrapper + the step3.5
     * !hasChain branch (single-hop principal signature path) all use dual-key fallback:
     * when current signature verification fails, if proof.created ≤ previousValidBefore, fall back to
     * previous (consistent with the delegation-validator dual-key semantics).
     *
     * Not injected → automatically wrapped from resolvePublicKey into a STABLE state (backward compatible);
     * during ROTATING, a legitimate token signed with the previous key is rejected as
     * `delegation_leaf_signature_invalid`.
     *
     * **Signature aligned with the PublicKeyResolver port**:
     * - `now?: Date` passes through the logical clock, so replay/skew-controlled deployments can replay historical tokens within the window
     * - Returns `ResolvedPublicKeys | null`; an unknown DID returns null, and the caller takes the
     * `token_issuer_unknown` rejection path
     *
     * Compatible with federatedResolver / resolvePublicKey:
     * - resolvePublicKeys + federatedResolver / resolvePublicKey can coexist
     *   (resolvePublicKeys takes priority)
     * - Injecting only resolvePublicKeys passes the construction check (dual-key mode)
     */
    resolvePublicKeys?: (
        did: DID,
        now?: Date,
    ) => Promise<ResolvedPublicKeys | null>;

    /**
     * Authorization closure: resolve the sender agent document for the principalDid consistency check.
     * Changed from "optional/degraded" to "required on the capability path".
     * Enforced at construction time when tokenStore is injected to enable capability authorization semantics (avoids
     * the "looks startable per the comments, but every first capability request is rejected" config bomb).
     */
    resolveAgentDocument?: (did: DID) => Promise<AgentIdentityDocument | null>;

    /**
     * Token store (read by tokenId). Not injected = agent-pool path (when the envelope
     * carries no capabilityTokenRef, RuntimeGuard agent-pool authorization is used).
     * **Injected = capability authorization semantics enabled**: in this case all the following ports are required (verified at construction):
     *   - delegationChainValidator
     *   - revocationChecker
     *   - resolveAgentDocument
     *   - policyRecorder
     * Missing any one → construction throws ProtocolError(INTERNAL_ERROR) naming which is missing.
     */
    tokenStore?: TokenStoreReader;

    /**
     * Revocation checker (for the DelegationChainValidator + leaf revocation callback).
     * Changed from "optional/skipped" to "required on the capability path",
     * to avoid a security downgrade where revocation checks are actually skipped at runtime, contradicting the comment contract.
     */
    revocationChecker?: (tokenId: string) => Promise<boolean>;

    /**
     * Delegation chain validator.
     * Defaults to referencing validateDelegationChain from @coivitas/identity;
     * the injection point is exposed for test mocking.
     */
    delegationChainValidator?: DelegationChainValidator;

    /**
     * step3.5 authorization rejections must write an ActionRecord (L5 audit invariant).
     * recorder is required as a companion to tokenStore; in a mixed-version deployment, an agent-pool-only node +
     * a capability-bound envelope triggers a
     * `delegation_phase2_dependencies_missing` rejection but with no recorder → no audit trail.
     *
     * Therefore `policyRecorder` is unconditionally required (enforced at construction). Any node that
     * could possibly call handleEnvelope must be able to write a REJECTED record on a step3.5 rejection.
     */
    policyRecorder: PolicyRecorder;

    /**
     * sender token cumulative_limit evaluation port (atomic).
     *
     * TODO(known-gaps) —— the recipient having no cross-trust-domain settle authority is a spec-level
     * architectural constraint; currently only best-effort cancel + reliance on the tracker TTL fallback is possible.
     * True bidirectional reconciliation is deferred to a later release.
     *
     * **Trust model**: ledger_key is independent of agent_key and held by the sender principal's
     * operations side; cross-trust-domain access by the recipient requires operations to explicitly provide a
     * query path (e.g. a bidirectional trusted-ledger mirror / principal-signed endpoint).
     *
     * **Atomicity constraint**: a pure read-only query under concurrency can over-limit via TOCTOU —
     * N envelopes simultaneously read cumulative + reserveAmount ≤ max and all pass.
     * The spec requires serialization at `(principalDid, metric, window)` granularity (DB row lock /
     * Reservation / CAS, any one). Therefore the port changes from a read-only getCumulativeValue
     * to an atomic checkAndReserve, explicitly handing serialization responsibility to the tracker implementer.
     *
     * **Policy**:
     *   - Not injected → fail-closed when the sender token contains a cumulative_limit
     *     (reason=`delegation_cumulative_limit_unverifiable`)
     *   - Injected → checkAndReserve does an atomic query+reservation; when it returns allowed:false
     *     the orchestrator rejects (reason=`delegation_cumulative_limit_exceeded`)
     *
     * **settlement ownership**: the recipient side does **not** call settleReservation.
     * Reason: the recipient writes the recipient-side ActionRecord and has no settle authority over the
     * sender principal's ledger; settle must be in the same transaction as the sender-side ActionRecord.append.
     *
     * **The sender-side tracker implementer MUST provide one of the following fallbacks** (otherwise the reservation
     * hangs forever and real quota is illegitimately locked):
     *   (a) a background reclamation job based on created_at + a configurable TTL (5 minutes recommended):
     *       expired SUM-metric REJECTED/ERROR are released, COUNT+"*" are turned to SETTLED;
     *   (b) an out-of-band settle channel with the sender agent side (e.g. on business success the sender
     *       agent calls settleReservation itself to complete reconciliation);
     *   (c) both.
     *
     * **best-effort cancel**: when the recipient-side orchestrator's reservation has already succeeded but a
     * later path (step4/business/response build) fails, it best-effort calls
     * `cancelReservation?.(recordId)` (see the port method) to speed up reclamation, but this capability does **not
     * replace** the (a)/(b) fallbacks — cross-process calls may be lost.
     *
     * **Idempotency key**: the orchestrator generates pendingRecordId via randomUUID() in handleEnvelope
     * as the recordId prefix. It no longer uses the sender-controlled
     * envelope.id — the sender cannot bypass cumulative idempotency with the same id + different params.
     * Under a same-envelope TCP retry, the recipient generates a new pendingRecordId each time →
     * non-idempotent; TCP-level retry idempotency should be covered by the envelope.id-level ResponseIdempotencyCache
     * (response-level short-circuit, not a reservation responsibility; see the idempotencyCache field below).
     */
    senderCumulativeTracker?: SenderCumulativeTrackerReader;

    /**
     * **Response-level idempotency cache** (**not** an at-most-once ledger).
     *
     * TODO —— concurrency atomicity / crash window / business-level at-most-once await resolution by a true
     * EnvelopeLedger; the current version's safe degradation is at its limit.
     *
     * **Semantic promise** (read it strictly literally; do not over-interpret it as "transaction-level dedup"):
     *   - hit → return the previously built response envelope directly, do not descend further;
     *   - miss → run the full verifyCapability / checkAndReserve / businessHandler
     *     flow and record uniformly in handleEnvelope's finally.
     *
     * **What is NOT promised** (make this explicit to the caller):
     *   1. **Concurrent same-envelope**: two requests arrive almost simultaneously and both check a miss
     *      → both pass through to the executor; the cache is only effective for **temporally later** retries.
     *   2. **Crash window**: if the executor has committed external side effects (e.g. an HTTP call to an external bank) but
     *      the finally record() has not completed when the process crashes → a re-delivery after restart **will re-run**
     *      the executor. The in-memory implementation loses everything on crash; the Postgres implementation mitigates but the risk is non-zero.
     *   3. **Business-level at-most-once**: this field is **not** an envelope ledger. If the caller
     *      needs at-most-once business semantics, it must:
     *      (a) make the business handler idempotent (the core responsibility);
     *      (b) use a persistent cache implementation (across processes/restarts);
     *      (c) align database transaction boundaries (recorder + tracker + cache in the same transaction).
     *
     * **Upgrade path**: a true `EnvelopeLedger` (atomic claim/finalize protocol +
     * PENDING/COMMITTED state machine + PostgreSQL transaction) is deferred to a later release. This field is a
     * transitional form that only provides **best-effort response caching**.
     *
     * **Not injected** → the orchestrator emits a one-time console.warn on the first handleEnvelope,
     * but does not force a rejection (backward compatible).
     */
    idempotencyCache?: ResponseIdempotencyCache;

    /**
     * Bounded-wait timeout (ms) for `idempotencyCache.record()`.
     *
     * **Background**: the `record()` in the finally phase is a **correctness dependency** (it promises "a later
     * retry can hit the same response"), not a performance option. So the main path must `await` it — if it were
     * async fire-and-forget, the cache would still be unwritten within the retry hit window → re-running the full
     * execution → duplicate auditing + duplicate business side effects, breaking the idempotency promise.
     *
     * **But** an unbounded await means that once the cache backend (Postgres/Redis) hangs, it stalls every response,
     * forcing callers into TCP timeouts and re-delivery, which amplifies the very duplicate-delivery problem it was meant to solve.
     *
     * **What this timeout does**: `Promise.race([record(), timeout])` — a timeout is treated as a cache-write
     * failure, and after a `console.error` alert the main flow immediately returns the already-built response envelope;
     * business correctness does not depend on this record succeeding (the worst case for a later re-delivery is re-running the
     * idempotent business handler once), but observability is preserved (the alert points at the cache backend).
     *
     * **Default 2000 ms**: Postgres/Redis P99 under normal load is far below this; cross-region deployments
     * or high-latency links can raise it; low-latency environments can lower it but should not go below 500 ms (to avoid
     * mistaking an occasional GC pause for a timeout).
     */
    idempotencyCacheWriteTimeoutMs?: number;

    /**
     * Injectable logging port. When not injected, defaults to `console.warn / error / log`, preserving
     * existing behavior (assertions that spy directly on `console.*` in tests are unchanged).
     *
     * Why injection is needed:
     *   - The `idempotencyCache` not-configured warning would flood the logs in a single-instance multi-tenant orchestrator deployment;
     *     injecting a logger lets it route to a structured logging backend (pino / winston / OpenTelemetry).
     *   - `step3.5 REJECTED record write failed` is an audit-invariant-break signal and
     *     must route to an operations alert channel rather than the stderr log ocean.
     *   - `verbose` step tracing is noisy in tests; injecting a no-op logger silences it entirely.
     *
     * Semantic conventions (consistent with the default console adapter):
     *   - `warn` / `error` are emitted unconditionally, not gated by `config.verbose`;
     *   - `info` is emitted only when `config.verbose=true` (for per-step tracing);
     *   - `debug` is reserved for future fine-grained tracing and is currently unused.
     */
    logger?: OrchestratorLogger;
}

/**
 * Structured logging port — the orchestrator itself does not depend on any third-party logger implementation,
 * it only requires the caller to provide a minimal set of methods.
 *
 * Compatible with pino/winston/OpenTelemetry Bridge: the Logger objects of those libraries all
 * naturally satisfy this interface (same method names, compatible signatures).
 */
export interface OrchestratorLogger {
    warn(message: string): void;
    error(message: string): void;
    info(message: string): void;
    debug?(message: string): void;
}

/**
 * Default console adapter — preserves the historical pre-injection behavior:
 *   - `warn` → `console.warn`
 *   - `error` → `console.error`
 *   - `info` → `console.log` (same target as the `console.log` in logStep / logVerbose / logFailure / logTotal,
 *     ensuring test spies still hit in the verbose=true scenario)
 */
const DEFAULT_CONSOLE_LOGGER: OrchestratorLogger = {
    warn: (message) => console.warn(message),
    error: (message) => console.error(message),
    info: (message) => console.log(message),
};

/** Default bounded timeout for `idempotencyCache.record()` (see the config comment). */
const IDEMPOTENCY_CACHE_WRITE_TIMEOUT_MS_DEFAULT = 2000;

/**
 * sender-side cumulative_limit atomic query+reservation port.
 *
 * Signature aligned with the L3 CumulativeTracker.checkAndReserve.
 * The perspective is the **principal**, not the agent — multiple agents under the same principal share the cumulative.
 *
 * The implementer (sender-principal-side operations) must guarantee:
 *   - serialization at `(principalDid, meterField.metric, windowStart)` granularity
 *   - recordId as the idempotency key: retrying the same recordId returns the same result
 *   - the reservation counts toward the cumulative (PENDING occupies quota)
 *   - a TTL or out-of-band settle mechanism to prevent a reservation from hanging forever
 */
export interface SenderCumulativeTrackerReader {
    checkAndReserve(
        recordId: string,
        principalDid: DID,
        meterField: MeterFieldRef,
        windowStart: Date,
        now: Date,
        reserveAmount: number,
    ): Promise<{ allowed: boolean; currentCumulative: number }>;

    /**
     * best-effort reservation cancellation.
     *
     * Semantics: called by the recipient-side orchestrator within the window where the **reservation has succeeded
     * but a later path fails** (step4 policy rejection / business executor throws / an exception in the response-build
     * phase), to notify the tracker to release the PENDING reservation for the given recordId.
     *
     * **Why it is optional**:
     *   - the recipient side cannot do a same-transaction settle across the trust domain (see the settlement-ownership comment above);
     *   - the spec permits "a PENDING reservation is automatically turned to SETTLED/RELEASED by a background cleanup job
     *     (based on a created_at timeout)" as a fallback;
     *   - the tracker implementer may skip this method if its TTL policy is sufficient.
     *
     * **Caller-side filtering (already done by the orchestrator)**:
     *   the orchestrator only issues cancelReservation for metrics with `countFilter='SUCCESS'`;
     *   the recordId of a metric with `countFilter='*'` (e.g. api_call_count)
     *   is never passed to this method — this is defense in depth, so that even if the tracker implementation ignores
     *   countFilter semantics, the failure count of a COUNT+`*` metric cannot be bypassed.
     *
     * **Implementation constraints** (if implemented):
     *   - MUST be idempotent (cancelling the same recordId repeatedly must not throw);
     *   - MUST tolerate a recordId that "was never reserved" (this happens with cross-trust-domain best-effort calls);
     *   - MUST treat cancel for a `countFilter='*'` metric (`api_call_count`, etc.) as
     *     "turn to SETTLED" (do not release the count) — the spec requires failures/ERROR to also count toward the cumulative, preventing a failed
     *     retry from bypassing the limit. If the tracker cannot look up the metric's
     *     aggregation+countFilter by recordId on its own, it must **not implement**
     *     this method (fall back to the TTL fallback), and must not blindly release.
     *   - the orchestrator caller swallows exceptions via try/catch and routes them to console.error (a non-blocking
     *     path), so a tracker throw will not break the main flow but will still pollute the logs.
     */
    cancelReservation?(recordId: string): Promise<void>;
}

/**
 * **Response-level idempotency cache** (note the name —
 * this is **not** a ledger; a ledger's core property is being an "immutable source of truth", which a cache is not).
 *
 * Background: the recordId of the sender cumulative reservation changed from a
 * sender-controlled envelope.id to a recipient-generated UUID, closing the attack where the sender bypasses quota with the
 * same id + different params. But correspondingly, "TCP retries of the same envelope"
 * are no longer automatically deduplicated by the reservation idempotency mechanism — a resend is treated as a new request and runs the full
 * verifyCapability + checkAndReserve + businessHandler flow, amplifying into multiple
 * deductions + multiple business side effects.
 *
 * **This interface provides a "last-writer-wins" response cache**, solving the narrow case of "a temporally later retry
 * hitting the previous response": before handleEnvelope enters step3.5, the cache is looked up by
 * `(senderDid, sessionId, envelopeId)`; on a hit → return the cached response directly;
 * on a miss → run the full flow and record in finally.
 *
 * **What this interface does NOT provide** (the consumer must understand the boundaries):
 *   1. **Concurrency atomicity**: when two same-envelope requests arrive concurrently, both check a miss and both
 *      pass through to the executor. The current implementation is check-then-record, **not** claim/finalize.
 *   2. **Crash recovery**: if the executor has committed external business side effects but record() has not completed when it crashes
 *      → a re-delivery after restart re-runs it. The in-memory implementation loses everything on crash, and a persistent implementation can only mitigate.
 *   3. **Business-level at-most-once**: this is **the business handler's responsibility** (the handler must be
 *      idempotent), not this cache's responsibility.
 *
 * **Upgrade path**: `EnvelopeLedger` (atomic claim/finalize + a PENDING/
 * COMMITTED state machine + Postgres transactions) is deferred to a later release. The current
 * interface is a transitional form; **do not** mistake it for a ledger.
 *
 * **Not injected** → the orchestrator emits a one-time console.warn on the first handleEnvelope,
 * but does not force a rejection (maintains backward compatibility). Production deployments **should** inject a persistent implementation (Postgres/Redis
 * shared across processes), and the business handler **must** be idempotent.
 */
/**
 * The idempotency key must be partitioned by the **recipient agent** (i.e. the agent that owns the cache),
 * otherwise a shared backend (Postgres/Redis) would wrongly reuse agent A's response for agent B —
 * the scenario where the sender sends the same envelope.id + same sessionId to two different recipients.
 *
 * `recipientDid` field semantics: **the DID of the agent that owns this cache** (i.e.
 * the orchestrator's `config.agentDid`), not the `recipientDid` in the original request envelope header
 * (the two are usually identical, but conceptually the former is "which agent stamped the cache entry"
 * and the latter is "whom the envelope was signed for").
 */
export interface IdempotencyKey {
    /** the DID of the agent that owns the cache — the strong-isolation dimension when multiple recipients share a backend. */
    recipientDid: DID;
    senderDid: DID;
    sessionId: string | null;
    envelopeId: string;
}

/**
 * **Cache the logical response spec rather than the original signed envelope**.
 *
 * Background: if a NegotiationEnvelope were cached directly, a HIT would return the old envelope verbatim, whose
 * `timestamp` field is fixed by the signature and immutable — a 10-minute default TTL > the 5-minute clock-skew
 * window (verifyEnvelope's ±300000ms cap) means a retry more than 5 minutes after the first response would get
 * an old response that **the protocol requires to be rejected**. The direct-envelope-caching design traps the
 * caller in a "returnable but always rejected" loop within the TTL window.
 *
 * Fix: cache the response's **logical spec** (immutable business data — kind/body/message/
 * recordId/...), and on a HIT use `rebuildEnvelopeFromSpec()` to re-sign a new
 * envelope against the current clock, so the timestamp is always fresh. The re-sign cost is Ed25519 ≈0.5ms, negligible; the idempotency promise
 * is fully preserved (the business result is unchanged), and TTL is fully decoupled from clock skew.
 *
 * discriminated union on `kind`: each branch keeps only the fields needed to construct its response envelope,
 * which TS enforces at compile time, preventing a future new response path from being missed.
 */
export type CachedResponseSpec =
    | {
          kind: 'SUCCESS';
          /** the response envelope's senderDid (= the cache-owning agent's agentDid). */
          agentDid: DID;
          /** the response envelope's recipientDid (= the original request envelope's senderDid). */
          originalSenderDid: DID;
          sessionId: string | null;
          requestId: string;
          action: string;
          data: Record<string, unknown>;
          recordId: string;
          /**
           * the response envelope's sequenceNumber; aligned with the request envelope: when the request has no
           * sequenceNumber (a non-session message), the response does not carry one either, so this is
           * undefined. rebuildEnvelopeFromSpec passes it through as-is.
           */
          sequenceNumber?: number;
      }
    | {
          kind: 'AUTHORIZATION_INSUFFICIENT' | 'IDENTITY_VERIFICATION_FAILED';
          agentDid: DID;
          originalSenderDid: DID;
          sessionId: string | null;
          relatedEnvelopeId: string;
          message?: string;
      }
    | {
          kind: 'INTERNAL_ERROR' | 'INVALID_ENVELOPE';
          agentDid: DID;
          originalSenderDid: DID;
          sessionId: string | null;
          relatedEnvelopeId?: string;
          message?: string;
      };

/**
 * Response-level idempotency cache contract.
 *
 * This interface does **not** store the envelope — it stores the spec. On a HIT the orchestrator calls
 * `rebuildEnvelopeFromSpec()` to re-sign a new envelope against the current clock (fresh timestamp),
 * avoiding the case where TTL > clock skew causes an old envelope to be rejected as expired.
 */
export interface ResponseIdempotencyCache {
    /**
     * Query whether the (recipientDid, senderDid, sessionId, envelopeId) tuple has already been processed.
     *
     * The key introduces the `recipientDid` dimension (= the cache-owning agent's
     * agentDid). When different recipients share a persistent backend, this dimension provides strong isolation, avoiding
     * cross-agent response cross-talk.
     *
     * @returns hit → return the CachedResponseSpec (the caller rebuilds a new envelope);
     *          miss → return null (the caller continues the normal flow and eventually calls record).
     *
     * Implementation constraints: when sessionId is null (a non-session message), use '' (empty string)
     * in key construction; `check` itself is atomic, but is not atomic together with the later `record` — a concurrent same
     * envelope will still pass through (a known semantic boundary of the interface, see the comment above).
     */
    check(key: IdempotencyKey): Promise<CachedResponseSpec | null>;

    /**
     * Record this handleEnvelope's response spec. Only a "post-commit-boundary terminal state" or a "deterministic
     * permanent failure" is passed here by the orchestrator (the `cacheable`
     * whitelist has already filtered); a HIT-returned response does **not** call record again (avoiding prolonging its life).
     *
     * Implementation constraints: MUST be idempotent (recording the same key repeatedly must not throw); the TTL is chosen by the implementer
     * and is **decoupled** from the envelope `verifyEnvelope` clock-skew window (on a HIT the orchestrator
     * re-signs the envelope, unaffected by the old timestamp).
     */
    record(key: IdempotencyKey, spec: CachedResponseSpec): Promise<void>;
}

/**
 * Rebuild and re-sign the response envelope from a spec.
 *
 * Called on every HIT, producing an envelope with a fresh timestamp and a valid signature. The Ed25519
 * signing cost is ≈0.5ms, negligible for the TCP-retry scenario (a small number of requests by nature).
 *
 * @param spec the logical response returned by a cache HIT
 * @param senderPrivateKey this agent's private key — must come from the caller (the orchestrator's
 *                         `config.agentPrivateKey`), and is not persisted as a spec field.
 */
export function rebuildEnvelopeFromSpec(
    spec: CachedResponseSpec,
    senderPrivateKey: string,
): NegotiationEnvelope {
    if (spec.kind === 'SUCCESS') {
        return buildEnvelope({
            senderDid: spec.agentDid,
            senderPrivateKey,
            recipientDid: spec.originalSenderDid,
            sessionId: spec.sessionId,
            messageType: 'NEGOTIATION_RESPONSE',
            body: {
                requestId: spec.requestId,
                action: spec.action,
                status: 'SUCCESS',
                data: spec.data,
                recordId: spec.recordId,
            },
            sequenceNumber: spec.sequenceNumber,
        });
    }

    if (spec.kind === 'AUTHORIZATION_INSUFFICIENT') {
        return buildAuthorizationInsufficientEnvelope({
            senderDid: spec.agentDid,
            senderPrivateKey,
            recipientDid: spec.originalSenderDid,
            sessionId: spec.sessionId,
            message: spec.message,
            relatedEnvelopeId: spec.relatedEnvelopeId,
        });
    }

    if (spec.kind === 'IDENTITY_VERIFICATION_FAILED') {
        return buildIdentityVerificationFailedEnvelope({
            senderDid: spec.agentDid,
            senderPrivateKey,
            recipientDid: spec.originalSenderDid,
            sessionId: spec.sessionId,
            message: spec.message,
            relatedEnvelopeId: spec.relatedEnvelopeId,
        });
    }

    if (spec.kind === 'INVALID_ENVELOPE') {
        return buildInvalidEnvelopeEnvelope({
            senderDid: spec.agentDid,
            senderPrivateKey,
            recipientDid: spec.originalSenderDid,
            sessionId: spec.sessionId,
            message: spec.message,
            relatedEnvelopeId: spec.relatedEnvelopeId,
        });
    }

    // INTERNAL_ERROR
    return buildInternalErrorEnvelope({
        senderDid: spec.agentDid,
        senderPrivateKey,
        recipientDid: spec.originalSenderDid,
        sessionId: spec.sessionId,
        message: spec.message,
        relatedEnvelopeId: spec.relatedEnvelopeId,
    });
}

/**
 * In-memory `ResponseIdempotencyCache` reference implementation.
 *
 * - The Map stores `${recipientDid}#${senderDid}#${sessionId ?? ''}#${envelopeId}`
 *   → `{ spec, createdAt }`; the recipient dimension is included in the key.
 * - It stores a `CachedResponseSpec` (the logical response), **not** the envelope;
 *   this avoids an old signed envelope being rejected by verifyEnvelope after clock skew.
 * - Cleaned up by `createdAt` TTL (default 10 minutes, decoupled from envelope clock skew —
 *   on a HIT the orchestrator re-signs a new envelope).
 * - **Single-process in-memory**, not shared across workers; on a process crash **all data is lost** (an inherent limitation).
 * - "lazy eviction on record" (O(1) amortized), with no timer.
 *
 * **Suitable scenarios**: local development, unit tests, demo (golden-path), single-instance best-effort
 *   response dedup.
 *
 * **Unsuitable scenarios**:
 *   - financial-grade business (needs cross-process persistence + an idempotent business handler);
 *   - multi-worker deployment (needs cross-process sharing, switch to a Postgres/Redis implementation);
 *   - scenarios requiring strict at-most-once (need the `EnvelopeLedger`).
 */
export class InMemoryResponseIdempotencyCache implements ResponseIdempotencyCache {
    private readonly store = new Map<
        string,
        { spec: CachedResponseSpec; createdAt: number }
    >();
    private readonly ttlMs: number;

    public constructor(options?: { ttlMs?: number }) {
        this.ttlMs = options?.ttlMs ?? 10 * 60 * 1000;
    }

    public check(key: IdempotencyKey): Promise<CachedResponseSpec | null> {
        const k = this.buildKey(key);
        const entry = this.store.get(k);
        if (!entry) return Promise.resolve(null);
        if (Date.now() - entry.createdAt > this.ttlMs) {
            this.store.delete(k);
            return Promise.resolve(null);
        }
        return Promise.resolve(entry.spec);
    }

    public record(
        key: IdempotencyKey,
        spec: CachedResponseSpec,
    ): Promise<void> {
        const now = Date.now();
        // Lazy eviction: on each write, also scan once for expired entries (amortized O(n) / n writes)
        for (const [existingKey, entry] of this.store) {
            if (now - entry.createdAt > this.ttlMs) {
                this.store.delete(existingKey);
            }
        }
        this.store.set(this.buildKey(key), { spec, createdAt: now });
        return Promise.resolve();
    }

    private buildKey(key: IdempotencyKey): string {
        return `${key.recipientDid}#${key.senderDid}#${key.sessionId ?? ''}#${key.envelopeId}`;
    }
}

export type BusinessHandler = (
    context: BusinessHandlerContext,
) => Promise<Record<string, unknown>>;

export interface BusinessHandlerContext {
    action: string;
    params: Record<string, unknown>;
    senderDid: DID;
    sessionId: string | null;
}

export interface OrchestratorHandleResult {
    handled: boolean;
    responseEnvelope: NegotiationEnvelope;
    recordId?: string;
    rejectionReason?: string;
    /**
     * The **terminal-state whitelist** flag for the response-level idempotency cache.
     *
     * Semantics:
     *   - omitted / `true` → the response is a "post-commit-boundary terminal state" or a "deterministic permanent failure",
     *     and the finally phase **must** write idempotencyCache so a later TCP retry hits and avoids
     *     duplicate side effects.
     *   - `false` → the response is a **pre-commit-boundary** transient failure (e.g. the INTERNAL_ERROR
     *     escalation in the step3.5 REJECTED path due to an audit recorder write failure, or an
     *     INTERNAL_ERROR with committed=false in the outer catch). In this case the business **has not landed**,
     *     and caching this response would **poison** a retryable failure into a permanent failure within the TTL window (the caller
     *     would hit the old error even after its dependency recovers and it retries, never re-running the authorization/execution path).
     *
     * **Decision principles** (a new return path must be evaluated explicitly; do not rely on the default):
     *   - identity verification failure → cacheable (deterministic permanent rejection)
     *   - step3.5 authorization rejection (the REJECTED audit has landed) → cacheable
     *   - the INTERNAL_ERROR escalated from a step3.5 audit recorder throw → **NOT** cacheable
     *   - step4 policy rejection (the REJECTED audit has landed) → cacheable
     *   - step4/5 SUCCESS → cacheable
     *   - outer catch: committed=true (business has landed) → cacheable; otherwise → NOT
     *   - outer catch INVALID_MESSAGE (failed before parseEnvelope, so idempotencyKey
     *     is not yet initialized and finally will not write) → the field is meaningless, keep the default
     *
     * **This field does not appear in the wire format**: it does not enter the response envelope, is not signed, and is not written to
     * the ledger; it is only used internally by the orchestrator in finally to decide whether to call
     * `idempotencyCache.record`.
     */
    cacheable?: boolean;

    /**
     * The logical response spec used by the outer finally's `idempotencyCache.record()`.
     * The cache does **not** store the original signed envelope (TTL > clock skew would cause the old
     * envelope to be rejected by the verifyEnvelope time window); it stores the spec + re-signs a new envelope on a HIT.
     *
     * Semantics:
     *   - a return path with `cacheable: true` MUST produce a spec (sourced from responseEnvelope
     *     with one-to-one fields) — finally uses it to write the cache.
     *   - when `cacheable: false`, or `cacheable` defaults to true but the spec is missing (the outer catch
     *     INVALID_MESSAGE branch where idempotencyKey is not yet initialized), the finally guard
     *     skips record and this field's value is ignored.
     *   - the response of the HIT path (cacheable=false) comes from re-signing the cache spec and is not written again —
     *     the spec itself can be omitted.
     *
     * **This field likewise does not appear in the wire format** (an orchestrator-internal convention).
     */
    responseSpec?: CachedResponseSpec;
}

/** Token read port (a subset of the L3 TokenStore). */
export interface TokenStoreReader {
    getToken(tokenId: string): Promise<CapabilityToken | null>;
}

/** Delegation chain validator (a function-signature abstraction of the L2 validateDelegationChain).
 *
 * The 2nd parameter was upgraded from resolvePublicKey(string) to resolvePublicKeys(ResolvedPublicKeys),
 * supporting ROTATING dual-key fallback; the original 6th parameter resolveKeyRotationState was removed.
 */
export type DelegationChainValidator = (
    token: CapabilityToken,
    resolvePublicKeys: (did: DID) => Promise<ResolvedPublicKeys | null>,
    isRevoked?: (tokenId: string) => Promise<boolean>,
    now?: Timestamp,
    resolveToken?: (tokenId: string) => Promise<CapabilityToken | null>,
) => Promise<DelegationChainValidationResult>;

type StepStatus = 'OK' | 'FAIL';

/**
 * Structured handle for a sender cumulative reservation.
 * Carries countFilter so cancelReservedRecords can filter per spec — '*' means failures
 * also count (api_call_count, etc.) and cannot be cancelled; 'SUCCESS' allows cancel (SUM or
 * COUNT+SUCCESS, where failures should not count).
 */
interface Reservation {
    readonly recordId: string;
    readonly metric: string;
    readonly countFilter: 'SUCCESS' | '*';
}

export class Orchestrator {
    private readonly config: OrchestratorConfig;
    private readonly resolvePublicKey: (did: DID) => Promise<string | null>;
    /**
     * Dual-key resolution (current + previous + rotationState).
     * Adopted directly when OrchestratorConfig.resolvePublicKeys is injected; otherwise wrapped from
     * resolvePublicKey into a STABLE state (backward compatible; during ROTATING a token signed with the
     * previous key is still rejected as STABLE in this mode).
     */
    private readonly resolvePublicKeys: (
        did: DID,
        now?: Date,
    ) => Promise<ResolvedPublicKeys | null>;
    /**
     * Flags whether resolvePublicKeys was explicitly injected via config.
     * Only when explicitly injected is the step3.5 null → token_issuer_unknown rejection path enabled;
     * a null from the fallback-wrapper-wrapped resolvePublicKey does not trigger that path and keeps the
     * did:key-derivation fallback (backward compat).
     */
    private readonly resolvePublicKeysExplicit: boolean;
    private readonly resolveAgentDocument?: (
        did: DID,
    ) => Promise<AgentIdentityDocument | null>;
    private readonly delegationChainValidator?: DelegationChainValidator;
    // Sender-side scope evaluation reuses the L3 ScopeEvaluator. cumulative_limit needs
    // ledger access (see the OrchestratorConfig.senderCumulativeTracker comment);
    // when the port is not injected, verifyCapability() explicitly fail-closes; when injected, the port evaluates separately
    // and ScopeEvaluator only handles allowlist/numeric_limit/temporal_scope.
    private readonly scopeEvaluator: ScopeEvaluator = new ScopeEvaluator();
    private readonly policyRecorder: PolicyRecorder;
    private readonly senderCumulativeTracker?: SenderCumulativeTrackerReader;
    private readonly idempotencyCache?: ResponseIdempotencyCache;
    /** When idempotencyCache is not injected, emit a one-time warning on the first handleEnvelope to avoid a log storm. */
    private idempotencyCacheWarnEmitted = false;
    /** Bounded timeout for `idempotencyCache.record()` (see OrchestratorConfig). */
    private readonly idempotencyCacheWriteTimeoutMs: number;

    /** Injected or default console adapter — all log output must go through this.logger.*. */
    private readonly logger: OrchestratorLogger;

    public constructor(config: OrchestratorConfig) {
        this.config = config;
        this.logger = config.logger ?? DEFAULT_CONSOLE_LOGGER;

        // federatedResolver and resolvePublicKey are mutually exclusive, to avoid ambiguity over which path
        // takes effect in staged-rollout scenarios. If caching is needed, wrap the cache inside the FederatedResolver implementation.
        if (config.federatedResolver && config.resolvePublicKey) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'Orchestrator config conflict: federatedResolver and resolvePublicKey are mutually exclusive. Pick one (wrap caching inside FederatedResolver if needed).',
            );
        }

        if (
            !config.federatedResolver &&
            !config.resolvePublicKey &&
            !config.resolveAgentDocument
        ) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'Orchestrator requires one of: federatedResolver, resolvePublicKey, resolveAgentDocument.',
            );
        }

        // managedServiceClient assembly.
        // If managedServiceClient is injected, wrap its resolveDid into a FederatedResolver-compatible
        // interface, overriding the federatedResolver path. ManagedServiceClient handles fallback internally,
        // so the caller need not be aware of managed-service availability.
        // Not injected (default) = use the federatedResolver path directly, with behavior unchanged.
        const effectiveFederatedResolver:
            | import('@coivitas/types').FederatedResolver
            | undefined = config.managedServiceClient
            ? (() => {
                  const msc = config.managedServiceClient;
                  return {
                      resolve: (did) => msc.resolveDid(did),
                      invalidateCache: () => {
                          /* the managed-service client has no local cache, noop */
                      },
                      getMetrics: () => ({
                          resolveTotal: 0,
                          resolveSuccess: 0,
                          resolveNull: 0,
                          resolveInternalError: 0,
                          latencyP50Ms: 0,
                          latencyP95Ms: 0,
                          latencyP99Ms: 0,
                          nodes: {},
                          versionConflictCount: 0,
                          signatureInvalidCount: 0,
                          quorumUnmetCount: 0,
                          cacheHit: 0,
                          cacheMiss: 0,
                          quorumVoteSplitCount: 0,
                          dnsRebindingBlockedCount: 0,
                          quorumReachedCount: 0,
                      }),
                      close: () => Promise.resolve(),
                  };
              })()
            : config.federatedResolver;

        // Document-resolution priority: explicit resolveAgentDocument > derived from effectiveFederatedResolver > undefined
        // Used only for the step3.5 principalDid consistency check.
        if (config.resolveAgentDocument) {
            this.resolveAgentDocument = config.resolveAgentDocument;
        } else if (effectiveFederatedResolver) {
            const federated = effectiveFederatedResolver;
            this.resolveAgentDocument = (did) => federated.resolve(did);
        }

        // Public-key resolution priority:
        // derived from effectiveFederatedResolver > legacy resolvePublicKey > derived from resolveAgentDocument
        // The mutual-exclusivity constraint was checked above, so at most one of these three branches takes effect.
        if (effectiveFederatedResolver) {
            const federated = effectiveFederatedResolver;
            this.resolvePublicKey = async (did) => {
                const doc = await federated.resolve(did);
                return doc?.publicKey ?? null;
            };
        } else if (config.resolvePublicKey) {
            this.resolvePublicKey = config.resolvePublicKey;
        } else {
            // At this point resolveAgentDocument is guaranteed to exist (ensured by the construction check)
            const docResolver = this.resolveAgentDocument!;
            this.resolvePublicKey = async (did) => {
                const doc = await docResolver(did);
                return doc?.publicKey ?? null;
            };
        }

        // Dual-key resolution port assembly.
        // Priority: config.resolvePublicKeys (dual-key mode) > resolvePublicKey wrapped as STABLE.
        // In STABLE mode a previous-key token during ROTATING is still rejected (consistent with the prior single-key behavior);
        // dual-key mode being enabled = it truly takes effect after IdentityRegistry.resolvePublicKeys is injected.
        if (config.resolvePublicKeys) {
            this.resolvePublicKeys = config.resolvePublicKeys;
            this.resolvePublicKeysExplicit = true;
        } else {
            const fallback = this.resolvePublicKey;
            this.resolvePublicKeys = async (did) => {
                const key = await fallback(did);
                if (key === null) return null;
                return { current: key, rotationState: 'STABLE' };
            };
            this.resolvePublicKeysExplicit = false;
        }

        // ── policyRecorder unconditionally required ──
        // Any orchestrator instance may reach the authorization-rejection path at step3.5 (even a
        // agent-pool-only node in a mixed-version deployment receiving a capability-bound envelope will
        // trigger a delegation_phase2_dependencies_missing rejection). The L5 audit
        // invariant requires exactly-one ActionRecord per handleEnvelope (excluding format/sig
        // errors), so policyRecorder is decoupled from tokenStore and is always required.
        if (!config.policyRecorder) {
            throw new ProtocolError(
                'INTERNAL_ERROR',
                'Orchestrator requires policyRecorder (audit invariant: step3.5 rejection must produce ActionRecord regardless of capability wiring).',
            );
        }

        // ── One-time check of the capability path's required dependencies ──
        // Injecting tokenStore = declaring capability authorization semantics → the other three companion ports are required.
        // Missing any one → construction throws ProtocolError naming which is missing, avoiding a "config bomb" where the deployment
        // succeeds but 100% rejects on the first capability-bound envelope.
        // Note: resolveAgentDocument can be derived from federatedResolver, so check the derived result
        // `this.resolveAgentDocument` rather than `config.resolveAgentDocument`.
        if (config.tokenStore) {
            const missing: string[] = [];
            if (!config.delegationChainValidator)
                missing.push('delegationChainValidator');
            if (!config.revocationChecker) missing.push('revocationChecker');
            if (!this.resolveAgentDocument)
                missing.push('resolveAgentDocument');
            if (missing.length > 0) {
                throw new ProtocolError(
                    'INTERNAL_ERROR',
                    `Orchestrator capability path requires tokenStore companion dependencies: ${missing.join(', ')}.`,
                );
            }
        }
        this.delegationChainValidator = config.delegationChainValidator;
        this.policyRecorder = config.policyRecorder;
        this.senderCumulativeTracker = config.senderCumulativeTracker;
        this.idempotencyCache = config.idempotencyCache;
        this.idempotencyCacheWriteTimeoutMs =
            config.idempotencyCacheWriteTimeoutMs ??
            IDEMPOTENCY_CACHE_WRITE_TIMEOUT_MS_DEFAULT;
    }

    public async handleEnvelope(
        incoming: NegotiationEnvelope,
    ): Promise<OrchestratorHandleResult> {
        const startedAt = Date.now();

        // ── Response-level idempotency cache (not an at-most-once ledger) ──
        // After step2 verifyEnvelope succeeds (signature + time-window valid), look up idempotencyCache by the
        // (senderDid, sessionId, envelope.id) tuple. On a hit → return the cached
        // response directly (do not descend into verifyCapability / step4 / businessHandler),
        // avoiding a single request being amplified by TCP retries into multiple deductions + multiple business side effects.
        // Every return path records uniformly via `idempotencyCache.record` at the end of the function.

        // **Semantic boundaries** (read strictly literally, see the ResponseIdempotencyCache interface comment):
        // - this cache is only effective for **temporally later** retries (check miss → run the full flow
        // → finally record → next hit);
        // - concurrent same-envelope: both may miss and both pass through to the executor;
        // - crash window: if the executor has committed side effects but record has not completed when it crashes → a re-delivery
        // re-runs it.
        // - business-level at-most-once is **not guaranteed by this cache**; it is guaranteed by an idempotent business handler.

        // idempotencyCache not injected: emit a one-time warn, do not force a rejection (maintains compatibility).
        if (!this.idempotencyCache && !this.idempotencyCacheWarnEmitted) {
            this.idempotencyCacheWarnEmitted = true;
            this.logger.warn(
                '[ORCH] idempotencyCache is not configured — duplicate envelopes will NOT be short-circuited. ' +
                    'Note: this cache provides **response-level** idempotency only, **not** at-most-once business semantics — ' +
                    'business handlers MUST be idempotent regardless of cache presence. ' +
                    'Production deployments SHOULD inject a persistent ResponseIdempotencyCache (e.g., Postgres/Redis) ' +
                    'to short-circuit TCP retries; a future release will deliver a true EnvelopeLedger (atomic claim/finalize).',
            );
        }

        // The idempotency key is constructed only after parsed.header.senderDid/sessionId is first obtained;
        // this variable is assigned inside try and read in the finally phase to write the cache.
        // The key adds the recipientDid dimension (see the IdempotencyKey definition).
        let idempotencyKey: IdempotencyKey | null = null;

        // Final result: assigned on every return path, written to the cache in the finally phase.
        // A throw is extremely rare (handleEnvelope promises in theory never to throw), but for
        // finally type safety we keep an undefined initial value + a runtime guard.
        let finalResult: OrchestratorHandleResult | undefined;
        const handleResult = async (): Promise<OrchestratorHandleResult> => {
            const result = await this.handleEnvelopeInner(
                incoming,
                startedAt,
                (key) => {
                    idempotencyKey = key;
                },
            );
            finalResult = result;
            return result;
        };

        try {
            return await handleResult();
        } finally {
            // finally writes the response cache uniformly.

            // The five preconditions for writing (record only when all are satisfied):
            // 1) idempotencyCache is injected (not injected = best-effort compatibility path);
            // 2) idempotencyKey was initialized after step2 verifyEnvelope succeeded —
            // not initialized means the main flow failed at the parse/identity phase, and the next
            // call will re-attempt parseEnvelope, so it should not short-circuit anyway;
            // 3) finalResult was already assigned on inner's return path (in theory always true,
            // the runtime guard is kept in case an inner exception escapes and breaks the finally invariant);
            // 4) finalResult.cacheable !== false. Only a post-commit-boundary terminal state or a deterministic
            // permanent failure is cached; **retryable transient failures** like "the INTERNAL_ERROR
            // escalated from a step3.5 recorder throw" and "the INTERNAL_ERROR with committed=false in the outer
            // catch" are explicitly set to false, to avoid poisoning a temporary
            // failure into a permanent failure within the TTL window; the HIT path is also false,
            // to avoid prolonging an existing entry's life (it already exists, no need to rewrite).
            // 5) finalResult.responseSpec must exist (the cache stores a
            // CachedResponseSpec, not an envelope). In theory every return path with cacheable=
            // true explicitly produces a spec; the guard is defense in depth.

            // `record()` is wrapped in a bounded timeout via `Promise.race`. A timeout is treated the same as a record
            // failure — after an alert it does not block the main flow; business correctness does not depend on this record
            // succeeding (the worst case for a later re-delivery is re-running the idempotent business handler once).

            // **Why it is not async**: fire-and-forget would let a later request within the retry window
            // check a miss → re-run the full execution → duplicate auditing/duplicate business side effects, directly
            // breaking the idempotency promise. The cache is a correctness dependency and must be awaited synchronously (but with an upper bound on the wait).
            if (
                this.idempotencyCache &&
                idempotencyKey !== null &&
                finalResult !== undefined &&
                finalResult.cacheable !== false &&
                finalResult.responseSpec !== undefined
            ) {
                const cache = this.idempotencyCache;
                const spec = finalResult.responseSpec;
                const writeTimeoutMs = this.idempotencyCacheWriteTimeoutMs;
                let timeoutHandle: NodeJS.Timeout | undefined;
                try {
                    await Promise.race([
                        cache.record(idempotencyKey, spec),
                        new Promise<never>((_resolve, reject) => {
                            timeoutHandle = setTimeout(() => {
                                reject(
                                    new Error(
                                        `idempotencyCache.record exceeded ${writeTimeoutMs}ms`,
                                    ),
                                );
                            }, writeTimeoutMs);
                            // Allow the process to exit without waiting for this timer
                            timeoutHandle.unref?.();
                        }),
                    ]);
                } catch (cacheError) {
                    // record failed or timed out — the response envelope is already available to return,
                    // only an alert is written. A later re-delivery of the same envelope re-runs the full flow (the business
                    // handler must be idempotent), which is the established boundary.
                    this.logger.error(
                        `[ORCH] idempotencyCache.record failed: ${
                            cacheError instanceof Error
                                ? cacheError.message
                                : 'unknown error'
                        }. Duplicate deliveries of this envelope may be re-processed.`,
                    );
                } finally {
                    if (timeoutHandle !== undefined) {
                        clearTimeout(timeoutHandle);
                    }
                }
            }
        }
    }

    /**
     * Inner helper for the handleEnvelope main flow. All of the original try/catch logic lives here.
     *
     * @param onIdempotencyKeyReady called back after the parsed envelope is first obtained, to expose the
     *                              idempotency key to the outer finally for uniform
     *                              cache writing.
     */
    private async handleEnvelopeInner(
        incoming: NegotiationEnvelope,
        startedAt: number,
        onIdempotencyKeyReady: (key: IdempotencyKey) => void,
    ): Promise<OrchestratorHandleResult> {
        // step3.5 may have already successfully reserved the sender cumulative.
        // Hoist the handle outside try so that even if step4/step5/businessHandler throws and triggers the
        // outer catch, it can best-effort cancel (otherwise quota stays locked until the TTL fallback).
        // A structured Reservation array; the cancel path filters by countFilter.
        let reservationsFromCapability: readonly Reservation[] = [];

        // The commit flag.
        // Semantics: once step4's executor() returns successfully (the business side effect has occurred),
        // the sender-side cumulative reservation is already "bound" to the real business; the outer catch
        // must not cancel that reservation, otherwise:
        // 1) quota is underestimated (actually consumed but the quota is released);
        // 2) a caller retrying on "insufficient quota" could re-trigger the same business side effect, producing
        // a costly inconsistency where it executes multiple times but counts as 1.
        // The binding of quota and ledger, in the spec's settle semantics,
        // is equivalent to "SUCCESS → PENDING turned to SETTLED"; there is no atomic settle API on the sender side,
        // so the tracker TTL fallback turns PENDING→SETTLED instead (aligned with ActionRecord(SUCCESS)).
        // This committed flag prevents the degradation of "an explicit cancel overriding the TTL settle".

        // Setting committed to true cannot be placed after executeWithPolicy **returns** successfully:
        // the order inside the engine's try block is executor() → recorder.record(SUCCESS), and
        // if recorder.record throws (DB failure, etc.), executeWithPolicy throws,
        // committed is still false, and the outer catch cancels the reservation of a business that actually committed.
        // Fix: via the engine-injected `onExecutorSuccess` hook, set committed to true early after the executor succeeds
        // and before the recorder writes — so even if the recorder then fails and throws,
        // the reservation is not wrongly cancelled.
        let committed = false;

        // recipient-generated pre-allocated ActionRecord id.
        // Previously the sender-side cumulative reservation's recordId used envelope.id
        // as a prefix, but envelope.id is a sender-controlled value (although it is covered by the signature
        // in the signedPayload, the sender can still re-sign multiple envelopes with the same id + different params):
        // tracker.checkAndReserve returns idempotently for the same recordId and does not deduct again →
        // the sender could send requests of different amounts under the same id to bypass cumulative_limit.

        // Fix: the recipient locally generates pendingRecordId via randomUUID(), used as:
        // - the idempotency key of the sender-side tracker.checkAndReserve(pendingRecordId#metric#window);
        // - passed to the recorder via executeWithPolicy({ recordId: pendingRecordId })
        // as the ActionRecord.id, so the reservation and the ledger share the id (the spec's
        // "consistent with ActionRecord.id" contract).

        // The sender cannot influence pendingRecordId, so the attack surface is closed. If the sender needs TCP-level
        // retry idempotency, the recipient should short-circuit it at the envelope.id level via the ResponseIdempotency
        // Cache (a cache hit returns the previous response directly), rather than repurposing the cumulative
        // reservation's idempotency key.
        const pendingRecordId = randomUUID();

        try {
            const parsed = this.runStep('step1', 'parseEnvelope', () =>
                parseEnvelope(incoming),
            );

            const verification = await this.runAsyncStep(
                'step2',
                'verifyEnvelope',
                async () =>
                    await verifyEnvelope(parsed, {
                        resolvePublicKey: this.resolvePublicKey,
                    }),
            );

            if (!verification.valid) {
                this.logFailure(
                    'step2',
                    'verifyEnvelope',
                    verification.reason ?? 'verification failed',
                );

                return {
                    handled: false,
                    rejectionReason:
                        verification.reason ?? 'identity verification failed',
                    responseEnvelope: buildIdentityVerificationFailedEnvelope({
                        senderDid: this.config.agentDid,
                        senderPrivateKey: this.config.agentPrivateKey,
                        recipientDid: parsed.header.senderDid,
                        sessionId: parsed.header.sessionId,
                        relatedEnvelopeId: parsed.id,
                        message: verification.reason,
                    }),
                };
            }

            // envelope signature + time window passed → it is now
            // safe to pass (recipientDid, senderDid, sessionId, envelope.id) to
            // idempotencyCache for the check. The recipientDid dimension
            // (= this agent's agentDid): strong isolation across multiple recipients on a shared persistent backend,
            // avoiding hitting each other's responses when the sender sends the same envelope.id to two different agents.

            // The cached value is a CachedResponseSpec (not an envelope); on a HIT,
            // use `rebuildEnvelopeFromSpec()` to **re-sign** a new envelope against the current clock,
            // ensuring a fresh timestamp (an old envelope past clock skew would be rejected by the caller's
            // verifyEnvelope); a HIT is flagged `cacheable: false` to avoid finally
            // prolonging the old entry's life.
            const idempotencyKey: IdempotencyKey = {
                recipientDid: this.config.agentDid,
                senderDid: parsed.header.senderDid,
                sessionId: parsed.header.sessionId,
                envelopeId: parsed.id,
            };
            onIdempotencyKeyReady(idempotencyKey);
            if (this.idempotencyCache) {
                const cachedSpec =
                    await this.idempotencyCache.check(idempotencyKey);
                if (cachedSpec !== null) {
                    this.logVerbose(
                        'step2.5',
                        'idempotencyCache',
                        'OK',
                        `HIT → rebuilding fresh response envelope for id=${parsed.id}`,
                    );
                    const rebuilt = rebuildEnvelopeFromSpec(
                        cachedSpec,
                        this.config.agentPrivateKey,
                    );
                    return {
                        handled: true,
                        responseEnvelope: rebuilt,
                        // A HIT does not trigger finally's record (avoiding prolonging the existing entry's life)
                        cacheable: false,
                    };
                }
            }

            const actionPayload = this.runStep('step3', 'extractAction', () =>
                extractActionPayload(parsed),
            );

            this.logVerbose(
                'step3',
                'extractAction',
                'OK',
                `→ action=${actionPayload.action} params=${JSON.stringify(actionPayload.params)}`,
            );

            // step3.5 delegation chain validation (capabilityTokenRef resolution + DelegationChainValidator).
            // Pass action/params along too, so the sender token's action/scope are also checked in this step.
            // pendingRecordId is the idempotency key of the sender cumulative reservation
            // (replacing the sender-controlled envelope.id).
            const capabilityResult = await this.runAsyncStep(
                'step3.5',
                'verifyCapability',
                async () =>
                    await this.verifyCapability(
                        parsed,
                        actionPayload.action,
                        actionPayload.params,
                        pendingRecordId,
                    ),
            );

            if (!capabilityResult.allowed) {
                this.logFailure(
                    'step3.5',
                    'verifyCapability',
                    capabilityResult.reason,
                );

                // A step3.5 authorization rejection must write a REJECTED ActionRecord (L5 audit invariant).
                // policyRecorder is unconditionally required (enforced at construction), so this path
                // no longer has an optional guard — ensuring every step3.5 rejection on the recipient side
                // leaves an audit trail, regardless of capability wiring.

                // A recorder failure cannot be silent — if record() throws,
                // escalate the response to INTERNAL_ERROR and unconditionally console.error
                // (not gated by verbose), so the audit invariant is still observable when a dependency degrades.
                let rejectionRecordId: string | undefined;
                let recorderFailed = false;
                let recorderFailureDetail: string | undefined;
                try {
                    const writeResult = await this.policyRecorder.record({
                        agentDid: this.config.agentDid,
                        principalDid: this.config.principalDid,
                        actionType: actionPayload.action,
                        parametersSummary: actionPayload.params,
                        authorizationRef:
                            capabilityResult.tokenId !== undefined
                                ? { tokenId: capabilityResult.tokenId }
                                : null,
                        resultSummary: {
                            status: 'REJECTED',
                            reason: capabilityResult.reason,
                            phase: 'step3.5',
                        },
                        actorPrivateKey: this.config.agentPrivateKey,
                        // The rejection path also passes delegationDepth through (undefined on a pre-token
                        // rejection, the chain length on a post-token rejection)
                        delegationDepth: capabilityResult.delegationDepth,
                    });
                    rejectionRecordId = writeResult.recordId;
                } catch (recorderError) {
                    recorderFailed = true;
                    recorderFailureDetail =
                        recorderError instanceof Error
                            ? recorderError.message
                            : 'unknown recorder error';
                    // The audit invariant is broken: signal unconditionally (error level, not gated by verbose).
                    // Operations must be able to see this event when the recorder degrades.
                    this.logger.error(
                        `[ORCH] step3.5 REJECTED record write failed: ${recorderFailureDetail}. ` +
                            `Original rejection reason=${capabilityResult.reason}, ` +
                            `tokenId=${capabilityResult.tokenId ?? 'none'}, ` +
                            `agentDid=${this.config.agentDid}. ` +
                            `Response escalated to INTERNAL_ERROR (audit invariant broken).`,
                    );
                }

                if (recorderFailed) {
                    // Audit chain broken → return INTERNAL_ERROR. The rejection still takes effect
                    // (it is not downgraded to allow), but the response semantics escalate to express "the system failed to
                    // leave a compliant audit record" rather than masquerading as an ordinary authorization rejection.

                    // **Pre-commit-boundary** — a recorder throw is a transient failure such as DB
                    // degradation; the audit chain has not landed and the business has not executed. If this response is written to
                    // idempotencyCache, then within the TTL window the caller, even after its dependency recovers and it retries,
                    // would hit the old INTERNAL_ERROR and cannot re-run the authorization/execution path →
                    // poisoning it into a permanent failure. Explicit `cacheable: false`.
                    return {
                        handled: false,
                        rejectionReason: capabilityResult.reason,
                        responseEnvelope: buildInternalErrorEnvelope({
                            senderDid: this.config.agentDid,
                            senderPrivateKey: this.config.agentPrivateKey,
                            recipientDid: parsed.header.senderDid,
                            sessionId: parsed.header.sessionId,
                            relatedEnvelopeId: parsed.id,
                            message:
                                'audit record persistence failed during authorization rejection',
                        }),
                        cacheable: false,
                    };
                }

                // step3.5 REJECTED authz-insufficient response —
                // the audit has landed, it is a deterministic permanent rejection, and it is cacheable. It also produces a spec for
                // finally record (these logical fields are reused when re-signing a new envelope).
                return {
                    handled: false,
                    recordId: rejectionRecordId,
                    rejectionReason: capabilityResult.reason,
                    responseEnvelope: buildAuthorizationInsufficientEnvelope({
                        senderDid: this.config.agentDid,
                        senderPrivateKey: this.config.agentPrivateKey,
                        recipientDid: parsed.header.senderDid,
                        sessionId: parsed.header.sessionId,
                        relatedEnvelopeId: parsed.id,
                        message: capabilityResult.reason,
                    }),
                    responseSpec: {
                        kind: 'AUTHORIZATION_INSUFFICIENT',
                        agentDid: this.config.agentDid,
                        originalSenderDid: parsed.header.senderDid,
                        sessionId: parsed.header.sessionId,
                        relatedEnvelopeId: parsed.id,
                        message: capabilityResult.reason,
                    },
                };
            }

            // cumulative_limit semantics: the authorization spec requires a check on every scope,
            // so the default is fail-closed + real evaluation after senderCumulativeTracker is injected,
            // rather than "allow + warn".
            // Reaching this branch means: (a) there is no cumulative_limit scope, or (b) the tracker has
            // passed evaluation. No extra warn is needed; when an audit marker is needed, check capabilityResult.senderCumulativeChecked.

            // Expose step3.5's reservations to the outer catch.
            if (capabilityResult.reservations) {
                reservationsFromCapability = capabilityResult.reservations;
            }

            // Two independent authorization layers:
            // - step3.5 (above) verified envelope.capabilityTokenRef → proving the sender's calling
            // authority is granted by the sender's principal; tokenId is bound to the sender's authorization context.
            // - step4 RuntimeGuard independently does local policy authorization against the recipient agent's own Token pool —
            // "is this agent authorized to respond to this action", unrelated to the sender's tokenId.
            // The sender-token-id must not be passed as requestedTokenId into the recipient-side guard,
            // otherwise RuntimeGuard would filter the recipient's Token pool by the sender tokenId
            // → not found → reject (a design error from a prior round).
            const policyResult = await this.runAsyncStep(
                'step4',
                'policyEngine',
                async () =>
                    await this.config.policyEngine.executeWithPolicy({
                        action: actionPayload.action,
                        params: actionPayload.params,
                        agentDid: this.config.agentDid,
                        principalDid: this.config.principalDid,
                        actorPrivateKey: this.config.agentPrivateKey,
                        // Pass the recipient-generated pendingRecordId to
                        // engine → recorder, so ActionRecord.id shares the same id as the sender
                        // cumulative reservation's recordId prefix
                        // (the spec's "consistent with ActionRecord.id" contract).
                        recordId: pendingRecordId,
                        // After the executor succeeds and before recorder.record(SUCCESS),
                        // set committed to true early. This way, even if recorder.record
                        // throws due to a DB failure and causes executeWithPolicy to throw, the outer
                        // catch does not cancel the reservation of a committed business.
                        onExecutorSuccess: () => {
                            committed = true;
                        },
                        // ── Mandatory L3/L4 boundary wrapper (production path) ──
                        // businessHandler may descend into a sub-protocol entry (audit-share verifyAuditRequest /
                        // hcc verifyHashChain / settlement-retry executeSettlementRetry / dispute-arbitration
                        // runDisputeArbitration7Steps / audit-tamper-proof writeAuditEvent / credential-resolver
                        // resolveCredential) and throw one of the 6 sub-protocol L0 errors; the wrap uniformly
                        // unwraps it at the executor boundary to ProtocolError('INTERNAL_ERROR', '<SUB_CODE>: <msg>'), preventing it from escaping the L5 boundary
                        // and being handled by the outer catch as an unknown error (which would lose the sub-code context).
                        // requestId passes through envelope.id to make audit-log correlation easy.
                        executor: async () =>
                            await wrapSubProtocolBoundary(
                                () =>
                                    this.config.businessHandler({
                                        action: actionPayload.action,
                                        params: actionPayload.params,
                                        senderDid: parsed.header.senderDid,
                                        sessionId: parsed.header.sessionId,
                                    }),
                                parsed.id,
                            ),
                    }),
            );

            if (!policyResult.executed) {
                this.logVerbose(
                    'step4',
                    'policyEngine',
                    'OK',
                    `→ executed=false recordId=${policyResult.recordId}`,
                );

                // The sender cumulative reservations reserved in step3.5
                // need a best-effort cancel after a step4 rejection (filtered by
                // countFilter). The reservations field exists only when capabilityResult.allowed === true;
                // cancelReservedRecords filters by countFilter internally.
                if (capabilityResult.allowed && capabilityResult.reservations) {
                    await this.cancelReservedRecords(
                        capabilityResult.reservations,
                    );
                }

                // The step4 policy-rejection audit has landed, it is cacheable; produce a spec.
                return {
                    handled: false,
                    recordId: policyResult.recordId,
                    rejectionReason: policyResult.reason,
                    responseEnvelope: buildAuthorizationInsufficientEnvelope({
                        senderDid: this.config.agentDid,
                        senderPrivateKey: this.config.agentPrivateKey,
                        recipientDid: parsed.header.senderDid,
                        sessionId: parsed.header.sessionId,
                        relatedEnvelopeId: parsed.id,
                        message: policyResult.reason,
                    }),
                    responseSpec: {
                        kind: 'AUTHORIZATION_INSUFFICIENT',
                        agentDid: this.config.agentDid,
                        originalSenderDid: parsed.header.senderDid,
                        sessionId: parsed.header.sessionId,
                        relatedEnvelopeId: parsed.id,
                        message: policyResult.reason,
                    },
                };
            }

            this.logVerbose(
                'step4',
                'policyEngine',
                'OK',
                `→ executed=true recordId=${policyResult.recordId}`,
            );

            // committed was already set to true in the onExecutorSuccess hook
            // (inside the engine, after the executor returns and before the recorder writes). No need to set it again here.
            // Reaching this line means executor+recorder(SUCCESS) all succeeded; proceed to step5
            // buildEnvelope, and if it throws the outer catch handles it per the committed guard.

            // Assemble the SUCCESS spec (the logical response) first, then use buildEnvelope
            // to construct the first response. The same spec is also given to finally record — on a HIT
            // rebuildEnvelopeFromSpec re-signs a new envelope with a fresh timestamp.
            const successRequestId = actionPayload.requestId ?? parsed.id;
            const successSequenceNumber = nextSequenceNumber(
                parsed.header.sequenceNumber,
            );
            const successSpec: CachedResponseSpec = {
                kind: 'SUCCESS',
                agentDid: this.config.agentDid,
                originalSenderDid: parsed.header.senderDid,
                sessionId: parsed.header.sessionId,
                requestId: successRequestId,
                action: actionPayload.action,
                data: policyResult.result,
                recordId: policyResult.recordId,
                sequenceNumber: successSequenceNumber,
            };

            const responseEnvelope = this.runStep(
                'step5',
                'buildEnvelope',
                () =>
                    buildEnvelope({
                        senderDid: this.config.agentDid,
                        senderPrivateKey: this.config.agentPrivateKey,
                        recipientDid: parsed.header.senderDid,
                        sessionId: parsed.header.sessionId,
                        messageType: 'NEGOTIATION_RESPONSE',
                        body: {
                            requestId: successRequestId,
                            action: actionPayload.action,
                            status: 'SUCCESS',
                            data: policyResult.result,
                            recordId: policyResult.recordId,
                        },
                        sequenceNumber: successSequenceNumber,
                    }),
            );

            this.logTotal(startedAt, 'OK');

            return {
                handled: true,
                responseEnvelope,
                recordId: policyResult.recordId,
                responseSpec: successSpec,
            };
        } catch (error) {
            // The outer catch covers step4/step5/buildEnvelope exceptions.
            // If step3.5 already reserved the sender cumulative, best-effort cancel here;
            // cancelReservedRecords filters by countFilter internally, ensuring that metrics where failures also count, such as api_call_count
            // (COUNT+'*'), are not wrongly released.

            // Cancel the reservation only when the business has not committed.
            // committed is set to true by the engine's onExecutorSuccess hook (after the executor returns and
            // before recorder.record(SUCCESS)). Classification of the failure point that reaches this catch:
            // - before step3.5 (parsing the envelope / identity chain verification): the reservation
            // has not been issued, cancelReservedRecords's list is empty, no-op;
            // - reserved at step3.5 but before step4 (the two are adjacent in try, so this does not occur);
            // - step4 executor throws: the engine takes the catch branch, onExecutorSuccess
            // is not called → committed=false → cancel (correct);
            // - step4 executor succeeds, recorder.record(SUCCESS) throws (DB failure):
            // the engine throw is caught by the outer catch, but the hook already set committed=
            // true → **do not cancel** (the business has landed, the quota must be
            // retained, otherwise a sender retry would consume the business again but the reservation was already released);
            // - step4 fully succeeds, step5 buildEnvelope throws (BigInt, etc.): same as above,
            // committed=true → **do not cancel**.
            if (!committed && reservationsFromCapability.length > 0) {
                await this.cancelReservedRecords(reservationsFromCapability);
            }

            const protocolError = normalizeProtocolError(error);
            const incomingHeader =
                isEnvelopeLike(incoming) && isHeaderLike(incoming.header)
                    ? incoming.header
                    : null;
            const fallbackRecipient =
                incomingHeader?.senderDid ?? this.config.agentDid;
            const fallbackSessionId = incomingHeader?.sessionId ?? null;
            const fallbackRelated =
                isEnvelopeLike(incoming) && typeof incoming.id === 'string'
                    ? incoming.id
                    : undefined;

            const responseEnvelope =
                protocolError.code === 'INVALID_MESSAGE'
                    ? buildInvalidEnvelopeEnvelope({
                          senderDid: this.config.agentDid,
                          senderPrivateKey: this.config.agentPrivateKey,
                          recipientDid: fallbackRecipient,
                          sessionId: fallbackSessionId,
                          relatedEnvelopeId: fallbackRelated,
                          message: protocolError.detail,
                      })
                    : buildInternalErrorEnvelope({
                          senderDid: this.config.agentDid,
                          senderPrivateKey: this.config.agentPrivateKey,
                          recipientDid: fallbackRecipient,
                          sessionId: fallbackSessionId,
                          relatedEnvelopeId: fallbackRelated,
                          message: protocolError.detail,
                      });

            this.logFailure('stepX', 'handleEnvelope', protocolError.detail);
            this.logTotal(startedAt, 'FAIL');

            // The outer catch's cache whitelist.
            // - INVALID_MESSAGE: failed before parseEnvelope. When reaching this branch,
            // `idempotencyKey` has not yet been exposed to the outer finally via `onIdempotencyKeyReady`
            // → finally itself will not write (guard condition 2); this flag stays
            // true only for formal uniformity (actually unreachable).
            // - INTERNAL_ERROR + committed=true: the step4 executor already succeeded (the business
            // has landed, the onExecutorSuccess hook has fired), and the failure originates from the recorder
            // writing SUCCESS / step5 buildEnvelope. A caller re-delivery would only re-trigger the already
            // landed business → it must hit the cache and return the same INTERNAL_ERROR, avoiding a second
            // side effect.
            // - INTERNAL_ERROR + committed=false: the executor did not run or threw during execution
            // (not committed), and the business **has not landed**. Caching would poison the transient failure into
            // a permanent failure within the TTL window — the caller, after its dependency recovers, would still hit the old error on re-delivery
            // and cannot re-run the authorization/execution path. Explicit `cacheable: false`.
            const cacheable =
                protocolError.code === 'INVALID_MESSAGE' ? true : committed;

            // Produce a spec only on the branch that "will actually write the cache" — i.e.
            // INTERNAL_ERROR + committed=true. Although INVALID_MESSAGE is cacheable=true,
            // idempotencyKey is not initialized and the finally guard blocks it; with committed=false then
            // cacheable=false, which likewise does not write.
            const responseSpec: CachedResponseSpec | undefined =
                cacheable && protocolError.code !== 'INVALID_MESSAGE'
                    ? {
                          kind: 'INTERNAL_ERROR',
                          agentDid: this.config.agentDid,
                          originalSenderDid: fallbackRecipient,
                          sessionId: fallbackSessionId,
                          relatedEnvelopeId: fallbackRelated,
                          message: protocolError.detail,
                      }
                    : undefined;

            return {
                handled: false,
                rejectionReason: protocolError.detail,
                responseEnvelope,
                cacheable,
                responseSpec,
            };
        }
    }

    /**
     * Delegation chain validation flow (receiver-side, 5 steps).
     *
     * Key principle — fail-closed: once the envelope carries a capabilityTokenRef, the caller has declared
     * capability authorization semantics. The receiver being unable to fully verify ≠ downgrading to agent-pool authorization; it rejects.
     * The allowed downgrade path: the envelope carries no capabilityTokenRef (the regular agent-pool path).
     *
     * This step verifies the **sender's authorization boundary** (whether the tokenRef Alice signed for Agent A can be
     * used by Agent A to request this action). It is **not used for** the recipient's own policy authorization —
     * that is decided independently by step4 RuntimeGuard within the recipient's Token pool.
     *
     * Verification chain:
     *  1. tokenRef existence + dependency completeness
     *  2. tokenStore resolves the token
     *  3. token.issuedTo === envelope.senderDid (holder binding)
     *  4. token.principalDid === senderDocument.principalDid (delegation-source binding)
     *  5. leaf validity: expiresAt > now, issuedAt <= now, revocation(token.id)
     *  6. leaf signature:
     *      - no chain → verifyCapabilityToken (single-hop, did:key issuer only)
     *      - has chain → **the signer = chain[last].delegatorDid** (not senderDid).
     *        First do a verificationMethod-vs-delegatorDid consistency check, then use that DID's public key
     *        to verify the top-level proof.
     *  7. sender token scope evaluation:
     *      - allowlist/numeric_limit/temporal_scope → evaluated by the L3 ScopeEvaluator with
     *        AND semantics (consistent with RuntimeGuard)
     *      - cumulative_limit → requires the senderCumulativeTracker port; not injected →
     *        fail-closed (delegation_cumulative_limit_unverifiable),
     *        and when injected, call checkAndReserve for an atomic query+reservation
     *  8. delegation chain (when chain is non-empty): validateDelegationChain
     *
     * Known gaps (handled later):
     *  - The **recipient-local delegated token** on the step4 RuntimeGuard path (see
     *    `runtime-guard.ts:validateDelegationChain`) requires the delegationChainValidator
     *     + resolvePublicKey ports to be injected. It is already routed to the validator,
     *      and its delegationDepth audit field awaits an ActionRecord schema extension.
     *     TODO —— land the delegationDepth schema; the formal implementation must build on the existing skeleton, do not rewrite.
     *
     * Return-value semantics:
     *  - allowed=true + tokenId?: the sender tokenRef has passed verification; tokenId is for audit/logging only
     *  - allowed=true + no tokenId: no tokenRef (agent-pool path)
     *  - allowed=true + senderCumulativeChecked: a cumulative evaluation was done (audit marker)
     *  - allowed=false + reason: rejected (the `delegation_*` prefix aids audit classification)
     */
    private async verifyCapability(
        envelope: NegotiationEnvelope,
        action: string,
        params: Record<string, unknown>,
        pendingRecordId: string,
    ): Promise<CapabilityVerificationResult> {
        const tokenRef = envelope.header.capabilityTokenRef;

        // An envelope with no tokenRef (the regular 0.1.0 path) → RuntimeGuard authorizes by the agent pool.
        if (!tokenRef) {
            return { allowed: true };
        }

        // Capability dependency-completeness check (fail-closed, prevents downgrade attacks).
        // The caller declaring capabilityTokenRef is equivalent to requiring capability semantics; if the receiver
        // is not fully configured it must reject, and must not fall back to the agent-pool behavior of scanning the entire agent pool.
        if (
            !this.config.tokenStore ||
            !this.delegationChainValidator ||
            !this.config.revocationChecker ||
            !this.resolveAgentDocument
        ) {
            return {
                allowed: false,
                reason: 'delegation_phase2_dependencies_missing',
            };
        }

        const token = await this.config.tokenStore.getToken(tokenRef);
        if (!token) {
            return {
                allowed: false,
                reason: 'delegation_token_not_found',
            };
        }

        // Once the sender token is resolved, depth can be computed directly from delegationChain.length.
        // When chain is non-empty, depth = chain.length; an empty/missing chain = single hop, depth = 0.
        const senderDepth = Array.isArray(token.delegationChain)
            ? token.delegationChain.length
            : 0;

        // Authorization spec step 4: token.issuedTo must be bound to the sender agent.
        const senderDid = envelope.header.senderDid;
        if (token.issuedTo !== senderDid) {
            return {
                allowed: false,
                reason: 'delegation_token_sender_mismatch',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }

        // Authorization spec step 5: token.principalDid must equal
        // the principalDid in the sender agent document (fail-closed, no longer downgraded/skipped).
        const senderDocument = await this.resolveAgentDocument(senderDid);
        if (!senderDocument) {
            return {
                allowed: false,
                reason: 'delegation_sender_document_not_found',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }
        if (token.principalDid !== senderDocument.principalDid) {
            return {
                allowed: false,
                reason: 'delegation_principal_mismatch',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }

        // ── leaf token's own validity check (time window + revocation + signature) ────────
        // Respect the injected clock port; fall back to wall-clock when not injected.
        const nowIso =
            this.config.now?.() ?? (new Date().toISOString() as Timestamp);

        // Time window (before signature; an expired/not-yet-valid Token must be rejected even if the signature is valid)
        if (new Date(token.issuedAt).getTime() > new Date(nowIso).getTime()) {
            return {
                allowed: false,
                reason: 'delegation_token_not_yet_valid',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }
        if (new Date(token.expiresAt).getTime() <= new Date(nowIso).getTime()) {
            return {
                allowed: false,
                reason: 'delegation_token_expired',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }

        // Revocation (the leaf itself, not the parent; the parent is handled by validateDelegationChain)
        const leafRevoked = await this.config.revocationChecker(token.id);
        if (leafRevoked) {
            return {
                allowed: false,
                reason: 'delegation_token_revoked',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }

        // Signature: a fork
        // - no chain (single hop / principal key rotation):
        // verifyCapabilityToken. When resolvePublicKeys is injected, pass in the dual-key structure to
        // enable the ROTATING grace-period fallback.
        // When not injected, keep the single-key path (derived from did:key), with behavior consistent with the prior single-key mode.
        // - has chain (delegated leaf): the top-level proof is signed by the final did:agent delegator,
        // and verifyCapabilityToken would fail-closed (it does not do did:agent public-key resolution).
        // Instead, verify the leaf's own proof directly with the sender public key + crypto.verify.
        const hasChain =
            Array.isArray(token.delegationChain) &&
            token.delegationChain.length > 0;

        if (!hasChain) {
            // When resolvePublicKeys is injected, resolve the issuerDid's dual-key state and pass it through.
            // When not injected, resolvedKeys=undefined → verifyCapabilityToken's single-key path.
            // fail-closed: if resolvePublicKeys throws, do not silently ignore it; reject directly.

            // Pass now through to resolvePublicKeys (aligned with the ports);
            // so a replay/skew-controlled deployment can also obtain the previous key when replaying a historical token within the window.
            // Handle a null return (unknown DID) — return a rejection directly,
            // do not pass null to verifyCapabilityToken (which would trigger INTERNAL_ERROR).
            let resolvedKeys: ResolvedPublicKeys | undefined;
            // Enable the resolution port only when config.resolvePublicKeys is explicitly injected
            // (feeding token.issuerDid's dual-key state to verifyCapabilityToken).
            // The fallback wrapper does not take this path — it keeps the did:key-derived
            // single-key behavior (backward compat: avoids falsely rejecting an unknown DID as
            // token_issuer_unknown when no explicit port is injected, since there verifyCapabilityToken derives the did:key public key itself).
            if (this.resolvePublicKeysExplicit) {
                const result = await this.resolvePublicKeys(
                    token.issuerDid,
                    new Date(nowIso),
                );
                if (result === null) {
                    return {
                        allowed: false,
                        reason: 'delegation_leaf_token_issuer_unknown',
                        tokenId: token.id,
                        delegationDepth: senderDepth,
                    };
                }
                resolvedKeys = result;
            }
            const leafVerify = verifyCapabilityToken(
                token,
                nowIso,
                resolvedKeys,
            );
            if (!leafVerify.valid) {
                const code = leafVerify.code
                    ? leafVerify.code.toLowerCase()
                    : 'invalid';
                return {
                    allowed: false,
                    reason: `delegation_leaf_${code}`,
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }
        } else {
            // A delegated child token's top-level proof is signed by the **last-hop delegator**,
            // not issuedTo (= senderDid = delegateeDid). Resolving the public key by senderDid
            // would falsely reject every legitimate token produced by a real delegateCapabilityToken().
            const chain = token.delegationChain ?? [];
            const lastHop = chain[chain.length - 1];
            if (!lastHop) {
                return {
                    allowed: false,
                    reason: 'delegation_leaf_missing_last_hop',
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }

            // verificationMethod consistency: must point to the chain-tail delegatorDid; prevents an attacker
            // from reassigning the signature to another DID by modifying verificationMethod.
            const vmPrefix = token.proof.verificationMethod.split('#')[0];
            if (vmPrefix !== lastHop.delegatorDid) {
                return {
                    allowed: false,
                    reason: 'delegation_leaf_verification_method_mismatch',
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }

            // Dual-key ROTATING path leaf signature verification.
            // Obtain ResolvedPublicKeys via resolvePublicKeys (injected or STABLE-wrapped);
            // try current first, and on failure, if proof.created ≤ previousValidBefore, try previous
            // (symmetric with the delegation-validator dual-key semantics, a fail-closed time-window constraint).
            const leafKeys = await this.resolvePublicKeys(lastHop.delegatorDid);
            if (!leafKeys) {
                return {
                    allowed: false,
                    reason: 'delegation_leaf_signer_publickey_not_found',
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }
            const payloadBytes = createCapabilityTokenPayload({
                id: token.id,
                specVersion: token.specVersion,
                issuerDid: token.issuerDid,
                principalDid: token.principalDid,
                issuedTo: token.issuedTo,
                issuedAt: token.issuedAt,
                expiresAt: token.expiresAt,
                capabilities: token.capabilities,
                revocationUrl: token.revocationUrl,
                delegationChain: token.delegationChain,
            });
            let leafSigOk = verify(
                payloadBytes,
                token.proof.value,
                leafKeys.current,
            );
            if (
                !leafSigOk &&
                leafKeys.previous !== undefined &&
                leafKeys.previousValidBefore !== undefined
            ) {
                // The top-level proof has no created field; the leaf token uses token.issuedAt
                // as the issuance-time anchor (the leaf delegator signs proof.value at the issuedAt instant).
                // Fallback is allowed only when ≤ previousValidBefore; beyond the time window, fail-closed.
                if (
                    new Date(token.issuedAt).getTime() <=
                    new Date(leafKeys.previousValidBefore).getTime()
                ) {
                    leafSigOk = verify(
                        payloadBytes,
                        token.proof.value,
                        leafKeys.previous,
                    );
                }
            }
            if (!leafSigOk) {
                return {
                    allowed: false,
                    reason: 'delegation_leaf_signature_invalid',
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }
        }

        // ── sender token scope evaluation (the sender-side self-attestation boundary) ─────────────────
        // Reuses the L3 ScopeEvaluator (AND semantics, wildcard, timezone).
        // cumulative_limit defaults to fail-closed semantics (aligned with the authorization spec's
        // "perform a Scope check for every action"),
        // so when senderCumulativeTracker is not injected, any cumulative_limit appearing causes a reject;
        // when injected, it is evaluated separately alongside ScopeEvaluator (the port encapsulates cross-trust-domain access).
        const matchingScopes = token.capabilities
            .filter((cap) => cap.action === action)
            .map((cap) => cap.scope);
        if (matchingScopes.length === 0) {
            return {
                allowed: false,
                reason: 'delegation_invalid_action',
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }

        const cumulativeScopes = matchingScopes.filter(
            (s): s is CumulativeLimitScope => s.type === 'cumulative_limit',
        );
        const nonCumulativeScopes = matchingScopes.filter(
            (s) => s.type !== 'cumulative_limit',
        );

        // Non-cumulative_limit scopes: evaluated by ScopeEvaluator with AND semantics.
        const scopeResult = await this.scopeEvaluator.evaluateAll(
            nonCumulativeScopes,
            params,
            new Date(nowIso),
        );
        if (!scopeResult.allowed) {
            return {
                allowed: false,
                reason: `delegation_scope_denied: ${scopeResult.reason ?? 'unknown'}`,
                tokenId: token.id,
                delegationDepth: senderDepth,
            };
        }

        // ── Delegation chain validation (only when chain is non-empty) ────────────────────────────
        // Chain validation must precede the cumulative reservation.
        // Reason: checkAndReserve is an operation **with side effects** (it consumes the sender principal's
        // real ledger quota), whereas chain validation is a **read-only** trust decision. Completing all read-only
        // validation before issuing the side-effecting action avoids an illegal delegation (parent revoked / chain-attenuation
        // violation / snapshot mismatch) repeatedly rotating envelope.id to consume legitimate quota after the leaf signature passes.
        // Even if the cancelReservation hook is implemented, cross-trust-domain calls are unreliable,
        // and letting an illegal path touch the reservation at all is itself an architectural misalignment.

        // In the empty-chain case validateDelegationChain returns valid=true directly,
        // so it need not be called (avoiding misleading the reader into thinking it covers the leaf verification).
        if (hasChain) {
            // Directly reuse this.resolvePublicKeys (which keeps previous +
            // previousValidBefore after the dual-key port assembly). Bypassing the old STABLE-wrapper path — after pushing the dual-key semantics down into the chain
            // validator, a rotated intermediate delegator's previous-key proof can also pass via fallback within the time window.
            const chainResult = await this.delegationChainValidator(
                token,
                this.resolvePublicKeys,
                this.config.revocationChecker,
                nowIso,
                (id) => this.config.tokenStore!.getToken(id),
            );

            if (!chainResult.valid) {
                const reasonCode = chainResult.reason
                    ? chainResult.reason.toLowerCase()
                    : 'invalid';
                return {
                    allowed: false,
                    reason: `delegation_${reasonCode}`,
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }
        }

        // cumulative_limit scope: an explicit port is required. **This block must be the last step before
        // verifyCapability returns allowed:true** — once a reservation is made it may
        // consume the sender principal's real quota, and any subsequent rejection needs a best-effort cancel.
        let senderCumulativeChecked = false;
        const reservations: Reservation[] = [];
        if (cumulativeScopes.length > 0) {
            if (!this.senderCumulativeTracker) {
                // Spec step 7: neither allowing it through nor a silent bypass is permitted.
                // If the caller wants to enable a cumulative_limit token, it must inject a trusted ledger query port.
                return {
                    allowed: false,
                    reason: 'delegation_cumulative_limit_unverifiable',
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }
            const cumulativeOutcome = await this.evaluateSenderCumulativeScopes(
                cumulativeScopes,
                params,
                senderDocument.principalDid,
                new Date(nowIso),
                // Use the recipient-generated pendingRecordId as the recordId prefix.
                // The sender cannot influence this value (randomly generated for this call), closing the attack surface of
                // "the sender bypassing cumulative idempotency with the same id + different params".
                // For a sender TCP-level retry: the recipient receiving the same envelope a second time generates a new
                // pendingRecordId → a double deduction; this scenario should be short-circuited by the envelope.id-level
                // ResponseIdempotencyCache, which is not the reservation idempotency key's responsibility.
                pendingRecordId,
            );
            if (cumulativeOutcome.denialReason !== null) {
                // Within the same scope list, a scope that successfully reserved earlier
                // must be cancelled upon a later scope's failure. best-effort (failure relies on the TTL fallback).
                await this.cancelReservedRecords(
                    cumulativeOutcome.reservations,
                );
                return {
                    allowed: false,
                    reason: cumulativeOutcome.denialReason,
                    tokenId: token.id,
                    delegationDepth: senderDepth,
                };
            }
            senderCumulativeChecked = true;
            reservations.push(...cumulativeOutcome.reservations);
        }

        return {
            allowed: true,
            tokenId: token.id,
            senderCumulativeChecked: senderCumulativeChecked || undefined,
            delegationDepth: senderDepth,
            reservations: reservations.length > 0 ? reservations : undefined,
        };
    }

    /**
     * Batch evaluation of sender-side cumulative_limit scopes.
     * A single token may contain multiple cumulative_limit entries (different metric/window); evaluated strictly
     * with AND semantics; any one failing rejects the whole.
     *
     * Computation rules:
     *   - Resolve the METER_FIELD_REGISTRY entry (unregistered → fail-closed)
     *   - computeWindowStart(scope.window, now) takes the UTC calendar boundary
     *   - aggregation === 'COUNT' → reserveAmount = 1
     *   - aggregation === 'SUM' → reserveAmount = params[entry.requestField];
     *     missing → fail-closed (a strict constraint, reject if the metered value cannot be extracted)
     *   - tracker.checkAndReserve(recordId, principalDid, ...) does an atomic query+reservation,
     *     and returning allowed:false rejects (serialization is the tracker implementation's responsibility)
     *
     * **recordId composition**: `${pendingRecordId}#${metric}#${window}`.
     * pendingRecordId is generated by the recipient at the top of the handleEnvelope try block via
     * randomUUID() — no longer using the sender-controlled envelope.id.
     *
     * Returns a structured `Reservation` array (with metric+countFilter),
     * letting the cancel path decide whether each is cancellable by the metric's countFilter — a metric with `countFilter='*'`
     * (api_call_count, etc.) must **not** be cancelled, as the spec
     * requires failures to also count toward the cumulative, preventing a failed retry from bypassing the limit.
     *
     * @returns denialReason=null means all passed; non-empty is the failure reason.
     *   reservations: the reservations successfully made within this call (with countFilter).
     */
    private async evaluateSenderCumulativeScopes(
        scopes: readonly CumulativeLimitScope[],
        params: Record<string, unknown>,
        senderPrincipalDid: DID,
        now: Date,
        pendingRecordId: string,
    ): Promise<{
        denialReason: string | null;
        reservations: Reservation[];
    }> {
        const tracker = this.senderCumulativeTracker!; // the caller has guaranteed injection
        const reserved: Reservation[] = [];
        for (const scope of scopes) {
            // The sender side must also fail-closed the three-state source,
            // staying symmetric with the scope-evaluator. Otherwise a 0.3.0 token using an 'external_witness' /
            // 'consensus_meter' source would bypass the recipient check and directly reserve sender quota,
            // while a reservation (especially countFilter='*') would not be cancelled on failure.
            if (scope.meterField.source !== 'action_record') {
                return {
                    denialReason: `delegation_cumulative_limit_metric_source_not_implemented: source='${scope.meterField.source}' (fail-closed)`,
                    reservations: reserved,
                };
            }
            const entry = METER_FIELD_REGISTRY[scope.meterField.metric];
            if (!entry) {
                return {
                    denialReason: `delegation_cumulative_limit_unregistered_metric: ${scope.meterField.metric}`,
                    reservations: reserved,
                };
            }

            let reserveAmount: number;
            if (entry.aggregation === 'COUNT') {
                reserveAmount = 1;
            } else {
                // SUM aggregation: extract the amount value specified by requestField from params
                const fieldName = entry.requestField;
                if (fieldName === undefined) {
                    return {
                        denialReason: `delegation_cumulative_limit_meter_field_missing_request_field: ${scope.meterField.metric}`,
                        reservations: reserved,
                    };
                }
                const raw = params[fieldName];
                if (typeof raw !== 'number') {
                    return {
                        denialReason: `delegation_cumulative_limit_request_value_missing: ${scope.meterField.metric}.${fieldName}`,
                        reservations: reserved,
                    };
                }
                reserveAmount = raw;
            }

            const windowStart = computeWindowStart(scope.window, now);
            // recordId = pendingRecordId#metric#window: uniqueness-key alignment.
            const recordId = `${pendingRecordId}#${scope.meterField.metric}#${scope.window}`;

            // tracker.checkAndReserve's signature does not include `scope.max`; under a single principalDid
            // multiple tokens with different max can coexist (e.g. monthly 1000 / monthly 500), and the tracker,
            // armed only with (principalDid, metric, window), cannot know which limit applies to this call.
            // Pushing the max decision entirely to the tracker implementation would, when connecting a real backend, create
            // the dilemma of "either hardcode a policy that falsely rejects legitimate traffic, or default allowed:true and bypass all limits".

            // So responsibility is split:
            // - the tracker only does (atomic read of the cumulative + write PENDING + return currentCumulative),
            // and the `allowed` field's semantics degrade to "whether the reservation atomically succeeded";
            // - the token-level max decision returns to the evaluator locally: projected > scope.max rejects.

            // When the local decision triggers, the reservation has already been written, so it must immediately cancel (for a countFilter='SUCCESS'
            // reservation) and return a failure; a countFilter='*' reservation like api_call_count
            // must not be released per spec — cancelReservedRecords
            // filters by countFilter internally.
            let result: Awaited<
                ReturnType<SenderCumulativeTrackerReader['checkAndReserve']>
            >;
            try {
                result = await tracker.checkAndReserve(
                    recordId,
                    senderPrincipalDid,
                    scope.meterField,
                    windowStart,
                    now,
                    reserveAmount,
                );
            } catch (error) {
                // When checkAndReserve throws, the reservations successfully reserved earlier in the loop,
                // if not actively cancelled, can only be reclaimed via the TTL (default 5 minutes).
                // The active cancel is part of the best-effort
                // compensation promise; cancelReservedRecords swallows errors via its own try/catch,
                // so it does not mask the original error.
                await this.cancelReservedRecords(reserved);
                throw error;
            }

            const projected = result.currentCumulative + reserveAmount;
            if (!result.allowed || projected > scope.max) {
                // Two failures converge to the same branch:
                // (a) the tracker already short-circuit-rejected (implementer's choice: backend policy / this tracker's most conservative estimate under concurrent contention);
                // (b) the tracker successfully reserved but this token's local max decision exceeds the limit — in this case
                // PENDING already exists, so this reservation also needs to be cancelled.
                const newlyReservedHere =
                    result.allowed && projected > scope.max
                        ? ([
                              {
                                  recordId,
                                  metric: scope.meterField.metric,
                                  countFilter: entry.countFilter,
                              },
                          ] satisfies Reservation[])
                        : [];
                if (newlyReservedHere.length > 0) {
                    await this.cancelReservedRecords(newlyReservedHere);
                }
                return {
                    denialReason: `delegation_cumulative_limit_exceeded: current=${result.currentCumulative}+reserve=${reserveAmount}>max=${scope.max} (window=${scope.window}, metric=${scope.meterField.metric})`,
                    reservations: reserved,
                };
            }
            reserved.push({
                recordId,
                metric: scope.meterField.metric,
                countFilter: entry.countFilter,
            });
        }
        return { denialReason: null, reservations: reserved };
    }

    /**
     * best-effort cancel of already-reserved sender cumulative
     * reservations. **Filtered by metric.countFilter**: only `countFilter='SUCCESS'`
     * reservations are cancelled; `countFilter='*'` ones are skipped (the spec requires
     * api_call_count and similar failures to also count, so they cannot be released).
     *
     * Call scenarios:
     *   - during multi-scope evaluation inside verifyCapability, a later scope's failure requires rolling back the ones that passed;
     *   - when handleEnvelope fails at any of the step4/business/response phases after step3.5 passes,
     *     cancel the reservations already reserved in step3.5.
     *
     * **Defense in depth**: even if the tracker implementation wrongly treats a COUNT+'*' cancelReservation
     * as a "release", we never passed its recordId to the tracker at this layer — a failed retry is still
     * counted toward api_call_count and cannot bypass the limit.
     *
     * **Best-effort semantics**: when the tracker does not implement cancelReservation (an optional port) or
     * the call throws, it only logs via console.error and does not break the main flow. The spec's
     * TTL fallback is the ultimate backstop.
     */
    private async cancelReservedRecords(
        reservations: readonly Reservation[],
    ): Promise<void> {
        if (reservations.length === 0) return;
        const tracker = this.senderCumulativeTracker;
        if (!tracker?.cancelReservation) return;
        for (const reservation of reservations) {
            // A countFilter='*' metric (api_call_count) counts failures too,
            // so it cannot be cancelled; filtered at the orchestrator layer to prevent a tracker implementation from wrongly releasing.
            if (reservation.countFilter !== 'SUCCESS') continue;
            try {
                await tracker.cancelReservation(reservation.recordId);
            } catch (error) {
                const detail =
                    error instanceof Error ? error.message : 'unknown error';
                // Best-effort: do not throw, do not break the main flow; only error so operations
                // can spot a tracker cancel-path anomaly (otherwise it is only reclaimed after the TTL expires).
                this.logger.error(
                    `[ORCH] senderCumulativeTracker.cancelReservation failed for ${reservation.recordId}: ${detail}`,
                );
            }
        }
    }

    private runStep<T>(step: string, label: string, fn: () => T): T {
        const startedAt = Date.now();
        const result = fn();
        this.logStep(step, label, 'OK', Date.now() - startedAt);
        return result;
    }

    private async runAsyncStep<T>(
        step: string,
        label: string,
        fn: () => Promise<T>,
    ): Promise<T> {
        const startedAt = Date.now();
        const result = await fn();
        this.logStep(step, label, 'OK', Date.now() - startedAt);
        return result;
    }

    private logStep(
        step: string,
        label: string,
        status: StepStatus,
        durationMs: number,
    ): void {
        if (!this.config.verbose) {
            return;
        }

        this.logger.info(
            `[ORCH] ${step.padEnd(6)} ${label.padEnd(20)} ${status.padEnd(4)} (${durationMs}ms)`,
        );
    }

    private logVerbose(
        step: string,
        label: string,
        status: StepStatus,
        details: string,
    ): void {
        if (!this.config.verbose) {
            return;
        }

        this.logger.info(
            `[ORCH] ${step.padEnd(6)} ${label.padEnd(20)} ${status.padEnd(4)} ${details}`,
        );
    }

    private logFailure(step: string, label: string, reason: string): void {
        if (!this.config.verbose) {
            return;
        }

        this.logger.info(
            `[ORCH] ${step.padEnd(6)} ${label.padEnd(20)} FAIL ${reason}`,
        );
    }

    private logTotal(startedAt: number, status: StepStatus): void {
        if (!this.config.verbose) {
            return;
        }

        this.logger.info(
            `[ORCH] total                        ${status.padEnd(4)} (${Date.now() - startedAt}ms)`,
        );
    }
}

type CapabilityVerificationResult =
    | {
          allowed: true;
          tokenId?: string;
          /**
           * step3.5 did an atomic checkAndReserve on the sender token's cumulative_limit
           * and the reservation succeeded (senderCumulativeTracker was injected
           * and the scope passed evaluation). Used to write an audit marker on ActionRecord.authorizationRef,
           * distinguishing the two allow states "a cumulative reservation was made" vs "no cumulative_limit scope".
           */
          senderCumulativeChecked?: boolean;
          /**
           * The sender token's delegationChain.length (0 =
           * single hop). Lets the ActionRecord on both the step3.5 allow path and reject path write the
           * delegationDepth audit field.
           */
          delegationDepth?: number;
          /**
           * The sender cumulative reservations successfully reserved in step3.5
           * (with metric+countFilter).
           *
           * When handleEnvelope fails at any of the step4/business/response phases, it needs to
           * best-effort call senderCumulativeTracker.cancelReservation to roll back;
           * if this request ultimately settles successfully, the tracker relies on its own settle channel or TTL for terminal settlement
           * (the recipient does not bear settle responsibility, see the senderCumulativeTracker comment).
           *
           * The structured array carries countFilter, letting the cancel path
           * filter per spec — a countFilter='*' metric (api_call_count)
           * counts failures too and cannot be released.
           */
          reservations?: readonly Reservation[];
      }
    | {
          allowed: false;
          reason: string;
          tokenId?: string;
          /**
           * The sender token's delegationChain.length when it is resolvable.
           * Has a value only on a rejection path after "the token is resolved" (scope_denied / cumulative_exceeded
           * / delegation_* chain-validation failure); undefined on a pre-token rejection (dependencies_missing
           * / token_not_found).
           */
          delegationDepth?: number;
      };

interface ActionPayload {
    action: string;
    params: Record<string, unknown>;
    requestId?: string;
}

function extractActionPayload(envelope: NegotiationEnvelope): ActionPayload {
    if (
        envelope.messageType !== 'NEGOTIATION_REQUEST' &&
        envelope.messageType !== 'NEGOTIATION_CONFIRM'
    ) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `Unsupported messageType for orchestration: ${envelope.messageType}`,
        );
    }

    const body = envelope.body;
    const action = body['action'];
    const params = body['params'];

    if (typeof action !== 'string' || action.length === 0) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'Envelope body must include a non-empty action field.',
        );
    }

    if (!params || typeof params !== 'object' || Array.isArray(params)) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'Envelope body must include an object params field.',
        );
    }

    const requestId =
        typeof body['requestId'] === 'string' ? body['requestId'] : undefined;

    return {
        action,
        params: params as Record<string, unknown>,
        requestId,
    };
}

function nextSequenceNumber(
    sequenceNumber: number | undefined,
): number | undefined {
    return sequenceNumber === undefined ? undefined : sequenceNumber + 1;
}

function normalizeProtocolError(error: unknown): ProtocolError {
    if (error instanceof ProtocolError) {
        return error;
    }

    return new ProtocolError(
        'INTERNAL_ERROR',
        error instanceof Error ? error.message : 'Unknown orchestrator error.',
    );
}

function isEnvelopeLike(value: unknown): value is Partial<NegotiationEnvelope> {
    return Boolean(value) && typeof value === 'object';
}

function isHeaderLike(
    value: unknown,
): value is Partial<NegotiationEnvelope['header']> {
    return Boolean(value) && typeof value === 'object';
}
