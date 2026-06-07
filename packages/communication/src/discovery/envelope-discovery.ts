/**
 * Envelope-based discovery dispatcher
 *
 * Scope: wire reception + handler registration slot + dispatch logic only.
 * Does not include end-to-end Transport integration (handled separately).
 * The well-known fallback (agent-card-routes / discovery-service) remains unchanged.
 *
 * Implementation anchor: packages/communication/src/discovery/envelope-discovery.ts
 */

import { randomUUID } from 'node:crypto';

import type {
    DID,
    DiscoveryRequestBody,
    DiscoveryResponseBody,
    NegotiationEnvelope,
    Timestamp,
} from '@coivitas/types';
import { ProtocolError, SPEC_VERSION_0_3_0 } from '@coivitas/types';
import { canonicalize, sign } from '@coivitas/crypto';

// ── Error codes (per the discovery spec) ──────────────────────────────────
// Valid error codes: DISCOVERY_NOT_SUPPORTED / DISCOVERY_TARGET_MISMATCH are new;
// the rest reuse envelope-level error codes (INVALID_MESSAGE / CLOCK_SKEW_EXCEEDED, etc.).
// Introducing future namespaces is forbidden (DISCOVERY_DHT_* / DISCOVERY_BROADCAST_* / DISCOVERY_REGISTRY_*).

export type DiscoveryErrorCode =
    | 'DISCOVERY_NOT_SUPPORTED' // no handler registered
    | 'DISCOVERY_TARGET_MISMATCH' // response.agentDid !== request.targetDid
    | 'INVALID_MESSAGE' // body parsing failed
    | 'CLOCK_SKEW_EXCEEDED' // requestedAt clock skew
    | 'SIGNATURE_INVALID' // envelope signature verification failed
    | 'AGENT_CARD_NOT_FOUND' // handler returned null
    | 'INTERNAL_ERROR'; // handler threw an exception

// ── DiscoveryHandler function signature (per the discovery spec) ───────────

/**
 * DISCOVERY_REQUEST handler function signature
 *
 * @param request - the parsed DiscoveryRequestBody (already schema-validated)
 * @param senderDid - envelope.header.senderDid (already signature-verified, trusted)
 * @returns a DiscoveryResponseBody or null (null means this DID cannot be handled)
 */
export type DiscoveryHandler = (
    request: DiscoveryRequestBody,
    senderDid: DID,
) => Promise<DiscoveryResponseBody | null>;

// ── DiscoveryDispatcher interface (per the discovery spec) ─────────────────

/**
 * Envelope-based discovery dispatcher interface
 *
 * The L4 layer provides a handler registration slot so that
 * Envelopes of type DISCOVERY_REQUEST can be dispatched to the registered handler.
 *
 * Scope: registration slot + dispatch logic only.
 * The actual discovery flow (IdentityRegistry lookup -> build AgentCard -> wrap in DISCOVERY_RESPONSE)
 * is implemented inside the handler.
 *
 */
export interface DiscoveryDispatcher {
    /**
     * Registers the DISCOVERY_REQUEST handler
     *
     * Only one handler may be registered at a time; re-registering overwrites the previous one.
     */
    registerDiscoveryHandler(handler: DiscoveryHandler): void;

    /**
     * Dispatches a DISCOVERY_REQUEST Envelope
     *
     * Called by the Envelope dispatch main loop when messageType === 'DISCOVERY_REQUEST'.
     * The input envelope MUST have already passed verifyEnvelope signature verification.
     *
     * @returns a DISCOVERY_RESPONSE envelope or an ERROR envelope
     */
    dispatch(envelope: NegotiationEnvelope): Promise<NegotiationEnvelope>;
}

// ── DiscoveryDispatcherOptions ────────────────────────────────────────────

export interface DiscoveryDispatcherOptions {
    /**
     * Responder DID (used as the senderDid when building the DISCOVERY_RESPONSE envelope)
     */
    responderDid: DID;

    /**
     * Responder Ed25519 private key (hex or 64B extended), used to sign the response envelope
     */
    responderPrivateKey: string;

    /**
     * Allowed clock skew (milliseconds), default 300_000 (5 minutes).
     * Corresponds to verifyEnvelope's clockSkewMs parameter; used to validate requestedAt.
     */
    clockSkewMs?: number;

    /**
     * Injected current time (for testing), default Date.now
     */
    now?: () => number;
}

// ── Internal utility: DID format check ─────────────────────────────────────

const DID_AGENT_PATTERN = /^did:agent:[a-f0-9]{40}$/;

function isValidDID(value: unknown): value is DID {
    return typeof value === 'string' && DID_AGENT_PATTERN.test(value);
}

// ── Internal utility: ISO 8601 UTC Timestamp format check ─────────────────

const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function isValidTimestamp(value: unknown): value is Timestamp {
    return typeof value === 'string' && TIMESTAMP_PATTERN.test(value);
}

// ── Internal utility: DiscoveryRequestBody schema validation ──────────────

/**
 * Parses and validates envelope.body as a DiscoveryRequestBody
 *
 * Corresponds to step [2] of the dispatch flow.
 * Validation rules: targetDid / requestedAt are required + format constraints.
 */
function parseDiscoveryRequestBody(
    body: Record<string, unknown>,
): DiscoveryRequestBody {
    const { targetDid, requestedAt } = body;

    if (!isValidDID(targetDid)) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `Invalid DISCOVERY_REQUEST body.targetDid: ${String(targetDid)} (expected did:agent:<40 hex chars>)`,
        );
    }

    if (!isValidTimestamp(requestedAt)) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `Invalid DISCOVERY_REQUEST body.requestedAt: ${String(requestedAt)} (expected ISO 8601 UTC)`,
        );
    }

    // Reject unknown fields (additionalProperties: false)
    const knownKeys = new Set(['targetDid', 'requestedAt']);
    for (const key of Object.keys(body)) {
        if (!knownKeys.has(key)) {
            throw new ProtocolError(
                'INVALID_MESSAGE',
                `DISCOVERY_REQUEST body contains an unknown field: ${key}`,
            );
        }
    }

    return { targetDid, requestedAt };
}

// ── Internal utility: build an ERROR envelope (for the discovery scenario) ──

/**
 * Builds an ERROR NegotiationEnvelope carrying a discovery error code
 *
 * The error code is restricted to the valid set defined by the discovery spec.
 * Introducing future namespaces is forbidden.
 */
function buildDiscoveryErrorEnvelope(
    responderDid: DID,
    responderPrivateKey: string,
    recipientDid: DID,
    relatedEnvelopeId: string,
    code: DiscoveryErrorCode,
    message: string,
): NegotiationEnvelope {
    const id = randomUUID();
    const timestamp = new Date().toISOString() as Timestamp;

    const body = {
        code,
        message,
        relatedEnvelopeId,
    };

    const signedPayload = {
        id,
        specVersion: SPEC_VERSION_0_3_0,
        header: {
            senderDid: responderDid,
            recipientDid,
            sessionId: null as string | null,
        },
        messageType: 'ERROR' as const,
        body,
        timestamp,
    };

    const canonical = canonicalize(signedPayload);
    const bytes = new TextEncoder().encode(canonical);
    const signature = sign(bytes, responderPrivateKey, 'hex');

    return {
        ...signedPayload,
        signature: signature as NegotiationEnvelope['signature'],
    };
}

// ── Internal utility: build a DISCOVERY_RESPONSE envelope ─────────────────

function buildDiscoveryResponseEnvelope(
    responderDid: DID,
    responderPrivateKey: string,
    recipientDid: DID,
    relatedEnvelopeId: string,
    responseBody: DiscoveryResponseBody,
): NegotiationEnvelope {
    const id = randomUUID();
    const timestamp = new Date().toISOString() as Timestamp;

    const body: Record<string, unknown> = {
        agentDid: responseBody.agentDid,
        agentCardJson: responseBody.agentCardJson,
        respondedAt: responseBody.respondedAt,
        documentVersion: responseBody.documentVersion,
    };

    const signedPayload = {
        id,
        specVersion: SPEC_VERSION_0_3_0,
        header: {
            senderDid: responderDid,
            recipientDid,
            sessionId: null as string | null,
        },
        messageType: 'DISCOVERY_RESPONSE' as const,
        body,
        timestamp,
    };

    const canonical = canonicalize(signedPayload);
    const bytes = new TextEncoder().encode(canonical);
    const signature = sign(bytes, responderPrivateKey, 'hex');

    return {
        ...signedPayload,
        signature: signature as NegotiationEnvelope['signature'],
    };
}

// ── EnvelopeDiscoveryDispatcher (DiscoveryDispatcher implementation) ──────

/**
 * EnvelopeDiscoveryDispatcher
 *
 * Implements the DiscoveryDispatcher interface, dispatching DISCOVERY_REQUEST
 * Envelopes per the discovery spec dispatch flow:
 *
 * [1] Validate specVersion >= 0.3.0 (a dispatcher requirement; passed in by the caller after verifyEnvelope)
 * [2] Parse body into a DiscoveryRequestBody (schema validation)
 * [2.5] Validate requestedAt clock skew
 * [3] Check whether a handler is registered
 * [4] Call handler(request, senderDid)
 * [5] Build the DISCOVERY_RESPONSE envelope
 * [6] Return the response envelope
 *
 * Note: the caller MUST complete verifyEnvelope signature verification before
 * calling dispatch (security requirement #1, per the discovery spec).
 * EnvelopeDiscoveryDispatcher does not re-verify the signature, but it does verify the specVersion constraint.
 */
export class EnvelopeDiscoveryDispatcher implements DiscoveryDispatcher {
    private readonly responderDid: DID;
    private readonly responderPrivateKey: string;
    private readonly clockSkewMs: number;
    private readonly now: () => number;
    private handler: DiscoveryHandler | null = null;

    public constructor(options: DiscoveryDispatcherOptions) {
        this.responderDid = options.responderDid;
        this.responderPrivateKey = options.responderPrivateKey;
        this.clockSkewMs = options.clockSkewMs ?? 300_000;
        this.now = options.now ?? (() => Date.now());
    }

    /**
     * Registers the DISCOVERY_REQUEST handler
     *
     * Re-registering overwrites the previous one (per the discovery spec).
     */
    public registerDiscoveryHandler(handler: DiscoveryHandler): void {
        this.handler = handler;
    }

    /**
     * Dispatches a DISCOVERY_REQUEST Envelope
     *
     * Executes the dispatch flow:
     * - body parsing fails -> INVALID_MESSAGE ERROR
     * - requestedAt clock skew -> CLOCK_SKEW_EXCEEDED ERROR
     * - no handler -> DISCOVERY_NOT_SUPPORTED ERROR
     * - handler returns null -> AGENT_CARD_NOT_FOUND ERROR
     * - handler throws -> INTERNAL_ERROR ERROR
     * - success -> DISCOVERY_RESPONSE envelope
     *
     * Fail-closed: any error condition returns an ERROR envelope rather than being silently dropped.
     */
    public async dispatch(
        envelope: NegotiationEnvelope,
    ): Promise<NegotiationEnvelope> {
        const senderDid = envelope.header.senderDid;
        const relatedEnvelopeId = envelope.id;

        // Step [1]: specVersion must be >= 0.3.0 (the valid specVersion range for DISCOVERY_* types)
        // Per the discovery spec:
        // DISCOVERY_* with specVersion < 0.3.0 must be rejected (fail-closed).
        const specVersion = envelope.specVersion;
        if (!this.isSpecVersion030OrAbove(specVersion)) {
            return buildDiscoveryErrorEnvelope(
                this.responderDid,
                this.responderPrivateKey,
                senderDid,
                relatedEnvelopeId,
                'INVALID_MESSAGE',
                `DISCOVERY_REQUEST requires specVersion >= 0.3.0, received ${specVersion}`,
            );
        }

        // Step [2]: parse body into a DiscoveryRequestBody (equivalent to AJV schema validation)
        let request: DiscoveryRequestBody;
        try {
            request = parseDiscoveryRequestBody(envelope.body);
        } catch (err) {
            return buildDiscoveryErrorEnvelope(
                this.responderDid,
                this.responderPrivateKey,
                senderDid,
                relatedEnvelopeId,
                'INVALID_MESSAGE',
                err instanceof ProtocolError ? err.message : String(err),
            );
        }

        // Step [2.5]: validate requestedAt clock skew (reuses verifyEnvelope's clockSkewMs parameter)
        const requestedAtTime = new Date(request.requestedAt).getTime();
        if (
            !isFinite(requestedAtTime) ||
            Math.abs(requestedAtTime - this.now()) > this.clockSkewMs
        ) {
            return buildDiscoveryErrorEnvelope(
                this.responderDid,
                this.responderPrivateKey,
                senderDid,
                relatedEnvelopeId,
                'CLOCK_SKEW_EXCEEDED',
                `DISCOVERY_REQUEST body.requestedAt clock skew exceeds the allowed range (±${this.clockSkewMs}ms)`,
            );
        }

        // Step [3]: check whether a handler is registered
        if (this.handler === null) {
            return buildDiscoveryErrorEnvelope(
                this.responderDid,
                this.responderPrivateKey,
                senderDid,
                relatedEnvelopeId,
                'DISCOVERY_NOT_SUPPORTED',
                'DISCOVERY_NOT_SUPPORTED: this node has no discovery handler registered; please fall back to the well-known path',
            );
        }

        // Step [4]: call the handler
        let responseBody: DiscoveryResponseBody | null;
        try {
            responseBody = await this.handler(request, senderDid);
        } catch (err) {
            return buildDiscoveryErrorEnvelope(
                this.responderDid,
                this.responderPrivateKey,
                senderDid,
                relatedEnvelopeId,
                'INTERNAL_ERROR',
                `Discovery handler error: ${err instanceof Error ? err.message : String(err)}`,
            );
        }

        // handler returns null -> AGENT_CARD_NOT_FOUND
        if (responseBody === null) {
            return buildDiscoveryErrorEnvelope(
                this.responderDid,
                this.responderPrivateKey,
                senderDid,
                relatedEnvelopeId,
                'AGENT_CARD_NOT_FOUND',
                `AGENT_CARD_NOT_FOUND: no AgentCard exists for target DID ${request.targetDid}`,
            );
        }

        // Step [5]: build and sign the DISCOVERY_RESPONSE envelope
        return buildDiscoveryResponseEnvelope(
            this.responderDid,
            this.responderPrivateKey,
            senderDid,
            relatedEnvelopeId,
            responseBody,
        );
    }

    /**
     * Checks whether specVersion is a valid value >= 0.3.0
     *
     * Currently only the exact value '0.3.0' is accepted (within the SUPPORTED_SPEC_VERSIONS
     * allowlist and >= 0.3.0). This is a strict-allowlist requirement; no broad forward-version matching is done.
     */
    private isSpecVersion030OrAbove(specVersion: string): boolean {
        // Valid DISCOVERY_* specVersion value set: only '0.3.0'.
        // If 0.4.0 is added to SUPPORTED_SPEC_VERSIONS in the future, update this in sync.
        return specVersion === '0.3.0';
    }
}

// ── Convenience utility: validate a DiscoveryResponseBody (receiver side) ──

/**
 * Validates a DISCOVERY_RESPONSE envelope body
 *
 * Called on the receiver side: after receiving a DISCOVERY_RESPONSE, validate the body
 * structure and that agentDid matches the requested targetDid (per the discovery spec).
 *
 * Note: the caller MUST first complete:
 * 1. verifyEnvelope (signature + specVersion + clock)
 * 2. AgentCard signature verification + IdentityRegistry cross-validation (per the discovery spec)
 *
 * @param body - envelope.body (untyped)
 * @param expectedTargetDid - the targetDid used when the request was initiated (for the agentDid consistency check)
 * @throws ProtocolError('INVALID_MESSAGE') when the body format is invalid
 * @throws ProtocolError('DISCOVERY_TARGET_MISMATCH') when agentDid !== targetDid
 */
export function validateDiscoveryResponseBody(
    body: Record<string, unknown>,
    expectedTargetDid: DID,
): DiscoveryResponseBody {
    const { agentDid, agentCardJson, respondedAt, documentVersion } = body;

    if (!isValidDID(agentDid)) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `Invalid DISCOVERY_RESPONSE body.agentDid: ${String(agentDid)}`,
        );
    }

    if (typeof agentCardJson !== 'string' || agentCardJson.length === 0) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            'DISCOVERY_RESPONSE body.agentCardJson must be a non-empty string',
        );
    }

    if (!isValidTimestamp(respondedAt)) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `Invalid DISCOVERY_RESPONSE body.respondedAt: ${String(respondedAt)}`,
        );
    }

    if (
        typeof documentVersion !== 'number' ||
        !Number.isInteger(documentVersion) ||
        documentVersion < 1
    ) {
        throw new ProtocolError(
            'INVALID_MESSAGE',
            `DISCOVERY_RESPONSE body.documentVersion must be a positive integer >= 1, received ${String(documentVersion)}`,
        );
    }

    // agentDid vs request.targetDid consistency check
    if (agentDid !== expectedTargetDid) {
        throw new ProtocolError(
            'DISCOVERY_TARGET_MISMATCH',
            `DISCOVERY_TARGET_MISMATCH: response.agentDid (${agentDid}) !== request.targetDid (${expectedTargetDid})`,
        );
    }

    return { agentDid, agentCardJson, respondedAt, documentVersion };
}
