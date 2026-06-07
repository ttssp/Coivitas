/**
 * Golden Path extended Step 21-25
 *
 *   Step 21 Agent A initiates key rotation (initiateKeyRotation -> RotatingDocument)
 *   Step 22 Within the grace period: sign envelope with old private key + old public key resolver -> verification passes
 *   Step 23 completeKeyRotation + grace expiry: new signature passes, old signature fails
 *   Step 24 temporal_scope: rejected outside the window, allowed inside the window (controlled time injected via RuntimeGuard.now)
 *   Step 25 cumulative_limit: rejected when the cumulative total exceeds the limit, allowed when within the limit
 *
 * Design notes:
 *   - Step 21 does not go through IdentityRegistry (to avoid the extra test complexity of the
 *     registry.update + rotation_state SQL state machine); it only validates the document-layer contract
 *     defined by key rotation. In a real deployment Registry.update drives state transitions; the demo uses
 *     an in-memory closure to simulate resolver behavior.
 *   - Step 22/23 verify signatures directly via verifyEnvelope, using two different resolvePublicKey closures
 *     to simulate the two states "accept old key within grace / accept new key only outside grace".
 *   - Step 24 builds a NumericLimit + TemporalScope capability; RuntimeGuard's now port is replaced inside
 *     the step with a controllable fake time, first outside the window then inside it.
 *   - Step 25 uses PostgresCumulativeTracker (real DB) + pre-written ActionRecords accumulating 4500;
 *     first 600 exceeds the limit -> rejected, then 400 stays within -> allowed.
 */

import { randomUUID } from 'node:crypto';

import { canonicalize, generateKeyPair, sign } from '@coivitas/crypto';
import { buildEnvelope, verifyEnvelope } from '@coivitas/communication';
import {
    completeKeyRotation,
    createAgentIdentity,
    didKeyFromPublicKey,
    initiateKeyRotation,
} from '@coivitas/identity';
import {
    ActionRecorder,
    PostgresCumulativeTracker,
    RuntimeGuard,
    ScopeEvaluator,
    TokenStore,
} from '@coivitas/policy';
import type {
    Capability,
    CapabilityToken,
    DID,
    Signature,
    Timestamp,
} from '@coivitas/types';
import { SPEC_VERSION_0_2_0 } from '@coivitas/types';

import type { GoldenPathContext } from './context.js';

// ── helpers: issue a 0.2.0 token (supports temporal_scope / cumulative_limit) ────────

// Background: identity layer's issueCapabilityToken hardcodes specVersion='0.1.0' --
// but the extended scope types (temporal_scope / cumulative_limit) require specVersion='0.2.0'.
// The Golden Path Step 24/25 scenarios need a local helper to build a 0.2.0 token, using canonicalize + sign
// directly to align with createCapabilityTokenPayload's signing payload format, without changing the identity layer's public API.

function issuePhase2Token(params: {
    issuerDid: DID;
    issuerPrivateKey: string;
    issuedTo: DID;
    capabilities: Capability[];
    expiresAt: Timestamp;
    revocationUrl: string;
    issuedAt?: Timestamp;
}): CapabilityToken {
    const issuedAt = (params.issuedAt ?? new Date().toISOString()) as Timestamp;
    const payload = {
        capabilities: params.capabilities,
        expiresAt: params.expiresAt,
        id: `urn:cap:${randomUUID()}`,
        issuedAt,
        issuedTo: params.issuedTo,
        issuerDid: params.issuerDid,
        principalDid: params.issuerDid,
        revocationUrl: params.revocationUrl,
        specVersion: SPEC_VERSION_0_2_0,
    } as const;
    const signatureBytes = new TextEncoder().encode(canonicalize(payload));
    return {
        ...payload,
        proof: {
            type: 'Ed25519Signature2026',
            created: issuedAt,
            verificationMethod: `${params.issuerDid}#key-1`,
            value: sign(
                signatureBytes,
                params.issuerPrivateKey,
            ) as CapabilityToken['proof']['value'],
        },
    } as CapabilityToken;
}

// ── Step 21: initiate key rotation ────────────────────────────────────────────

export function runStep21(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentADocument, 'Agent-A document is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.aliceKeyPair, 'Alice key pair is missing.');

    const newKeyPair = generateKeyPair();
    const rotatedAt = new Date().toISOString() as Timestamp;

    // principalApproval: key rotation requires that the principal's private key never enters the Agent Runtime,
    // so the caller pre-signs externally. In the demo we sign the payload directly with Alice's private key.
    const payloadBytes = new TextEncoder().encode(
        canonicalize({
            agentDid: ctx.agentADocument.id,
            newPublicKey: newKeyPair.publicKey,
            oldPublicKey: ctx.agentADocument.publicKey,
            rotatedAt,
        }),
    );
    const principalApproval = sign(
        payloadBytes,
        ctx.aliceKeyPair.privateKey,
    ) as Signature;

    const rotating = initiateKeyRotation({
        currentDoc: ctx.agentADocument,
        currentPrivateKey: ctx.agentAPrivateKey,
        newKeyPair,
        principalApproval,
        rotatedAt,
    });

    // White-box assertions: publicKey switched to new; previousPublicKey retains the old; rotationProof has all three signatures.
    if (rotating.publicKey !== newKeyPair.publicKey) {
        throw new Error(
            'RotatingDocument.publicKey did not switch to new key.',
        );
    }
    if (rotating.previousPublicKey !== ctx.agentADocument.publicKey) {
        throw new Error(
            'RotatingDocument.previousPublicKey must equal old key.',
        );
    }
    if (!rotating.rotationProof) {
        throw new Error('RotatingDocument.rotationProof is missing.');
    }

    ctx.agentANewKeyPair = newKeyPair;
    ctx.agentARotatingDocument = rotating;
    ctx.agentARotatedAt = rotatedAt;
    ctx.agentARotationState = 'ROTATING';
    // principalDid is derived via didKeyFromPublicKey to avoid typos -- validation only
    void didKeyFromPublicKey(Buffer.from(ctx.aliceKeyPair.publicKey, 'hex'));
    return Promise.resolve();
}

// ── Step 22: within the grace period -- the old signature still verifies ──────

export async function runStep22(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.agentADocument, 'Agent-A document is missing.');
    assertContext(ctx.agentARotatingDocument, 'Rotating document missing.');

    // Scenario: after rotating in Step 21, Agent A continues signing new messages with the old private key during the grace period.
    // The business side signs with the "old" agentAPrivateKey; the verification side's resolvePublicKey returns
    // RotatingDocument.previousPublicKey (i.e. the old public key) -- simulating the dual-key acceptance window during rotation.
    const envelope = buildEnvelope({
        senderDid: ctx.agentADid,
        senderPrivateKey: ctx.agentAPrivateKey, // still the old key
        recipientDid: ctx.agentBDid,
        sessionId: `rotation-grace-${randomUUID()}`,
        messageType: 'NEGOTIATION_REQUEST',
        body: { requestId: randomUUID(), action: 'INQUIRY', params: {} },
        sequenceNumber: 1,
    });

    // Within grace: the resolver returns the old public key (= previousPublicKey).
    const previousPublicKey = ctx.agentARotatingDocument.previousPublicKey;
    if (!previousPublicKey) {
        throw new Error(
            'RotatingDocument.previousPublicKey is unexpectedly missing.',
        );
    }
    const result = await verifyEnvelope(envelope, {
        resolvePublicKey: (did): Promise<string | null> => {
            if (did !== ctx.agentADid) return Promise.resolve(null);
            return Promise.resolve(previousPublicKey);
        },
        now: () => new Date(envelope.timestamp).getTime(),
    });

    if (!result.valid) {
        throw new Error(
            `Grace-period envelope (signed by old key) should verify, got: ${result.reason ?? 'unknown'}.`,
        );
    }
}

// ── Step 23: complete rotation -- old signature invalidated, new signature valid ──

export async function runStep23(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.agentARotatingDocument, 'Rotating document missing.');
    assertContext(ctx.agentANewKeyPair, 'New key pair missing.');

    // 23.a completeKeyRotation: RotatingDocument -> AgentIdentityDocument (no _rotatingState)
    const completed = completeKeyRotation(ctx.agentARotatingDocument);
    if (completed.publicKey !== ctx.agentANewKeyPair.publicKey) {
        throw new Error('Completed document publicKey should be the new key.');
    }
    ctx.agentADocument = completed;
    ctx.agentARotationState = 'ACTIVE';

    // 23.a+ Persist the new public key to IdentityRegistry
    // Why: from now on the runtime signs actorSignature with ctx.agentANewKeyPair.privateKey
    // (Step 25 recorder.record), while downstream IntegrityChecker/PostgresCumulativeTracker
    // resolve Agent-A's public key via resolveDemoPublicKey -> registry.query.
    // If the registry still holds the old public key, signer and verifier would operate on different
    // key pairs, breaking signature semantics.
    // Known simplification: registry.update's rotation path sets rotation_state to 'ROTATING' and has no
    // "complete rotation -> ACTIVE" API. The current golden-path downstream
    // (IntegrityChecker/Tracker) does not consume rotation_state, so the ROTATING side effect
    // has no real impact; the rotation_state -> ACTIVE state machine upgrade is deferred to a later refinement.
    assertContext(ctx.identityRegistry, 'IdentityRegistry missing.');
    await ctx.identityRegistry.update(completed, 1);

    // 23.b grace has passed: the resolver returns only the new public key.
    // ── Envelope signed with the old key should fail verification ──
    const envelopeOld = buildEnvelope({
        senderDid: ctx.agentADid,
        senderPrivateKey: ctx.agentAPrivateKey, // old private key
        recipientDid: ctx.agentBDid,
        sessionId: `rotation-post-${randomUUID()}`,
        messageType: 'NEGOTIATION_REQUEST',
        body: { requestId: randomUUID(), action: 'INQUIRY', params: {} },
        sequenceNumber: 1,
    });
    const resolverNewOnly = (did: DID): Promise<string | null> => {
        if (did !== ctx.agentADid) return Promise.resolve(null);
        return Promise.resolve(ctx.agentANewKeyPair!.publicKey);
    };
    const oldResult = await verifyEnvelope(envelopeOld, {
        resolvePublicKey: resolverNewOnly,
        now: () => new Date(envelopeOld.timestamp).getTime(),
    });
    if (oldResult.valid) {
        throw new Error(
            'Post-grace envelope signed by old key should fail, but verified as valid.',
        );
    }

    // ── Envelope signed with the new key should verify successfully ──
    const envelopeNew = buildEnvelope({
        senderDid: ctx.agentADid,
        senderPrivateKey: ctx.agentANewKeyPair.privateKey, // new private key
        recipientDid: ctx.agentBDid,
        sessionId: `rotation-post-${randomUUID()}`,
        messageType: 'NEGOTIATION_REQUEST',
        body: { requestId: randomUUID(), action: 'INQUIRY', params: {} },
        sequenceNumber: 2,
    });
    const newResult = await verifyEnvelope(envelopeNew, {
        resolvePublicKey: resolverNewOnly,
        now: () => new Date(envelopeNew.timestamp).getTime(),
    });
    if (!newResult.valid) {
        throw new Error(
            `Post-grace envelope signed by new key should verify, got: ${newResult.reason ?? 'unknown'}.`,
        );
    }

    // Formally switch the business context to the new key -- subsequent steps will sign envelopes with the new key.
    ctx.agentAPrivateKey = ctx.agentANewKeyPair.privateKey;
}

// ── Step 24: temporal_scope ─────────────────────────────────────────────────

export async function runStep24(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.aliceDid, 'Alice DID is missing.');
    assertContext(ctx.aliceKeyPair, 'Alice key pair is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.tokenStoreA, 'Token store A is missing.');
    assertContext(ctx.revocationList, 'Revocation list is missing.');

    // Build a token whose time window runs "from 1h out to 2h out".
    // issuedAt is explicitly passed as nowMs-1s to avoid "issuedAt > now" at millisecond granularity
    // relative to RuntimeGuard's injected fakeNowMs=nowMs -- which would cause verifyCapabilityToken to reject it as INVALID_TOKEN_FORMAT.
    const nowMs = Date.now();
    const tokenIssuedAt = new Date(nowMs - 1000).toISOString() as Timestamp;
    const notBefore = new Date(
        nowMs + 60 * 60 * 1000,
    ).toISOString() as Timestamp;
    const notAfter = new Date(
        nowMs + 2 * 60 * 60 * 1000,
    ).toISOString() as Timestamp;
    const tokenExpiresAt = new Date(
        nowMs + 3 * 60 * 60 * 1000,
    ).toISOString() as Timestamp;

    const token = issuePhase2Token({
        issuerDid: ctx.aliceDid,
        issuerPrivateKey: ctx.aliceKeyPair.privateKey,
        issuedTo: ctx.agentADid,
        capabilities: [
            {
                action: 'INQUIRY',
                scope: {
                    type: 'temporal_scope',
                    notBefore,
                    notAfter,
                },
            },
        ],
        expiresAt: tokenExpiresAt,
        revocationUrl: 'https://revocations.local/api/v1/revocations/{id}',
        issuedAt: tokenIssuedAt,
    });

    await ctx.tokenStoreA.store(ctx.agentADid, token);
    ctx.tokenATemporal = token;

    // RuntimeGuard's now port is injectable; first set now=current time (outside the window, before it starts), then
    // set now to fall inside the window (after notBefore, before notAfter), running one check each.
    const buildGuard = (fakeNowMs: number): RuntimeGuard =>
        new RuntimeGuard({
            tokenStore: ctx.tokenStoreA!,
            revocationChecker: async (tokenId) =>
                await ctx.revocationList!.isRevoked(tokenId),
            now: () => new Date(fakeNowMs).toISOString() as Timestamp,
        });

    // Outside the window: now is before notBefore -> rejected.
    const outside = await buildGuard(nowMs).check(
        'INQUIRY',
        {},
        ctx.agentADid,
        token.id,
    );
    if (outside.allowed) {
        throw new Error(
            'temporal_scope window pre-notBefore check should be denied.',
        );
    }
    if (!/temporal_scope/.test(outside.reason ?? '')) {
        throw new Error(
            `Expected temporal_scope rejection reason, got: ${outside.reason ?? 'unknown'}.`,
        );
    }

    // Inside the window: now is between notBefore and notAfter -> allowed.
    const midWindow = nowMs + 90 * 60 * 1000; // 1.5h out
    const inside = await buildGuard(midWindow).check(
        'INQUIRY',
        {},
        ctx.agentADid,
        token.id,
    );
    if (!inside.allowed) {
        throw new Error(
            `temporal_scope in-window check should be allowed, got: ${inside.reason ?? 'unknown'}.`,
        );
    }
}

// ── Step 25: cumulative_limit ───────────────────────────────────────────────

// Why introduce a separate Agent C:
// PostgresCumulativeTracker aggregates all SUCCESS action_records by (agent_did, window).
// Step 12 wrote a record on Agent A with result_summary={status:'SUCCESS'} and no amount field --
// using Agent A for the cumulative_limit demo would cause the tracker to aggregate this amount-less record
// into the transaction_amount window -> fail-closed.

// An earlier version cleaned up with DELETE FROM policy.action_records -- which violates the
// "append-only, immutable ledger" hard constraint (the migration script explicitly REVOKEs DELETE).
// Instead, Step 25 uses a separate Agent C + a separate ledger key + a separate recorder/tokenStore,
// so the aggregation window is naturally isolated from Agent A without rewriting the ledger.

export async function runStep25(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.pool, 'pool missing.');
    assertContext(ctx.identityRegistry, 'IdentityRegistry missing.');
    assertContext(ctx.revocationList, 'Revocation list is missing.');
    assertContext(ctx.ledgerPrivateKey, 'ledgerPrivateKey missing.');

    // 25.0 Establish a separate Principal-C / Agent-C identity context
    const principalC = generateKeyPair();
    const principalCDid = didKeyFromPublicKey(
        Buffer.from(principalC.publicKey, 'hex'),
    );
    const agentC = createAgentIdentity({
        principalDid: principalCDid,
        principalPrivateKey: principalC.privateKey,
        capabilities: ['CONFIRM'],
        serviceEndpoints: [
            {
                id: 'negotiation',
                type: 'NegotiationEndpoint',
                url: 'https://agent-c.local/negotiation',
            },
        ],
    });
    await ctx.identityRegistry.register(agentC.document);

    const tokenStoreC = new TokenStore(ctx.pool);
    const recorderC = new ActionRecorder(ctx.pool, {
        kind: 'standard',
        ledgerPrivateKey: ctx.ledgerPrivateKey,
    });

    // 25.1 Issue a token with cumulative_limit (transaction_amount SUM, window=hour, max=5000)
    const nowMs = Date.now();
    const tokenIssuedAt = new Date(nowMs - 1000).toISOString() as Timestamp;
    const token = issuePhase2Token({
        issuerDid: principalCDid,
        issuerPrivateKey: principalC.privateKey,
        issuedTo: agentC.document.id,
        issuedAt: tokenIssuedAt,
        capabilities: [
            {
                action: 'CONFIRM',
                scope: {
                    type: 'cumulative_limit',
                    meterField: {
                        source: 'action_record',
                        metric: 'transaction_amount',
                    },
                    max: 5000,
                    window: 'hour',
                    currency: 'USD',
                },
            },
            // Beyond cumulative_limit, also carry a lenient numeric_limit to ensure the amount field has a valid type.
            {
                action: 'CONFIRM',
                scope: {
                    type: 'numeric_limit',
                    field: 'amount',
                    max: 10000,
                },
            },
        ],
        expiresAt: new Date(
            nowMs + 24 * 60 * 60 * 1000,
        ).toISOString() as Timestamp,
        revocationUrl: 'https://revocations.local/api/v1/revocations/{id}',
    });
    await tokenStoreC.store(agentC.document.id, token);
    ctx.tokenACumulative = token;

    // 25.2 Pre-write two ActionRecords, accumulating sum=4500 (amount 2500 + 2000)
    // Agent-C has no other records in this window, so the tracker's aggregation window is clean.
    for (const amount of [2500, 2000]) {
        await recorderC.record({
            agentDid: agentC.document.id,
            principalDid: principalCDid,
            actionType: 'CONFIRM',
            parametersSummary: { amount },
            authorizationRef: { tokenId: token.id },
            resultSummary: { status: 'SUCCESS', amount },
            actorPrivateKey: agentC.privateKey,
        });
    }

    // 25.3 Build PostgresCumulativeTracker -> ScopeEvaluator(tracker) -> guard
    const tracker = new PostgresCumulativeTracker(
        ctx.pool,
        recorderC.ledgerPublicKey,
    );
    const scopeEvaluator = new ScopeEvaluator(tracker);
    const guard = new RuntimeGuard({
        tokenStore: tokenStoreC,
        revocationChecker: async (tokenId) =>
            await ctx.revocationList!.isRevoked(tokenId),
        scopeEvaluator,
    });

    // 25.4a amount=600 -> cumulative 4500+600=5100 > 5000 -> rejected
    const exceeded = await guard.check(
        'CONFIRM',
        { amount: 600 },
        agentC.document.id,
        token.id,
    );
    if (exceeded.allowed) {
        throw new Error(
            'cumulative_limit should reject amount=600 (4500+600>5000).',
        );
    }
    if (!/cumulative_limit/.test(exceeded.reason ?? '')) {
        throw new Error(
            `Expected cumulative_limit rejection, got: ${exceeded.reason ?? 'unknown'}.`,
        );
    }

    // 25.4b amount=400 -> cumulative 4500+400=4900 <= 5000 -> allowed
    const allowed = await guard.check(
        'CONFIRM',
        { amount: 400 },
        agentC.document.id,
        token.id,
    );
    if (!allowed.allowed) {
        throw new Error(
            `cumulative_limit should allow amount=400 (4500+400<=5000), got: ${allowed.reason ?? 'unknown'}.`,
        );
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

function assertContext<T>(
    value: T | undefined,
    message: string,
): asserts value is T {
    if (value === undefined) {
        throw new Error(message);
    }
}
