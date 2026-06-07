import { randomUUID } from 'node:crypto';

import {
    buildEnvelope,
    HandshakeInitiator,
    HandshakeResponder,
    HttpTransport,
    verifyEnvelope,
} from '@coivitas/communication';
import { resolveAgentDID } from '@coivitas/identity';

import {
    InMemoryResponseIdempotencyCache,
    Orchestrator,
} from '../orchestrator.js';
import type { GoldenPathContext } from './context.js';
import { resolveDemoPublicKey } from './utils.js';

export async function runStep5(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    const document = await resolveAgentDID(
        ctx.agentBDid,
        ctx.identityRegistryUrl,
    );

    if (!document) {
        throw new Error(`Unable to resolve ${ctx.agentBDid}.`);
    }

    ctx.agentBDocument = document;
}

export async function runStep6(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentBPrivateKey, 'Agent-B private key is missing.');
    assertContext(ctx.policyEngineB, 'Policy engine B is missing.');
    assertContext(ctx.recorderB, 'Action recorder B is missing.');

    ctx.transportA = new HttpTransport();
    ctx.transportB = new HttpTransport();

    const responder = new HandshakeResponder({
        responderDid: ctx.agentBDid,
        responderPrivateKey: ctx.agentBPrivateKey,
        resolvePublicKey: async (did) =>
            await resolveDemoPublicKey(did, ctx.identityRegistryUrl),
        verifyInitiator: () => Promise.resolve(true),
        capabilities: ['QUOTE', 'CONFIRM'],
    });

    // The golden-path injects an in-memory ResponseIdempotencyCache.

    // Scope note (do not over-interpret):
    // - This demo is a single-process, single-responder happy-path walkthrough; the in-memory cache is sufficient
    // to demonstrate the behavior where "a later retry of the same envelope is short-circuited by ordering";
    // - This cache does **not** provide at-most-once business semantics -- the business handler must be idempotent;
    // - Production deployments MUST swap in a durable implementation (Postgres/Redis) and ensure the business handler is idempotent;
    // - a future release will provide a real `EnvelopeLedger` (atomic claim/finalize),
    // at which point this cache's responsibilities will be correspondingly narrowed (or replaced).
    const idempotencyCache = new InMemoryResponseIdempotencyCache();

    ctx.orchestratorB = new Orchestrator({
        agentDid: ctx.agentBDid,
        agentPrivateKey: ctx.agentBPrivateKey,
        principalDid: ctx.bobDid!,
        policyEngine: ctx.policyEngineB,
        policyRecorder: ctx.recorderB,
        transport: ctx.transportB,
        resolvePublicKey: async (did) =>
            await resolveDemoPublicKey(did, ctx.identityRegistryUrl),
        idempotencyCache,
        businessHandler: ({ action, params }) => {
            if (action === 'INQUIRY') {
                return Promise.resolve({
                    quote_id: randomUUID(),
                    inquiry_id: toStringField(params['inquiry_id']),
                    unit_price: 45,
                    currency: 'USD',
                    quantity: 100,
                    total_price: 4500,
                    delivery_days: 5,
                    validity_hours: 48,
                });
            }

            if (action === 'CONFIRM') {
                return Promise.resolve({
                    order_id: toStringField(params['order_id']) ?? randomUUID(),
                    status: 'confirmed',
                });
            }

            return Promise.resolve({ status: 'unsupported' });
        },
        verbose: ctx.verbose,
    });

    const port = await ctx.transportB.listen(0, async (incoming) => {
        if (incoming.messageType === 'HANDSHAKE_INIT') {
            return await responder.respond(incoming);
        }

        const result = await ctx.orchestratorB!.handleEnvelope(incoming);
        return result.responseEnvelope;
    });
    ctx.responderPort = port;
    ctx.cleanups.push(async () => {
        await ctx.transportB?.close();
        await ctx.transportA?.close();
    });

    const initiator = new HandshakeInitiator({
        initiatorDid: ctx.agentADid,
        initiatorPrivateKey: ctx.agentAPrivateKey,
        transport: ctx.transportA,
        resolvePublicKey: async (did) =>
            await resolveDemoPublicKey(did, ctx.identityRegistryUrl),
        capabilities: ['INQUIRY', 'QUOTE', 'CONFIRM'],
    });

    const handshake = await initiator.initiate({
        responderDid: ctx.agentBDid,
        responderEndpoint: `http://127.0.0.1:${port}`,
    });

    ctx.handshake = handshake;
    ctx.sessionId = handshake.sessionId;
    ctx.negotiatedCapabilities = handshake.negotiatedCapabilities;
}

export async function runStep7(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.transportA, 'Transport A is missing.');
    assertContext(ctx.responderPort, 'Responder port is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.sessionId, 'Session id is missing.');

    const inquiryId = randomUUID();
    const requestId = randomUUID();
    ctx.inquiryRequestId = requestId;

    const envelope = buildEnvelope({
        senderDid: ctx.agentADid,
        senderPrivateKey: ctx.agentAPrivateKey,
        recipientDid: ctx.agentBDid,
        sessionId: ctx.sessionId,
        messageType: 'NEGOTIATION_REQUEST',
        body: {
            requestId,
            action: 'INQUIRY',
            params: {
                product_category: 'electronics',
                quantity: 100,
                budget_usd: 5000,
                inquiry_id: inquiryId,
            },
            tokenId: ctx.tokenA?.id,
        },
        sequenceNumber: 1,
    });

    const response = await ctx.transportA.send(
        envelope,
        `http://127.0.0.1:${ctx.responderPort}`,
    );

    if (!response) {
        throw new Error('No quote response returned from responder.');
    }

    const verification = await verifyEnvelope(response, {
        resolvePublicKey: async (did) =>
            await resolveDemoPublicKey(did, ctx.identityRegistryUrl),
        now: () => new Date(response.timestamp).getTime(),
    });

    if (!verification.valid) {
        throw new Error(
            `Quote response verification failed: ${verification.reason}`,
        );
    }

    ctx.quoteRequestId = requestId;
    ctx.inquiryResponseBody = response.body;
}

export function runStep8(): Promise<void> {
    // The responder-side authorization happens inside Orchestrator.handleEnvelope
    // during step 7. This step exists to preserve the architected 15-step trace.
    return Promise.resolve();
}

export function runStep9(ctx: GoldenPathContext): Promise<void> {
    if (!ctx.inquiryResponseBody) {
        throw new Error('Quote response body is missing.');
    }

    const status = ctx.inquiryResponseBody['status'];
    if (status !== 'SUCCESS') {
        throw new Error(`Quote response status was ${String(status)}.`);
    }

    return Promise.resolve();
}

function assertContext<T>(
    value: T | undefined,
    message: string,
): asserts value is T {
    if (value === undefined) {
        throw new Error(message);
    }
}

function toStringField(value: unknown): string | undefined {
    return typeof value === 'string' ? value : undefined;
}
