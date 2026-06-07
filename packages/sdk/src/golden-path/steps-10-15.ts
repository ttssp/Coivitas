import { randomUUID } from 'node:crypto';

import { buildEnvelope } from '@coivitas/communication';

import type { GoldenPathContext } from './context.js';

export async function runStep10(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.guardA, 'Guard A is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.inquiryResponseBody, 'Inquiry response body is missing.');

    const quoteData = getQuoteData(ctx);
    const check = await ctx.guardA.check(
        'CONFIRM',
        {
            quote_id: String(quoteData['quote_id']),
            inquiry_id: String(quoteData['inquiry_id']),
            confirmed_quantity: Number(quoteData['quantity']),
            confirmed_price: Number(quoteData['total_price']),
            currency: String(quoteData['currency']),
        },
        ctx.agentADid,
    );

    if (!check.allowed) {
        throw new Error(check.reason ?? 'Confirm authorization failed.');
    }
}

export async function runStep11(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.transportA, 'Transport A is missing.');
    assertContext(ctx.responderPort, 'Responder port is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');
    assertContext(ctx.sessionId, 'Session id is missing.');
    assertContext(ctx.inquiryResponseBody, 'Inquiry response body is missing.');

    const quoteData = getQuoteData(ctx);
    const requestId = randomUUID();
    ctx.confirmRequestId = requestId;

    const envelope = buildEnvelope({
        senderDid: ctx.agentADid,
        senderPrivateKey: ctx.agentAPrivateKey,
        recipientDid: ctx.agentBDid,
        sessionId: ctx.sessionId,
        messageType: 'NEGOTIATION_CONFIRM',
        body: {
            requestId,
            action: 'CONFIRM',
            params: {
                quote_id: String(quoteData['quote_id']),
                inquiry_id: String(quoteData['inquiry_id']),
                confirmed_quantity: Number(quoteData['quantity']),
                confirmed_price: Number(quoteData['total_price']),
                currency: String(quoteData['currency']),
                shipping_address: 'Shanghai, CN',
                order_id: randomUUID(),
                human_approved: true,
            },
            tokenId: ctx.tokenA?.id,
        },
        sequenceNumber: 2,
    });

    const response = await ctx.transportA.send(
        envelope,
        `http://127.0.0.1:${ctx.responderPort}`,
    );

    if (!response) {
        throw new Error('No confirm response returned from responder.');
    }

    ctx.confirmResponseBody = response.body;
}

export async function runStep12(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.recorderA, 'Recorder A is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.aliceDid, 'Alice DID is missing.');
    assertContext(ctx.agentAPrivateKey, 'Agent-A private key is missing.');

    const record = await ctx.recorderA.record({
        agentDid: ctx.agentADid,
        principalDid: ctx.aliceDid,
        actionType: 'CONFIRM',
        parametersSummary: {
            requestId: ctx.confirmRequestId,
        },
        authorizationRef: {
            tokenId: ctx.tokenA?.id ?? null,
        },
        resultSummary: {
            status: 'SUCCESS',
        },
        actorPrivateKey: ctx.agentAPrivateKey,
    });

    ctx.recordIdA = record.recordId;

    const resultB = await ctx.recorderB?.query({
        agentDid: ctx.agentBDid,
    });
    ctx.recordIdB = resultB?.records.at(-1)?.recordId;
}

export async function runStep13(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.integrityCheckerA, 'Integrity checker A is missing.');
    assertContext(ctx.integrityCheckerB, 'Integrity checker B is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');
    assertContext(ctx.agentBDid, 'Agent-B DID is missing.');

    const [resultA, resultB] = await Promise.all([
        ctx.integrityCheckerA.verifyIntegrity(ctx.agentADid),
        ctx.integrityCheckerB.verifyIntegrity(ctx.agentBDid),
    ]);

    if (!resultA.valid) {
        throw new Error(`Agent-A integrity failed: ${resultA.reason}`);
    }

    if (!resultB.valid) {
        throw new Error(`Agent-B integrity failed: ${resultB.reason}`);
    }
}

export async function runStep14(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.revocationList, 'Revocation list is missing.');
    assertContext(ctx.aliceDid, 'Alice DID is missing.');
    assertContext(ctx.tokenA, 'Token A is missing.');

    const revocation = await ctx.revocationList.revoke({
        tokenId: ctx.tokenA.id,
        revokedBy: ctx.aliceDid,
        reason: 'MANUAL_REVOCATION',
    });

    ctx.revokedAt = revocation.revokedAt;
}

export async function runStep15(ctx: GoldenPathContext): Promise<void> {
    assertContext(ctx.guardA, 'Guard A is missing.');
    assertContext(ctx.agentADid, 'Agent-A DID is missing.');

    const result = await ctx.guardA.check(
        'INQUIRY',
        {
            product_category: 'electronics',
            quantity: 100,
            budget_usd: 5000,
        },
        ctx.agentADid,
    );

    if (result.allowed || result.reason !== 'capability revoked') {
        throw new Error(
            `Expected revoked token denial, received ${JSON.stringify(result)}.`,
        );
    }
}

function getQuoteData(ctx: GoldenPathContext): Record<string, unknown> {
    const data = ctx.inquiryResponseBody?.['data'];
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('Quote response did not include a valid data object.');
    }

    return data as Record<string, unknown>;
}

function assertContext<T>(
    value: T | undefined,
    message: string,
): asserts value is T {
    if (value === undefined) {
        throw new Error(message);
    }
}
