import { afterEach, describe, expect, it } from 'vitest';

import type {
    DID,
    NegotiationEnvelope,
    Signature,
    Timestamp,
} from '@coivitas/types';

import { HttpTransport } from '../http.js';
import { WebSocketTransport } from '../websocket.js';

const describeIfWs =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;
const describeIfSockets =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

const envelope: NegotiationEnvelope = {
    id: '860e8400-e29b-41d4-a716-446655440001',
    specVersion: '1.0.0',
    header: {
        senderDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
        recipientDid:
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
        sessionId: 'session-cross-transport',
        sequenceNumber: 3,
    },
    messageType: 'NEGOTIATION_REQUEST',
    body: {
        action: 'CONFIRM',
        decision: 'approve',
    },
    signature: 'c'.repeat(128) as Signature,
    timestamp: '2026-04-02T10:10:00.000Z' as Timestamp,
};

describeIfSockets('transport integration', () => {
    const httpServers: HttpTransport[] = [];
    const wsServers: WebSocketTransport[] = [];

    afterEach(async () => {
        await Promise.all(httpServers.map(async (server) => server.close()));
        await Promise.all(wsServers.map(async (server) => server.close()));
        httpServers.length = 0;
        wsServers.length = 0;
    });

    it('supports request-response semantics over HTTP', async () => {
        const server = new HttpTransport();
        httpServers.push(server);

        const port = await server.listen(0, (incoming) =>
            Promise.resolve({
                ...incoming,
                messageType: 'NEGOTIATION_CONFIRM',
                body: {
                    status: 'ok',
                    receivedSessionId: incoming.header.sessionId,
                },
            }),
        );

        const client = new HttpTransport();
        await expect(
            client.send(envelope, `http://127.0.0.1:${port}`),
        ).resolves.toEqual({
            ...envelope,
            messageType: 'NEGOTIATION_CONFIRM',
            body: {
                status: 'ok',
                receivedSessionId: 'session-cross-transport',
            },
        });
    });

    describeIfWs('websocket compatibility', () => {
        it('supports request-response semantics over WebSocket', async () => {
            const server = new WebSocketTransport();
            wsServers.push(server);

            const port = await server.listen(0, (incoming) =>
                Promise.resolve({
                    ...incoming,
                    messageType: 'NEGOTIATION_CONFIRM',
                    body: {
                        status: 'ok',
                        receivedSessionId: incoming.header.sessionId,
                    },
                }),
            );

            const client = new WebSocketTransport();
            await expect(
                client.send(envelope, `ws://127.0.0.1:${port}`),
            ).resolves.toEqual({
                ...envelope,
                messageType: 'NEGOTIATION_CONFIRM',
                body: {
                    status: 'ok',
                    receivedSessionId: 'session-cross-transport',
                },
            });
        });
    });
});
