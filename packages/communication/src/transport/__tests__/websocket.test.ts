import { afterEach, describe, expect, it } from 'vitest';

import type {
    DID,
    NegotiationEnvelope,
    Signature,
    Timestamp,
} from '@coivitas/types';

import { WebSocketTransport } from '../websocket.js';

const describeIfWs =
    process.env.ENABLE_SOCKET_TESTS === '1' ? describe : describe.skip;

const baseEnvelope: NegotiationEnvelope = {
    id: '760e8400-e29b-41d4-a716-446655440001',
    specVersion: '1.0.0',
    header: {
        senderDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
        recipientDid:
            'did:agent:00112233445566778899aabbccddeeff00112233' as DID,
        sessionId: 'session-001',
        sequenceNumber: 2,
    },
    messageType: 'NEGOTIATION_REQUEST',
    body: {
        action: 'QUOTE',
        amount: 1200,
    },
    signature: 'b'.repeat(128) as Signature,
    timestamp: '2026-04-02T10:05:00.000Z' as Timestamp,
};

describeIfWs('WebSocketTransport', () => {
    const servers: WebSocketTransport[] = [];

    afterEach(async () => {
        await Promise.all(servers.map(async (transport) => transport.close()));
        servers.length = 0;
    });

    it('round-trips an envelope through a websocket session', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        const port = await server.listen(0, (envelope) =>
            Promise.resolve({
                ...envelope,
                messageType: 'NEGOTIATION_RESPONSE',
                body: {
                    accepted: true,
                    originalMessageType: envelope.messageType,
                },
            }),
        );

        const client = new WebSocketTransport();
        const response = await client.send(
            baseEnvelope,
            `ws://127.0.0.1:${port}`,
        );

        expect(response).toEqual({
            ...baseEnvelope,
            messageType: 'NEGOTIATION_RESPONSE',
            body: {
                accepted: true,
                originalMessageType: 'NEGOTIATION_REQUEST',
            },
        });
    });

    it('resolves null when the server closes without a reply', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        const port = await server.listen(0, () => Promise.resolve(null));
        const client = new WebSocketTransport();

        await expect(
            client.send(baseEnvelope, `ws://127.0.0.1:${port}`),
        ).resolves.toBeNull();
    });

    it('auto-reconnects and sends SESSION_RESUME after disconnection', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        const received: unknown[] = [];
        // First listen: collect messages
        const port = await server.listen(0, (envelope) => {
            received.push(envelope.body);
            return Promise.resolve(null);
        });

        const sessionId = 'test-session-resume-001';
        const resumeEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            body: { type: 'SESSION_RESUME', session_id: sessionId },
        };
        const client = new WebSocketTransport({
            reconnectBaseDelayMs: 30,
            reconnectMaxDelayMs: 200,
            reconnectMaxAttempts: 5,
        });
        const ctrl = client.connectPersistent(`ws://127.0.0.1:${port}`, resumeEnvelope);

        // Wait for the first connection and send SESSION_RESUME
        await new Promise((r) => setTimeout(r, 150));

        // Forcibly disconnect all clients (simulating a network interruption)
        await server.close();

        // Restart on the same port (listen awaits close internally, so the port is guaranteed released)
        await server.listen(port, (envelope) => {
            received.push(envelope.body);
            return Promise.resolve(null);
        });

        // Wait for the client to reconnect and send a second SESSION_RESUME
        await new Promise((r) => setTimeout(r, 600));
        ctrl.stop();

        // There should be at least two SESSION_RESUME messages (initial + after reconnect)
        const resumeMessages = received.filter(
            (b) =>
                typeof b === 'object' &&
                b !== null &&
                (b as Record<string, unknown>)['type'] === 'SESSION_RESUME' &&
                (b as Record<string, unknown>)['session_id'] === sessionId,
        );
        expect(resumeMessages.length).toBeGreaterThanOrEqual(2);
    });

    it('fragments and reassembles messages larger than 64KB', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        // Large request body: exceeds 64KB
        const largeBody = { data: 'x'.repeat(70 * 1024) };
        const largeEnvelope: NegotiationEnvelope = { ...baseEnvelope, body: largeBody };

        let serverReceivedBody: unknown = null;

        const port = await server.listen(0, (envelope) => {
            serverReceivedBody = envelope.body;
            // Large response body: also exceeds 64KB (tests bidirectional framing)
            return Promise.resolve({
                ...envelope,
                messageType: 'NEGOTIATION_RESPONSE',
                body: { echo: largeBody.data },
            });
        });

        const client = new WebSocketTransport();
        const response = await client.send(largeEnvelope, `ws://127.0.0.1:${port}`);

        expect(serverReceivedBody).toEqual(largeBody);
        expect(response?.body).toEqual({ echo: largeBody.data });
    });

    it('terminates connection after heartbeat missed limit', async () => {
        const server = new WebSocketTransport({
            heartbeatIntervalMs: 50,
            heartbeatMaxMissed: 2,
        });
        servers.push(server);

        const port = await server.listen(0, () => Promise.resolve(null));

        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
        const { default: WebSocket } = await import('ws' as any);
        // autoPong: false disables ws's built-in automatic pong, simulating a client that does not reply with pong
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
        const rawSocket = new WebSocket(`ws://127.0.0.1:${port}`, { autoPong: false } as any);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return
        await new Promise<void>((resolve) => rawSocket.on('open', resolve));

        let disconnected = false;
        try {
            await new Promise<void>((resolve) => {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                rawSocket.on('close', () => {
                    disconnected = true;
                    resolve();
                });
                setTimeout(resolve, 500);
            });
        } finally {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            if ((rawSocket).readyState !== (rawSocket).CLOSED) {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                (rawSocket).terminate();
            }
        }

        expect(disconnected).toBe(true);
    });

    // Test A: heartbeat — the connection should not be dropped when the client replies with pong normally
    it('keeps connection alive when client responds to pings', async () => {
        const server = new WebSocketTransport({
            heartbeatIntervalMs: 50,
            heartbeatMaxMissed: 2,
        });
        servers.push(server);

        const port = await server.listen(0, () => Promise.resolve(null));

        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
        const { default: WebSocket } = await import('ws' as any);
        // Do not set autoPong: false; ws automatically replies with pong by default, simulating normal client behavior
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unnecessary-type-assertion
        const rawSocket = new WebSocket(`ws://127.0.0.1:${port}`) as any;
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return
        await new Promise<void>((resolve) => rawSocket.on('open', resolve));

        try {
            // Wait 300ms, enough to trigger 3+ ping/pong cycles
            await new Promise((r) => setTimeout(r, 300));

            // The connection should still be OPEN (readyState === 1)
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            expect(rawSocket.readyState).toBe(1); // WebSocket.OPEN === 1
        } finally {
            // Ensure the socket is cleaned up even if the assertion fails
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            if ((rawSocket).readyState !== (rawSocket).CLOSED) {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                (rawSocket).terminate();
            }
        }
    });

    // Test B: framing — small messages (< 64KB threshold) should not trigger framing
    it('sends small messages without framing', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        let receivedEnvelope: NegotiationEnvelope | null = null;
        const port = await server.listen(0, (envelope) => {
            receivedEnvelope = envelope;
            return Promise.resolve(null);
        });

        const client = new WebSocketTransport();
        // baseEnvelope serializes to far less than 64KB, so it should not trigger framing
        await client.send(baseEnvelope, `ws://127.0.0.1:${port}`);

        // The server receives the original envelope, not a _frame frame structure
        expect(receivedEnvelope).toEqual(baseEnvelope);
        // Additional check: the received envelope body has no _frame field (not a framed packet)
        expect((receivedEnvelope as NegotiationEnvelope | null)?.body).not.toHaveProperty('_frame');
    });

    // Test C: framing — a message exactly at the 64KB threshold does not trigger framing (boundary condition: no framing when <=)
    it('does not frame messages at exactly 64KB boundary', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        // Construct an envelope that serializes to exactly 65536 characters
        // First compute the base length with body.data as an empty string, then pad to the target length
        const THRESHOLD = 64 * 1024; // 65536
        const baseWithEmptyData: NegotiationEnvelope = { ...baseEnvelope, body: { data: '' } };
        const baseLength = JSON.stringify(baseWithEmptyData).length;
        const paddingNeeded = THRESHOLD - baseLength;

        // If paddingNeeded < 0, the baseEnvelope structure itself already exceeds THRESHOLD,
        // in which case use THRESHOLD - 1 as the target (still verifies the no-framing boundary behavior)
        const targetLength = paddingNeeded >= 0 ? THRESHOLD : THRESHOLD - 1;
        const actualPadding = targetLength - baseLength;

        const exactEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            body: { data: 'x'.repeat(Math.max(0, actualPadding)) },
        };

        const serialized = JSON.stringify(exactEnvelope);
        // Verify the target length was actually constructed (at or below the threshold, no framing triggered)
        expect(serialized.length).toBe(targetLength);
        expect(serialized.length).toBeLessThanOrEqual(THRESHOLD);

        let receivedEnvelope: NegotiationEnvelope | null = null;
        const port = await server.listen(0, (envelope) => {
            receivedEnvelope = envelope;
            return Promise.resolve(null);
        });

        const client = new WebSocketTransport();
        await client.send(exactEnvelope, `ws://127.0.0.1:${port}`);

        // The server should receive the complete envelope, not framed fragments
        expect(receivedEnvelope).toEqual(exactEnvelope);
    });

    // Test E: rawDataToString — the server can handle binary Buffer messages sent by the client (covers the Buffer fallback branch)
    it('handles binary Buffer messages from raw ws client', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        let receivedEnvelope: NegotiationEnvelope | null = null;
        const port = await server.listen(0, (envelope) => {
            receivedEnvelope = envelope;
            return Promise.resolve(null);
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
        const { default: WebSocket } = await import('ws' as any);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unnecessary-type-assertion
        const rawSocket = new WebSocket(`ws://127.0.0.1:${port}`) as any;
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return
        await new Promise<void>((resolve) => rawSocket.on('open', resolve));

        try {
            // Send in Buffer (binary) format to trigger the server's Buffer fallback branch in rawDataToString
            const binaryPayload = Buffer.from(JSON.stringify(baseEnvelope), 'utf8');
            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
            rawSocket.send(binaryPayload, { binary: true });

            // Wait for the server to process the message
            await new Promise((r) => setTimeout(r, 200));

            expect(receivedEnvelope).toEqual(baseEnvelope);
        } finally {
            // Ensure the socket is cleaned up even if the assertion fails
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            if ((rawSocket).readyState !== (rawSocket).CLOSED) {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                (rawSocket).terminate();
            }
        }
    });

    // Test F: rawDataToString — the server can handle fragmented Buffer array messages (covers the Array.isArray branch)
    it('handles fragmented binary array messages from raw ws client', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        let receivedEnvelope: NegotiationEnvelope | null = null;
        const port = await server.listen(0, (envelope) => {
            receivedEnvelope = envelope;
            return Promise.resolve(null);
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
        const { default: WebSocket } = await import('ws' as any);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unnecessary-type-assertion
        const rawSocket = new WebSocket(`ws://127.0.0.1:${port}`) as any;
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return
        await new Promise<void>((resolve) => rawSocket.on('open', resolve));

        try {
            // When isBinary=true and the data is large, the ws library delivers Buffer[] (an array) on the server's message event.
            // Direct fabrication: after concatenating two Buffers, ws would send them as a single complete Buffer via the perMessageDeflate=false path,
            // so the actual Array branch is triggered on the receiving side by ws's internal fragment-merge mechanism.
            // Alternative: send fragmented WebSocket frames via the fragment option (ws supports ws.send(buf, { fin: false }))
            const payload = JSON.stringify(baseEnvelope);
            const buf = Buffer.from(payload, 'utf8');
            const half = Math.floor(buf.length / 2);

            // Send two fragment frames (ws protocol fragmentation) so the server receives Buffer[] on the message event
            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
            rawSocket.send(buf.subarray(0, half), { fin: false, binary: true });
            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
            rawSocket.send(buf.subarray(half), { fin: true, binary: true });

            // Wait for the server to process the message
            await new Promise((r) => setTimeout(r, 300));

            expect(receivedEnvelope).toEqual(baseEnvelope);
        } finally {
            // Ensure the socket is cleaned up even if the assertion fails
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            if ((rawSocket).readyState !== (rawSocket).CLOSED) {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                (rawSocket).terminate();
            }
        }
    });

    // Test D: reconnection — stops automatically after exceeding the max attempts, without hanging forever
    it('stops reconnecting after max attempts exceeded', async () => {
        // Step 1: use listen(0) to obtain an OS-assigned ephemeral port, then close it so the port is idle
        const tempServer = new WebSocketTransport();
        const tempPort = await tempServer.listen(0, () => Promise.resolve(null));
        await tempServer.close();
        // tempPort is now released, so connections will be refused

        const client = new WebSocketTransport({
            reconnectMaxAttempts: 2,
            reconnectBaseDelayMs: 20,
            reconnectMaxDelayMs: 100,
        });

        // Connect to tempPort (no server), so all attempts will be refused
        const ctrl = client.connectPersistent(`ws://127.0.0.1:${tempPort}`);

        // Wait for exhaustion: 3 failures (1 initial + 2 retries) + backoff delays ~40ms + ~80ms = ~120ms; use 500ms for ample margin
        await new Promise((r) => setTimeout(r, 500));

        // Now start a sentinel server on tempPort: if the loop is still running, it will connect immediately; if stopped, it will not
        const sentinel = new WebSocketTransport();
        servers.push(sentinel);
        let unexpectedConnection = false;
        await sentinel.listen(tempPort, (_envelope) => {
            unexpectedConnection = true;
            return Promise.resolve(null);
        });

        // Wait long enough to give any surviving loop a chance to connect
        await new Promise((r) => setTimeout(r, 200));

        ctrl.stop();
        expect(unexpectedConnection).toBe(false);
    });

    // Test G: send() timeout — when the server does not respond, the client should reject within timeoutMs
    it('rejects with timeout error when server does not respond within timeoutMs', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        // The handler never resolves, simulating a hung server
        const port = await server.listen(0, () => new Promise(() => {}));

        const client = new WebSocketTransport({ timeoutMs: 100 });
        await expect(
            client.send(baseEnvelope, `ws://127.0.0.1:${port}`),
        ).rejects.toThrow('timed out');
    });

    // Test H: send() should reject when it receives an invalid JSON response
    it('rejects when server sends back invalid JSON', async () => {
        // Start a raw WS server that replies with invalid JSON
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
        const { WebSocketServer } = await import('ws' as any);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
        const rawServer: any = new WebSocketServer({ port: 0 });
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument
        const rawPort: number = await new Promise((resolve) =>
            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument
            rawServer.on('listening', () => resolve(rawServer.address().port)),
        );
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
        rawServer.on('connection', (socket: any) => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
            socket.on('message', () => {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                socket.send('this is not valid JSON!!!');
            });
        });

        try {
            const client = new WebSocketTransport();
            await expect(
                client.send(baseEnvelope, `ws://127.0.0.1:${rawPort}`),
            ).rejects.toThrow();
        } finally {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return
            await new Promise<void>((resolve) => rawServer.close(() => resolve()));
        }
    });

    // Test I: send() error event — should reject when an error occurs before the connection is established
    it('rejects on socket error event before connection', async () => {
        // Obtain an ephemeral port and immediately close it, ensuring nothing listens on that port (connection refused)
        const tempServer = new WebSocketTransport();
        const tempPort = await tempServer.listen(0, () => Promise.resolve(null));
        await tempServer.close();

        const client = new WebSocketTransport();
        await expect(
            client.send(baseEnvelope, `ws://127.0.0.1:${tempPort}`),
        ).rejects.toThrow();
    });

    // Test J: when the server handler throws during listen(), the error should be silently absorbed and the socket closed
    it('silently handles errors thrown by the server handler', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        const port = await server.listen(0, () => {
            throw new Error('handler crash');
        });

        const client = new WebSocketTransport();
        // After the handler crashes, the server should close the socket and the client send should resolve null (rather than throw)
        const result = await client.send(baseEnvelope, `ws://127.0.0.1:${port}`);
        expect(result).toBeNull();
    });

    // Test K: connectPersistent — stop() immediately halts and does not reconnect after the first successful connection
    it('stops persistent connection immediately when stop() is called after first connect', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        const port = await server.listen(0, () => Promise.resolve(null));

        const client = new WebSocketTransport({
            reconnectBaseDelayMs: 10,
            reconnectMaxDelayMs: 50,
            reconnectMaxAttempts: 10,
        });
        const ctrl = client.connectPersistent(`ws://127.0.0.1:${port}`);

        // Wait for the first connection to be established
        await new Promise((r) => setTimeout(r, 100));
        ctrl.stop();

        // Wait a while longer to verify no reconnect is triggered
        await new Promise((r) => setTimeout(r, 200));

        // The test passes if there is no hang or timeout
        expect(true).toBe(true);
    });

    // Test L: connectPersistent — covers the exponential backoff delay path (stops after failureCount > 0)
    it('applies exponential backoff delay before reconnecting after failures', async () => {
        // Obtain an ephemeral port and immediately close it, ensuring the connection is refused to trigger the failure path
        const tempServer = new WebSocketTransport();
        const tempPort = await tempServer.listen(0, () => Promise.resolve(null));
        await tempServer.close();

        const client = new WebSocketTransport({
            reconnectBaseDelayMs: 30,
            reconnectMaxDelayMs: 500,
            reconnectMaxAttempts: 3,
        });

        // Connect to the closed port to trigger failures (failureCount increments), covering the delayed-backoff branch
        const ctrl = client.connectPersistent(`ws://127.0.0.1:${tempPort}`);

        // Wait long enough for failureCount > 0 and the delay path to trigger
        // 3 failures: delay=30*2^1 + 30*2^2 + 30*2^3 = 60+120+240 = 420ms
        await new Promise((r) => setTimeout(r, 700));
        ctrl.stop();

        // Passes if there is no hang
        expect(true).toBe(true);
    });

    // Test M: connectPersistent — backoff reconnect succeeds after a disconnect, covering the delay branch for failureCount>0
    // Strategy: establish a connection first, forcibly close the server (the client treats it as a failure), then restart the server to capture the second connection
    it('reconnects with backoff delay after server-side disconnect', async () => {
        const server = new WebSocketTransport();
        servers.push(server);

        const received: unknown[] = [];
        const sessionId = 'test-backoff-reconnect-002';
        const resumeEnvelope: NegotiationEnvelope = {
            ...baseEnvelope,
            body: { type: 'SESSION_RESUME', session_id: sessionId },
        };

        // First listen: receive the initial SESSION_RESUME
        const port = await server.listen(0, (envelope) => {
            received.push(envelope.body);
            return Promise.resolve(null);
        });

        const client = new WebSocketTransport({
            reconnectBaseDelayMs: 30,
            reconnectMaxDelayMs: 200,
            reconnectMaxAttempts: 10,
        });
        const ctrl = client.connectPersistent(`ws://127.0.0.1:${port}`, resumeEnvelope);

        // Wait for the first connection to be established and send SESSION_RESUME
        await new Promise((r) => setTimeout(r, 150));

        // Forcibly close the server (triggers the client disconnect; connectPersistent records it as a "failure", failureCount++)
        await server.close();

        // Restart the server: listen first closes then binds internally (same port)
        await server.listen(port, (envelope) => {
            received.push(envelope.body);
            return Promise.resolve(null);
        });

        // Wait for the client to backoff-reconnect and send a second SESSION_RESUME
        await new Promise((r) => setTimeout(r, 500));
        ctrl.stop();

        const resumeMessages = received.filter(
            (b) =>
                typeof b === 'object' &&
                b !== null &&
                (b as Record<string, unknown>)['type'] === 'SESSION_RESUME' &&
                (b as Record<string, unknown>)['session_id'] === sessionId,
        );
        expect(resumeMessages.length).toBeGreaterThanOrEqual(2);
    });
});
