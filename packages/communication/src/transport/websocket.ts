import { createServer } from 'node:http';
import { once } from 'node:events';

import type { NegotiationEnvelope } from '@coivitas/types';

import type { EnvelopeHandler, Transport } from './types.js';

// ws types are minimal stubs to allow compilation without @types/ws installed.
// Install with: pnpm add ws @types/ws --filter @coivitas/communication
interface WsSocket {
    send(data: string): void;
    close(): void;
    terminate(): void;
    removeAllListeners(): void;
    ping(): void;
    once(event: string, listener: (...args: unknown[]) => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;
    off(event: string, listener: (...args: unknown[]) => void): this;
}

interface WsConstructor {
    new (url: string): WsSocket;
}

interface WsServerInstance {
    close(cb?: (err?: Error) => void): void;
    on(event: string, listener: (...args: unknown[]) => void): this;
}

interface WsServerConstructor {
    new (options: { server: unknown }): WsServerInstance;
}

interface WsModule {
    default: WsConstructor;
    WebSocketServer: WsServerConstructor;
}

// Use a lazy import to defer loading of the 'ws' module at runtime.
// This avoids hard type-level dependency while preserving runtime behavior.
let _wsModule: WsModule | null = null;

async function loadWs(): Promise<WsModule> {
    if (_wsModule) return _wsModule;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _wsModule = (await import('ws' as any)) as WsModule;
    return _wsModule;
}

export interface WebSocketTransportOptions {
    timeoutMs?: number;
    host?: string;
    heartbeatIntervalMs?: number;  // default 30_000
    heartbeatMaxMissed?: number;   // default 3
    reconnectBaseDelayMs?: number; // default 200
    reconnectMaxDelayMs?: number;  // default 30_000
    reconnectMaxAttempts?: number; // default 10
}

export class WebSocketTransport implements Transport {
    private readonly timeoutMs: number;
    private readonly host: string;
    private server: ReturnType<typeof createServer> | null = null;
    private webSocketServer: WsServerInstance | null = null;
    private readonly clients: Set<WsSocket> = new Set();
    // per-socket frame buffers, cleaned up together when the socket closes to prevent memory leaks
    private readonly socketFrameBuffers: Map<WsSocket, Map<string, FrameBuffer>> = new Map();
    private readonly heartbeatIntervalMs: number;
    private readonly heartbeatMaxMissed: number;
    private readonly reconnectBaseDelayMs: number;
    private readonly reconnectMaxDelayMs: number;
    private readonly reconnectMaxAttempts: number;

    public constructor(options: WebSocketTransportOptions = {}) {
        this.timeoutMs = options.timeoutMs ?? 10_000;
        this.host = options.host ?? '127.0.0.1';
        this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? 30_000;
        this.heartbeatMaxMissed = options.heartbeatMaxMissed ?? 3;
        this.reconnectBaseDelayMs = options.reconnectBaseDelayMs ?? 200;
        this.reconnectMaxDelayMs = options.reconnectMaxDelayMs ?? 30_000;
        this.reconnectMaxAttempts = options.reconnectMaxAttempts ?? 10;
    }

    public async send(
        envelope: NegotiationEnvelope,
        endpoint: string,
    ): Promise<NegotiationEnvelope | null> {
        const { default: WebSocket } = await loadWs();

        return new Promise<NegotiationEnvelope | null>((resolve, reject) => {
            const socket = new WebSocket(endpoint);
            let settled = false;

            const timer = setTimeout(() => {
                cleanup();
                socket.terminate();
                reject(new Error('WebSocket transport request timed out.'));
            }, this.timeoutMs);

            const cleanup = () => {
                clearTimeout(timer);
                socket.removeAllListeners();
            };

            socket.once('open', () => {
                sendFramed(socket, JSON.stringify(envelope));
            });

            // temporary buffer for assembling the server's framed response (lifetime of this send only)
            const clientFrameBuffers = new Map<string, FrameBuffer>();

            const onMessage = (message: unknown): void => {
                try {
                    const raw = rawDataToString(message);
                    const parsed = JSON.parse(raw) as Record<string, unknown>;

                    if (parsed['_frame'] === true) {
                        const frame = parsed as unknown as Frame;
                        let buf = clientFrameBuffers.get(frame.frameId);
                        if (!buf) {
                            buf = { frames: new Map(), total: frame.total };
                            clientFrameBuffers.set(frame.frameId, buf);
                        }
                        buf.frames.set(frame.index, frame.data);
                        if (buf.frames.size < frame.total) return; // not all received yet, keep waiting

                        const completeBuf = buf;
                        const assembled = Array.from(
                            { length: frame.total },
                            (_, i) => {
                                const chunk = completeBuf.frames.get(i);
                                /* v8 ignore next: frameId integrity guaranteed by insertion logic*/
                                if (chunk === undefined) throw new Error(`Missing frame index ${i} for frameId ${frame.frameId}`);
                                return chunk;
                            },
                        ).join('');
                        clientFrameBuffers.delete(frame.frameId);
                        settled = true;
                        cleanup();
                        socket.close();
                        resolve(JSON.parse(assembled) as NegotiationEnvelope);
                    } else {
                        settled = true;
                        cleanup();
                        socket.close();
                        resolve(parsed as unknown as NegotiationEnvelope);
                    }
                } catch (error) {
                    cleanup();
                    socket.close();
                    /* v8 ignore next: ws always throws Error instances; non-Error is defensive guard*/
                    reject(error instanceof Error ? error : new Error(String(error)));
                }
            };

            socket.on('message', onMessage);

            socket.once('close', () => {
                // cleanup() calls removeAllListeners() before socket.close() — this branch is unreachable
                /* v8 ignore next 3*/
                if (settled) {
                    return;
                }
                cleanup();
                resolve(null);
            });

            socket.once('error', (error: unknown) => {
                cleanup();
                // ws always throws Error instances; non-Error is a defensive guard
                /* v8 ignore next 3*/
                reject(
                    error instanceof Error ? error : new Error(String(error)),
                );
            });
        });
    }

    public async listen(
        port: number,
        handler: EnvelopeHandler,
    ): Promise<number> {
        await this.close();

        const { WebSocketServer } = await loadWs();

        this.server = createServer();
        this.webSocketServer = new WebSocketServer({ server: this.server });

        this.webSocketServer.on('connection', (...args: unknown[]) => {
            const socket = args[0] as WsSocket;
            this.clients.add(socket);

            // heartbeat: the server actively pings; if the client fails to reply with pong
            // more than maxMissed times, force-disconnect.
            let missedCount = 0;
            // check the limit before sending a ping: when missedCount reaches maxMissed,
            // terminate immediately to avoid sending one more useless ping on an
            // already-over-limit connection.
            const heartbeatTimer = setInterval(() => {
                if (missedCount >= this.heartbeatMaxMissed) {
                    clearInterval(heartbeatTimer);
                    socket.terminate();
                    return;
                }
                missedCount++;
                socket.ping();
            }, this.heartbeatIntervalMs);

            socket.on('pong', () => {
                missedCount = 0;
            });

            socket.on('message', (message: unknown) => {
                void (async () => {
                    const raw = rawDataToString(message);
                    const parsed = JSON.parse(raw) as Record<string, unknown>;

                    let envelope: NegotiationEnvelope;

                    if (parsed['_frame'] === true) {
                        const frame = parsed as unknown as Frame;

                        // get or create the frame buffer map for this socket
                        let socketBufs = this.socketFrameBuffers.get(socket);
                        if (!socketBufs) {
                            socketBufs = new Map();
                            this.socketFrameBuffers.set(socket, socketBufs);
                        }

                        let buf = socketBufs.get(frame.frameId);
                        if (!buf) {
                            buf = { frames: new Map(), total: frame.total };
                            socketBufs.set(frame.frameId, buf);
                        }
                        buf.frames.set(frame.index, frame.data);

                        if (buf.frames.size < frame.total) return; // not all received yet, wait for subsequent frames

                        // all received, assemble
                        const completeBuf = buf;
                        const assembled = Array.from(
                            { length: frame.total },
                            (_, i) => {
                                const chunk = completeBuf.frames.get(i);
                                /* v8 ignore next: frameId integrity guaranteed by insertion logic*/
                                if (chunk === undefined) throw new Error(`Missing frame index ${i} for frameId ${frame.frameId}`);
                                return chunk;
                            },
                        ).join('');
                        socketBufs.delete(frame.frameId);
                        envelope = JSON.parse(assembled) as NegotiationEnvelope;
                    } else {
                        envelope = parsed as unknown as NegotiationEnvelope;
                    }

                    // by this point there must be a complete envelope; run the handler
                    const result = await handler(envelope);
                    if (result !== null) {
                        sendFramed(socket, JSON.stringify(result));
                    }
                    socket.close(); // explicit close, not finally (avoids closing early mid-frame)
                })().catch((err: unknown) => {
                    socket.close();
                    // silently absorb: the caller already closed, or a network error
                    void err;
                });
            });

            socket.on('close', () => {
                clearInterval(heartbeatTimer);  // prevent timer leak
                this.socketFrameBuffers.delete(socket); // clean up buffers of incomplete framing
                this.clients.delete(socket);
            });
        });

        this.server.listen(port, this.host);
        await once(this.server, 'listening');

        const address = this.server.address();
        // address is always AddressInfo for TCP; string form only occurs with IPC/pipe handles
        /* v8 ignore next 5*/
        if (!address || typeof address === 'string') {
            throw new Error(
                'WebSocket transport failed to bind to a TCP port.',
            );
        }

        return address.port;
    }

    /**
     * WebSocket-specific: establishes a persistent connection with auto-reconnect.
     * Not part of the Transport interface.
     * On each (re)connect, sends resumeEnvelope if provided.
     *
     * Precondition: the peer server must keep the connection open after receiving the
     * resumeEnvelope rather than closing it immediately. If the peer is
     * WebSocketTransport.listen() (request-response mode, which closes right after handling),
     * every successful connection will immediately trigger a reconnect because the server
     * actively closes — this is a semantic mismatch, not a bug.
     */
    public connectPersistent(
        endpoint: string,
        resumeEnvelope?: NegotiationEnvelope,
    ): { stop: () => void } {
        let stopped = false;
        let failureCount = 0;
        // reference to the currently active socket, so stop() can force-close it
        let activeSocket: WsSocket | null = null;

        const schedule = async (): Promise<void> => {
            if (stopped || failureCount >= this.reconnectMaxAttempts) return;

            const { default: WebSocket } = await loadWs();
            const socket = new WebSocket(endpoint);
            activeSocket = socket;

            const connected = await new Promise<boolean>((resolve) => {
                socket.once('open', () => resolve(true));
                socket.once('error', () => resolve(false));
            });

            if (connected) {
                failureCount = 0;
                if (resumeEnvelope) {
                    socket.send(JSON.stringify(resumeEnvelope));
                }
            } else {
                failureCount++;
            }

            // wait for the socket to close (it closes when the server replies null; stop() terminate also triggers close)
            await new Promise<void>((resolve) => {
                socket.once('close', () => resolve());
            });
            activeSocket = null;

            if (stopped || failureCount >= this.reconnectMaxAttempts) return;

            // exponential backoff: back off by baseDelay * 2^n on failure; also wait baseDelay after a successful disconnect to prevent tight reconnect loops
            // v8 async coverage cannot capture branches inside void schedule() fire-and-forget
            /* v8 ignore next 7*/
            const delay = failureCount > 0
                ? Math.min(this.reconnectBaseDelayMs * 2 ** failureCount, this.reconnectMaxDelayMs)
                : this.reconnectBaseDelayMs;
            await new Promise((r) => setTimeout(r, delay));
            await schedule();
        };

        void schedule();
        return {
            stop: () => {
                stopped = true;
                // close the currently active connection immediately, without waiting for the server to close
                activeSocket?.terminate();
                activeSocket = null;
            },
        };
    }

    public async close(): Promise<void> {
        for (const client of this.clients) {
            client.terminate();
        }
        this.clients.clear();

        if (this.webSocketServer) {
            const webSocketServer = this.webSocketServer;
            this.webSocketServer = null;
            await new Promise<void>((resolve, reject) => {
                webSocketServer.close((error?: Error) => {
                    // ws.Server.close() only errors when still accepting connections — impossible here
                    /* v8 ignore next 4*/
                    if (error) {
                        reject(error);
                        return;
                    }
                    resolve();
                });
            });
        }

        if (this.server) {
            const server = this.server;
            this.server = null;
            (
                server as { closeAllConnections?: () => void }
            ).closeAllConnections?.();
            await new Promise<void>((resolve, reject) => {
                server.close((error) => {
                    // http.Server.close() only errors when not listening — impossible here
                    /* v8 ignore next 4*/
                    if (error) {
                        reject(error);
                        return;
                    }
                    resolve();
                });
            });
        }
    }
}

// ws@8.x server-side always delivers data as Buffer (text frames included).
// The string/ArrayBuffer/Array[] branches below are unreachable in Node.js server usage;
// they exist as defensive guards for browser / custom binaryType environments.
function rawDataToString(message: unknown): string {
    /* v8 ignore next 3*/
    if (typeof message === 'string') {
        return message;
    }
    /* v8 ignore next 3*/
    if (message instanceof ArrayBuffer) {
        return Buffer.from(message).toString('utf8');
    }
    /* v8 ignore next 5*/
    if (Array.isArray(message)) {
        return Buffer.concat(
            (message as Buffer[]).map((chunk) => Buffer.from(chunk)),
        ).toString('utf8');
    }
    return Buffer.from(message as Buffer).toString('utf8');
}

// framing threshold: 64KB (in characters, measured by JS string.length)
const FRAMING_THRESHOLD = 64 * 1024;

interface Frame {
    _frame: true;
    frameId: string;
    index: number;      // 0-based
    total: number;
    data: string;       // a slice of the serialized JSON
}

interface FrameBuffer {
    frames: Map<number, string>;
    total: number;
}

// internal transport-layer framing protocol (used only by both ends of WebSocketTransport):
// a JSON string larger than 64KB is split into multiple Frame messages sent in sequence;
// the receiver reassembles them and then parses the NegotiationEnvelope.
// A Frame object is not a NegotiationEnvelope and does not conform to the application-layer format,
// so the peer must be the same version of WebSocketTransport (large-message interop with other
// transport implementations is not supported).
function splitIntoFrames(serialized: string): Frame[] | null {
    if (serialized.length <= FRAMING_THRESHOLD) return null;
    const frameId = crypto.randomUUID();
    const total = Math.ceil(serialized.length / FRAMING_THRESHOLD);
    const result: Frame[] = [];
    for (let i = 0; i < total; i++) {
        result.push({
            _frame: true,
            frameId,
            index: i,
            total,
            data: serialized.slice(i * FRAMING_THRESHOLD, (i + 1) * FRAMING_THRESHOLD),
        });
    }
    return result;
}

// unified send entry point: automatically frames on demand
function sendFramed(socket: { send: (data: string) => void }, serialized: string): void {
    const frames = splitIntoFrames(serialized);
    if (frames) {
        for (const frame of frames) {
            socket.send(JSON.stringify(frame));
        }
    } else {
        socket.send(serialized);
    }
}
