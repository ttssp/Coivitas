import { once } from 'node:events';

import type { Application } from 'express';

import { ProtocolError } from '@coivitas/types';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../src/server.js';
import {
    createTestServer,
    makeRequest,
    type TestServerContext,
} from '../src/test-utils.js';

describe('server', () => {
    const servers: TestServerContext[] = [];

    afterEach(async () => {
        vi.restoreAllMocks();
        await Promise.all(
            servers.splice(0).map(async (server) => server.close()),
        );
    });

    it('responds to GET /health', async () => {
        const server = await createServer(servers, () => undefined);

        const response = await makeRequest(server.url, 'GET', '/health');

        expect(response.status).toBe(200);
        expect(response.body).toEqual({ status: 'ok' });
    });

    it('parses JSON bodies and applies CORS policy', async () => {
        const app = createApp({
            corsOrigins: ['https://example.com'],
        });

        app.post('/echo', (request, response) => {
            response.status(200).json(request.body);
        });

        const server = await listenApp(app);
        servers.push(server);
        const rawResponse = await fetch(`${server.url}/echo`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                origin: 'https://example.com',
            },
            body: JSON.stringify({ hello: 'world' }),
        });

        expect(rawResponse.status).toBe(200);
        expect(rawResponse.headers.get('access-control-allow-origin')).toBe(
            'https://example.com',
        );
        expect(await rawResponse.json()).toEqual({ hello: 'world' });
    });

    it('maps ProtocolError to the configured HTTP status and payload', async () => {
        const server = await createServer(servers, (app) => {
            app.get('/boom', () => {
                throw new ProtocolError(
                    'IDENTITY_NOT_FOUND',
                    'agent is missing',
                );
            });
        });

        const response = await makeRequest(server.url, 'GET', '/boom');

        expect(response.status).toBe(404);
        expect(response.body).toEqual({
            error: {
                code: 'IDENTITY_NOT_FOUND',
                message: 'agent is missing',
            },
        });
    });

    it('returns a standardized 500 response for unexpected errors', async () => {
        const server = await createServer(servers, (app) => {
            app.get('/boom', () => {
                throw new Error('unexpected');
            });
        });

        const response = await makeRequest(server.url, 'GET', '/boom');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            error: {
                code: 'INTERNAL_ERROR',
                message: 'Internal server error',
            },
        });
    });

    it('logs requests with status and duration', async () => {
        const loggerSpy = vi
            .spyOn(console, 'info')
            .mockImplementation(() => undefined);
        const server = await createServer(servers, (app) => {
            app.get('/logged', (_request, response) => {
                response.status(204).end();
            });
        });

        await makeRequest(server.url, 'GET', '/logged');

        expect(loggerSpy).toHaveBeenCalledTimes(1);
        expect(String(loggerSpy.mock.calls[0]?.[0])).toContain(
            'GET /logged 204',
        );
    });
});

async function createServer(
    servers: TestServerContext[],
    configure: (app: Application) => void,
): Promise<TestServerContext> {
    const server = await createTestServer((app) => {
        configure(app);
    });
    servers.push(server);

    return server;
}

async function listenApp(app: Application): Promise<TestServerContext> {
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');

    const address = server.address();
    if (!address || typeof address === 'string') {
        throw new Error('Test server failed to bind to a TCP port');
    }

    return {
        url: `http://127.0.0.1:${address.port}`,
        close: async () => {
            server.closeAllConnections?.();
            await new Promise<void>((resolve, reject) => {
                server.close((error) => {
                    if (error) {
                        reject(error);
                        return;
                    }

                    resolve();
                });
            });
        },
    };
}
