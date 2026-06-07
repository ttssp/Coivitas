import { describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';
import { generateKeyPair } from '@coivitas/crypto';
import type { AgentIdentityDocument, DID, Signature, Timestamp } from '@coivitas/types';
import { EventEmitter } from 'node:events';
import { buildAgentCard } from '../agent-card.js';
import { AgentCardService } from '../agent-card-service.js';
import { createAgentCardRoute } from '../agent-card-routes.js';

function makeDoc(): AgentIdentityDocument {
    const { publicKey } = generateKeyPair();
    return {
        id: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
        specVersion: '0.1.0',
        principalDid: 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QbdU6D' as DID,
        publicKey,
        bindingProof: {
            principalDid: 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QbdU6D' as DID,
            agentDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
            issuedAt: '2026-04-01T00:00:00.000Z' as Timestamp,
            expiresAt: null,
            signature: 'a'.repeat(128) as unknown as Signature,
        },
        capabilities: ['INQUIRY'],
        serviceEndpoints: [{ id: 'main', type: 'NegotiationEndpoint', url: 'https://agent.example.com' }],
        createdAt: '2026-04-01T00:00:00.000Z' as Timestamp,
        updatedAt: '2026-04-15T10:00:00.000Z' as Timestamp,
        version: 1,
    };
}

function makeMockRes() {
    const res = {
        setHeader: vi.fn().mockReturnThis(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
    } as unknown as Response;
    return res;
}

describe('createAgentCardRoute', () => {
    it('should respond with 200, correct headers, and AgentCard JSON on success', async () => {
        const { privateKey, publicKey } = generateKeyPair();
        const doc = makeDoc();
        const card = buildAgentCard({ doc: { ...doc, publicKey }, privateKey });
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: doc.id,
            buildCard: () => Promise.resolve(card),
            eventEmitter: emitter,
        });

        const handler = createAgentCardRoute(service);
        const req = {} as Request;
        const res = makeMockRes();

        handler(req, res, vi.fn());

        // wait for the promise chain to settle
        await new Promise((resolve) => setImmediate(resolve));

        expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/json; charset=utf-8');
        expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'public, max-age=300');
        expect(res.status).toHaveBeenCalledWith(200);
        expect(res.json).toHaveBeenCalledWith(card);
    });

    it('should respond with 500 and INTERNAL_ERROR code when getCard throws an Error', async () => {
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
            buildCard: () => Promise.reject(new Error('build failed')),
            eventEmitter: emitter,
        });

        const handler = createAgentCardRoute(service);
        const req = {} as Request;
        const res = makeMockRes();

        handler(req, res, vi.fn());

        await new Promise((resolve) => setImmediate(resolve));

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ code: 'INTERNAL_ERROR', message: 'build failed' });
    });

    it('should respond with 500 and generic message when getCard throws a non-Error', async () => {
        const emitter = new EventEmitter();
        const service = new AgentCardService({
            agentDid: 'did:agent:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0' as DID,
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            buildCard: () => Promise.reject('string error'),
            eventEmitter: emitter,
        });

        const handler = createAgentCardRoute(service);
        const req = {} as Request;
        const res = makeMockRes();

        handler(req, res, vi.fn());

        await new Promise((resolve) => setImmediate(resolve));

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ code: 'INTERNAL_ERROR', message: 'Internal error' });
    });
});
