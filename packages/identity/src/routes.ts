import type { Application } from 'express';

import {
    ProtocolError,
    type AgentIdentityDocument,
    type DID,
} from '@coivitas/types';

import { createAgentDID } from './did.js';
import { verifyBindingProof } from './binding.js';
import { IdentityRegistry } from './registry.js';

// Federation broadcast configuration (optional). If omitted, register() performs no broadcast.
export interface FederationBroadcastOptions {
    // The list of federation nodes (id + url)
    nodes: Array<{ id: string; url: string }>;
    // An injectable fetch implementation (for easy replacement in unit tests)
    fetch?: typeof globalThis.fetch;
    // Broadcast timeout (milliseconds, default 5000)
    timeoutMs?: number;
}

export function registerIdentityRoutes(
    app: Application,
    registry: IdentityRegistry,
    federation?: FederationBroadcastOptions,
): void {
    // Closure-level variable: updated after each successful /federation/sync; isolated inside the function to avoid module-shared state polluting tests
    let lastSyncAt: string | null = null;

    app.post('/api/v1/identities', async (request, response) => {
        const document = request.body as AgentIdentityDocument;
        await registry.register(document);
        response.status(201).json({ did: document.id });

        // fire-and-forget: a broadcast failure does not block the response and does not surface errors to the caller
        // Note: the retry queue is deferred to a later release; for now failures are silent
        if (federation && federation.nodes.length > 0) {
            void broadcastToNodes(document, federation);
        }
    });

    app.get('/api/v1/identities/:did', async (request, response) => {
        const did = request.params.did as DID;
        const document = await registry.query(did);

        if (!document) {
            throw new ProtocolError(
                'IDENTITY_NOT_FOUND',
                `Identity ${did} was not found.`,
            );
        }

        response.status(200).json(document);
    });

    app.delete('/api/v1/identities/:did', async (request, response) => {
        await registry.deactivate(request.params.did as DID);
        response.status(204).end();
    });

    // 05a: POST /federation/sync — receive document updates pushed by other federation nodes, verify the signature, then store
    app.post('/federation/sync', async (request, response) => {
        const document = request.body as AgentIdentityDocument;

        // Basic structural check
        if (
            !document ||
            typeof document !== 'object' ||
            !document.id ||
            !document.publicKey
        ) {
            response.status(400).json({
                error: {
                    code: 'INVALID_DOCUMENT',
                    message: 'document.id and document.publicKey are required.',
                },
            });
            return;
        }

        // Signature verification: bindingProof must exist and be valid
        if (!document.bindingProof) {
            response.status(400).json({
                error: {
                    code: 'INVALID_DOCUMENT',
                    message: 'document.bindingProof is required.',
                },
            });
            return;
        }

        // Cross-node proof-reuse attack defense: agentDid must match document.id
        // Prevents a valid proof from being attached to a document with a different DID and passing verification
        if (document.bindingProof.agentDid !== document.id) {
            response.status(400).json({
                error: {
                    code: 'SIGNATURE_INVALID',
                    message:
                        'bindingProof.agentDid does not match document.id.',
                },
            });
            return;
        }

        // Self-certification check: at v=1 the DID must be derived from publicKey
        if (!document.version || document.version === 1) {
            const expectedDid = createAgentDID(document.publicKey);
            if (expectedDid !== document.id) {
                response.status(400).json({
                    error: {
                        code: 'SIGNATURE_INVALID',
                        message: 'DID does not match publicKey.',
                    },
                });
                return;
            }
        }

        // bindingProof signature check
        const bindingValid = verifyBindingProof(document.bindingProof);
        if (!bindingValid) {
            response.status(400).json({
                error: {
                    code: 'SIGNATURE_INVALID',
                    message: 'bindingProof signature is invalid.',
                },
            });
            return;
        }

        // Storage: idempotently handle IDENTITY_ALREADY_EXISTS (a remote node may push duplicates)
        // Use instanceof ProtocolError rather than a type assertion, to avoid silently swallowing other error objects that happen to have a code field
        try {
            await registry.register(document);
        } catch (e: unknown) {
            if (
                !(e instanceof ProtocolError) ||
                e.code !== 'IDENTITY_ALREADY_EXISTS'
            )
                throw e;
        }

        lastSyncAt = new Date().toISOString();
        response.status(200).json({ ok: true });
    });

    // 05c: GET /federation/health — return a federation-node status snapshot
    app.get('/federation/health', (_request, response) => {
        response.status(200).json({
            status: 'ok',
            version: process.env['npm_package_version'] ?? '0.0.0',
            knownNodes: federation?.nodes.length ?? 0,
            lastSyncAt,
        });
    });
}

// broadcastToNodes: fire-and-forget broadcast of an AgentIdentityDocument to federation nodes.
// Failures are silent: each node has its own try/catch and does not propagate to the caller.
// Returns a Promise (for tests to await; ignored in production).
export async function broadcastToNodes(
    document: AgentIdentityDocument,
    options: FederationBroadcastOptions,
): Promise<Array<{ nodeId: string; ok: boolean; error?: string }>> {
    const fetchFn = options.fetch ?? globalThis.fetch;
    const timeoutMs = options.timeoutMs ?? 5000;

    const results = await Promise.allSettled(
        options.nodes.map(async (node) => {
            try {
                const res = await fetchFn(`${node.url}/federation/sync`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(document),
                    signal: AbortSignal.timeout(timeoutMs),
                });
                return { nodeId: node.id, ok: res.ok };
            } catch (e: unknown) {
                const error = e instanceof Error ? e.message : String(e);
                return { nodeId: node.id, ok: false, error };
            }
        }),
    );

    return results.map((r) =>
        r.status === 'fulfilled'
            ? r.value
            : { nodeId: 'unknown', ok: false, error: String(r.reason) },
    );
}
