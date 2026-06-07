import type { RequestHandler } from 'express';
import type { AgentCardService } from './agent-card-service.js';

export function createAgentCardRoute(service: AgentCardService): RequestHandler {
    return (_req, res) => {
        service
            .getCard()
            .then((card) => {
                res.setHeader('Content-Type', 'application/json; charset=utf-8');
                res.setHeader('Cache-Control', 'public, max-age=300');
                res.status(200).json(card);
            })
            .catch((error: unknown) => {
                const message = error instanceof Error ? error.message : 'Internal error';
                res.status(500).json({ code: 'INTERNAL_ERROR', message });
            });
    };
}
