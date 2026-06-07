import type { Application } from 'express';

import type { DID, Timestamp } from '@coivitas/types';

import { RevocationList } from './revocation.js';

export function registerRevocationRoutes(
    app: Application,
    revocations: RevocationList,
): void {
    app.post('/api/v1/revocations', async (request, response) => {
        const { tokenId, revokedBy, reason } = request.body as {
            reason?: string;
            revokedBy?: DID;
            tokenId?: string;
        };

        if (!tokenId || !revokedBy) {
            response.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'tokenId and revokedBy are required.',
                },
            });
            return;
        }

        const record = await revocations.revoke({ tokenId, revokedBy, reason });
        response.status(201).json({
            token_id: record.tokenId,
            revoked_by: record.revokedBy,
            revoked_at: record.revokedAt,
            reason: record.reason,
        });
    });

    app.get('/api/v1/revocations/:tokenId', async (request, response) => {
        const record = await revocations.getRevocation(request.params.tokenId);

        if (!record) {
            response.status(200).json({ revoked: false });
            return;
        }

        response.status(200).json({
            revoked: true,
            revoked_at: record.revokedAt,
            reason: record.reason ?? undefined,
        });
    });

    app.get('/api/v1/revocations', async (request, response) => {
        const since =
            typeof request.query.since === 'string'
                ? (request.query.since as Timestamp)
                : undefined;
        const records = await revocations.getRevocations(since);

        response.status(200).json({
            revocations: records.map((record) => ({
                token_id: record.tokenId,
                revoked_by: record.revokedBy,
                revoked_at: record.revokedAt,
                reason: record.reason,
            })),
        });
    });
}
