import type { NextFunction, Request, Response } from 'express';

import { ProtocolError } from '@coivitas/types';

const protocolErrorStatusMap: Record<string, number> = {
    IDENTITY_NOT_FOUND: 404,
    IDENTITY_ALREADY_EXISTS: 409,
    SIGNATURE_INVALID: 401,
    TOKEN_EXPIRED: 401,
    TOKEN_REVOKED: 401,
    SCOPE_EXCEEDED: 403,
    BINDING_PROOF_INVALID: 401,
    HANDSHAKE_FAILED: 400,
    ACTION_REJECTED: 403,
    HUMAN_APPROVAL_REQUIRED: 403,
    INTERNAL_ERROR: 500,
    RATE_LIMIT_EXCEEDED: 429,
};

export function errorHandler(
    error: unknown,
    _request: Request,
    response: Response,
    _next: NextFunction,
): void {
    void _next;

    if (error instanceof ProtocolError) {
        response.status(protocolErrorStatusMap[error.code] ?? 500).json({
            error: {
                code: error.code,
                message: error.detail,
            },
        });
        return;
    }

    response.status(500).json({
        error: {
            code: 'INTERNAL_ERROR',
            message: 'Internal server error',
        },
    });
}
