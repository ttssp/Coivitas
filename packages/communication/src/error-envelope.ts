import type { DID, NegotiationEnvelope } from '@coivitas/types';

import { buildEnvelope } from './envelope.js';

export const STANDARD_ERROR_CODES = [
    'AUTHORIZATION_INSUFFICIENT',
    'IDENTITY_VERIFICATION_FAILED',
    'SESSION_NOT_FOUND',
    'INVALID_ENVELOPE',
    'INTERNAL_ERROR',
] as const;

export type StandardErrorCode = (typeof STANDARD_ERROR_CODES)[number];

export interface ErrorEnvelopeBody extends Record<string, unknown> {
    code: StandardErrorCode;
    message: string;
    relatedEnvelopeId?: string;
}

export interface BuildErrorEnvelopeParams {
    senderDid: DID;
    senderPrivateKey: string;
    recipientDid: DID;
    sessionId: string | null;
    code: StandardErrorCode;
    message?: string;
    relatedEnvelopeId?: string;
    sequenceNumber?: number;
}

const defaultMessages: Record<StandardErrorCode, string> = {
    AUTHORIZATION_INSUFFICIENT:
        'Authorization insufficient for the requested action.',
    IDENTITY_VERIFICATION_FAILED: 'Identity verification failed.',
    SESSION_NOT_FOUND: 'The requested session was not found.',
    INVALID_ENVELOPE: 'The received envelope is invalid.',
    INTERNAL_ERROR: 'Internal server error.',
};

export function buildErrorEnvelope(
    params: BuildErrorEnvelopeParams,
): NegotiationEnvelope {
    const body: ErrorEnvelopeBody = {
        code: params.code,
        message: params.message ?? defaultMessages[params.code],
        ...(params.relatedEnvelopeId
            ? { relatedEnvelopeId: params.relatedEnvelopeId }
            : {}),
    };
    const bodyRecord: Record<string, unknown> = {
        code: body.code,
        message: body.message,
        ...(body.relatedEnvelopeId
            ? { relatedEnvelopeId: body.relatedEnvelopeId }
            : {}),
    };

    return buildEnvelope({
        senderDid: params.senderDid,
        senderPrivateKey: params.senderPrivateKey,
        recipientDid: params.recipientDid,
        sessionId: params.sessionId,
        messageType: 'ERROR',
        body: bodyRecord,
        sequenceNumber: params.sequenceNumber,
    });
}

export function buildAuthorizationInsufficientEnvelope(
    params: Omit<BuildErrorEnvelopeParams, 'code'>,
): NegotiationEnvelope {
    return buildErrorEnvelope({
        ...params,
        code: 'AUTHORIZATION_INSUFFICIENT',
    });
}

export function buildIdentityVerificationFailedEnvelope(
    params: Omit<BuildErrorEnvelopeParams, 'code'>,
): NegotiationEnvelope {
    return buildErrorEnvelope({
        ...params,
        code: 'IDENTITY_VERIFICATION_FAILED',
    });
}

export function buildSessionNotFoundEnvelope(
    params: Omit<BuildErrorEnvelopeParams, 'code'>,
): NegotiationEnvelope {
    return buildErrorEnvelope({
        ...params,
        code: 'SESSION_NOT_FOUND',
    });
}

export function buildInvalidEnvelopeEnvelope(
    params: Omit<BuildErrorEnvelopeParams, 'code'>,
): NegotiationEnvelope {
    return buildErrorEnvelope({
        ...params,
        code: 'INVALID_ENVELOPE',
    });
}

export function buildInternalErrorEnvelope(
    params: Omit<BuildErrorEnvelopeParams, 'code'>,
): NegotiationEnvelope {
    return buildErrorEnvelope({
        ...params,
        code: 'INTERNAL_ERROR',
    });
}
