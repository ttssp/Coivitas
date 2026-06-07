import { ed25519 } from '@noble/curves/ed25519';

import {
    canonicalize,
    hash,
    sign,
    toHex,
    verify,
} from '@coivitas/crypto';
import type { DID, Signature, Timestamp } from '@coivitas/types';

import type { PersistedActionRecord } from '../types.js';

const textEncoder = new TextEncoder();

export function normalizeSigningPrivateKey(privateKey: string): string {
    if (privateKey.length === 64) {
        const privateKeySeed = Uint8Array.from(Buffer.from(privateKey, 'hex'));
        const publicKey = ed25519.getPublicKey(privateKeySeed);
        const expanded = new Uint8Array(
            privateKeySeed.length + publicKey.length,
        );
        expanded.set(privateKeySeed, 0);
        expanded.set(publicKey, privateKeySeed.length);
        return toHex(expanded);
    }

    return privateKey;
}

export function derivePublicKeyFromPrivateKey(privateKey: string): string {
    const normalized = normalizeSigningPrivateKey(privateKey);
    return normalized.slice(64);
}

export function buildUnsignedRecordPayload(params: {
    recordId: string;
    agentDid: DID;
    principalDid: DID;
    actionType: string;
    parametersSummary: Record<string, unknown> | null;
    authorizationRef: Record<string, unknown> | null;
    resultSummary: Record<string, unknown> | null;
    previousRecordHash: string;
    createdAt: Timestamp;
    delegationDepth?: number;
    sessionId?: string;
}): Record<string, unknown> {
    const payload: Record<string, unknown> = {
        recordId: params.recordId,
        agentDid: params.agentDid,
        principalDid: params.principalDid,
        actionType: params.actionType,
        parametersSummary: params.parametersSummary,
        authorizationRef: params.authorizationRef,
        resultSummary: params.resultSummary,
        previousRecordHash: params.previousRecordHash,
        createdAt: params.createdAt,
    };
    if (params.delegationDepth !== undefined) {
        payload['delegationDepth'] = params.delegationDepth;
    }
    if (params.sessionId !== undefined) {
        payload['sessionId'] = params.sessionId;
    }
    return payload;
}

export function computeRecordHash(
    payload: Record<string, unknown>,
    previousRecordHash: string,
    outputEncoding: 'hex' | 'base64url' = 'hex',
): string {
    const canonical = canonicalize(payload);
    const recordBytes = textEncoder.encode(canonical);
    const previousBytes = textEncoder.encode(previousRecordHash);
    const bytes = new Uint8Array(previousBytes.length + recordBytes.length);
    bytes.set(previousBytes, 0);
    bytes.set(recordBytes, previousBytes.length);
    return hash(bytes, outputEncoding);
}

export function createRecordSignature(
    payload: Record<string, unknown>,
    privateKey: string,
    outputEncoding: 'hex' | 'base64url' = 'hex',
): Signature {
    return sign(
        textEncoder.encode(canonicalize(payload)),
        normalizeSigningPrivateKey(privateKey),
        outputEncoding,
    ) as Signature;
}

export function verifyRecordSignature(
    payload: Record<string, unknown>,
    signature: string,
    publicKey: string,
): boolean {
    return verify(
        textEncoder.encode(canonicalize(payload)),
        signature,
        publicKey,
    );
}

export function toPersistedRecord(params: {
    recordId: string;
    agentDid: DID;
    principalDid: DID;
    actionType: string;
    parametersSummary: Record<string, unknown> | null;
    authorizationRef: Record<string, unknown> | null;
    resultSummary: Record<string, unknown> | null;
    previousRecordHash: string;
    recordHash: string;
    actorSignature: Signature;
    ledgerSignature: Signature;
    delegationDepth?: number;
    sessionId?: string;
    createdAt: Timestamp;
}): PersistedActionRecord {
    return {
        recordId: params.recordId,
        agentDid: params.agentDid,
        principalDid: params.principalDid,
        actionType: params.actionType,
        parametersSummary: params.parametersSummary,
        authorizationRef: params.authorizationRef,
        resultSummary: params.resultSummary,
        previousRecordHash: params.previousRecordHash,
        recordHash: params.recordHash,
        actorSignature: params.actorSignature,
        ledgerSignature: params.ledgerSignature,
        delegationDepth: params.delegationDepth,
        sessionId: params.sessionId,
        createdAt: params.createdAt,
    };
}
