import { canonicalize, sign, verify } from '@coivitas/crypto';
import type { BindingProof, DID, Timestamp } from '@coivitas/types';

import {
    extractPublicKeyFromDIDKey,
    isDidAgent,
    isDidKey,
    isTimestampExpired,
} from './did.js';
import { IDENTITY_ENCODING } from './encoding-config.js';

export interface CreateBindingParams {
    principalDid: DID;
    agentDid: DID;
    principalPrivateKey: string;
    issuedAt?: Timestamp;
    expiresAt?: Timestamp | null;
}

/**
 * Build the BindingProof signing payload
 *
 * Conclusion: the signing payload does not include the specVersion field (consistent with the v0.1.0 baseline).
 * Previously introducing specVersion into the v0.2.0 preimage was a mistake: all existing documents are v0.1.0,
 * and hardcoding '0.2.0' into the payload would make every createBinding output unverifiable by the old verifyBinding.
 * The signature encoding switched from hex to base64url, but the set of fields covered by the signature is unchanged.
 */
function bindingPayload(
    proof: Pick<BindingProof, 'agentDid' | 'issuedAt' | 'principalDid'>,
): Uint8Array {
    return new TextEncoder().encode(
        canonicalize({
            agentDid: proof.agentDid,
            issuedAt: proof.issuedAt,
            principalDid: proof.principalDid,
        }),
    );
}

export function createBinding(params: CreateBindingParams): BindingProof {
    const issuedAt = (params.issuedAt ?? new Date().toISOString()) as Timestamp;
    const expiresAt = params.expiresAt ?? null;

    if (!isDidKey(params.principalDid)) {
        throw new Error(
            `Invalid principal DID: ${String(params.principalDid)}`,
        );
    }

    if (!isDidAgent(params.agentDid)) {
        throw new Error(`Invalid agent DID: ${String(params.agentDid)}`);
    }

    const proof: BindingProof = {
        principalDid: params.principalDid,
        agentDid: params.agentDid,
        issuedAt,
        expiresAt,
        signature: '' as BindingProof['signature'],
    };

    return {
        ...proof,
        signature: sign(
            bindingPayload(proof),
            params.principalPrivateKey,
            IDENTITY_ENCODING,
        ) as BindingProof['signature'],
    };
}

export function verifyBinding(
    proof: BindingProof,
    now: Timestamp = new Date().toISOString() as Timestamp,
): boolean {
    try {
        if (!isDidKey(proof.principalDid) || !isDidAgent(proof.agentDid)) {
            return false;
        }

        if (
            proof.expiresAt !== null &&
            isTimestampExpired(proof.expiresAt, now)
        ) {
            return false;
        }

        const publicKey = extractPublicKeyFromDIDKey(proof.principalDid);

        // Dual-encoding compatibility:
        // crypto.verify() internally uses detectEncoding to auto-detect the signature encoding (hex / base64url);
        // both signature formats use the same preimage (no specVersion), so no payload switching by encoding is needed.
        return verify(bindingPayload(proof), proof.signature, publicKey);
    } catch {
        return false;
    }
}

export const createBindingProof = createBinding;
export const verifyBindingProof = verifyBinding;
