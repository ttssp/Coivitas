import { detectEncoding, fromBase64Url, fromHex, hash, toHex } from '@coivitas/crypto';
import type { DID, Timestamp } from '@coivitas/types';

import { decodeDidKeyPayload, publicKeyToDidKey } from './did-key.js';

const DID_AGENT_PATTERN = /^did:agent:[a-f0-9]{40}$/;
const DID_KEY_PATTERN = /^did:key:[1-9A-HJ-NP-Za-km-z]+$/;

export function isDidAgent(did: string): did is DID {
    return DID_AGENT_PATTERN.test(did);
}

export function isDidKey(did: string): did is DID {
    return DID_KEY_PATTERN.test(did);
}

export function createAgentDID(publicKeyInput: string): DID {
    // The identity schema's publicKey supports both hex (64 chars) and base64url (43 chars);
    // createAgentDID originally only accepted hex, so base64url input would make fromHex() throw.
    // Fix: route to the correct decode function via detectEncoding.
    const bytes =
        detectEncoding(publicKeyInput) === 'hex'
            ? fromHex(publicKeyInput)
            : fromBase64Url(publicKeyInput);
    const digest = hash(bytes);
    return `did:agent:${digest.slice(0, 40)}` as DID;
}

export function extractPublicKeyFromDIDKey(didKey: DID): string {
    if (!isDidKey(didKey)) {
        throw new Error(`Invalid did:key DID: ${String(didKey)}`);
    }

    return toHex(decodeDidKeyPayload(didKey.slice('did:key:'.length)));
}

export function didKeyFromPublicKey(publicKeyBytes: Uint8Array): DID {
    return publicKeyToDidKey(publicKeyBytes) as DID;
}

export function isTimestampExpired(
    expiresAt: Timestamp,
    now: Timestamp,
): boolean {
    return new Date(expiresAt).getTime() <= new Date(now).getTime();
}
