import { sha256 } from '@noble/hashes/sha256';

import { toBase64Url, toHex } from './encoding.js';

const textEncoder = new TextEncoder();

// Defaults to hex output, consistent with wire-format-freeze; base64url is optional for compact scenarios
export function hash(data: Uint8Array | string, encoding: 'hex' | 'base64url' = 'hex'): string {
    const bytes = typeof data === 'string' ? textEncoder.encode(data) : data;
    const digest = sha256(bytes);

    return encoding === 'base64url' ? toBase64Url(digest) : toHex(digest);
}
