import { ed25519 } from '@noble/curves/ed25519';

import { toHex } from './encoding.js';
import type { KeyPair } from './types.js';

export function generateKeyPair(): KeyPair {
    const privateKeySeed = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKeySeed);
    const privateKey = new Uint8Array(privateKeySeed.length + publicKey.length);

    privateKey.set(privateKeySeed, 0);
    privateKey.set(publicKey, privateKeySeed.length);

    return {
        publicKey: toHex(publicKey),
        privateKey: toHex(privateKey),
    };
}
