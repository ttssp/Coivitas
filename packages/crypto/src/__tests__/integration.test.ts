import { describe, expect, it } from 'vitest';

import {
    HashChain,
    canonicalize,
    generateKeyPair,
    hash,
    sign,
    verify,
} from '../index.js';

const textEncoder = new TextEncoder();

describe('crypto integration', () => {
    it('supports the end-to-end flow from key generation to hash chain verification', () => {
        const keyPair = generateKeyPair();
        const payload = {
            principal: 'did:example:alice',
            scopes: ['read', 'write'],
            version: 1,
        };
        const canonical = canonicalize(payload);
        const bytes = textEncoder.encode(canonical);
        const signature = sign(bytes, keyPair.privateKey);
        const digest = hash(bytes);
        const chain = new HashChain();

        const firstRecord = {
            id: '1',
            digest,
            payload: canonical,
            prevHash: null,
        };
        const firstHash = chain.append(firstRecord);
        const secondRecord = {
            id: '2',
            digest: hash(signature),
            payload: signature,
            prevHash: firstHash,
        };
        chain.append(secondRecord);

        expect(verify(bytes, signature, keyPair.publicKey)).toBe(true);
        expect(digest).toHaveLength(64);
        expect(chain.verify([firstRecord, secondRecord])).toEqual({
            valid: true,
            chainLength: 2,
        });
    });
});
