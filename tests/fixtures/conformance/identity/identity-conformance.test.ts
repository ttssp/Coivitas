import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
    fromHex,
    sign,
    verify,
} from '../../../../packages/crypto/src/index.js';
import {
    didKeyFromPublicKey,
    extractPublicKeyFromDIDKey,
    verifyBinding,
} from '../../../../packages/identity/src/index.js';
import { validateAgainstSchema } from '../../../../packages/types/src/index.js';

interface FixtureCase<T> {
    id: string;
    data: T;
    valid?: boolean;
    publicKey?: string;
    principalPublicKey?: string;
    privateKey?: string;
    messageHex?: string;
    signature?: string;
    didKey?: string;
}

interface FixtureFile<T> {
    valid: FixtureCase<T>[];
    invalid: FixtureCase<T>[];
    boundary?: FixtureCase<T>[];
}

const fixturesDir = path.dirname(fileURLToPath(import.meta.url));

describe('identity conformance fixtures', () => {
    it('validates agent identity document fixtures', async () => {
        const fixtures = await loadFixture<unknown>(
            'agent-identity-document.json',
        );

        for (const sample of fixtures.valid) {
            expect(
                validateAgainstSchema(sample.data, 'agentIdentityDocument'),
            ).toEqual({
                valid: true,
                errors: [],
            });
        }

        for (const sample of fixtures.invalid) {
            expect(
                validateAgainstSchema(sample.data, 'agentIdentityDocument')
                    .valid,
            ).toBe(false);
        }

        for (const sample of fixtures.boundary ?? []) {
            expect(
                validateAgainstSchema(sample.data, 'agentIdentityDocument')
                    .valid,
            ).toBe(sample.valid ?? true);
        }
    });

    it('validates binding proof fixtures at schema and signature levels', async () => {
        const fixtures = await loadFixture<unknown>('binding-proof.json');

        for (const sample of fixtures.valid) {
            expect(
                validateAgainstSchema(sample.data, 'bindingProof').valid,
            ).toBe(true);
            expect(verifyBinding(sample.data as never)).toBe(true);
        }

        for (const sample of fixtures.invalid) {
            const schemaValid = validateAgainstSchema(
                sample.data,
                'bindingProof',
            ).valid;
            expect(schemaValid && verifyBinding(sample.data as never)).toBe(
                false,
            );
        }

        for (const sample of fixtures.boundary ?? []) {
            expect(
                validateAgainstSchema(sample.data, 'bindingProof').valid,
            ).toBe(true);
            expect(
                verifyBinding(
                    sample.data as never,
                    '2026-04-03T08:00:00.000Z' as never,
                ),
            ).toBe(sample.valid ?? true);
        }
    });

    it('validates did:key round-trip fixtures', async () => {
        const fixtures = await loadFixture<unknown>('did-key.json');

        for (const sample of fixtures.valid) {
            expect(didKeyFromPublicKey(fromHex(sample.publicKey!))).toBe(
                sample.didKey,
            );
            expect(extractPublicKeyFromDIDKey(sample.didKey as never)).toBe(
                sample.publicKey,
            );
        }

        for (const sample of fixtures.invalid) {
            expect(() =>
                extractPublicKeyFromDIDKey(sample.didKey as never),
            ).toThrow();
        }
    });

    it('validates signing vectors used by identity proofs', async () => {
        const fixtures = await loadFixture<unknown>('crypto-signing.json');

        for (const sample of fixtures.valid) {
            const message = fromHex(sample.messageHex ?? '');
            expect(sign(message, sample.privateKey!)).toBe(sample.signature);
            expect(verify(message, sample.signature!, sample.publicKey!)).toBe(
                true,
            );
        }

        for (const sample of fixtures.invalid) {
            const message = fromHex(sample.messageHex ?? '');
            expect(verify(message, sample.signature!, sample.publicKey!)).toBe(
                false,
            );
        }
    });
});

async function loadFixture<T>(filename: string): Promise<FixtureFile<T>> {
    const content = await readFile(path.join(fixturesDir, filename), 'utf8');
    return JSON.parse(content) as FixtureFile<T>;
}
