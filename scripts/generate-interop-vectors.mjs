import { readFile } from 'node:fs/promises';

const sourcePath = new URL(
    '../tests/fixtures/conformance/identity/crypto-signing.json',
    import.meta.url,
);

const fixture = JSON.parse(await readFile(sourcePath, 'utf8'));

const vectors = [
    ...fixture.valid.map((sample) => ({
        id: sample.id,
        message_hex: sample.messageHex,
        public_key_hex: sample.publicKey,
        signature_hex: sample.signature,
        expected: 'valid',
    })),
    ...fixture.invalid.map((sample) => ({
        id: sample.id,
        message_hex: sample.messageHex,
        public_key_hex: sample.publicKey,
        signature_hex: sample.signature,
        expected: 'invalid',
    })),
];

console.log(
    JSON.stringify(
        {
            generated_from:
                'tests/fixtures/conformance/identity/crypto-signing.json',
            generated_at: '2026-04-03',
            vectors,
        },
        null,
        4,
    ),
);
