#!/usr/bin/env tsx
/**
 * generate-cross-lang-fixtures.ts —
 *
 * TS-locked golden bytes fixture generator for cross-lang true anchor pipeline.
 *
 * Usage:
 *   pnpm cross-lang:ts-fixtures:regenerate → --regenerate mode: write out the 3 fixture files
 *   pnpm cross-lang:ts-fixtures:check → --check mode: compare existing fixtures against a regeneration; diff → exit 1
 *
 * Constraints:
 *   - fail-closed: in --check mode, exit 1 + emit the diff to stderr when the diff is non-empty
 *   - determinism: identical input → byte-equal output (no dependency on timestamps / Math.random)
 *   - type boundary: base64 / bytes / Buffer boundary-crossing points are annotated
 *   - public-key guard: for every entry.public_key_hex that is non-empty, generateSignatureVectors
 *     empirically derives via ed25519.getPublicKey(seed) and compares; on mismatch → fail-closed exit 1
 *
 * Authoritative sources:
 *   - packages/crypto/src/canonicalization.ts (RFC 8785 canonicalize)
 *   - packages/crypto/src/signing.ts (Ed25519 sign/verify)
 *   - packages/crypto/src/encoding.ts (base64url / hex)
 *   - packages/crypto/src/hashing.ts (sha256)
 *   - tests/fixtures/conformance/negotiation-envelope.json (envelope samples)
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '@coivitas/crypto';
import { fromHex, toBase64Url } from '@coivitas/crypto';
import { sign } from '@coivitas/crypto';
import { ed25519 } from '@noble/curves/ed25519';

// ─── Path constants ─────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, '..', '..', '..');

const INPUT_DIR = resolve(__dirname, 'cross-lang-input-vectors');
const FIXTURE_OUT_DIR = resolve(REPO_ROOT, 'tests', 'fixtures', 'cross-lang');
const CONFORMANCE_DIR = resolve(REPO_ROOT, 'tests', 'fixtures', 'conformance');

const CANONICALIZE_INPUTS_PATH = resolve(INPUT_DIR, 'canonicalize-inputs.json');
const SIGNATURE_INPUTS_PATH = resolve(INPUT_DIR, 'signature-inputs.json');
const NEGOTIATION_ENVELOPE_PATH = resolve(
    CONFORMANCE_DIR,
    'negotiation-envelope.json',
);

const OUT_CANONICALIZE = resolve(FIXTURE_OUT_DIR, 'canonicalize-vectors.json');
const OUT_SIGNATURE = resolve(FIXTURE_OUT_DIR, 'signature-vectors.json');
const OUT_ENVELOPE = resolve(FIXTURE_OUT_DIR, 'envelope-wire-vectors.json');

// ─── Helper: SHA-256 hex ────────────────────────────────────────────────────────

function sha256Hex(data: string | Uint8Array): string {
    // type boundary: string → UTF-8 bytes → sha256 hex output
    const buf =
        typeof data === 'string'
            ? Buffer.from(data, 'utf-8')
            : Buffer.from(data);
    return createHash('sha256').update(buf).digest('hex');
}

// ─── Step 1: canonicalize-vectors.json ───────────────────────────────────────

// ─── Input schema validation helpers ────────────────────────────────────

function assertFieldIsString(
    obj: Record<string, unknown>,
    field: string,
    entryId: string,
    filePath: string,
): void {
    if (typeof obj[field] !== 'string') {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${filePath}:\n` +
                `  entry id=${JSON.stringify(entryId)}: field "${field}" must be a string,` +
                ` got ${typeof obj[field]}\n` +
                `  Fix the input JSON file and retry.\n`,
        );
        process.exit(1);
    }
}

function validateCanonicalizeInputEntry(
    entry: unknown,
    index: number,
    filePath: string,
): void {
    if (typeof entry !== 'object' || entry === null) {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${filePath}:\n` +
                `  vectors[${index}] must be an object, got ${typeof entry}\n`,
        );
        process.exit(1);
    }
    const e = entry as Record<string, unknown>;
    assertFieldIsString(e, 'id', String(index), filePath);
    assertFieldIsString(e, 'description', String(e['id']), filePath);
}

function validateSignatureInputEntry(
    entry: unknown,
    index: number,
    filePath: string,
): void {
    if (typeof entry !== 'object' || entry === null) {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${filePath}:\n` +
                `  vectors[${index}] must be an object, got ${typeof entry}\n`,
        );
        process.exit(1);
    }
    const e = entry as Record<string, unknown>;
    assertFieldIsString(e, 'id', String(index), filePath);
    assertFieldIsString(e, 'description', String(e['id']), filePath);
    assertFieldIsString(e, 'private_key_hex', String(e['id']), filePath);
    assertFieldIsString(e, 'public_key_hex', String(e['id']), filePath);
    assertFieldIsString(e, 'message_hex', String(e['id']), filePath);
    // private_key_hex must be a 64-char hex string (32 bytes)
    const privHex = e['private_key_hex'] as string;
    if (privHex.length !== 64) {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${filePath}:\n` +
                `  entry id=${JSON.stringify(e['id'])}: private_key_hex must be 64 hex chars (32 bytes),` +
                ` got length=${privHex.length}\n` +
                `  Fix the input JSON file and retry.\n`,
        );
        process.exit(1);
    }
    if (!/^[0-9a-f]+$/i.test(privHex)) {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${filePath}:\n` +
                `  entry id=${JSON.stringify(e['id'])}: private_key_hex is not valid hex\n` +
                `  Fix the input JSON file and retry.\n`,
        );
        process.exit(1);
    }
}

// ─── Step 1: canonicalize-vectors.json ───────────────────────────────────────

interface CanonicalizeInputEntry {
    id: string;
    description: string;
    input?: Record<string, unknown>;
}

interface CanonicalizeVectorOutput {
    id: string;
    description: string;
    input: Record<string, unknown>;
    expected_output: string;
    expected_sha256: string;
}

function generateCanonicalizeVectors(): object {
    const rawParsed: unknown = JSON.parse(
        readFileSync(CANONICALIZE_INPUTS_PATH, 'utf-8'),
    );
    if (
        typeof rawParsed !== 'object' ||
        rawParsed === null ||
        !Array.isArray((rawParsed as Record<string, unknown>)['vectors'])
    ) {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${CANONICALIZE_INPUTS_PATH}:\n` +
                `  top-level must be an object with a "vectors" array\n`,
        );
        process.exit(1);
    }
    const raw = rawParsed as { description: string; vectors: unknown[] };
    // validate each entry before use
    raw.vectors.forEach((entry, i) =>
        validateCanonicalizeInputEntry(entry, i, CANONICALIZE_INPUTS_PATH),
    );

    const vectors: CanonicalizeVectorOutput[] = (
        raw.vectors as CanonicalizeInputEntry[]
    ).map((entry) => {
        const inputObj = entry.input ?? {};
        const output = canonicalize(inputObj);
        return {
            id: entry.id,
            description: entry.description,
            input: inputObj,
            expected_output: output,
            expected_sha256: sha256Hex(output),
        };
    });

    return {
        version: 'v0.1',
        generated_by: 'packages/sdk/scripts/generate-cross-lang-fixtures.ts',
        ts_canonicalize_lib: 'canonicalize@2.1.0',
        vectors,
    };
}

// ─── Step 2: signature-vectors.json ──────────────────────────────────────────

interface SignatureInputEntry {
    id: string;
    description: string;
    private_key_hex: string;
    public_key_hex: string;
    message_hex: string;
}

interface SignatureVectorOutput {
    id: string;
    description: string;
    private_key_hex: string;
    public_key_hex: string;
    message_hex: string;
    expected_signature_hex: string;
    expected_signature_base64url: string;
}

function derivePublicKey(privateKeyHex: string): string {
    // type boundary: hex string → Uint8Array → Ed25519 public key → hex string
    const seed = fromHex(privateKeyHex).subarray(0, 32);
    const pubKeyBytes = ed25519.getPublicKey(seed);
    // type boundary: Uint8Array → hex string
    return Array.from(pubKeyBytes, (b) => b.toString(16).padStart(2, '0')).join(
        '',
    );
}

function generateSignatureVectors(): object {
    const rawParsed: unknown = JSON.parse(
        readFileSync(SIGNATURE_INPUTS_PATH, 'utf-8'),
    );
    if (
        typeof rawParsed !== 'object' ||
        rawParsed === null ||
        !Array.isArray((rawParsed as Record<string, unknown>)['vectors'])
    ) {
        process.stderr.write(
            `[fixture-generator] SCHEMA ERROR in ${SIGNATURE_INPUTS_PATH}:\n` +
                `  top-level must be an object with a "vectors" array\n`,
        );
        process.exit(1);
    }
    const raw = rawParsed as { description: string; vectors: unknown[] };
    // validate each entry before use
    raw.vectors.forEach((entry, i) =>
        validateSignatureInputEntry(entry, i, SIGNATURE_INPUTS_PATH),
    );

    const vectors: SignatureVectorOutput[] = (
        raw.vectors as SignatureInputEntry[]
    ).map((entry) => {
        // type boundary: hex → Uint8Array (message bytes)
        const messageBytes =
            entry.message_hex.length > 0
                ? fromHex(entry.message_hex)
                : new Uint8Array(0);

        // deterministic signature (Ed25519 is deterministic)
        const sigHex = sign(messageBytes, entry.private_key_hex, 'hex');

        // type boundary: hex → Uint8Array → base64url (signature encoding conversion)
        const sigBytes = fromHex(sigHex);
        const sigBase64url = toBase64Url(sigBytes);

        // Empirically derive public_key — regardless of whether input provides it, derive via noble and compare against input
        // (fail-closed: on mismatch → exit 1 + emit the empirical value to stderr)
        const derivedPubKeyHex = derivePublicKey(entry.private_key_hex);

        if (entry.public_key_hex.length > 0) {
            // compare the input-provided public_key_hex against noble's empirically derived value
            if (entry.public_key_hex !== derivedPubKeyHex) {
                process.stderr.write(
                    `[fixture-generator] PUBKEY MISMATCH for entry id=${JSON.stringify(entry.id)}:\n` +
                        `  input JSON public_key_hex = ${entry.public_key_hex}\n` +
                        `  noble-derived pubkey     = ${derivedPubKeyHex}\n` +
                        `  (seed: ${entry.private_key_hex})\n` +
                        `  Fix signature-inputs.json to use noble-derived value, then retry.\n`,
                );
                process.exit(1);
            }
        }

        // public_key: use noble's empirically derived value (consistency with input already verified)
        const pubKeyHex = derivedPubKeyHex;

        return {
            id: entry.id,
            description: entry.description,
            private_key_hex: entry.private_key_hex,
            public_key_hex: pubKeyHex,
            message_hex: entry.message_hex,
            expected_signature_hex: sigHex,
            expected_signature_base64url: sigBase64url,
        };
    });

    return {
        version: 'v0.1',
        generated_by: 'packages/sdk/scripts/generate-cross-lang-fixtures.ts',
        vectors,
    };
}

// ─── Step 3: envelope-wire-vectors.json ──────────────────────────────────────

interface EnvelopeConformanceSample {
    id: string;
    description: string;
    data: Record<string, unknown>;
}

interface EnvelopeWireVectorOutput {
    id: string;
    description: string;
    input: Record<string, unknown>;
    expected_wire_bytes_base64: string;
    expected_sha256: string;
}

// Hand-written boundary envelope vectors (5 entries)
const BOUNDARY_ENVELOPES: Array<{
    id: string;
    description: string;
    data: Record<string, unknown>;
}> = [
    {
        id: 'boundary-empty-body',
        description: 'envelope with an empty body',
        data: {
            id: 'aaaaaaaa-0000-0000-0000-000000000001',
            specVersion: '0.4.0',
            header: {
                senderDid: 'did:agent:aabbccdd',
                recipientDid: 'did:agent:eeff0011',
                sessionId: null,
                sequenceNumber: 0,
            },
            messageType: 'HANDSHAKE_INIT',
            body: {},
            signature:
                'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
            timestamp: '2026-01-01T00:00:00.000Z',
        },
    },
    {
        id: 'boundary-spec-v040',
        description: 'specVersion 0.4.0 envelope',
        data: {
            id: 'bbbbbbbb-0000-0000-0000-000000000002',
            specVersion: '0.4.0',
            header: {
                senderDid: 'did:agent:a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
                recipientDid:
                    'did:agent:b4e2c3d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1',
                sessionId: 'sess-cccccccc-0000-0000-0000-000000000003',
                sequenceNumber: 5,
            },
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                action: 'INQUIRY',
                params: { sku: 'SKU-001', quantity: 10 },
                requestId: 'req-boundary-001',
            },
            signature:
                'ccccddddeeee00001111222233334444555566667777888899990000aaaabbbbccccddddeeee00001111222233334444555566667777888899990000aaaabbbbcc',
            timestamp: '2026-05-12T00:00:00.000Z',
        },
    },
    {
        id: 'boundary-unicode-body',
        description: 'body containing Unicode characters',
        data: {
            id: 'cccccccc-0000-0000-0000-000000000003',
            specVersion: '0.4.0',
            header: {
                senderDid: 'did:agent:a1b2c3d4',
                recipientDid: 'did:agent:e5f6a7b8',
                sessionId: null,
                sequenceNumber: 0,
            },
            messageType: 'NEGOTIATION_REQUEST',
            body: {
                description: '中文描述 + emoji 🚀',
                tags: ['标签一', '标签二'],
            },
            signature:
                'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
            timestamp: '2026-05-12T01:00:00.000Z',
        },
    },
    {
        id: 'boundary-null-session',
        description: 'sessionId=null boundary — handshake initiation',
        data: {
            id: 'dddddddd-0000-0000-0000-000000000004',
            specVersion: '0.1.0',
            header: {
                senderDid: 'did:agent:11223344',
                recipientDid: 'did:agent:55667788',
                sessionId: null,
                sequenceNumber: 0,
            },
            messageType: 'HANDSHAKE_INIT',
            body: {
                nonce: 'ffffffffffffffffffffffffffffffff',
                capabilities: ['INQUIRY'],
                initiatorDid: 'did:agent:11223344',
            },
            signature:
                'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
            timestamp: '2026-05-12T02:00:00.000Z',
        },
    },
    {
        id: 'boundary-large-sequence-number',
        description: 'sequenceNumber large integer (within JS safe range)',
        data: {
            id: 'eeeeeeee-0000-0000-0000-000000000005',
            specVersion: '0.2.0',
            header: {
                senderDid: 'did:agent:aabbccdd',
                recipientDid: 'did:agent:00112233',
                sessionId: 'sess-ffffffff-0000-0000-0000-000000000006',
                sequenceNumber: 9007199254740991,
            },
            messageType: 'ERROR',
            body: {
                code: 'SCOPE_EXCEEDED',
                detail: 'Sequence number overflow boundary test.',
                requestId: 'req-boundary-max',
            },
            signature:
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            timestamp: '2026-05-12T03:00:00.000Z',
        },
    },
];

function generateEnvelopeWireVectors(): object {
    // Load the valid samples from the conformance fixture
    const conformanceRaw = JSON.parse(
        readFileSync(NEGOTIATION_ENVELOPE_PATH, 'utf-8'),
    ) as { valid: EnvelopeConformanceSample[] };

    const conformanceSamples = conformanceRaw.valid;

    // Merge: conformance valid samples + 5 boundary envelopes
    const allInputs: Array<{
        id: string;
        description: string;
        data: Record<string, unknown>;
    }> = [
        ...conformanceSamples.map((s) => ({
            id: `conformance-${s.id}`,
            description: `conformance fixture: ${s.description}`,
            data: s.data,
        })),
        ...BOUNDARY_ENVELOPES,
    ];

    const vectors: EnvelopeWireVectorOutput[] = allInputs.map((entry) => {
        // wire format = RFC 8785 canonicalize(envelope) → UTF-8 bytes
        const wireStr = canonicalize(entry.data);
        // type boundary: string → UTF-8 bytes → base64 encode (wire bytes passed cross-language)
        const wireBytes = Buffer.from(wireStr, 'utf-8');
        const wireBytesBase64 = wireBytes.toString('base64');
        const sha256 = createHash('sha256').update(wireBytes).digest('hex');

        return {
            id: entry.id,
            description: entry.description,
            input: entry.data,
            expected_wire_bytes_base64: wireBytesBase64,
            expected_sha256: sha256,
        };
    });

    return {
        version: 'v0.1',
        generated_by: 'packages/sdk/scripts/generate-cross-lang-fixtures.ts',
        vectors,
    };
}

// ─── Serialize fixture (deterministic: sorted keys + 4-space indent) ───────────────────────

function serializeFixture(data: object): string {
    // determinism: JSON.stringify does not guarantee key order, so use a replacer to preserve object key insertion order
    // (JS objects guarantee insertion order for string keys; the generator structure is a literal with fixed order)
    return JSON.stringify(data, null, 4);
}

// ─── --regenerate mode ────────────────────────────────────────────────────────

function runRegenerate(): void {
    mkdirSync(FIXTURE_OUT_DIR, { recursive: true });

    const canonicalizeData = generateCanonicalizeVectors();
    const signatureData = generateSignatureVectors();
    const envelopeData = generateEnvelopeWireVectors();

    writeFileSync(
        OUT_CANONICALIZE,
        serializeFixture(canonicalizeData) + '\n',
        'utf-8',
    );
    writeFileSync(
        OUT_SIGNATURE,
        serializeFixture(signatureData) + '\n',
        'utf-8',
    );
    writeFileSync(OUT_ENVELOPE, serializeFixture(envelopeData) + '\n', 'utf-8');

    process.stdout.write(
        `[fixtures:regenerate] wrote 3 fixture files:\n` +
            `  ${OUT_CANONICALIZE}\n` +
            `  ${OUT_SIGNATURE}\n` +
            `  ${OUT_ENVELOPE}\n`,
    );
}

// ─── --check mode (fail-closed) ──────────────────────────────────────────

function runCheck(): void {
    // Generate the expected content (without writing to disk)
    const expected: Record<string, string> = {
        [OUT_CANONICALIZE]:
            serializeFixture(generateCanonicalizeVectors()) + '\n',
        [OUT_SIGNATURE]: serializeFixture(generateSignatureVectors()) + '\n',
        [OUT_ENVELOPE]: serializeFixture(generateEnvelopeWireVectors()) + '\n',
    };

    let hasDiff = false;
    const diffs: string[] = [];

    for (const [outPath, expectedContent] of Object.entries(expected)) {
        if (!existsSync(outPath)) {
            diffs.push(
                `MISSING: ${outPath} — run 'pnpm cross-lang:ts-fixtures:regenerate'`,
            );
            hasDiff = true;
            continue;
        }

        const actual = readFileSync(outPath, 'utf-8');
        if (actual !== expectedContent) {
            // line-level diff summary (fail-closed: emit the diff to stderr)
            const actualLines = actual.split('\n');
            const expectedLines = expectedContent.split('\n');
            const maxLen = Math.max(actualLines.length, expectedLines.length);
            const diffLines: string[] = [`DIFF in ${outPath}:`];
            let diffCount = 0;
            for (let i = 0; i < maxLen && diffCount < 20; i++) {
                const a = actualLines[i] ?? '(missing)';
                const e = expectedLines[i] ?? '(missing)';
                if (a !== e) {
                    diffLines.push(`  line ${i + 1}: actual  = ${a}`);
                    diffLines.push(`  line ${i + 1}: expected= ${e}`);
                    diffCount++;
                }
            }
            if (diffCount >= 20) {
                diffLines.push('  ... (truncated at 20 diff lines)');
            }
            diffs.push(diffLines.join('\n'));
            hasDiff = true;
        }
    }

    if (hasDiff) {
        // fail-closed: emit to stderr + exit 1
        process.stderr.write(
            `[fixtures:check] FAIL — cross-lang fixtures are stale or missing.\n` +
                `Run 'pnpm cross-lang:ts-fixtures:regenerate' and commit the updated fixture files.\n\n` +
                diffs.join('\n\n') +
                '\n',
        );
        process.exit(1);
    }

    process.stdout.write(
        '[fixtures:check] PASS — all cross-lang fixtures match TS output.\n',
    );
}

// ─── Entry point ─────────────────────────────────────────────────────────

const args = process.argv.slice(2);
if (args.includes('--regenerate')) {
    runRegenerate();
} else if (args.includes('--check')) {
    runCheck();
} else {
    process.stderr.write(
        'Usage: generate-cross-lang-fixtures.ts --regenerate | --check\n',
    );
    process.exit(1);
}
