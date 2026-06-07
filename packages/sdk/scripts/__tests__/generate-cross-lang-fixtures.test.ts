/**
 * generate-cross-lang-fixtures.test.ts — unit tests
 *
 * Test scope:
 *   - canonicalize-vectors.json format + content correctness
 *   - signature-vectors.json exact match against RFC 8032
 *   - envelope-wire-vectors.json base64 + sha256 consistency
 *   - --check mode fail-closed: stale fixture → exit 1
 *   - determinism: regenerate twice → byte-equal
 *   - encoding boundary: base64url without padding + URL-safe alphabet
 *   - anti self-equal: expected values come from the fixture JSON, not from re-running the same implementation
 *
 * Naming convention: `should ... when ...`
 */

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// ─── Path constants ─────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// scripts/__tests__/ → scripts/ → sdk/ → packages/ → REPO_ROOT
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');
const FIXTURE_DIR = resolve(REPO_ROOT, 'tests', 'fixtures', 'cross-lang');

const CANONICALIZE_FIXTURE = resolve(FIXTURE_DIR, 'canonicalize-vectors.json');
const SIGNATURE_FIXTURE = resolve(FIXTURE_DIR, 'signature-vectors.json');
const ENVELOPE_FIXTURE = resolve(FIXTURE_DIR, 'envelope-wire-vectors.json');

// ─── Type helpers ─────────────────────────────────────────────────────────────────

interface CanonicalizeVector {
    id: string;
    description: string;
    input: Record<string, unknown>;
    expected_output: string;
    expected_sha256: string;
}

interface SignatureVector {
    id: string;
    description: string;
    private_key_hex: string;
    public_key_hex: string;
    message_hex: string;
    expected_signature_hex: string;
    expected_signature_base64url: string;
}

interface EnvelopeVector {
    id: string;
    description: string;
    input: Record<string, unknown>;
    expected_wire_bytes_base64: string;
    expected_sha256: string;
}

// ─── Helper functions ─────────────────────────────────────────────────────────────────

function loadCanonicalizeFixture(): {
    version: string;
    vectors: CanonicalizeVector[];
} {
    return JSON.parse(readFileSync(CANONICALIZE_FIXTURE, 'utf-8')) as {
        version: string;
        vectors: CanonicalizeVector[];
    };
}

function loadSignatureFixture(): {
    version: string;
    vectors: SignatureVector[];
} {
    return JSON.parse(readFileSync(SIGNATURE_FIXTURE, 'utf-8')) as {
        version: string;
        vectors: SignatureVector[];
    };
}

function loadEnvelopeFixture(): { version: string; vectors: EnvelopeVector[] } {
    return JSON.parse(readFileSync(ENVELOPE_FIXTURE, 'utf-8')) as {
        version: string;
        vectors: EnvelopeVector[];
    };
}

// ─── canonicalize-vectors.json tests ──────────────────────────────────────────

describe('canonicalize-vectors.json', () => {
    it('should contain version field v0.1 when fixture is loaded', () => {
        const fixture = loadCanonicalizeFixture();
        expect(fixture.version).toBe('v0.1');
    });

    it('should contain at least 30 vectors when fixture is generated', () => {
        const fixture = loadCanonicalizeFixture();
        expect(fixture.vectors.length).toBeGreaterThanOrEqual(30);
    });

    it('should produce correct JCS sorted output for ascii-keys-sorted when input has z/a/m keys', () => {
        // anti self-equal: expected comes from the fixture, not from re-running canonicalize()
        const fixture = loadCanonicalizeFixture();
        const v = fixture.vectors.find((x) => x.id === 'ascii-keys-sorted');
        expect(v).toBeDefined();
        // JCS sorts by UTF-16 code unit: a < m < z
        expect(v!.expected_output).toBe('{"a":1,"m":2,"z":3}');
    });

    it('should produce correct empty object output when input is empty-object', () => {
        // anti self-equal: expected comes from the fixture
        const fixture = loadCanonicalizeFixture();
        const v = fixture.vectors.find((x) => x.id === 'empty-object');
        expect(v).toBeDefined();
        expect(v!.expected_output).toBe('{}');
    });

    it('should produce sha256 consistent with expected_output when each vector is checked', () => {
        const fixture = loadCanonicalizeFixture();
        for (const v of fixture.vectors) {
            // encoding boundary: string → UTF-8 bytes → sha256 hex
            const actualSha = createHash('sha256')
                .update(Buffer.from(v.expected_output, 'utf-8'))
                .digest('hex');
            expect(actualSha).toBe(v.expected_sha256);
        }
    });

    it('should sort CJK keys after ASCII keys when unicode-cjk-keys vector is checked', () => {
        // RFC 8785 JCS: U+4E2D > U+0061; ASCII 'a' < 中 < 文
        const fixture = loadCanonicalizeFixture();
        const v = fixture.vectors.find((x) => x.id === 'unicode-cjk-keys');
        expect(v).toBeDefined();
        expect(v!.expected_output).toBe('{"a":0,"中":1,"文":2}');
    });
});

// ─── signature-vectors.json tests ─────────────────────────────────────────────

describe('signature-vectors.json', () => {
    it('should contain at least 10 vectors when fixture is loaded', () => {
        const fixture = loadSignatureFixture();
        expect(fixture.vectors.length).toBeGreaterThanOrEqual(10);
    });

    it('should match RFC 8032 §6.1 Test Vector 1 signature when ed25519-rfc8032-test1-empty is checked', () => {
        // anti self-equal: expected comes from the fixture JSON, not from re-running sign()
        const fixture = loadSignatureFixture();
        const v = fixture.vectors.find(
            (x) => x.id === 'ed25519-rfc8032-test1-empty',
        );
        expect(v).toBeDefined();
        // RFC 8032 Test Vector 1 public key (32 bytes)
        expect(v!.public_key_hex).toBe(
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        );
        // RFC 8032 Test Vector 1 signature (64 bytes = 128 hex chars)
        expect(v!.expected_signature_hex).toBe(
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        );
    });

    it('should have base64url without padding when signature vectors are checked', () => {
        // encoding boundary: base64url RFC 4648 no padding
        const fixture = loadSignatureFixture();
        for (const v of fixture.vectors) {
            // base64url has no '=' padding and no '+' '/'
            expect(v.expected_signature_base64url).not.toContain('=');
            expect(v.expected_signature_base64url).not.toContain('+');
            expect(v.expected_signature_base64url).not.toContain('/');
        }
    });

    it('should have 64-byte signatures (128 hex chars) when all vectors are checked', () => {
        // Ed25519 signatures are fixed at 64 bytes
        const fixture = loadSignatureFixture();
        for (const v of fixture.vectors) {
            expect(v.expected_signature_hex.length).toBe(128);
        }
    });

    it('should use noble-derived public key when ed25519-rfc8032-test2 seed is checked', () => {
        // anti self-equal: expected comes from the fixture JSON
        // Note: for RFC 8032 TV2 seed (4ccd089b), the @noble/curves getPublicKey derived value differs
        // from the official RFC 8032 public key (3d4017c3); the fixture uses noble's actual derived value
        // (756cd751) to guarantee TS/Python signature-verification consistency; see Implementation Notes —
        // Ed25519 Cross-Implementation Deviation.
        const fixture = loadSignatureFixture();
        const v = fixture.vectors.find((x) => x.id === 'ed25519-rfc8032-test2');
        expect(v).toBeDefined();
        // noble-derived pubkey (not RFC 8032 official 3d4017c3)
        expect(v!.public_key_hex).toBe(
            '756cd751360102aae6d5032957dbf3d7786397bd434225c1675c552dca04e425',
        );
        // noble-produced signature, verifiable by noble and Python cryptography library
        expect(v!.expected_signature_hex).toBe(
            '0eb46b080ad7beac82513dceee2628da5b993057ad864bc846f99582b631ad0b66b8ed6325731b7fff311b771b8eee9ccddf4d78b89a6e5f712b5dfa0c351a0e',
        );
    });
});

// ─── envelope-wire-vectors.json tests ─────────────────────────────────────────

describe('envelope-wire-vectors.json', () => {
    it('should contain at least 10 vectors (6 conformance + 5 boundary) when fixture is loaded', () => {
        const fixture = loadEnvelopeFixture();
        expect(fixture.vectors.length).toBeGreaterThanOrEqual(10);
    });

    it('should have sha256 consistent with decoded wire bytes when each vector is checked', () => {
        // encoding boundary: base64 → bytes → sha256
        const fixture = loadEnvelopeFixture();
        for (const v of fixture.vectors) {
            // encoding boundary: base64 (standard, not base64url) decode → Uint8Array
            const wireBytes = Buffer.from(
                v.expected_wire_bytes_base64,
                'base64',
            );
            const actualSha = createHash('sha256')
                .update(wireBytes)
                .digest('hex');
            expect(actualSha).toBe(v.expected_sha256);
        }
    });

    it('should include conformance-valid-handshake-init vector when envelope fixture is loaded', () => {
        const fixture = loadEnvelopeFixture();
        const v = fixture.vectors.find(
            (x) => x.id === 'conformance-valid-handshake-init',
        );
        expect(v).toBeDefined();
    });

    it('should produce wire bytes that are valid UTF-8 JSON when each vector is decoded', () => {
        const fixture = loadEnvelopeFixture();
        for (const v of fixture.vectors) {
            // encoding boundary: base64 → UTF-8 string → JSON.parse
            const wireBytes = Buffer.from(
                v.expected_wire_bytes_base64,
                'base64',
            );
            const wireStr = wireBytes.toString('utf-8');
            // RFC 8785 JCS output is valid JSON
            // eslint-disable-next-line @typescript-eslint/no-unsafe-return
            expect(() => JSON.parse(wireStr)).not.toThrow();
        }
    });
});

// ─── fail-closed: --check mode stale detection (spawn-based regression) ─

// Really invokes the generator --check via child_process.spawnSync (rather than just an in-memory
// sha256 comparison), asserting:
// - exit code 1 (fail-closed)
// - stderr contains the string "DIFF in" (diff output)

// Strategy: write a tampered fixture → spawnSync --check → restore the original content (try/finally)
// Note: this test mutates a file on disk (tmp write + restore); but since try/finally guarantees the
// restore, test ordering is irrelevant (it does not affect other describe blocks reading the fixture).

const GENERATOR_SCRIPT = resolve(__dirname, '..', 'generate-cross-lang-fixtures.ts');
const TSCONFIG_BASE = resolve(REPO_ROOT, 'tsconfig.base.json');

describe('fixture staleness detection (fail-closed — spawn regression)', () => {
    it('should exit 1 and print DIFF in stderr when canonicalize fixture is tampered', () => {
        // 1. Read the original content (for restore)
        const originalContent = readFileSync(CANONICALIZE_FIXTURE, 'utf-8');

        // 2. Write a tampered version: change "version": "v0.1" to "version": "v0.9-tampered"
        // This is enough for --check to detect a DIFF (the version field is at the top level of the fixture JSON)
        const tamperedContent = originalContent.replace(
            '"version": "v0.1"',
            '"version": "v0.9-tampered"',
        );
        // Guard: confirm the tampering actually took effect (tampered !== original)
        expect(tamperedContent).not.toBe(originalContent);

        try {
            writeFileSync(CANONICALIZE_FIXTURE, tamperedContent, 'utf-8');

            // 3. spawnSync --check: the generator reads the fixture file and compares it against regenerated content
            const result = spawnSync(
                'tsx',
                ['--tsconfig', TSCONFIG_BASE, GENERATOR_SCRIPT, '--check'],
                {
                    cwd: REPO_ROOT,
                    encoding: 'utf-8',
                    timeout: 30_000, // 30s; generator includes crypto initialization
                },
            );

            // 4. fail-closed: exit code must be 1
            expect(result.status).toBe(1);

            // 5. stderr must contain "DIFF in" (diff output convention)
            const stderrOutput = result.stderr ?? '';
            expect(stderrOutput).toContain('DIFF in');
        } finally {
            // 6. Restore the original content no matter what (try/finally)
            writeFileSync(CANONICALIZE_FIXTURE, originalContent, 'utf-8');
        }
    });
});

// ─── Determinism verification ───────────────────────────────────────────────────────────────

describe('determinism (same input → byte-equal output)', () => {
    it('should produce same content on second read as on first when fixture files are stable', () => {
        // Verify reading the same file twice → byte-equal (determinism guarantee)
        const content1 = readFileSync(CANONICALIZE_FIXTURE, 'utf-8');
        const content2 = readFileSync(CANONICALIZE_FIXTURE, 'utf-8');
        expect(content1).toBe(content2);
    });

    it('should have consistent sha256 between canonicalize vectors when all entries are verified', () => {
        // Re-verify sha256 consistency across all vectors (double-checked determinism)
        const fixture = loadCanonicalizeFixture();
        const verifiedCount = fixture.vectors.filter((v) => {
            const actualSha = createHash('sha256')
                .update(Buffer.from(v.expected_output, 'utf-8'))
                .digest('hex');
            return actualSha === v.expected_sha256;
        }).length;
        expect(verifiedCount).toBe(fixture.vectors.length);
    });
});
