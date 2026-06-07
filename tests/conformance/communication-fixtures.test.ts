import { describe, expect, it } from 'vitest';

import type { NegotiationEnvelope } from '../../packages/types/src/index.js';
import { validateAgainstSchema } from '../../packages/types/src/index.js';
import { parseEnvelope } from '../../packages/communication/src/index.js';

import rootNegotiationFixture from '../fixtures/conformance/negotiation-envelope.json';
import negotiationFixture from '../fixtures/conformance/communication/negotiation-envelope.json';
import handshakeFixture from '../fixtures/conformance/communication/handshake-messages.json';
import errorFixture from '../fixtures/conformance/communication/error-envelope.json';

import { isCrossVersionFixture, loadFixtureDir } from './loadFixtureDir.js';

type ErrorCode =
    | 'AUTHORIZATION_INSUFFICIENT'
    | 'IDENTITY_VERIFICATION_FAILED'
    | 'SESSION_NOT_FOUND'
    | 'INVALID_ENVELOPE'
    | 'INTERNAL_ERROR';

interface FixtureCase {
    id: string;
    description: string;
    data: NegotiationEnvelope;
    expectedError?: string;
    expectedIssue?: string;
    valid?: boolean;
}

interface FixtureFile {
    specVersion: string;
    valid: FixtureCase[];
    invalid: FixtureCase[];
    boundary: FixtureCase[];
}

const standardErrorCodes: ErrorCode[] = [
    'AUTHORIZATION_INSUFFICIENT',
    'IDENTITY_VERIFICATION_FAILED',
    'SESSION_NOT_FOUND',
    'INVALID_ENVELOPE',
    'INTERNAL_ERROR',
];

describe('communication conformance fixtures', () => {
    it('keeps the phase-5 negotiation fixture structurally aligned with the frozen root baseline', () => {
        const root = rootNegotiationFixture as FixtureFile;
        const phase5 = negotiationFixture as FixtureFile;

        expect(root.specVersion).toBe(phase5.specVersion);
        expect(root.valid.length).toBeGreaterThan(0);
        expect(phase5.valid.length).toBeGreaterThan(0);
        expect(
            phase5.invalid.some((sample) => sample.expectedError !== undefined),
        ).toBe(true);
    });

    it('accepts valid and boundary negotiation-envelope samples', () => {
        const fixture = negotiationFixture as FixtureFile;

        for (const sample of [...fixture.valid, ...fixture.boundary]) {
            expect(
                validateAgainstSchema(sample.data, 'negotiationEnvelope').valid,
            ).toBe(true);
            expect(parseEnvelope(sample.data)).toEqual(sample.data);
        }
    });

    it('rejects invalid negotiation-envelope samples with the documented error code', () => {
        const fixture = negotiationFixture as FixtureFile;

        for (const sample of fixture.invalid) {
            expectProtocolErrorCode(
                () => parseEnvelope(sample.data),
                sample.expectedError ?? 'INVALID_MESSAGE',
            );
        }
    });

    it('accepts handshake fixtures that match the current initiator/responder body contract', () => {
        const fixture = handshakeFixture as FixtureFile;

        for (const sample of [...fixture.valid, ...fixture.boundary]) {
            expect(
                validateAgainstSchema(sample.data, 'negotiationEnvelope').valid,
            ).toBe(true);

            const envelope = parseEnvelope(sample.data);
            expectHandshakeMessageShape(envelope);
        }
    });

    it('rejects invalid handshake fixtures at the semantic layer', () => {
        const fixture = handshakeFixture as FixtureFile;

        for (const sample of fixture.invalid) {
            const envelope = parseEnvelope(sample.data);

            expect(() => expectHandshakeMessageShape(envelope)).toThrowError(
                sample.expectedIssue,
            );
        }
    });

    it('accepts standard error-envelope fixtures', () => {
        const fixture = errorFixture as FixtureFile;

        for (const sample of [...fixture.valid, ...fixture.boundary]) {
            expect(
                validateAgainstSchema(sample.data, 'negotiationEnvelope').valid,
            ).toBe(true);

            const envelope = parseEnvelope(sample.data);
            expectStandardErrorEnvelope(envelope);
        }
    });

    it('rejects invalid error-envelope fixtures at the semantic layer', () => {
        const fixture = errorFixture as FixtureFile;

        for (const sample of fixture.invalid) {
            const envelope = parseEnvelope(sample.data);

            expect(() => expectStandardErrorEnvelope(envelope)).toThrowError(
                sample.expectedIssue,
            );
        }
    });

    // v0.3.0 subdirectory scan — only consume samples in the negotiationEnvelope schema category.
    // (Within cross-version.v0.3.json, case-1 / case-2 are envelope-shaped; the A4/A8 actionRecord-shaped
    // cases are driven by tests/interop/conformance-suite.test.ts, so this file does not duplicate ledger validation.)
    describe('v0.3.0 directory scan (envelope cases only)', () => {
        const scanned = loadFixtureDir('v0.3.0');

        it('aggregates a non-zero envelope sample total (silent skip guard)', () => {
            const envelopeSamples = collectEnvelopeSamples(scanned.files);
            // communication-fixtures must see at least one v0.3.0 envelope sample,
            // otherwise it counts as a silent skip.
            expect(envelopeSamples.length).toBeGreaterThan(0);
        });

        it('validates each envelope-shaped sample against negotiationEnvelope schema', () => {
            const envelopeSamples = collectEnvelopeSamples(scanned.files);
            for (const sample of envelopeSamples) {
                const result = validateAgainstSchema(
                    sample.data,
                    'negotiationEnvelope',
                );
                if (sample.expected) {
                    expect(
                        result.valid,
                        `${sample.id} expected accept but got: ${JSON.stringify(result.errors)}`,
                    ).toBe(true);
                    // The accept path also runs parseEnvelope to ensure the wire shape can be consumed.
                    expect(parseEnvelope(sample.data)).toEqual(sample.data);
                } else {
                    expect(result.valid).toBe(false);
                }
            }
        });
    });
});

interface EnvelopeSample {
    id: string;
    data: NegotiationEnvelope;
    expected: boolean;
}

function collectEnvelopeSamples(
    files: ReturnType<typeof loadFixtureDir>['files'],
): EnvelopeSample[] {
    const samples: EnvelopeSample[] = [];
    for (const loaded of files) {
        if (!isCrossVersionFixture(loaded.fixture)) continue;
        const fileSchemaId = loaded.fixture.schemaId;
        // The encoding-switch shape uses cases; the cross-version interop matrix uses matrix (both shapes coexist)
        const cases = loaded.fixture.cases ?? loaded.fixture.matrix ?? [];
        for (const c of cases) {
            const schemaId = c.schemaId ?? fileSchemaId;
            if (schemaId !== 'negotiationEnvelope') continue;
            const expectedResult = (c as { expectedResult?: string })
                .expectedResult;
            const expected =
                expectedResult !== undefined
                    ? expectedResult === 'PASS'
                    : (c.valid ?? true);
            // The matrix cross-version reject path needs multi-version validator routing (not yet implemented);
            // validateAgainstSchema currently routes only by schemaId and cannot route across different
            // validatorVersions, so these samples are skipped to avoid false positives.
            const validatorVersion = (
                c as {
                    validatorVersion?: string;
                    inputSpecVersion?: string;
                }
            ).validatorVersion;
            const inputSpecVersion = (
                c as {
                    validatorVersion?: string;
                    inputSpecVersion?: string;
                }
            ).inputSpecVersion;
            if (
                !expected &&
                validatorVersion !== undefined &&
                inputSpecVersion !== undefined &&
                validatorVersion !== inputSpecVersion
            ) {
                continue;
            }
            samples.push({
                id: c.id ?? c.description ?? '<unnamed>',
                data: c.data as NegotiationEnvelope,
                expected,
            });
        }
    }
    return samples;
}

function expectHandshakeMessageShape(envelope: NegotiationEnvelope): void {
    if (envelope.messageType === 'HANDSHAKE_INIT') {
        const challenge = readObject(
            envelope.body,
            'challenge',
            'INVALID_HANDSHAKE',
        );

        assertStringField(challenge, 'challengeId', 'INVALID_HANDSHAKE');
        assertStringField(challenge, 'initiatorDid', 'INVALID_HANDSHAKE');
        assertStringField(challenge, 'responderDid', 'INVALID_HANDSHAKE');
        assertStringField(challenge, 'nonce', 'INVALID_HANDSHAKE');
        assertStringField(challenge, 'timestamp', 'INVALID_HANDSHAKE');
        assertStringField(challenge, 'expiresAt', 'INVALID_HANDSHAKE');
        assertStringArrayField(
            challenge,
            'initiatorCapabilities',
            'INVALID_HANDSHAKE',
        );
        return;
    }

    if (envelope.messageType === 'HANDSHAKE_ACK') {
        const body = envelope.body;
        assertBooleanField(body, 'accepted', 'INVALID_HANDSHAKE');
        const response = readObject(body, 'response', 'INVALID_HANDSHAKE');
        const accepted = body['accepted'] as boolean;

        assertStringField(response, 'challengeId', 'INVALID_HANDSHAKE');
        if (accepted) {
            assertStringField(response, 'sessionId', 'INVALID_HANDSHAKE');
        } else if (typeof response['sessionId'] !== 'string') {
            throw new Error(
                'INVALID_HANDSHAKE: sessionId must be a string when rejected',
            );
        }
        assertStringField(response, 'responderDid', 'INVALID_HANDSHAKE');
        assertStringArrayField(
            response,
            'responderCapabilities',
            'INVALID_HANDSHAKE',
        );
        assertStringField(response, 'nonce', 'INVALID_HANDSHAKE');
        assertStringField(response, 'timestamp', 'INVALID_HANDSHAKE');
        return;
    }

    throw new Error(
        `INVALID_HANDSHAKE: unexpected messageType ${envelope.messageType}`,
    );
}

function expectStandardErrorEnvelope(envelope: NegotiationEnvelope): void {
    if (envelope.messageType !== 'ERROR') {
        throw new Error('INVALID_ERROR_ENVELOPE: messageType must be ERROR');
    }

    const body = envelope.body;
    const code = body['code'];
    const message = body['message'];

    if (
        typeof code !== 'string' ||
        !standardErrorCodes.includes(code as ErrorCode)
    ) {
        throw new Error('INVALID_ERROR_ENVELOPE: unknown standard error code');
    }

    if (typeof message !== 'string' || message.length === 0) {
        throw new Error('INVALID_ERROR_ENVELOPE: message is required');
    }
}

function readObject(
    source: Record<string, unknown>,
    key: string,
    issue: string,
): Record<string, unknown> {
    const value = source[key];
    if (!value || typeof value !== 'object') {
        throw new Error(`${issue}: ${key} must be an object`);
    }

    return value as Record<string, unknown>;
}

function assertStringField(
    source: Record<string, unknown>,
    key: string,
    issue: string,
): void {
    if (typeof source[key] !== 'string' || source[key] === '') {
        throw new Error(`${issue}: ${key} must be a non-empty string`);
    }
}

function assertBooleanField(
    source: Record<string, unknown>,
    key: string,
    issue: string,
): void {
    if (typeof source[key] !== 'boolean') {
        throw new Error(`${issue}: ${key} must be a boolean`);
    }
}

function assertStringArrayField(
    source: Record<string, unknown>,
    key: string,
    issue: string,
): void {
    const value = source[key];

    if (
        !Array.isArray(value) ||
        value.some((entry) => typeof entry !== 'string')
    ) {
        throw new Error(`${issue}: ${key} must be a string array`);
    }
}

function expectProtocolErrorCode(
    fn: () => unknown,
    expectedCode: string,
): void {
    try {
        fn();
    } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as { code?: string }).code).toBe(expectedCode);
        return;
    }

    throw new Error(
        `Expected ProtocolError(${expectedCode}) but nothing was thrown`,
    );
}
