import { describe, expect, it } from 'vitest';

import {
    parseEnvelope,
    verifyEnvelope,
} from '../../packages/communication/src/index.js';
import { validateAgainstSchema } from '../../packages/types/src/index.js';
import {
    validateAgainstVersionedSchema,
    type ValidatorVersion,
} from './multi-version-validators.js';

import actionRecordFixture from '../fixtures/conformance/action-record.json';
import actionRecordV02Fixture from '../fixtures/conformance/action-record.v0.2.json';
import agentCardFixture from '../fixtures/conformance/discovery/agent-card.json';
import identityFixture from '../fixtures/conformance/agent-identity-document.json';
import identityV02Fixture from '../fixtures/conformance/agent-identity-document.v0.2.json';
import negotiationFixture from '../fixtures/conformance/negotiation-envelope.json';
import negotiationV02Fixture from '../fixtures/conformance/negotiation-envelope.v0.2.json';
import capabilityTokenFixture from '../fixtures/conformance/capability-token.json';
import capabilityTokenV02Fixture from '../fixtures/conformance/capability-token.v0.2.json';

import {
    isCrossVersionFixture,
    isEncodingPairsFixture,
    isNestedGroupFixture,
    loadFixtureDir,
    type CrossVersionFixture,
    type FixtureCase as ScannedCase,
    type SchemaIdHint,
    type ValidInvalidFixture,
} from '../conformance/loadFixtureDir.js';

interface FixtureCase<TData> {
    id: string;
    data: TData;
    valid?: boolean;
    expectedError?: string;
}

interface FixtureFile<TData> {
    valid: FixtureCase<TData>[];
    invalid: FixtureCase<TData>[];
    boundary: FixtureCase<TData>[];
}

// filename → schemaId registry (specific to the v0.3.0 subdirectory scan).
// Legacy fixed files retain their original explicit `describeFixtureFile` import paths, for backward compatibility.
// New v0.3.0 fixtures must declare a schemaId here, otherwise the loadFixtureDir-driven harness
// throws fail-closed (preventing new fixtures from going unregistered).
const V030_FIXTURE_SCHEMA_REGISTRY: Record<string, SchemaIdHint> = {
    // Dual-key rotation
    'dual-key-rotation.v0.3.json': 'resolvedPublicKeys',
    // delegationDepth required
    'delegation-depth-boundary.v0.3.json': 'actionRecord',
    // SESSION_SUPERSEDED ActionVocabulary
    'action-vocabulary-supersede.v0.3.json': 'actionRecord',
    // cross-version pairs (each pair carries its own schemaId override; this registry is only a fallback)
    'cross-version.v0.3.json': 'negotiationEnvelope',
    // control-plane action isolation (each case carries its own schemaId override:
    // the 6 kinds capability / agentIdentityDocument / agentCard / handshakeChallenge /
    // handshakeResponse / actionRecord)
    'control-plane-action-isolation.v0.3.json': 'capabilityToken',
};

describe('interop conformance suite', () => {
    describeFixtureFile(
        'AgentIdentityDocument',
        identityFixture as FixtureFile<unknown>,
        'agentIdentityDocument',
    );

    describeFixtureFile(
        'CapabilityToken',
        capabilityTokenFixture as FixtureFile<unknown>,
        'capabilityToken',
    );

    describeFixtureFile(
        'ActionRecord',
        actionRecordFixture as FixtureFile<unknown>,
        'actionRecord',
    );

    // specVersion 0.2.0 fixtures — coexist with the 0.1.0 baseline.
    describeFixtureFile(
        'AgentIdentityDocument (v0.2)',
        identityV02Fixture as FixtureFile<unknown>,
        'agentIdentityDocument',
    );

    describeFixtureFile(
        'CapabilityToken (v0.2)',
        capabilityTokenV02Fixture as FixtureFile<unknown>,
        'capabilityToken',
    );

    describeFixtureFile(
        'ActionRecord (v0.2)',
        actionRecordV02Fixture as FixtureFile<unknown>,
        'actionRecord',
    );

    // Boundary regression anchor for the AgentCard maxLength relaxation
    // (displayName 64→128, description 512→1024). The repo previously had no AgentCard conformance fixture, leaving the new boundaries without interop protection.
    describeFixtureFile(
        'AgentCard',
        agentCardFixture as FixtureFile<unknown>,
        'agentCard',
    );

    describeNegotiationEnvelopeFixture(
        'NegotiationEnvelope',
        negotiationFixture as FixtureFile<unknown>,
    );

    // specVersion 0.2.0 NegotiationEnvelope fixtures —
    // header.capabilityTokenRef version gate; coexist with the 0.1.0 baseline.
    describeNegotiationEnvelopeFixture(
        'NegotiationEnvelope (v0.2)',
        negotiationV02Fixture as FixtureFile<unknown>,
    );

    // v0.3.0 subdirectory scan entry point (breaking-format-change-v0.3.0 silent-skip guard).
    describeVersionDirFixtures('v0.3.0');
});

// Each version subdirectory scan goes through unified dispatch. Acceptance requirements:
// 1. The directory exists + at least one fixture is loaded (loadFixtureDir is fail-closed in strict mode).
// 2. Every valid sample must pass schema validation.
// 3. Every invalid sample must be rejected per its reason field (schema validation returns valid:false).
// 4. The cross-version shape is driven by each case's own schemaId + expected result.
// 5. A toBeGreaterThan(0) assertion is made on the total loaded sample count, as programmatic evidence that the subdirectory was actually scanned.
function describeVersionDirFixtures(version: 'v0.3.0' | 'v0.2-encoding'): void {
    const scanned = loadFixtureDir(version);

    describe(`conformance/<${version}> directory scan`, () => {
        it('loads at least one fixture file', () => {
            expect(scanned.files.length).toBeGreaterThan(0);
        });

        it('aggregates a non-zero sample total (silent skip guard)', () => {
            // breaking-format-change-v0.3.0: the interop report must show
            // an actually-loaded sample count > 0; this assertion is the programmatic evidence.
            expect(scanned.totalSamples).toBeGreaterThan(0);
        });

        for (const loaded of scanned.files) {
            describe(loaded.file, () => {
                if (isEncodingPairsFixture(loaded.fixture)) {
                    // encoding-switch-dual-format.v0.3.json: an encoding-comparison
                    // fixture with no schema-validation semantics. A placeholder it satisfies the silent-skip guard.
                    it('encoding pairs fixture (no schema validation)', () => {
                        const encPairs = (
                            loaded.fixture as { encoding_pairs?: unknown[] }
                        ).encoding_pairs;
                        expect(Array.isArray(encPairs)).toBe(true);
                        expect((encPairs as unknown[]).length).toBeGreaterThan(
                            0,
                        );
                    });
                    return;
                }
                if (isNestedGroupFixture(loaded.fixture)) {
                    // Nested-group fixture (v030-base64url-field-extensions.v0.3.json):
                    // the current model does not support per-group schemaId routing for nested groups; deferred.
                    it.skip('nested-group fixture (DEFER: nested per-group schema routing not implemented)', () => {});
                    return;
                }
                if (isCrossVersionFixture(loaded.fixture)) {
                    runCrossVersionFixture(loaded.fixture);
                    return;
                }

                runValidInvalidFixture(loaded.file, loaded.fixture);
            });
        }
    });
}

function runValidInvalidFixture(
    filename: string,
    fixture: ValidInvalidFixture,
): void {
    const defaultSchemaId =
        fixture.schemaId ?? V030_FIXTURE_SCHEMA_REGISTRY[filename];

    if (!defaultSchemaId) {
        throw new Error(
            `v0.3.0 fixture '${filename}' has no schemaId; either add to V030_FIXTURE_SCHEMA_REGISTRY or declare top-level schemaId in the JSON`,
        );
    }

    if (fixture.valid && fixture.valid.length > 0) {
        for (const sample of fixture.valid) {
            const schemaId = sample.schemaId ?? defaultSchemaId;
            const id = sample.id ?? sample.description ?? '<unnamed>';
            it(`accepts valid sample ${id}`, () => {
                const result = validateAgainstSchema(sample.data, schemaId);
                expect(result.valid, JSON.stringify(result.errors)).toBe(true);
            });
        }
    }

    if (fixture.invalid && fixture.invalid.length > 0) {
        for (const sample of fixture.invalid) {
            const schemaId = sample.schemaId ?? defaultSchemaId;
            const id = sample.id ?? sample.description ?? '<unnamed>';
            it(`rejects invalid sample ${id} with reason`, () => {
                const result = validateAgainstSchema(sample.data, schemaId);
                expect(result.valid).toBe(false);
                expect(result.errors.length).toBeGreaterThan(0);
                // expectedError must genuinely match, to avoid a false-positive window. See the
                // header comment of assertRejectionMatches for the matcher.
                assertRejectionMatches(sample, result.errors);
            });
        }
    }

    if (fixture.cross_version && fixture.cross_version.length > 0) {
        for (const sample of fixture.cross_version) {
            const schemaId = sample.schemaId ?? defaultSchemaId;
            const id = sample.id ?? sample.description ?? '<unnamed>';
            const expected = sample.valid ?? true;
            it(`cross-version sample ${id} → ${expected ? 'accept' : 'reject'}`, () => {
                const result = validateAgainstSchema(sample.data, schemaId);
                expect(
                    result.valid,
                    expected
                        ? `expected accept but got errors: ${JSON.stringify(result.errors)}`
                        : 'expected reject but accepted',
                ).toBe(expected);
                if (!expected) {
                    // The reject path also verifies the failure reason.
                    assertRejectionMatches(sample, result.errors);
                }
            });
        }
    }

    if (fixture.boundary && fixture.boundary.length > 0) {
        for (const sample of fixture.boundary) {
            const schemaId = sample.schemaId ?? defaultSchemaId;
            const id = sample.id ?? sample.description ?? '<unnamed>';
            it(`handles boundary sample ${id}`, () => {
                expect(validateAgainstSchema(sample.data, schemaId).valid).toBe(
                    sample.valid ?? true,
                );
            });
        }
    }
}

function runCrossVersionFixture(fixture: CrossVersionFixture): void {
    const defaultSchemaId = fixture.schemaId;
    // The legacy shape uses cases; the matrix shape uses matrix (each case carries expectedResult='PASS'/'FAIL').
    const samples = fixture.cases ?? fixture.matrix ?? [];

    expect(samples.length).toBeGreaterThan(0);

    for (const sample of samples) {
        const schemaId = sample.schemaId ?? defaultSchemaId;
        const id = sample.id ?? sample.description ?? '<unnamed>';
        const expectedResult = (sample as { expectedResult?: string })
            .expectedResult;
        // Tri-state: 'PASS'/'REJECT'/'RUNTIME_DEPENDENT' (fail-closed parsing)
        // - 'PASS' → expect=true (accept)
        // - 'REJECT' / 'FAIL' (legacy alias) → false
        // - 'RUNTIME_DEPENDENT' → null (skip + DEFER)
        // - undefined → fallback to sample.valid (legacy fixtures have no expectedResult)
        // - any other value (typo / unknown token) → throw (fail-closed, to avoid silently judging PASS)
        let expectedTri: boolean | null;
        if (expectedResult === undefined) {
            expectedTri = sample.valid ?? true;
        } else if (expectedResult === 'PASS') {
            expectedTri = true;
        } else if (expectedResult === 'REJECT' || expectedResult === 'FAIL') {
            expectedTri = false;
        } else if (expectedResult === 'RUNTIME_DEPENDENT') {
            expectedTri = null;
        } else {
            // Unknown expectedResult token: fail-closed to protect the acceptance gate
            throw new Error(
                `cross-version fixture '${id}' has unknown expectedResult='${expectedResult}'; expected one of PASS/REJECT/FAIL/RUNTIME_DEPENDENT`,
            );
        }

        // The matrix contains a validatorVersion field (e.g. '0.1.0' / '0.2.0' / '0.3.0').
        // The cross-version REJECT path is no longer skipped: when validatorVersion ≠ inputSpecVersion
        // and expected=reject, it routes to the legacy-version validators in multi-version-validators.ts
        // (the v0.1.0 / v0.2.0 narrowed variants).
        // schemaIds outside the coverage set are still skipped and marked as fallback.
        const validatorVersion = (
            sample as { validatorVersion?: string; inputSpecVersion?: string }
        ).validatorVersion;
        const inputSpecVersion = (
            sample as { validatorVersion?: string; inputSpecVersion?: string }
        ).inputSpecVersion;
        const needsMultiVersionRouting =
            validatorVersion !== undefined &&
            inputSpecVersion !== undefined &&
            validatorVersion !== inputSpecVersion;

        // RUNTIME_DEPENDENT (xv-09 kind) — the fixture explicitly notes "depends on the deployment-specific historical schema".
        // The current synthetic enum-narrowed validator cannot reliably answer "does v0.1 include anyOf base64url" → DEFER
        if (expectedTri === null) {
            it.skip(`${id} → RUNTIME_DEPENDENT (DEFER: requires an authoritative historical schema snapshot to decide; the current enum-narrow shim is insufficient)`, () => {});
            continue;
        }
        const expected = expectedTri;

        if (needsMultiVersionRouting && !expected) {
            // Attempt to route through the multi-version validator (an unknown validatorVersion is thrown by the validator itself, fail-closed)
            const versionedResult = validateAgainstVersionedSchema(
                sample.data,
                schemaId,
                validatorVersion as ValidatorVersion, // type-level cast; thrown at runtime by the validator
            );
            if (versionedResult === null) {
                // Outside the coverage set (e.g. schemaId is not negotiationEnvelope/actionRecord) → DEFER
                it.skip(`${id} → reject (DEFER: multi-version validator schemaId='${schemaId}' v${validatorVersion} not in coverage set; full schema-history routing pending)`, () => {});
                continue;
            }
            it(`${id} → reject [v${validatorVersion} validator]`, () => {
                expect(
                    versionedResult.valid,
                    `expected v${validatorVersion} validator to reject but got accept`,
                ).toBe(false);
                expect(versionedResult.errors.length).toBeGreaterThan(0);
                // Likewise match the failure reason against expectedError
                assertRejectionMatches(sample, versionedResult.errors);
            });
            continue;
        }
        it(`${id} → ${expected ? 'accept' : 'reject'}`, () => {
            const result = validateAgainstSchema(sample.data, schemaId);
            if (expected) {
                expect(
                    result.valid,
                    `expected accept but got errors: ${JSON.stringify(result.errors)}`,
                ).toBe(true);
            } else {
                expect(result.valid).toBe(false);
                expect(result.errors.length).toBeGreaterThan(0);
                // The reject path of cross-version pairs must also match the failure reason against expectedError.
                assertRejectionMatches(sample, result.errors);
            }
        });
    }
}

// Tighten the failure-reason check on the invalid / cross-version reject paths, to avoid the
// "valid:false + errors.length>0" false-positive window (the fixture intends to test gate X, but it also passes due to a field-Y error).

// Within the fixture, the expectedError field is a mixed shape of spec-prose and AJV-message,
// so strict string equality cannot be required. The matcher passes if any of its three layers hits:

// L1 field token: extract from expectedError a quoted property ('reason') or a leading
// identifier (known schema fields such as delegationDepth / agentDid / rotationState / specVersion).
// If that token is found in the last segment of some error's instancePath or in its message → L1 hit.
// L2 AJV phrase: extract the known AJV-style phrases in expectedError ("must be <= ",
// "must be >=", "must be integer", "must have required property",
// "must be equal to one of", "must be equal to constant", "must equal").
// If found as a substring in error.message → L2 hit.
// L3 keyword direct hit: expectedError contains an AJV keyword name (maximum/minimum/
// type/required/enum/const) → L3 hit.

// If none of the three layers hits → fail, and dump the full errors for diagnosis. When expectedError is missing, the
// matcher is skipped (treated as the fixture author declaring no reason anchor; the next commit must add expectedError).
type RejectionSample = {
    id?: string;
    description?: string;
    expectedError?: string;
};

type ValidationIssue = {
    instancePath: string;
    message: string;
    keyword: string;
};

const AJV_PHRASES: ReadonlyArray<string> = [
    'must be <= ',
    'must be >= ',
    'must be < ',
    'must be > ',
    'must be integer',
    'must be string',
    'must be number',
    'must be boolean',
    'must be array',
    'must be object',
    'must have required property',
    'must be equal to one of',
    'must be equal to constant',
    'must equal',
    'must match pattern',
    'must NOT have additional properties',
];

const AJV_KEYWORDS: ReadonlyArray<string> = [
    'maximum',
    'minimum',
    'exclusiveMaximum',
    'exclusiveMinimum',
    'type',
    'required',
    'enum',
    'const',
    'pattern',
    'additionalProperties',
    // schema-composition: not / oneOf / anyOf are used for state-field semantic constraints
    // (e.g. "STABLE state must not have previous key" is orchestrated by schema "not" + "if/then")
    'not',
    'oneOf',
    'anyOf',
    'allOf',
];

// Allowlist of leading-identifiers for known schema fields: avoid false positives from
// generic English words ("must"/"property", etc.) leaking into the token set.
const KNOWN_FIELD_TOKENS: ReadonlyArray<string> = [
    'delegationDepth',
    'agentDid',
    'principalDid',
    'rotationState',
    'specVersion',
    'reason',
    'oldSessionId',
    'newSessionId',
    'current',
    'previous',
    'capabilityTokenRef',
    'actorSignature',
    'ledgerSignature',
    'parametersSummary',
];

function extractFieldTokens(expectedError: string): string[] {
    const tokens = new Set<string>();
    // (a) quoted property name: 'reason' / "current"
    const quoted = expectedError.matchAll(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g);
    for (const m of quoted) {
        if (m[1]) tokens.add(m[1]);
    }
    // (b) leading identifier in expectedError (limited to the allowlist to prevent misjudgment)
    for (const known of KNOWN_FIELD_TOKENS) {
        if (expectedError.includes(known)) tokens.add(known);
    }
    return [...tokens];
}

function extractAjvPhrases(expectedError: string): string[] {
    return AJV_PHRASES.filter((phrase) => expectedError.includes(phrase));
}

function extractAjvKeywords(expectedError: string): string[] {
    const lower = expectedError.toLowerCase();
    return AJV_KEYWORDS.filter((kw) => lower.includes(kw.toLowerCase()));
}

function assertRejectionMatches(
    sample: RejectionSample,
    errors: ValidationIssue[],
): void {
    if (!sample.expectedError) {
        // The fixture author did not declare a reason anchor; keeping the already-asserted errors.length>0 is sufficient.
        return;
    }
    const id = sample.id ?? sample.description ?? '<unnamed>';
    const fieldTokens = extractFieldTokens(sample.expectedError);
    const phraseHints = extractAjvPhrases(sample.expectedError);
    const keywordHints = extractAjvKeywords(sample.expectedError);

    // L4 schema-composition fallback (state-field semantic constraints):
    // if expectedError contains "must not"/"must NOT"/"contradiction"/"mutually exclusive"
    // → accept a schema-composition keyword (not/oneOf/anyOf/allOf) as a reason hit.
    const compositionPhrasePresent =
        /must\s+NOT|must\s+not|contradict|mutually exclusive/i.test(
            sample.expectedError,
        );

    const matched = errors.some((err) => {
        // L1 field token: contained in an instancePath segment or in the message
        const l1 = fieldTokens.some(
            (t) => err.instancePath.includes(t) || err.message.includes(t),
        );
        // L2 AJV phrase substring
        const l2 = phraseHints.some((p) => err.message.includes(p));
        // L3 keyword direct hit
        const l3 = keywordHints.includes(err.keyword);
        // L4 composition phrase + composition keyword
        const l4 =
            compositionPhrasePresent &&
            ['not', 'oneOf', 'anyOf', 'allOf', 'if', 'then', 'else'].includes(
                err.keyword,
            );
        return l1 || l2 || l3 || l4;
    });

    expect(
        matched,
        `sample ${id}: expectedError "${sample.expectedError}" did not match any AJV error.\n` +
            `tokens=${JSON.stringify(fieldTokens)} phrases=${JSON.stringify(phraseHints)} keywords=${JSON.stringify(keywordHints)}\n` +
            `errors=${JSON.stringify(errors, null, 2)}`,
    ).toBe(true);
}

// The 'ScannedCase' type is kept for possible future extension (for example, wire-level parseEnvelope integration);
// currently it is only used to validate the V030_FIXTURE_SCHEMA_REGISTRY and loadFixtureDir output contract.
const _scannedCaseTypeWitness: ScannedCase | undefined = undefined;
void _scannedCaseTypeWitness;

function describeFixtureFile(
    label: string,
    fixture: FixtureFile<unknown>,
    schemaId:
        | 'agentIdentityDocument'
        | 'capabilityToken'
        | 'actionRecord'
        | 'agentCard',
): void {
    describe(label, () => {
        for (const sample of fixture.valid) {
            it(`accepts valid sample ${sample.id}`, () => {
                expect(validateAgainstSchema(sample.data, schemaId)).toEqual({
                    valid: true,
                    errors: [],
                });
            });
        }

        for (const sample of fixture.invalid) {
            it(`rejects invalid sample ${sample.id}`, () => {
                expect(validateAgainstSchema(sample.data, schemaId).valid).toBe(
                    false,
                );
            });
        }

        for (const sample of fixture.boundary) {
            it(`handles boundary sample ${sample.id}`, () => {
                expect(validateAgainstSchema(sample.data, schemaId).valid).toBe(
                    sample.valid ?? true,
                );
            });
        }
    });
}

function describeNegotiationEnvelopeFixture(
    label: string,
    fixture: FixtureFile<unknown>,
): void {
    describe(label, () => {
        for (const sample of fixture.valid) {
            it(`accepts valid sample ${sample.id}`, () => {
                expect(
                    validateAgainstSchema(sample.data, 'negotiationEnvelope'),
                ).toEqual({
                    valid: true,
                    errors: [],
                });
                expect(parseEnvelope(sample.data)).toEqual(sample.data);
            });
        }

        for (const sample of fixture.invalid) {
            it(`rejects invalid sample ${sample.id}`, () => {
                const schemaValid = validateAgainstSchema(
                    sample.data,
                    'negotiationEnvelope',
                ).valid;

                // v0.1-specific special case: major version 99.0.0 is rejected by the schema but
                // allowed through by parseEnvelope (format validation passes → the version gate is at the verifyEnvelope layer).
                if (sample.id === 'invalid-incompatible-spec-version') {
                    expect(schemaValid).toBe(false);
                    expect(parseEnvelope(sample.data)).toEqual(sample.data);
                    return;
                }

                expect(schemaValid).toBe(false);
                expect(() => parseEnvelope(sample.data)).toThrowError(
                    sample.expectedError ?? 'INVALID_MESSAGE',
                );
            });
        }

        for (const sample of fixture.boundary) {
            it(`handles boundary sample ${sample.id}`, async () => {
                const schemaResult = validateAgainstSchema(
                    sample.data,
                    'negotiationEnvelope',
                );

                // v0.1-specific special case: the clock-skew boundary — needs verifyEnvelope to run with an injected now.
                if (sample.id === 'boundary-clock-skew-exceeded') {
                    expect(schemaResult.valid).toBe(true);
                    const result = await verifyEnvelope(
                        parseEnvelope(sample.data),
                        {
                            resolvePublicKey: () =>
                                Promise.resolve(
                                    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
                                ),
                            now: () =>
                                new Date('2026-01-01T00:05:00.001Z').getTime(),
                        },
                    );
                    expect(result.valid).toBe(false);
                    return;
                }

                const expected = sample.valid ?? true;
                expect(schemaResult.valid).toBe(expected);

                if (expected) {
                    expect(parseEnvelope(sample.data)).toEqual(sample.data);
                }
            });
        }
    });
}
