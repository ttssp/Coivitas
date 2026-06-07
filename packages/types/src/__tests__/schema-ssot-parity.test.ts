// schema parity guard: prevents drift between inline schemas.ts and published .schema.json.

// Background:
// - inline `packages/types/src/schemas.ts` is the source of truth for runtime AJV validation (loaded by validation.ts);
// - published `packages/types/src/schemas/*.schema.json` is the publish artifact shipped to external consumers, hand-maintained;
// - the first layer of assertions covers specVersionCompat enum + $id + top-level $ref;
// - the second layer of assertions covers action enum / required / allOf subclause count, to detect when the ledger.schema.json
// body lags behind the inline evolution (e.g. delegationDepth / SESSION_SUPERSEDED branches). This test is the "programmatic
// evidence" of the protocol-consistency invariant: v0.3.0 inline and published must give the same valid/invalid verdict for the same v0.3.0 data.

// Naming-mismatch note:
// - inline uses `defs.specVersion` (schemas.ts L125); published uses `$defs.specVersionCompat`.
// - the two are semantically equivalent (the same set of valid specVersion strings); the test handles this legacy naming difference via a mapping table.

// Reference for each namespace's action enum location (inline schemas.ts BUSINESS_ACTION_VOCABULARY = 5 items;
// ledger.actionRecord.action = 6 items including the SESSION_SUPERSEDED control-plane action):
// - authorization.capability.action — 5-item BUSINESS_ACTION_VOCABULARY
// - communication.handshakeChallenge.initiatorCapabilities.items — 5-item BUSINESS_ACTION_VOCABULARY
// - communication.handshakeResponse.responderCapabilities.items — 5-item BUSINESS_ACTION_VOCABULARY
// - identity.agentIdentityDocument.capabilities.items — 5-item BUSINESS_ACTION_VOCABULARY
// - identity.agentCard.capabilitiesDeclared.items — 5-item BUSINESS_ACTION_VOCABULARY
// - ledger.actionRecord.action — 6-item ACTION_VOCABULARY (including SESSION_SUPERSEDED)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
    authorizationSchema,
    communicationSchema,
    encryptionSchema,
    identitySchema,
    ledgerSchema,
} from '../schemas.js';

const __filename = fileURLToPath(import.meta.url);
// __filename = packages/types/src/__tests__/schema-ssot-parity.test.ts
// SRC_ROOT = packages/types/src
const SRC_ROOT = path.resolve(path.dirname(__filename), '..');

interface ActionEnumLocation {
    /** human-readable path describing the assertion location (used for the it name + failure diagnostics) */
    readonly path: string;
    /** navigation path within inline / published $defs (dot-separated) */
    readonly inlineNav: readonly string[];
    readonly publishedNav: readonly string[];
}

interface AllOfShapeAssertion {
    /** top-level document name (looked up under $defs) */
    readonly docName: string;
    /** the expected allOf subclause count for both inline and published must equal this value */
    readonly expectedSubclauseCount: number;
}

interface NamespaceSpec {
    readonly name: string;
    readonly inline: Record<string, unknown>;
    readonly jsonRelPath: string;
    // inline uses 'specVersion'; published uses 'specVersionCompat' (naming mismatch but semantically equivalent).
    readonly inlineSpecVersionKey: 'specVersion';
    readonly publishedSpecVersionKey: 'specVersionCompat';
    // top-level document objects (at least one per namespace), whose properties.specVersion must $ref the def above.
    readonly publishedTopLevelDocs: readonly string[];
    // all action enum occurrences within each namespace (used for enum-equivalence assertions)
    readonly actionEnumLocations: readonly ActionEnumLocation[];
    // top-level document required-array equivalence assertion
    readonly publishedRequiredDocs: readonly string[];
    // top-level document allOf subclause-count equivalence assertion (only ledger has one)
    readonly allOfShapeAssertions: readonly AllOfShapeAssertion[];
    // top-level document if/then shape-existence assertion (applies to communication.negotiationEnvelope +
    // identity.agentIdentityDocument's rotationProof→previousPublicKey, etc.)
    readonly topLevelDocsWithIfThen: readonly string[];
}

const NAMESPACES: readonly NamespaceSpec[] = [
    {
        name: 'authorization',
        inline: authorizationSchema as unknown as Record<string, unknown>,
        jsonRelPath: 'schemas/authorization.schema.json',
        inlineSpecVersionKey: 'specVersion',
        publishedSpecVersionKey: 'specVersionCompat',
        publishedTopLevelDocs: ['capabilityToken'],
        actionEnumLocations: [
            {
                path: 'capability.action',
                inlineNav: ['capability', 'properties', 'action'],
                publishedNav: ['capability', 'properties', 'action'],
            },
        ],
        publishedRequiredDocs: ['capabilityToken'],
        allOfShapeAssertions: [],
        topLevelDocsWithIfThen: [],
    },
    {
        name: 'communication',
        inline: communicationSchema as unknown as Record<string, unknown>,
        jsonRelPath: 'schemas/communication.schema.json',
        inlineSpecVersionKey: 'specVersion',
        publishedSpecVersionKey: 'specVersionCompat',
        publishedTopLevelDocs: ['negotiationEnvelope'],
        actionEnumLocations: [
            {
                path: 'handshakeChallenge.initiatorCapabilities.items',
                inlineNav: [
                    'handshakeChallenge',
                    'properties',
                    'initiatorCapabilities',
                    'items',
                ],
                publishedNav: [
                    'handshakeChallenge',
                    'properties',
                    'initiatorCapabilities',
                    'items',
                ],
            },
            {
                path: 'handshakeResponse.responderCapabilities.items',
                inlineNav: [
                    'handshakeResponse',
                    'properties',
                    'responderCapabilities',
                    'items',
                ],
                publishedNav: [
                    'handshakeResponse',
                    'properties',
                    'responderCapabilities',
                    'items',
                ],
            },
        ],
        publishedRequiredDocs: ['negotiationEnvelope'],
        allOfShapeAssertions: [],
        topLevelDocsWithIfThen: ['negotiationEnvelope'],
    },
    {
        name: 'ledger',
        inline: ledgerSchema as unknown as Record<string, unknown>,
        jsonRelPath: 'schemas/ledger.schema.json',
        inlineSpecVersionKey: 'specVersion',
        publishedSpecVersionKey: 'specVersionCompat',
        publishedTopLevelDocs: ['actionRecord'],
        actionEnumLocations: [
            {
                path: 'actionRecord.action',
                inlineNav: ['actionRecord', 'properties', 'action'],
                publishedNav: ['actionRecord', 'properties', 'action'],
            },
        ],
        publishedRequiredDocs: ['actionRecord'],
        allOfShapeAssertions: [
            // ledger.actionRecord.allOf must have 4 subclauses
            // (specVersion 0.2 / specVersion 0.3 / business action strict mode / SESSION_SUPERSEDED control plane)
            { docName: 'actionRecord', expectedSubclauseCount: 4 },
        ],
        topLevelDocsWithIfThen: [],
    },
    {
        name: 'identity',
        inline: identitySchema as unknown as Record<string, unknown>,
        jsonRelPath: 'schemas/identity.schema.json',
        inlineSpecVersionKey: 'specVersion',
        publishedSpecVersionKey: 'specVersionCompat',
        publishedTopLevelDocs: ['agentIdentityDocument', 'agentCard'],
        actionEnumLocations: [
            {
                path: 'agentIdentityDocument.capabilities.items',
                inlineNav: [
                    'agentIdentityDocument',
                    'properties',
                    'capabilities',
                    'items',
                ],
                publishedNav: [
                    'agentIdentityDocument',
                    'properties',
                    'capabilities',
                    'items',
                ],
            },
            {
                path: 'agentCard.capabilitiesDeclared.items',
                inlineNav: [
                    'agentCard',
                    'properties',
                    'capabilitiesDeclared',
                    'items',
                ],
                publishedNav: [
                    'agentCard',
                    'properties',
                    'capabilitiesDeclared',
                    'items',
                ],
            },
        ],
        publishedRequiredDocs: ['agentIdentityDocument', 'agentCard'],
        allOfShapeAssertions: [],
        // identity.agentIdentityDocument top-level if/then
        // (rotationProof exists → previousPublicKey required; inline schemas.ts and
        // published identity.schema.json are in sync)
        topLevelDocsWithIfThen: ['agentIdentityDocument'],
    },
] as const;

const EXPECTED_NAMESPACE_COUNT = 4;
// identity.resolvedPublicKeys allOf subclause count (fail-closed guard)
// subclause 1: ROTATING → required previous + previousValidBefore
// subclause 2: STABLE/FROZEN → not anyOf [previous, previousValidBefore]
const EXPECTED_RESOLVED_PUBLIC_KEYS_ALLOF_COUNT = 2;

interface JsonSchemaShape {
    $id?: string;
    $defs?: Record<string, unknown>;
}

function loadJson(relPath: string): JsonSchemaShape {
    const raw = fs.readFileSync(path.join(SRC_ROOT, relPath), 'utf8');
    return JSON.parse(raw) as JsonSchemaShape;
}

function getDefs(schema: unknown): Record<string, unknown> {
    const $defs = (schema as JsonSchemaShape).$defs;
    if (!$defs) {
        throw new Error('schema is missing $defs');
    }
    return $defs;
}

function getEnum(def: unknown): readonly string[] {
    const enumValue = (def as { enum?: readonly unknown[] }).enum;
    if (!Array.isArray(enumValue)) {
        throw new Error('def is missing the enum array');
    }
    return enumValue.map(String);
}

/**
 * Recursively retrieves a nested object's field along navPath; throws if any segment is missing (fail-closed).
 */
function navigate(
    root: Record<string, unknown>,
    navPath: readonly string[],
): unknown {
    let cursor: unknown = root;
    for (const segment of navPath) {
        if (cursor === null || cursor === undefined) {
            throw new Error(
                `navigate: cursor null/undefined at segment "${segment}" in path ${navPath.join('.')}`,
            );
        }
        cursor = (cursor as Record<string, unknown>)[segment];
    }
    return cursor;
}

function getRequired(def: unknown): readonly string[] {
    const required = (def as { required?: readonly unknown[] }).required;
    if (!Array.isArray(required)) {
        throw new Error('def is missing the required array');
    }
    return required.map(String);
}

function getAllOfSubclauses(def: unknown): readonly unknown[] {
    const allOf = (def as { allOf?: readonly unknown[] }).allOf;
    if (!Array.isArray(allOf)) {
        throw new Error('def is missing the allOf array');
    }
    return allOf;
}

describe('schema source-of-truth parity (inline schemas.ts ↔ published *.schema.json)', () => {
    // fail-closed: sample-count guard, prevents a silent skip if NAMESPACES is accidentally emptied
    // (mirrors the same-pattern guard in tests/conformance/loadFixtureDir.ts).
    it(`NAMESPACES registry contains exactly ${EXPECTED_NAMESPACE_COUNT} entries (auth + comm + ledger + identity baseline)`, () => {
        expect(NAMESPACES.length).toBe(EXPECTED_NAMESPACE_COUNT);
    });

    for (const ns of NAMESPACES) {
        describe(`${ns.name}`, () => {
            const published = loadJson(ns.jsonRelPath);
            const inlineDefs = getDefs(ns.inline);
            const publishedDefs = getDefs(published);

            // dimension: $id consistency
            it('inline / published $id consistent (guards against $id drift)', () => {
                expect((ns.inline as JsonSchemaShape).$id).toBe(published.$id);
            });

            // dimension: specVersion enum equivalence + tristate coexistence
            it(`specVersion enum equivalent (inline.${ns.inlineSpecVersionKey} ↔ published.${ns.publishedSpecVersionKey}, includes 0.1.0 / 0.2.0 / 0.3.0)`, () => {
                const inlineEnum = [
                    ...getEnum(inlineDefs[ns.inlineSpecVersionKey]),
                ].sort();
                const publishedEnum = [
                    ...getEnum(publishedDefs[ns.publishedSpecVersionKey]),
                ].sort();

                // anti-drift main assertion: both enums must be deep-equal once sorted.
                expect(publishedEnum).toEqual(inlineEnum);

                // tristate-coexistence positive assertion: requires that the 0.3.0 validator MUST accept
                // 0.1.0 / 0.2.0 / 0.3.0.
                expect(publishedEnum).toEqual(['0.1.0', '0.2.0', '0.3.0']);
            });

            // dimension: top-level document specVersion connects to specVersionCompat via $ref
            it.each(ns.publishedTopLevelDocs)(
                'published top-level document %s.specVersion connects to #/$defs/specVersionCompat via $ref (guards against dead code where the enum is upgraded but the top level does not reference it)',
                (docName) => {
                    const doc = publishedDefs[docName] as
                        | {
                              properties?: {
                                  specVersion?: { $ref?: string };
                              };
                          }
                        | undefined;

                    expect(doc).toBeDefined();
                    expect(doc?.properties?.specVersion?.$ref).toBe(
                        '#/$defs/specVersionCompat',
                    );
                },
            );

            // dimension: action enum equivalence (inline ⇄ published at every enum occurrence)
            for (const loc of ns.actionEnumLocations) {
                it(`${loc.path} action enum equivalent (guards against ledger-style body drift)`, () => {
                    const inlineEnum = [
                        ...getEnum(navigate(inlineDefs, loc.inlineNav)),
                    ].sort();
                    const publishedEnum = [
                        ...getEnum(navigate(publishedDefs, loc.publishedNav)),
                    ].sort();
                    expect(publishedEnum).toEqual(inlineEnum);
                });
            }

            // dimension: top-level document required-array equivalence
            it.each(ns.publishedRequiredDocs)(
                '%s.required array equivalent (guards against required-field-set drift)',
                (docName) => {
                    const inlineReq = [
                        ...getRequired(inlineDefs[docName]),
                    ].sort();
                    const publishedReq = [
                        ...getRequired(publishedDefs[docName]),
                    ].sort();
                    expect(publishedReq).toEqual(inlineReq);
                },
            );

            // dimension: allOf subclause-count equivalence (only ledger.actionRecord)
            for (const assertion of ns.allOfShapeAssertions) {
                it(`${assertion.docName}.allOf subclause count = ${assertion.expectedSubclauseCount} (4 subclauses: specVersion 0.2 / 0.3 / business action / SESSION_SUPERSEDED)`, () => {
                    const inlineAllOf = getAllOfSubclauses(
                        inlineDefs[assertion.docName],
                    );
                    const publishedAllOf = getAllOfSubclauses(
                        publishedDefs[assertion.docName],
                    );
                    expect(inlineAllOf).toHaveLength(
                        assertion.expectedSubclauseCount,
                    );
                    expect(publishedAllOf).toHaveLength(
                        assertion.expectedSubclauseCount,
                    );
                });
            }

            // dimension: top-level document if/then shape existence. Covers communication.negotiationEnvelope +
            // identity.agentIdentityDocument (rotationProof→previousPublicKey).
            // Does not deep-compare contents (const literal differences do not affect the semantic verdict).
            for (const docName of ns.topLevelDocsWithIfThen) {
                it(`${docName} top-level if/then shape exists (guards against inline ↔ published conditional-branch drift)`, () => {
                    const inlineDoc = inlineDefs[docName] as
                        | { if?: unknown; then?: unknown }
                        | undefined;
                    const publishedDoc = publishedDefs[docName] as
                        | { if?: unknown; then?: unknown }
                        | undefined;

                    expect(inlineDoc?.if).toBeDefined();
                    expect(inlineDoc?.then).toBeDefined();
                    expect(publishedDoc?.if).toBeDefined();
                    expect(publishedDoc?.then).toBeDefined();
                });
            }

            // dimension (communication):
            // handshakeAckBody sub-schema equivalence — prevents the v0.4-added
            // accepted=true → response.sessionId minLength≥1 if/then constraint from drifting between inline ↔
            // published.
            if (ns.name === 'communication') {
                it('handshakeAckBody sub-schema equivalent (required keys + if/then shape exists)', () => {
                    const inlineAck = inlineDefs.handshakeAckBody as
                        | {
                              properties?: Record<string, unknown>;
                              required?: readonly unknown[];
                              if?: unknown;
                              then?: unknown;
                          }
                        | undefined;
                    const publishedAck = publishedDefs.handshakeAckBody as
                        | {
                              properties?: Record<string, unknown>;
                              required?: readonly unknown[];
                              if?: unknown;
                              then?: unknown;
                          }
                        | undefined;

                    expect(inlineAck).toBeDefined();
                    expect(publishedAck).toBeDefined();

                    // properties keys deep-equal once sorted
                    const inlineKeys = Object.keys(
                        inlineAck?.properties ?? {},
                    ).sort();
                    const publishedKeys = Object.keys(
                        publishedAck?.properties ?? {},
                    ).sort();
                    expect(publishedKeys).toEqual(inlineKeys);
                    expect(inlineKeys).toEqual(
                        ['accepted', 'reason', 'response'].sort(),
                    );

                    // required array equivalent (includes 'accepted' + 'response')
                    const inlineReq = [
                        ...getRequired(inlineAck as unknown),
                    ].sort();
                    const publishedReq = [
                        ...getRequired(publishedAck as unknown),
                    ].sort();
                    expect(publishedReq).toEqual(inlineReq);
                    expect(inlineReq).toEqual(['accepted', 'response']);

                    // if/then conditional-branch existence (accepted=true → sessionId minLength≥1)
                    expect(inlineAck?.if).toBeDefined();
                    expect(inlineAck?.then).toBeDefined();
                    expect(publishedAck?.if).toBeDefined();
                    expect(publishedAck?.then).toBeDefined();
                });

                // handshakeChallenge / handshakeResponse scalar fields (challengeId / nonce)
                // format/pattern must be equivalent between inline ↔ published. v0.1-v0.3 published uses
                // a generic 'minLength: 1', inline uses uuid/hash $ref → code generated externally from published
                // would accept a payload that the runtime rejects.
                it('handshakeChallenge / handshakeResponse scalar field format equivalent (challengeId uuid + nonce hash)', () => {
                    type FieldShape = {
                        $ref?: string;
                        type?: string;
                        pattern?: string;
                    };
                    type DocShape = {
                        properties?: Record<string, FieldShape>;
                    };
                    const checkFieldEquivalent = (
                        inlineField: FieldShape | undefined,
                        publishedField: FieldShape | undefined,
                        fieldPath: string,
                    ) => {
                        expect(
                            inlineField,
                            `inline ${fieldPath} should exist`,
                        ).toBeDefined();
                        expect(
                            publishedField,
                            `published ${fieldPath} should exist`,
                        ).toBeDefined();
                        // resolve the inline $ref (uuid / hash) → take the target def's pattern
                        const resolveRef = (
                            field: FieldShape | undefined,
                            defs: Record<string, unknown>,
                        ): string | undefined => {
                            if (!field) return undefined;
                            if (field.pattern) return field.pattern;
                            if (field.$ref) {
                                const refKey = field.$ref.replace(
                                    '#/$defs/',
                                    '',
                                );
                                const target = defs[refKey] as
                                    | FieldShape
                                    | undefined;
                                return target?.pattern;
                            }
                            return undefined;
                        };
                        const inlinePattern = resolveRef(
                            inlineField,
                            inlineDefs,
                        );
                        const publishedPattern = resolveRef(
                            publishedField,
                            publishedDefs,
                        );
                        expect(
                            publishedPattern,
                            `${fieldPath} pattern parity`,
                        ).toBe(inlinePattern);
                    };
                    const inlineChallenge = inlineDefs.handshakeChallenge as
                        | DocShape
                        | undefined;
                    const publishedChallenge =
                        publishedDefs.handshakeChallenge as
                            | DocShape
                            | undefined;
                    const inlineResponse = inlineDefs.handshakeResponse as
                        | DocShape
                        | undefined;
                    const publishedResponse =
                        publishedDefs.handshakeResponse as DocShape | undefined;
                    expect(inlineChallenge).toBeDefined();
                    expect(publishedChallenge).toBeDefined();
                    expect(inlineResponse).toBeDefined();
                    expect(publishedResponse).toBeDefined();
                    // challenge.challengeId / challenge.nonce
                    checkFieldEquivalent(
                        inlineChallenge?.properties?.['challengeId'],
                        publishedChallenge?.properties?.['challengeId'],
                        'handshakeChallenge.challengeId',
                    );
                    checkFieldEquivalent(
                        inlineChallenge?.properties?.['nonce'],
                        publishedChallenge?.properties?.['nonce'],
                        'handshakeChallenge.nonce',
                    );
                    // response.challengeId / response.nonce
                    checkFieldEquivalent(
                        inlineResponse?.properties?.['challengeId'],
                        publishedResponse?.properties?.['challengeId'],
                        'handshakeResponse.challengeId',
                    );
                    checkFieldEquivalent(
                        inlineResponse?.properties?.['nonce'],
                        publishedResponse?.properties?.['nonce'],
                        'handshakeResponse.nonce',
                    );
                });
            }

            // dimension (identity): identity.resolvedPublicKeys sub-schema equivalence
            // (the inline AJV schema must contain the previousValidBefore field
            // and stay in sync with published, otherwise a real ROTATING payload from resolvePublicKeys() would be rejected by AJV)
            if (ns.name === 'identity') {
                it('resolvedPublicKeys sub-schema equivalent (properties keys + allOf subclause count)', () => {
                    const inlineRpk = inlineDefs.resolvedPublicKeys as
                        | {
                              properties?: Record<string, unknown>;
                              allOf?: readonly unknown[];
                          }
                        | undefined;
                    const publishedRpk = publishedDefs.resolvedPublicKeys as
                        | {
                              properties?: Record<string, unknown>;
                              allOf?: readonly unknown[];
                          }
                        | undefined;

                    expect(inlineRpk).toBeDefined();
                    expect(publishedRpk).toBeDefined();

                    // properties keys deep-equal once sorted (includes previousValidBefore)
                    const inlineKeys = Object.keys(
                        inlineRpk?.properties ?? {},
                    ).sort();
                    const publishedKeys = Object.keys(
                        publishedRpk?.properties ?? {},
                    ).sort();
                    expect(publishedKeys).toEqual(inlineKeys);
                    // explicit positive assertion: includes previousValidBefore
                    expect(inlineKeys).toContain('previousValidBefore');

                    // allOf subclause-count equivalence + fail-closed guard
                    expect(inlineRpk?.allOf).toHaveLength(
                        EXPECTED_RESOLVED_PUBLIC_KEYS_ALLOF_COUNT,
                    );
                    expect(publishedRpk?.allOf).toHaveLength(
                        EXPECTED_RESOLVED_PUBLIC_KEYS_ALLOF_COUNT,
                    );
                });
            }
        });
    }
});

// audit.auditResourceBinding subclause-alignment parity
// guards against inline ↔ published drift on the 'ledger.head' subclause; hitting this drift would trigger a governor bootstrap
// deadlock (the schema lacks the 'ledger.head' subclause → the resource binding the router receives fails schema validation).
describe('audit.auditResourceBinding parity', () => {
    const expectedRoutes = [
        'records.list',
        'records.get',
        'records.verify',
        'records.chain.verify',
        'ledger.head',
    ] as const;

    function extractRoutes(arb: unknown): readonly string[] {
        const oneOf = (arb as { oneOf?: readonly unknown[] }).oneOf ?? [];
        return oneOf.map((clause) => {
            const route = ((
                clause as {
                    properties?: { route?: { const?: unknown } };
                }
            ).properties?.route?.const ?? '') as string;
            return route;
        });
    }

    it('inline schemas.ts auditResourceBinding contains 5 oneOf subclauses (including ledger.head)', async () => {
        const { auditSchema } = await import('../schemas.js');
        const inlineDefs = getDefs(
            auditSchema as unknown as Record<string, unknown>,
        );
        const inlineRoutes = extractRoutes(inlineDefs.auditResourceBinding);
        expect([...inlineRoutes].sort()).toEqual([...expectedRoutes].sort());
    });

    it('published audit.schema.json auditResourceBinding contains 5 oneOf subclauses (including ledger.head)', () => {
        const published = loadJson('schemas/audit.schema.json');
        const publishedDefs = getDefs(published);
        const publishedRoutes = extractRoutes(
            publishedDefs.auditResourceBinding,
        );
        expect([...publishedRoutes].sort()).toEqual([...expectedRoutes].sort());
    });

    it('inline ↔ published auditResourceBinding routes equivalent (anti-drift safeguard)', async () => {
        const { auditSchema } = await import('../schemas.js');
        const inlineDefs = getDefs(
            auditSchema as unknown as Record<string, unknown>,
        );
        const published = loadJson('schemas/audit.schema.json');
        const publishedDefs = getDefs(published);
        const inlineRoutes = [
            ...extractRoutes(inlineDefs.auditResourceBinding),
        ].sort();
        const publishedRoutes = [
            ...extractRoutes(publishedDefs.auditResourceBinding),
        ].sort();
        expect(publishedRoutes).toEqual(inlineRoutes);
    });
});

// encryption parity (2026-05-01) — encryptionSchema inline ↔ published drift protection
// prevents schemas.ts encryptionSchema.$defs and schemas/encryption.schema.json $defs from drifting on the
// required-field list / $id (EncryptedBody 6 required + MessageReceipt 6 required).
describe('encryption parity: inline encryptionSchema ↔ published encryption.schema.json', () => {
    function loadEncryptionPublished(): Record<string, unknown> {
        const p = path.resolve(SRC_ROOT, 'schemas/encryption.schema.json');
        return JSON.parse(fs.readFileSync(p, 'utf8')) as Record<
            string,
            unknown
        >;
    }

    it('$id matches', () => {
        const published = loadEncryptionPublished();
        expect(encryptionSchema.$id).toEqual(published.$id);
    });

    it('encryptedBody required fields equivalent inline ↔ published', () => {
        const published = loadEncryptionPublished();
        const publishedDefs = published.$defs as Record<
            string,
            { required?: string[] }
        >;
        const inlineRequired = [
            ...encryptionSchema.$defs.encryptedBody.required,
        ].sort();
        const publishedRequired = [
            ...(publishedDefs.encryptedBody.required ?? []),
        ].sort();
        expect(inlineRequired).toEqual(publishedRequired);
    });

    it('messageReceipt required fields equivalent inline ↔ published', () => {
        const published = loadEncryptionPublished();
        const publishedDefs = published.$defs as Record<
            string,
            { required?: string[] }
        >;
        const inlineRequired = [
            ...encryptionSchema.$defs.messageReceipt.required,
        ].sort();
        const publishedRequired = [
            ...(publishedDefs.messageReceipt.required ?? []),
        ].sort();
        expect(inlineRequired).toEqual(publishedRequired);
    });

    it('encryptedBodyType enum equivalent inline ↔ published', () => {
        const published = loadEncryptionPublished();
        const publishedDefs = published.$defs as Record<
            string,
            { enum?: string[] }
        >;
        const inlineEnum = [
            ...encryptionSchema.$defs.encryptedBodyType.enum,
        ].sort();
        const publishedEnum = [
            ...(publishedDefs.encryptedBodyType.enum ?? []),
        ].sort();
        expect(inlineEnum).toEqual(publishedEnum);
    });
});
