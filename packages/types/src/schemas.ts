import {
    SESSION_GOVERNOR_DID,
    SESSION_SUPERSEDED_REASONS,
} from './action-vocabulary.js';
import { MAX_DELEGATION_DEPTH } from './authorization.js';
import { ACTION_VOCABULARY, MESSAGE_TYPES } from './base.js';

// result status defines only the three values SUCCESS/REJECTED/ERROR; PENDING_APPROVAL
// is a PolicyEngine Step 2 intermediate state that never lands in the ledger, so it is not in the result status enum.
const ACTION_RESULT_STATUSES = ['SUCCESS', 'REJECTED', 'ERROR'] as const;
const PROTOCOL_ERROR_CODES = [
    'IDENTITY_NOT_FOUND',
    'IDENTITY_ALREADY_EXISTS',
    'SIGNATURE_INVALID',
    'TOKEN_EXPIRED',
    'TOKEN_REVOKED',
    'SESSION_TOKEN_MISMATCH',
    'SCOPE_EXCEEDED',
    'BINDING_PROOF_INVALID',
    'HANDSHAKE_FAILED',
    'HANDSHAKE_REJECTED',
    'HANDSHAKE_TIMEOUT',
    'INVALID_HANDSHAKE',
    'INVALID_MESSAGE',
    'SESSION_NOT_FOUND',
    'SESSION_CLOSED',
    'SPEC_VERSION_MISMATCH',
    'CLOCK_SKEW_EXCEEDED',
    'ACTION_REJECTED',
    'HUMAN_APPROVAL_REQUIRED',
    'INTERNAL_ERROR',
    'RATE_LIMIT_EXCEEDED',
    // Added
    'AGENT_CARD_NOT_FOUND',
    'ATTENUATION_VIOLATED',
    'DELEGATION_CHAIN_INVALID',
    'DEPTH_EXCEEDED',
    'PARENT_TOKEN_REVOKED',
    'PARENT_TOKEN_NOT_FOUND',
    'PARENT_TOKEN_EXPIRED',
    'CYCLE_DETECTED',
    'ROOT_NOT_PRINCIPAL',
    'DELEGATOR_MISMATCH',
    'SCOPE_TYPE_UNKNOWN',
    'METER_INTEGRITY_COMPROMISED',
    'FEDERATED_RESOLUTION_FAILED',
    'FEDERATED_VERSION_CONFLICT',
    'TRANSPORT_ERROR',
    'SESSION_RESUMED',
    'SESSION_SUPERSEDED',
    'AUDIT_ACCESS_DENIED',
    // Added in v0.2
    'AUDIT_NONCE_REPLAY',
    'SCOPE_PLUGIN_CONFLICT',
    'SCOPE_PLUGIN_SANDBOX_VIOLATION',
    'SESSION_HANDLE_REVOKED',
    'DECRYPTION_FAILED',
    'REKEY_FAILED',
    'ENCRYPTION_REQUIRED',
    'ENCRYPTION_REQUIRES_CAPABILITY_TOKEN',
    'INVALID_ENCRYPTED_BODY',
    'INVALID_ENCRYPTION_OFFER',
    'UNEXPECTED_RECEIPT_FOR_RECEIPT',
    // Added in v0.2.
    // Error codes added for the Envelope-based discovery channel:
    // - DISCOVERY_NOT_SUPPORTED: returned by the dispatcher when no handler is registered.
    // - DISCOVERY_TARGET_MISMATCH: rejected by the receiver when response.agentDid !== request.targetDid.
    // Note: the DISCOVERY_DHT_* / DISCOVERY_BROADCAST_* / DISCOVERY_REGISTRY_* namespaces
    // are permanently reserved for later versions and must not be used now.
    'DISCOVERY_NOT_SUPPORTED',
    'DISCOVERY_TARGET_MISMATCH',
    // The full set of E2E encryption error codes, completed.
    // All 33 error codes must be registered in errors.ts; this is the dual-source alignment.
    'ENCRYPTION_UNSUPPORTED',
    'KEY_AGREEMENT_FAILED',
    'AEAD_NONCE_REUSED',
    'ENCRYPTED_REPLAY_DETECTED',
    'REKEY_REJECTED_BY_AUTHORIZATION',
    'ENCRYPTION_DOWNGRADE_DETECTED',
    'EPHEMERAL_KEY_INVALID',
    'RECEIPT_REQUIRED',
    'RECEIPT_VERIFICATION_FAILED',
    'RECEIPT_SIGNATURE_INVALID',
    'RECEIPT_ENVELOPE_MISMATCH',
    'RECEIPT_SESSION_MISMATCH',
    'RECEIPT_PARAMS_HASH_MISMATCH',
    'RECEIPT_STALE',
    'RECEIPT_TIMEOUT',
    'RECEIPT_SHAPE_WITHOUT_RECEIPT_TYPE',
    'INVALID_RECEIPT_PAYLOAD',
    'CRYPTO_STATE_LOST',
    'AUDIT_INTENT_PERSIST_FAILED',
    'AUDIT_INTENT_TIMEOUT',
    'AUDIT_RECORD_UPDATE_FAILED',
    'POLICY_REQUIRES_OUTBOX',
    'ENCRYPTION_MIRROR_PROOF_UNAVAILABLE',
    // Keep PROTOCOL_ERROR_CODES in sync with the ProtocolErrorCode union
    // (otherwise the protocolError schema would reject legitimate thrown errors).
    'METRIC_SOURCE_NOT_IMPLEMENTED',
] as const;

// Audit query action enum.
// An audit query may filter on SESSION_SUPERSEDED (control-plane records can be read by an authorized requester via the governor lane).
const ACTION_VOCABULARY_AUDIT = [...ACTION_VOCABULARY] as const;

// Business authorization action enum = ACTION_VOCABULARY minus SESSION_SUPERSEDED.
// Control-plane actions (SESSION_SUPERSEDED, actor=did:system:session-governor)
// are legal only in ActionRecord.action (the ledger control plane) and MUST NOT appear in:
// - CapabilityToken.capabilities[*].scope... → capability.action
// - AgentIdentityDocument.capabilities[*]
// - AgentCard.capabilitiesDeclared[*]
// - HandshakeChallenge.initiatorCapabilities[*]
// - HandshakeResponse.responderCapabilities[*]
// Boundary statement: control-plane actions do not issue an envelope / token; they serve only as the actor identifier for ActionRecord.agentDid /
// principalDid.
// Semantically independent from ACTION_VOCABULARY_AUDIT: the latter governs audit query filtering; this governs schema fail-closed.
const BUSINESS_ACTION_VOCABULARY = ACTION_VOCABULARY.filter(
    (action) => action !== 'SESSION_SUPERSEDED',
);

const schemaVersion = 'http://json-schema.org/draft-07/schema#';
const didPattern =
    '^did:[a-z][a-z0-9-]*:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$';
const didKeyPattern = '^did:key:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*$';
const didAgentPattern = '^did:agent:[a-f0-9]{40}$';
const hex64Pattern = '^[0-9a-f]{64}$';
const hex128Pattern = '^[0-9a-f]{128}$';
// From v0.2.0 onward, signature/hash/public-key fields default to base64url output;
// AJV accepts both hex (backward compatible with v0.1.0) and base64url (v0.2.0+).
// Ed25519 signature 64 bytes → base64url 86 chars (unpadded)
const base64url86Pattern = '^[A-Za-z0-9_-]{86}$';
// SHA-256 hash / Ed25519 public key 32 bytes → base64url 43 chars (unpadded)
const base64url43Pattern = '^[A-Za-z0-9_-]{43}$';
const timestampPattern =
    '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$';
const uuidV4Pattern =
    '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const uuidPattern =
    '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const capabilityTokenIdPattern =
    '^urn:cap:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const recordIdPattern =
    '^rec-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
// EncryptedBody.keyId: the first 16 bytes of SHA-256.
// 16 bytes -> hex 32 chars or base64url 22 chars (three-state coexistence: v0.1.0/v0.2.0 hex;
// v0.3.0 defaults to base64url but accepts hex input for backward reads).
const keyIdPattern = '^([0-9a-f]{32}|[A-Za-z0-9_-]{22})$';

const defs = {
    did: {
        type: 'string',
        pattern: didPattern,
    },
    didKey: {
        type: 'string',
        pattern: didKeyPattern,
    },
    didAgent: {
        type: 'string',
        pattern: didAgentPattern,
    },
    // anyOf accepts both hex (v0.1.0) and base64url (v0.2.0+).
    signature: {
        type: 'string',
        anyOf: [{ pattern: hex128Pattern }, { pattern: base64url86Pattern }],
    },
    hash: {
        type: 'string',
        anyOf: [{ pattern: hex64Pattern }, { pattern: base64url43Pattern }],
    },
    publicKey: {
        type: 'string',
        anyOf: [{ pattern: hex64Pattern }, { pattern: base64url43Pattern }],
    },
    timestamp: {
        type: 'string',
        pattern: timestampPattern,
    },
    specVersion: {
        type: 'string',
        enum: ['0.1.0', '0.2.0', '0.3.0'],
    },
    uuidV4: {
        type: 'string',
        pattern: uuidV4Pattern,
    },
    uuid: {
        type: 'string',
        pattern: uuidPattern,
    },
    capabilityTokenId: {
        type: 'string',
        pattern: capabilityTokenIdPattern,
    },
    recordId: {
        type: 'string',
        anyOf: [{ pattern: uuidV4Pattern }, { pattern: recordIdPattern }],
    },
} as const;

export const identitySchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/identity.schema.json',
    $defs: {
        ...defs,
        serviceEndpoint: {
            type: 'object',
            properties: {
                id: { type: 'string', minLength: 1 },
                type: { type: 'string', minLength: 1 },
                url: { type: 'string', pattern: '^https://.+' },
            },
            required: ['id', 'type', 'url'],
            additionalProperties: false,
        },
        principalIdentity: {
            type: 'object',
            properties: {
                did: { $ref: '#/$defs/didKey' },
                publicKey: { $ref: '#/$defs/publicKey' },
                displayName: { type: 'string', maxLength: 100 },
                createdAt: { $ref: '#/$defs/timestamp' },
            },
            required: ['did', 'publicKey', 'createdAt'],
            additionalProperties: false,
        },
        bindingProof: {
            type: 'object',
            properties: {
                principalDid: { $ref: '#/$defs/didKey' },
                agentDid: { $ref: '#/$defs/didAgent' },
                issuedAt: { $ref: '#/$defs/timestamp' },
                expiresAt: {
                    anyOf: [{ $ref: '#/$defs/timestamp' }, { type: 'null' }],
                },
                signature: { $ref: '#/$defs/signature' },
            },
            required: [
                'principalDid',
                'agentDid',
                'issuedAt',
                'expiresAt',
                'signature',
            ],
            additionalProperties: false,
        },
        // Added: RotationProof schema.
        rotationProof: {
            type: 'object',
            properties: {
                oldPublicKey: { $ref: '#/$defs/publicKey' },
                newPublicKey: { $ref: '#/$defs/publicKey' },
                oldKeySignature: { $ref: '#/$defs/signature' },
                newKeySignature: { $ref: '#/$defs/signature' },
                principalSignature: { $ref: '#/$defs/signature' },
                agentDid: { $ref: '#/$defs/didAgent' },
                rotatedAt: { $ref: '#/$defs/timestamp' },
            },
            required: [
                'oldPublicKey',
                'newPublicKey',
                'oldKeySignature',
                'newKeySignature',
                'principalSignature',
                'agentDid',
                'rotatedAt',
            ],
            additionalProperties: false,
        },
        // Added in v0.3.0 (key rotation state machine).
        keyRotationState: {
            type: 'string',
            enum: ['STABLE', 'ROTATING', 'FROZEN'],
        },
        resolvedPublicKeys: {
            type: 'object',
            properties: {
                current: { $ref: '#/$defs/publicKey' },
                previous: { $ref: '#/$defs/publicKey' },
                // cutoff field, aligned with the ResolvedPublicKeys TS type.
                // Security invariant: an old key accepts only artifacts whose signing time is ≤ previousValidBefore,
                // preventing an attacker from issuing a new token with an old key after rotation (fail-closed security constraint).
                previousValidBefore: { $ref: '#/$defs/timestamp' },
                rotationState: { $ref: '#/$defs/keyRotationState' },
            },
            required: ['current', 'rotationState'],
            additionalProperties: false,
            // Semantic constraints (fail-closed):
            // - ROTATING: previous + previousValidBefore both required (including cutoff)
            // - STABLE/FROZEN: neither previous nor previousValidBefore may appear
            // (otherwise signature verification would fall back to the previous path, violating STABLE semantics)
            allOf: [
                {
                    if: {
                        properties: { rotationState: { const: 'ROTATING' } },
                        required: ['rotationState'],
                    },
                    then: {
                        required: ['previous', 'previousValidBefore'],
                    },
                },
                {
                    if: {
                        properties: {
                            rotationState: { enum: ['STABLE', 'FROZEN'] },
                        },
                        required: ['rotationState'],
                    },
                    then: {
                        not: {
                            anyOf: [
                                { required: ['previous'] },
                                { required: ['previousValidBefore'] },
                            ],
                        },
                    },
                },
            ],
        },
        agentIdentityDocument: {
            type: 'object',
            properties: {
                id: { $ref: '#/$defs/didAgent' },
                specVersion: { $ref: '#/$defs/specVersion' },
                principalDid: { $ref: '#/$defs/didKey' },
                publicKey: { $ref: '#/$defs/publicKey' },
                bindingProof: { $ref: '#/$defs/bindingProof' },
                capabilities: {
                    type: 'array',
                    items: {
                        type: 'string',
                        // Control-plane isolation: AgentIdentityDocument.capabilities does not accept control-plane actions.
                        enum: [...BUSINESS_ACTION_VOCABULARY],
                    },
                    maxItems: 20,
                    uniqueItems: true,
                },
                serviceEndpoints: {
                    type: 'array',
                    items: { $ref: '#/$defs/serviceEndpoint' },
                },
                createdAt: { $ref: '#/$defs/timestamp' },
                updatedAt: { $ref: '#/$defs/timestamp' },
                // format change #1
                version: { type: 'integer', minimum: 1 },
                previousPublicKey: { $ref: '#/$defs/publicKey' },
                rotationProof: { $ref: '#/$defs/rotationProof' },
            },
            required: [
                'id',
                'specVersion',
                'principalDid',
                'publicKey',
                'bindingProof',
                'createdAt',
                'updatedAt',
            ],
            // When rotationProof is present, previousPublicKey must also be present.
            if: { required: ['rotationProof'] },
            then: { required: ['previousPublicKey'] },
            additionalProperties: false,
        },
        // Added: AgentCard schema (discovery layer).
        agentCard: {
            type: 'object',
            properties: {
                did: { $ref: '#/$defs/didAgent' },
                specVersion: { $ref: '#/$defs/specVersion' },
                // Discovery-layer field constraints.
                displayName: { type: 'string', maxLength: 128 },
                description: { type: 'string', maxLength: 1024 },
                serviceEndpoints: {
                    type: 'array',
                    items: { $ref: '#/$defs/serviceEndpoint' },
                },
                capabilitiesDeclared: {
                    type: 'array',
                    items: {
                        type: 'string',
                        // Control-plane isolation: AgentCard.capabilitiesDeclared does not accept control-plane actions.
                        enum: [...BUSINESS_ACTION_VOCABULARY],
                    },
                    maxItems: 20,
                    uniqueItems: true,
                },
                publicKey: { $ref: '#/$defs/publicKey' },
                documentVersion: { type: 'integer', minimum: 1 },
                updatedAt: { $ref: '#/$defs/timestamp' },
                signature: { $ref: '#/$defs/signature' },
            },
            required: [
                'did',
                'specVersion',
                'serviceEndpoints',
                'capabilitiesDeclared',
                'publicKey',
                'documentVersion',
                'updatedAt',
                'signature',
            ],
            additionalProperties: false,
        },
    },
} as const;

export const authorizationSchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/authorization.schema.json',
    $defs: {
        ...defs,
        allowlistScope: {
            type: 'object',
            properties: {
                type: { const: 'allowlist' },
                field: { type: 'string', minLength: 1 },
                values: {
                    type: 'array',
                    items: { type: 'string', minLength: 1 },
                    minItems: 1,
                    maxItems: 100,
                },
            },
            required: ['type', 'field', 'values'],
            additionalProperties: false,
        },
        numericLimitScope: {
            type: 'object',
            properties: {
                type: { const: 'numeric_limit' },
                field: { type: 'string', minLength: 1 },
                max: { type: 'number', minimum: 0 },
                currency: { type: 'string', minLength: 3, maxLength: 3 },
            },
            required: ['type', 'field', 'max'],
            additionalProperties: false,
        },
        // Format change #2a: TemporalScope (time-window constraint).
        recurringWindow: {
            type: 'object',
            properties: {
                // Strictly limited to HH:MM, hours 00–23, minutes 00–59.
                startTime: {
                    type: 'string',
                    pattern: '^([01][0-9]|2[0-3]):[0-5][0-9]$',
                },
                endTime: {
                    type: 'string',
                    pattern: '^([01][0-9]|2[0-3]):[0-5][0-9]$',
                },
                // When explicitly provided, must contain at least one item; omitted = no day-of-week restriction.
                daysOfWeek: {
                    type: 'array',
                    items: { type: 'integer', minimum: 1, maximum: 7 },
                    uniqueItems: true,
                    minItems: 1,
                },
                timezone: { type: 'string', minLength: 1 },
            },
            required: ['startTime', 'endTime', 'timezone'],
            additionalProperties: false,
        },
        temporalScope: {
            type: 'object',
            properties: {
                type: { const: 'temporal_scope' },
                notBefore: { $ref: '#/$defs/timestamp' },
                notAfter: { $ref: '#/$defs/timestamp' },
                recurringWindow: { $ref: '#/$defs/recurringWindow' },
            },
            required: ['type', 'notBefore', 'notAfter'],
            additionalProperties: false,
        },
        // Format change #2b: CumulativeLimitScope (cumulative limit).
        // source is extended to a three-state enum.
        meterFieldRef: {
            type: 'object',
            properties: {
                source: {
                    type: 'string',
                    enum: [
                        'action_record',
                        'external_witness',
                        'consensus_meter',
                    ] as const,
                },
                metric: { type: 'string', minLength: 1 },
                unit: { type: 'string' },
                precision: { type: 'integer', minimum: 0 },
            },
            required: ['source', 'metric'],
            additionalProperties: false,
        },
        cumulativeLimitScope: {
            type: 'object',
            properties: {
                type: { const: 'cumulative_limit' },
                meterField: { $ref: '#/$defs/meterFieldRef' },
                max: { type: 'number', minimum: 0 },
                window: {
                    type: 'string',
                    enum: ['hour', 'day', 'week', 'month'],
                },
                currency: { type: 'string', minLength: 3, maxLength: 3 },
            },
            required: ['type', 'meterField', 'max', 'window'],
            additionalProperties: false,
        },
        // The Scope union is extended to 4 kinds (a 0.2.0 Token may use all of them; 0.1.0 runtime is still bound by semantic validation)
        scope: {
            oneOf: [
                { $ref: '#/$defs/allowlistScope' },
                { $ref: '#/$defs/numericLimitScope' },
                { $ref: '#/$defs/temporalScope' },
                { $ref: '#/$defs/cumulativeLimitScope' },
            ],
        },
        capability: {
            type: 'object',
            properties: {
                // Control-plane isolation: CapabilityToken.capabilities[*].action does not accept control-plane actions.
                action: {
                    type: 'string',
                    enum: [...BUSINESS_ACTION_VOCABULARY],
                },
                scope: { $ref: '#/$defs/scope' },
            },
            required: ['action', 'scope'],
            additionalProperties: false,
        },
        tokenProof: {
            type: 'object',
            properties: {
                type: { const: 'Ed25519Signature2026' },
                created: { $ref: '#/$defs/timestamp' },
                // Relaxation:
                // for a child Token containing a delegationChain, the top-level proof is issued by the final delegated agent,
                // and verificationMethod points to did:agent:...#key-1.
                // In non-delegation scenarios did:key is still required; this constraint is validated by the runtime semantic layer, not enforced in the Schema.
                verificationMethod: {
                    type: 'string',
                    pattern:
                        '^did:(?:key:[a-zA-Z0-9._%-]+(?::[a-zA-Z0-9._%-]+)*|agent:[a-f0-9]{40})#key-1$',
                },
                value: { $ref: '#/$defs/signature' },
            },
            required: ['type', 'created', 'verificationMethod', 'value'],
            additionalProperties: false,
        },
        // Format change #3: DelegationProof (delegation chain proof).
        // dc v0.3 net addition: the dcVersion optional field (independent namespace mode;
        // when omitted, the validator falls back to token.specVersion; v0.1 compatibility path).
        delegationProof: {
            type: 'object',
            properties: {
                parentTokenId: { type: 'string', minLength: 1 },
                delegatorDid: { $ref: '#/$defs/did' },
                delegateeDid: { $ref: '#/$defs/didAgent' },
                parentCapabilities: {
                    type: 'array',
                    items: { $ref: '#/$defs/capability' },
                    minItems: 1,
                    maxItems: 20,
                },
                parentExpiresAt: { $ref: '#/$defs/timestamp' },
                attenuatedCapabilities: {
                    type: 'array',
                    items: { $ref: '#/$defs/capability' },
                    minItems: 1,
                    maxItems: 20,
                },
                proof: { $ref: '#/$defs/tokenProof' },
                // dc v0.3 net addition: the dcVersion optional field
                // semver pattern: x.y.z (aligned with the DC_VERSION constant '0.3.0')
                dcVersion: {
                    type: 'string',
                    pattern: '^[0-9]+\\.[0-9]+\\.[0-9]+$',
                },
            },
            required: [
                'parentTokenId',
                'delegatorDid',
                'delegateeDid',
                'parentCapabilities',
                'parentExpiresAt',
                'attenuatedCapabilities',
                'proof',
            ],
            additionalProperties: false,
        },
        capabilityToken: {
            type: 'object',
            properties: {
                id: { $ref: '#/$defs/capabilityTokenId' },
                specVersion: { $ref: '#/$defs/specVersion' },
                issuerDid: { $ref: '#/$defs/didKey' },
                principalDid: { $ref: '#/$defs/didKey' },
                issuedTo: { $ref: '#/$defs/didAgent' },
                issuedAt: { $ref: '#/$defs/timestamp' },
                expiresAt: { $ref: '#/$defs/timestamp' },
                capabilities: {
                    type: 'array',
                    items: { $ref: '#/$defs/capability' },
                    minItems: 1,
                    maxItems: 20,
                },
                revocationUrl: {
                    type: 'string',
                    pattern: '^https://.+\\{id\\}.*$',
                },
                proof: { $ref: '#/$defs/tokenProof' },
                // Format change #3
                delegationChain: {
                    type: 'array',
                    items: { $ref: '#/$defs/delegationProof' },
                    maxItems: 5,
                },
            },
            required: [
                'id',
                'specVersion',
                'issuerDid',
                'principalDid',
                'issuedTo',
                'issuedAt',
                'expiresAt',
                'capabilities',
                'revocationUrl',
                'proof',
            ],
            additionalProperties: false,
        },
    },
} as const;

export const communicationSchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/communication.schema.json',
    $defs: {
        ...defs,
        envelopeHeader: {
            type: 'object',
            properties: {
                senderDid: { $ref: '#/$defs/didAgent' },
                recipientDid: { $ref: '#/$defs/didAgent' },
                sessionId: {
                    anyOf: [{ type: 'string', minLength: 1 }, { type: 'null' }],
                },
                sequenceNumber: { type: 'integer', minimum: 0 },
                // Format change #4
                capabilityTokenRef: { $ref: '#/$defs/capabilityTokenId' },
            },
            required: ['senderDid', 'recipientDid', 'sessionId'],
            additionalProperties: false,
        },
        negotiationEnvelope: {
            type: 'object',
            properties: {
                id: { $ref: '#/$defs/uuidV4' },
                specVersion: { $ref: '#/$defs/specVersion' },
                header: { $ref: '#/$defs/envelopeHeader' },
                messageType: { type: 'string', enum: [...MESSAGE_TYPES] },
                body: { type: 'object' },
                signature: { $ref: '#/$defs/signature' },
                timestamp: { $ref: '#/$defs/timestamp' },
            },
            required: [
                'id',
                'specVersion',
                'header',
                'messageType',
                'body',
                'signature',
                'timestamp',
            ],
            additionalProperties: false,
            // Version gate: an envelope containing capabilityTokenRef must use specVersion 0.2.0
            if: {
                properties: {
                    header: { required: ['capabilityTokenRef'] },
                },
            },
            then: {
                properties: {
                    specVersion: { const: '0.2.0' },
                },
            },
        },
        // Added: handshake message body schema (session persistence).
        handshakeChallenge: {
            type: 'object',
            properties: {
                challengeId: { $ref: '#/$defs/uuid' },
                initiatorDid: { $ref: '#/$defs/didAgent' },
                responderDid: { $ref: '#/$defs/didAgent' },
                principalDid: { $ref: '#/$defs/didKey' },
                nonce: { $ref: '#/$defs/hash' },
                timestamp: { $ref: '#/$defs/timestamp' },
                expiresAt: { $ref: '#/$defs/timestamp' },
                initiatorCapabilities: {
                    type: 'array',
                    items: {
                        type: 'string',
                        // Control-plane isolation: HandshakeChallenge.initiatorCapabilities does not accept control-plane actions.
                        enum: [...BUSINESS_ACTION_VOCABULARY],
                    },
                },
                // Optional fields added (session persistence).
                resumeSessionId: { type: 'string', minLength: 1 },
                capabilityTokenId: { $ref: '#/$defs/capabilityTokenId' },
                // Encryption negotiation parameters.
                // Omitted (field absent) = legacy OFF behavior, backward compatible with the earlier wire-format
                encryption: {
                    type: 'object',
                    properties: {
                        preference: {
                            type: 'string',
                            enum: ['OPT_IN', 'REQUIRED'],
                        },
                        initiatorEphemeralPublicKey: {
                            type: 'string',
                            minLength: 1,
                        },
                        encryptionProtocolVersion: {
                            type: 'string',
                            const: 'ap/e2e/v1',
                        },
                    },
                    required: [
                        'preference',
                        'initiatorEphemeralPublicKey',
                        'encryptionProtocolVersion',
                    ],
                    additionalProperties: false,
                },
            },
            required: [
                'challengeId',
                'initiatorDid',
                'responderDid',
                'nonce',
                'timestamp',
                'expiresAt',
                'initiatorCapabilities',
            ],
            additionalProperties: false,
        },
        handshakeResponse: {
            type: 'object',
            properties: {
                challengeId: { $ref: '#/$defs/uuid' },
                // Conditional-branch constraint:
                // at the schema layer sessionId is allowed to be empty (the responder reject path deliberately sends
                // sessionId='', which is an already-landed wire-format); the non-empty check is implemented via the handshakeAckBody
                // if/then constraint (which forces response.sessionId minLength=1 when accepted=true),
                // avoiding the schema rejecting reject-path envelopes. See the
                // handshakeAckBody def below.
                sessionId: { type: 'string' },
                responderDid: { $ref: '#/$defs/didAgent' },
                responderCapabilities: {
                    type: 'array',
                    items: {
                        type: 'string',
                        // Control-plane isolation: HandshakeResponse.responderCapabilities does not accept control-plane actions.
                        enum: [...BUSINESS_ACTION_VOCABULARY],
                    },
                },
                nonce: { $ref: '#/$defs/hash' },
                timestamp: { $ref: '#/$defs/timestamp' },
                // Optional field added (token binding confirmation)
                capabilityTokenId: { $ref: '#/$defs/capabilityTokenId' },
                // Encryption negotiation result.
                // Omitted (field absent) = a non-encrypted session, backward compatible with the earlier wire-format
                encryption: {
                    type: 'object',
                    properties: {
                        negotiatedMode: {
                            type: 'string',
                            enum: ['OFF', 'REQUIRED'],
                        },
                        responderPreference: {
                            type: 'string',
                            enum: ['OFF', 'OPT_IN', 'REQUIRED'],
                        },
                        responderEphemeralPublicKey: {
                            type: 'string',
                            minLength: 1,
                        },
                        encryptionProtocolVersion: {
                            type: 'string',
                            const: 'ap/e2e/v1',
                        },
                        transcriptHashConfirmation: { type: 'string' },
                        // The capabilityTokenFingerprint returned by HAV.validate,
                        // present only when negotiatedMode='REQUIRED' and challenge.capabilityTokenId !== null
                        authorizedTokenFingerprint: {
                            type: 'string',
                            minLength: 1,
                        },
                    },
                    required: [
                        'negotiatedMode',
                        'responderPreference',
                        'encryptionProtocolVersion',
                        'transcriptHashConfirmation',
                    ],
                    additionalProperties: false,
                },
            },
            required: [
                'challengeId',
                'sessionId',
                'responderDid',
                'responderCapabilities',
                'nonce',
                'timestamp',
            ],
            additionalProperties: false,
        },
        // schema codification of HandshakeAckBody (the responder → initiator HANDSHAKE_ACK envelope.body).
        // Wraps accepted (boolean) + response (handshakeResponse) +
        // optional reason. The consumer-side TS type HandshakeAckBody already exists
        // (packages/communication/src/handshake/types.ts:46); this def is merely the codification.
        //
        // if/then conditional-branch constraint:
        // accepted=true → response.sessionId must have minLength≥1 (prevents sessionId='' from making the
        // initiator wrongly believe the session is established)
        // accepted=false → response.sessionId may be empty (the responder reject path is already landed
        // wire-format, where sessionId='' is the agreed signal = no session)
        // This conditional constraint keeps "business-plane rules" in the schema layer rather than as an
        // inline guard inside the communication package — business-plane rules that the schema can express must be expressed at the schema layer.
        handshakeAckBody: {
            type: 'object',
            properties: {
                accepted: { type: 'boolean' },
                response: { $ref: '#/$defs/handshakeResponse' },
                reason: { type: 'string' },
            },
            required: ['accepted', 'response'],
            additionalProperties: false,
            if: {
                properties: { accepted: { const: true } },
                required: ['accepted'],
            },
            then: {
                properties: {
                    response: {
                        type: 'object',
                        properties: {
                            sessionId: { type: 'string', minLength: 1 },
                        },
                        required: ['sessionId'],
                    },
                },
            },
        },
        // Added in v0.2: discovery request body.
        // additionalProperties: false.
        discoveryRequestBody: {
            type: 'object',
            properties: {
                targetDid: { $ref: '#/$defs/didAgent' },
                requestedAt: { $ref: '#/$defs/timestamp' },
            },
            required: ['targetDid', 'requestedAt'],
            additionalProperties: false,
        },
        // Added in v0.2: discovery response body.
        // documentVersion: a positive integer >= 1, consistent with AgentCard.documentVersion.
        // additionalProperties: false.
        discoveryResponseBody: {
            type: 'object',
            properties: {
                agentDid: { $ref: '#/$defs/didAgent' },
                agentCardJson: { type: 'string', minLength: 1 },
                respondedAt: { $ref: '#/$defs/timestamp' },
                documentVersion: { type: 'integer', minimum: 1 },
            },
            required: [
                'agentDid',
                'agentCardJson',
                'respondedAt',
                'documentVersion',
            ],
            additionalProperties: false,
        },
    },
} as const;

export const ledgerSchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/ledger.schema.json',
    $defs: {
        ...defs,
        integrityProof: {
            type: 'object',
            properties: {
                agentDid: { $ref: '#/$defs/didAgent' },
                chainLength: { type: 'integer', minimum: 0 },
                headHash: { $ref: '#/$defs/hash' },
                computedAt: { $ref: '#/$defs/timestamp' },
                verifierDid: { $ref: '#/$defs/did' },
            },
            required: ['agentDid', 'chainLength', 'headHash', 'computedAt'],
            additionalProperties: false,
        },
        // result_summary object structure.
        // status excludes PENDING_APPROVAL (only the three terminal states are landed);
        // reason is for REJECTED; message is for ERROR; SUCCESS needs only status.
        // amount: the cumulative_limit aggregation field — listed explicitly rather than
        // opening additionalProperties, because: the contract is the core of the protocol, and opening it means handing
        // cross-implementation interoperability over to implicit conventions.
        resultSummaryStruct: {
            type: 'object',
            properties: {
                status: { type: 'string', enum: [...ACTION_RESULT_STATUSES] },
                reason: { type: 'string', maxLength: 500 },
                message: { type: 'string', maxLength: 500 },
                amount: { type: 'number' },
            },
            required: ['status'],
            additionalProperties: false,
        },
        // authorization_ref container.
        // tokenId allows null: explicitly preserves the "token ID could not be determined (exceptional case)" branch;
        // all three engine.ts paths already write { tokenId: guardResult.tokenId ?? null }.
        // When audit is protocolized, nonce / proofType / delegatedAuditKeyId may be appended.
        authorizationRefStruct: {
            type: 'object',
            properties: {
                tokenId: {
                    anyOf: [{ type: 'string', minLength: 1 }, { type: 'null' }],
                },
            },
            required: ['tokenId'],
            additionalProperties: false,
        },
        // The parametersSummary shape of the SESSION_SUPERSEDED control-plane event.
        // See packages/types/src/action-vocabulary.ts for details.
        // On the FORCED_CLOSE path newSessionId may be null (no successor session); other reasons force a non-empty string.
        sessionSupersededParams: {
            type: 'object',
            properties: {
                oldSessionId: { type: 'string', minLength: 1 },
                newSessionId: {
                    anyOf: [{ type: 'string', minLength: 1 }, { type: 'null' }],
                },
                reason: {
                    type: 'string',
                    enum: [...SESSION_SUPERSEDED_REASONS],
                },
                timestamp: { $ref: '#/$defs/timestamp' },
                // The affected business subjects.
                // The top-level SESSION_SUPERSEDED agentDid/principalDid are forced = the governor DID,
                // so the superseded business agent/principal must enter the immutable signed payload via the affected* fields,
                // otherwise audit accountability would have to rely on mutable side data outside the ledger.
                affectedAgentDid: { $ref: '#/$defs/didAgent' },
                affectedPrincipalDid: { $ref: '#/$defs/didKey' },
            },
            required: [
                'oldSessionId',
                'newSessionId',
                'reason',
                'timestamp',
                'affectedAgentDid',
                'affectedPrincipalDid',
            ],
            additionalProperties: false,
            // newSessionId === null is legal only when reason === 'FORCED_CLOSE'.
            // For other reasons, newSessionId === null triggers a type rejection via if/then.
            allOf: [
                {
                    if: {
                        properties: {
                            reason: {
                                type: 'string',
                                enum: [
                                    'EXPLICIT_CLOSE',
                                    'TOKEN_REVOKED',
                                    'IDLE_EXPIRED',
                                ],
                            },
                        },
                        required: ['reason'],
                    },
                    then: {
                        properties: {
                            newSessionId: { type: 'string', minLength: 1 },
                        },
                    },
                },
            ],
        },
        // ActionRecord ledger object shape.
        // Historical signature preimages (actor_signature / ledger_signature) are already computed over the object's
        // canonicalized payload; the object shape is preserved so as not to break the signing convention.
        actionRecord: {
            type: 'object',
            properties: {
                id: { $ref: '#/$defs/recordId' },
                specVersion: { $ref: '#/$defs/specVersion' },
                // Business actions (INQUIRY/QUOTE/CONFIRM/PUBLISH/RECORD)
                // are still validated under the strong didAgent / didKey pattern; the SESSION_SUPERSEDED control-plane event
                // reuses the base did pattern to accept `did:system:session-governor`.
                // Strict mode + equality constraints are enforced by the allOf if/then branches per action below.
                agentDid: { $ref: '#/$defs/did' },
                principalDid: { $ref: '#/$defs/did' },
                action: {
                    type: 'string',
                    enum: [...ACTION_VOCABULARY],
                },
                parametersSummary: {
                    anyOf: [{ type: 'object' }, { type: 'null' }],
                },
                authorizationRef: {
                    anyOf: [
                        { $ref: '#/$defs/authorizationRefStruct' },
                        { type: 'null' },
                    ],
                },
                // result_summary is object | null;
                // the scenarios where action-recorder.ts actually normalizes to null must be accepted.
                resultSummary: {
                    anyOf: [
                        { $ref: '#/$defs/resultSummaryStruct' },
                        { type: 'null' },
                    ],
                },
                timestamp: { $ref: '#/$defs/timestamp' },
                prevHash: {
                    anyOf: [{ $ref: '#/$defs/hash' }, { type: 'null' }],
                },
                ledgerSignature: { $ref: '#/$defs/signature' },
                // Format change #5.
                // Previously only minimum:0, while ledger.schema.json
                // already had maximum:5; the TS schema drift let the validator accept delegationDepth>5
                // data while external JSON Schema consumers rejected it — breaking cross-language interoperability.
                // Shares the constant with MAX_DELEGATION_DEPTH (authorization.ts:125).
                delegationDepth: {
                    type: 'integer',
                    minimum: 0,
                    maximum: MAX_DELEGATION_DEPTH,
                },
                sessionId: { type: 'string', minLength: 1 },
                actorSignature: { $ref: '#/$defs/signature' },
            },
            required: [
                'id',
                'specVersion',
                'agentDid',
                'principalDid',
                'action',
                'parametersSummary',
                'authorizationRef',
                'resultSummary',
                'timestamp',
                'prevHash',
                'ledgerSignature',
            ],
            // specVersion branch gate (three-state coexistence) +
            // action branch gate (the SESSION_SUPERSEDED control-plane event):
            // - 0.1.0: the baseline required set is the full constraint
            // - 0.2.0: actorSignature required (dual-signature non-repudiation)
            // - 0.3.0: actorSignature + delegationDepth required
            // (0.3.0 extends the 0.2.0 constraints)
            // - action !== SESSION_SUPERSEDED: agentDid forced to the didAgent pattern + principalDid forced to the didKey pattern
            // - action === SESSION_SUPERSEDED: specVersion forced to 0.3.0 + agentDid/principalDid forced
            // equal to SESSION_GOVERNOR_DID + parametersSummary shape forced to sessionSupersededParams
            allOf: [
                {
                    if: {
                        properties: { specVersion: { const: '0.2.0' } },
                        required: ['specVersion'],
                    },
                    then: {
                        required: ['actorSignature'],
                    },
                },
                {
                    if: {
                        properties: { specVersion: { const: '0.3.0' } },
                        required: ['specVersion'],
                    },
                    then: {
                        required: ['actorSignature', 'delegationDepth'],
                    },
                },
                // Business actions (the 5 frozen values): retain the strong DID pattern constraint.
                {
                    if: {
                        properties: {
                            action: {
                                type: 'string',
                                enum: [
                                    'INQUIRY',
                                    'QUOTE',
                                    'CONFIRM',
                                    'PUBLISH',
                                    'RECORD',
                                ],
                            },
                        },
                        required: ['action'],
                    },
                    then: {
                        properties: {
                            agentDid: { pattern: didAgentPattern },
                            principalDid: { pattern: didKeyPattern },
                        },
                    },
                },
                // SESSION_SUPERSEDED control-plane branch:
                // 1) specVersion must be 0.3.0 (the 0.1.0/0.2.0 validators already reject this action via enum;
                // the 0.3.0 validator additionally guarantees the write side does not misuse it under older versions);
                // 2) agentDid === principalDid === did:system:session-governor;
                // 3) the parametersSummary shape conforms to the sessionSupersededParams definition.
                {
                    if: {
                        properties: {
                            action: { const: 'SESSION_SUPERSEDED' },
                        },
                        required: ['action'],
                    },
                    then: {
                        properties: {
                            specVersion: { const: '0.3.0' },
                            agentDid: { const: SESSION_GOVERNOR_DID },
                            principalDid: { const: SESSION_GOVERNOR_DID },
                            parametersSummary: {
                                $ref: '#/$defs/sessionSupersededParams',
                            },
                        },
                        required: ['parametersSummary'],
                    },
                },
            ],
            additionalProperties: false,
        },
        protocolError: {
            type: 'object',
            properties: {
                code: { type: 'string', enum: [...PROTOCOL_ERROR_CODES] },
                message: { type: 'string', minLength: 1 },
                requestId: { type: 'string', minLength: 1 },
            },
            required: ['code', 'message'],
            additionalProperties: false,
        },
    },
} as const;

// Added: session persistence schema.
export const sessionSchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/session.schema.json',
    $defs: {
        ...defs,
        sessionState: {
            type: 'string',
            enum: ['CREATED', 'ACTIVE', 'IDLE', 'CLOSED'],
        },
        closeReason: {
            type: 'string',
            enum: [
                'IDLE_TIMEOUT',
                'EXPLICIT_CLOSE',
                'HANDSHAKE_REJECTED',
                'ERROR',
                'REVOKED_TOKEN',
            ],
        },
        sessionRecord: {
            type: 'object',
            properties: {
                sessionId: { $ref: '#/$defs/uuidV4' },
                initiatorDid: { $ref: '#/$defs/did' },
                responderDid: { $ref: '#/$defs/didAgent' },
                principalDid: { $ref: '#/$defs/didKey' },
                capabilityTokenId: {
                    anyOf: [
                        { $ref: '#/$defs/capabilityTokenId' },
                        { type: 'null' },
                    ],
                },
                capabilityTokenFingerprint: {
                    anyOf: [{ $ref: '#/$defs/hash' }, { type: 'null' }],
                },
                state: { $ref: '#/$defs/sessionState' },
                negotiatedCapabilities: {
                    type: 'array',
                    items: { type: 'string' },
                },
                establishedAt: {
                    anyOf: [{ $ref: '#/$defs/timestamp' }, { type: 'null' }],
                },
                lastSeenAt: { $ref: '#/$defs/timestamp' },
                lastAuthorizedAt: { $ref: '#/$defs/timestamp' },
                idleSince: {
                    anyOf: [{ $ref: '#/$defs/timestamp' }, { type: 'null' }],
                },
                closedAt: {
                    anyOf: [{ $ref: '#/$defs/timestamp' }, { type: 'null' }],
                },
                closeReason: {
                    anyOf: [{ $ref: '#/$defs/closeReason' }, { type: 'null' }],
                },
                supersedesSessionId: {
                    anyOf: [{ $ref: '#/$defs/uuidV4' }, { type: 'null' }],
                },
                didPairKey: { type: 'string', minLength: 1 },
                createdAt: { $ref: '#/$defs/timestamp' },
                updatedAt: { $ref: '#/$defs/timestamp' },
                revision: { type: 'string', pattern: '^[0-9]+$' },
            },
            required: [
                'sessionId',
                'initiatorDid',
                'responderDid',
                'principalDid',
                'capabilityTokenId',
                'capabilityTokenFingerprint',
                'state',
                'negotiatedCapabilities',
                'establishedAt',
                'lastSeenAt',
                'lastAuthorizedAt',
                'idleSince',
                'closedAt',
                'closeReason',
                'supersedesSessionId',
                'didPairKey',
                'createdAt',
                'updatedAt',
                'revision',
            ],
            additionalProperties: false,
        },
    },
} as const;

// Added: E2E encryption EncryptedBody / MessageReceipt schema.
// Type definition source: packages/types/src/encryption.ts (TypeScript interface definitions).
// Dual-source: this inline + packages/types/src/schemas/encryption.schema.json (the published artifact).
// v0.3.0 batch extension.
export const encryptionSchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/encryption.schema.json',
    $defs: {
        encryptedBodyType: {
            type: 'string',
            enum: ['BUSINESS', 'RECEIPT'],
        },
        encryptedBody: {
            type: 'object',
            properties: {
                // Encrypted-payload discriminator (literal true)
                encrypted: { type: 'boolean', const: true },
                // The only legal protocol version
                encryptionProtocolVersion: {
                    type: 'string',
                    const: 'ap/e2e/v1',
                },
                // Payload type: business plaintext | receipt
                type: { $ref: '#/$defs/encryptedBodyType' },
                // AEAD ciphertext (including the GCM authentication tag, hex or base64url)
                ciphertext: { type: 'string', minLength: 1 },
                // AEAD nonce (12B, hex or base64url)
                aeadNonce: { type: 'string', minLength: 1 },
                // Session key identifier (first 16 bytes of SHA-256, hex 32 chars or base64url 22 chars, three-state coexistence)
                keyId: { type: 'string', pattern: keyIdPattern },
                // Digest of business fields in the AAD (optional, plaintext-visible but protected by the AEAD tag)
                aadSummary: { type: 'object' },
            },
            required: [
                'encrypted',
                'encryptionProtocolVersion',
                'type',
                'ciphertext',
                'aeadNonce',
                'keyId',
            ],
            additionalProperties: false,
        },
        messageReceipt: {
            type: 'object',
            properties: {
                // The acknowledged envelope id (must be a NegotiationEnvelope.id, UUID v4 — packages/communication/src/envelope.ts generates it with randomUUID)
                ackEnvelopeId: { type: 'string', pattern: uuidV4Pattern },
                // session id
                sessionId: { type: 'string', minLength: 1 },
                // SHA-256(canonicalize(decrypted_params))
                paramsHash: { type: 'string', minLength: 1 },
                // the audit intent id returned by beforeExecute
                auditIntentId: { type: 'string', minLength: 1 },
                // Responder issuance time (ISO 8601 Timestamp)
                receivedAt: { type: 'string', pattern: timestampPattern },
                // Ed25519 signature (the receiver's identity key)
                receiptSignature: { type: 'string', minLength: 1 },
            },
            required: [
                'ackEnvelopeId',
                'sessionId',
                'paramsHash',
                'auditIntentId',
                'receivedAt',
                'receiptSignature',
            ],
            additionalProperties: false,
        },
    },
} as const;

// Added: audit query access model schema.
export const auditSchema = {
    $schema: schemaVersion,
    $id: 'https://coivitas.ai/schemas/audit.schema.json',
    $defs: {
        ...defs,
        auditResourceBinding: {
            oneOf: [
                {
                    type: 'object',
                    properties: {
                        route: { const: 'records.list' },
                        recordId: { type: 'null' },
                    },
                    required: ['route', 'recordId'],
                    additionalProperties: false,
                },
                {
                    type: 'object',
                    properties: {
                        route: { const: 'records.get' },
                        recordId: { $ref: '#/$defs/recordId' },
                    },
                    required: ['route', 'recordId'],
                    additionalProperties: false,
                },
                {
                    type: 'object',
                    properties: {
                        route: { const: 'records.verify' },
                        recordId: { $ref: '#/$defs/recordId' },
                    },
                    required: ['route', 'recordId'],
                    additionalProperties: false,
                },
                {
                    type: 'object',
                    properties: {
                        route: { const: 'records.chain.verify' },
                        recordId: { type: 'null' },
                    },
                    required: ['route', 'recordId'],
                    additionalProperties: false,
                },
                // governor lane bootstrap clause:
                // the resource binding for the signed /audit/ledger/head endpoint to participate in Ed25519 signature verification.
                {
                    type: 'object',
                    properties: {
                        route: { const: 'ledger.head' },
                        recordId: { type: 'null' },
                    },
                    required: ['route', 'recordId'],
                    additionalProperties: false,
                },
            ],
        },
        auditSnapshotBoundary: {
            type: 'object',
            properties: {
                headCreatedAt: { $ref: '#/$defs/timestamp' },
                headRecordId: { $ref: '#/$defs/recordId' },
                headRecordHash: { $ref: '#/$defs/hash' },
            },
            required: ['headCreatedAt', 'headRecordId'],
            additionalProperties: false,
        },
        signedAuditQuery: {
            type: 'object',
            properties: {
                // requesterDid stays didKey only.
                // In the audit lane, governor is **always the target**, never the requester;
                // control-plane query semantics = an external principal issues an introspection request against governor using its own did:key.
                // Relaxing requesterDid to governor would split the schema from runtime Step 9 signature verification.
                requesterDid: { $ref: '#/$defs/didKey' },
                // targetAgentDid is relaxed to didAgent ∪ SESSION_GOVERNOR_DID.
                // governor is the target of the audit lane, dispatched to ControlPlaneAuditAccessChecker by the dispatcher.
                targetAgentDid: {
                    anyOf: [
                        { $ref: '#/$defs/didAgent' },
                        { const: SESSION_GOVERNOR_DID },
                    ],
                },
                httpMethod: { const: 'GET' },
                resourceBinding: { $ref: '#/$defs/auditResourceBinding' },
                queryParams: {
                    type: 'object',
                    properties: {
                        // agentDid is relaxed like targetAgentDid, supporting governor filtering.
                        agentDid: {
                            anyOf: [
                                { $ref: '#/$defs/didAgent' },
                                { const: SESSION_GOVERNOR_DID },
                            ],
                        },
                        principalDid: { $ref: '#/$defs/didKey' },
                        action: {
                            type: 'string',
                            enum: [...ACTION_VOCABULARY_AUDIT],
                        },
                        sessionId: { type: 'string', minLength: 1 },
                        start: { $ref: '#/$defs/timestamp' },
                        end: { $ref: '#/$defs/timestamp' },
                        limit: { type: 'integer', minimum: 1, maximum: 500 },
                        cursor: { type: 'string', minLength: 1 },
                        // governor lane subject-scope filter fields. After the dispatcher forces
                        // targetAgentDid === governor to enter the control-plane lane,
                        // the true subject boundary = the affected* fields of the immutable SESSION_SUPERSEDED
                        // payload (already added to required).
                        affectedAgentDid: { $ref: '#/$defs/didAgent' },
                        affectedPrincipalDid: { $ref: '#/$defs/didKey' },
                    },
                    additionalProperties: false,
                },
                snapshotBoundary: { $ref: '#/$defs/auditSnapshotBoundary' },
                timestamp: { $ref: '#/$defs/timestamp' },
                signature: { $ref: '#/$defs/signature' },
                // Fields added in v0.2.
                // Their absence would cause additionalProperties: false to reject v0.2 queries.
                nonce: { $ref: '#/$defs/uuidV4' },
                proofType: { type: 'string', enum: ['Ed25519Signature2020'] },
                delegatedAuditKeyId: {
                    anyOf: [{ type: 'string', minLength: 1 }, { type: 'null' }],
                },
            },
            required: [
                'requesterDid',
                'targetAgentDid',
                'httpMethod',
                'resourceBinding',
                'queryParams',
                'timestamp',
                'signature',
            ],
            additionalProperties: false,
            // snapshotBoundary conditional-branch constraint.
            // The 'ledger.head' route is the head discovery bootstrap, where head is its output, not its input;
            // the snapshotBoundary field must be **forbidden**. Other routes must **require** snapshotBoundary.
            allOf: [
                {
                    if: {
                        properties: {
                            resourceBinding: {
                                properties: {
                                    route: { const: 'ledger.head' },
                                },
                            },
                        },
                    },
                    then: {
                        not: { required: ['snapshotBoundary'] },
                    },
                    else: {
                        required: ['snapshotBoundary'],
                    },
                },
            ],
        },
    },
} as const;
