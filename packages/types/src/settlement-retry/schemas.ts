/**
 * Settlement Retry (SR) sub-protocol v0.1 — JSON Schema definitions
 *
 *
 * Layer 2 of the triple line of defense: JSON Schema strict
 *   - 4 strict flags: strict / validateFormats / strictSchema / strictNumbers
 *   - additionalProperties: false (enforced across all Schemas; guards against field overflow)
 *   - exhaustive required fields (guards against missing fields)
 *
 * AJV is instantiated at L3 settlement-retry.ts (prevents L0 from pulling in an AJV runtime dependency).
 * This file only defines JSON Schema object constants (pure data; shareable across layers).
 */

// ─── SettlementOperation JSON Schema ─────────────────────────────────────────

/**
 * SETTLEMENT_OPERATION_SCHEMA — JSON Schema for the SettlementOperation object
 *
 * The field list is consistent across the triple-line-of-defense layers.
 * Corresponds to the settlement_operations table DDL (SQL 031 migration).
 */
export const SETTLEMENT_OPERATION_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'settlement-operation-v0.1',
    type: 'object',
    additionalProperties: false,
    required: [
        'id',
        'srVersion',
        'tenantId',
        'idempotencyKey',
        'settlementType',
        'principalDid',
        'counterpartyDid',
        'amount',
        'currency',
        'signedPayload',
        'currentState',
        'attemptCount',
        'revoked',
        'createdAt',
        'updatedAt',
    ],
    properties: {
        id: {
            type: 'string',
            format: 'uuid',
            description: 'OperationId (UUID v4)',
        },
        srVersion: {
            type: 'string',
            pattern: '^[0-9]+\\.[0-9]+\\.[0-9]+$',
            description: 'SR protocol version (semver)',
        },
        tenantId: {
            type: 'string',
            format: 'uuid',
            description: 'SrTenantId (UUID v4)',
        },
        idempotencyKey: {
            type: 'string',
            pattern: '^[0-9a-f]{64}$',
            description: 'SHA-256(JCS) hex idempotency key (64 lowercase hex)',
        },
        settlementType: {
            type: 'string',
            enum: ['fiat_transfer', 'digital_wallet'],
            description:
                'Settlement type (v0.1 fiat_transfer | digital_wallet)',
        },
        principalDid: {
            type: 'string',
            pattern: '^did:',
            description: 'Principal DID (initiating party)',
        },
        counterpartyDid: {
            type: 'string',
            pattern: '^did:',
            description: 'Counterparty DID (receiving party)',
        },
        amount: {
            type: 'integer',
            minimum: 1,
            description: 'Amount in minimum currency unit (cents)',
        },
        currency: {
            type: 'string',
            pattern: '^[A-Z]{3}$',
            description: 'ISO 4217 three-letter uppercase currency code',
        },
        signedPayload: {
            type: 'object',
            description:
                'SettlementOperationSignedPayload (csp 5-field invariant FULL)',
        },
        currentState: {
            type: 'string',
            enum: [
                'PENDING',
                'IN_PROGRESS',
                'SUCCEEDED',
                'FAILED',
                'DEAD_LETTER',
            ],
            description: 'Current state machine state',
        },
        attemptCount: {
            type: 'integer',
            minimum: 0,
            maximum: 5,
            description: 'Number of retry attempts made',
        },
        revoked: {
            type: 'boolean',
            description: 'Whether the operation has been revoked',
        },
        createdAt: {
            type: 'string',
            description: 'ISO 8601 creation timestamp',
        },
        updatedAt: {
            type: 'string',
            description: 'ISO 8601 last update timestamp',
        },
        finalizedAt: {
            type: ['string', 'null'],
            description:
                'ISO 8601 finalization timestamp (null if not finalized)',
        },
    },
} as const;

// ─── RetryAttempt JSON Schema ─────────────────────────────────────────────────

/**
 * RETRY_ATTEMPT_SCHEMA — JSON Schema for the RetryAttempt object
 *
 *  Field list; corresponds to the settlement_retries table DDL.
 */
export const RETRY_ATTEMPT_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'retry-attempt-v0.1',
    type: 'object',
    additionalProperties: false,
    required: [
        'id',
        'operationId',
        'attemptNumber',
        'fromState',
        'toState',
        'attemptedAt',
        'backoffDelayMs',
        'auditEventId',
    ],
    properties: {
        id: {
            type: 'string',
            format: 'uuid',
            description: 'RetryAttemptId (UUID v4)',
        },
        operationId: {
            type: 'string',
            format: 'uuid',
            description: 'Associated OperationId (UUID v4)',
        },
        attemptNumber: {
            type: 'integer',
            minimum: 1,
            maximum: 5,
            description: 'Attempt sequence number (1-based)',
        },
        fromState: {
            type: 'string',
            enum: [
                'PENDING',
                'IN_PROGRESS',
                'SUCCEEDED',
                'FAILED',
                'DEAD_LETTER',
            ],
        },
        toState: {
            type: 'string',
            enum: [
                'PENDING',
                'IN_PROGRESS',
                'SUCCEEDED',
                'FAILED',
                'DEAD_LETTER',
            ],
        },
        attemptedAt: {
            type: 'string',
            description: 'ISO 8601 attempt start timestamp',
        },
        completedAt: {
            type: ['string', 'null'],
            description: 'ISO 8601 attempt completion timestamp',
        },
        resultSummary: {
            type: ['string', 'null'],
            description: 'Human-readable result summary',
        },
        failureReason: {
            type: ['string', 'null'],
            enum: [
                null,
                'SR_PROVIDER_UNAVAILABLE',
                'SR_PROVIDER_TIMEOUT',
                'SR_PROVIDER_DECLINED',
                'SR_INSUFFICIENT_FUNDS',
                'SR_REGULATORY_REJECTED',
                'SR_INTERNAL_ERROR',
            ],
            description: 'Failure reason code (null if succeeded)',
        },
        backoffDelayMs: {
            type: 'integer',
            minimum: 0,
            maximum: 60000,
            description: 'Computed backoff delay before this attempt (ms)',
        },
        auditEventId: {
            type: 'string',
            format: 'uuid',
            description: 'Associated ATP audit event ID (UUID v4)',
        },
    },
} as const;

// ─── IdempotencyRecord JSON Schema ─────────────────────────────────────────────

/**
 * IDEMPOTENCY_RECORD_SCHEMA — JSON Schema for the IdempotencyRecord object
 *
 * Corresponds to the idempotency_records table DDL.
 */
export const IDEMPOTENCY_RECORD_SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'idempotency-record-v0.1',
    type: 'object',
    additionalProperties: false,
    required: ['key', 'tenantId', 'operationId', 'currentState', 'createdAt'],
    properties: {
        key: {
            type: 'string',
            pattern: '^[0-9a-f]{64}$',
            description: 'SHA-256(JCS) hex key (64 lowercase hex)',
        },
        tenantId: {
            type: 'string',
            format: 'uuid',
            description: 'SrTenantId (UUID v4)',
        },
        operationId: {
            type: 'string',
            format: 'uuid',
            description: 'Associated OperationId (UUID v4)',
        },
        currentState: {
            type: 'string',
            enum: [
                'PENDING',
                'IN_PROGRESS',
                'SUCCEEDED',
                'FAILED',
                'DEAD_LETTER',
            ],
        },
        createdAt: {
            type: 'string',
            description: 'ISO 8601 creation timestamp',
        },
        finalizedAt: {
            type: ['string', 'null'],
            description: 'ISO 8601 finalization timestamp',
        },
    },
} as const;
