import AjvModule, { type ErrorObject } from 'ajv';

import type { CapabilityToken } from './authorization.js';
import policyChangeRecordSchema from './schemas/policy-change-record.schema.json' with { type: 'json' };
import {
    auditSchema,
    authorizationSchema,
    communicationSchema,
    encryptionSchema,
    identitySchema,
    ledgerSchema,
    sessionSchema,
} from './schemas.js';

// Baseline schema ids plus newly added ids.
export const SCHEMA_IDS = {
    // baseline
    principalIdentity: 'principalIdentity',
    bindingProof: 'bindingProof',
    agentIdentityDocument: 'agentIdentityDocument',
    allowlistScope: 'allowlistScope',
    numericLimitScope: 'numericLimitScope',
    scope: 'scope',
    capability: 'capability',
    tokenProof: 'tokenProof',
    capabilityToken: 'capabilityToken',
    envelopeHeader: 'envelopeHeader',
    negotiationEnvelope: 'negotiationEnvelope',
    actionRecord: 'actionRecord',
    integrityProof: 'integrityProof',
    protocolError: 'protocolError',
    // v0.3.0 · ledger (A8 SESSION_SUPERSEDED control-plane params)
    sessionSupersededParams: 'sessionSupersededParams',
    // identity (key-rotation / discovery)
    rotationProof: 'rotationProof',
    agentCard: 'agentCard',
    // v0.3.0 · identity (dual-key schema)
    keyRotationState: 'keyRotationState',
    resolvedPublicKeys: 'resolvedPublicKeys',
    // authorization (delegation-chain / scope-extensions)
    temporalScope: 'temporalScope',
    cumulativeLimitScope: 'cumulativeLimitScope',
    meterFieldRef: 'meterFieldRef',
    recurringWindow: 'recurringWindow',
    delegationProof: 'delegationProof',
    // communication (handshake body extension)
    handshakeChallenge: 'handshakeChallenge',
    handshakeResponse: 'handshakeResponse',
    // v0.4: HandshakeAckBody schema codify
    // —— wraps accepted (boolean) + response (handshakeResponse) + optional reason;
    // used by initiator.ts on receiving HANDSHAKE_ACK to exhaustively validate in one pass
    // via validateAgainstSchema, replacing the existing inline guard enum-field approach.
    handshakeAckBody: 'handshakeAckBody',
    // newly added in v0.2 (discovery body)
    discoveryRequestBody: 'discoveryRequestBody',
    discoveryResponseBody: 'discoveryResponseBody',
    // session (session-persistence)
    sessionRecord: 'sessionRecord',
    // audit (audit-access-model)
    signedAuditQuery: 'signedAuditQuery',
    auditResourceBinding: 'auditResourceBinding',
    auditSnapshotBoundary: 'auditSnapshotBoundary',
    // v0.2 · encryption (encrypted body / message receipt)
    encryptedBody: 'encryptedBody',
    messageReceipt: 'messageReceipt',
    // policy-change-audit
    // fail-closed validation of PolicyChangeParams before writing policy_change_records
    policyChangeParams: 'policyChangeParams',
} as const;

type SchemaId = (typeof SCHEMA_IDS)[keyof typeof SCHEMA_IDS];

interface ValidationIssue {
    instancePath: string;
    message: string;
    keyword: string;
}

interface ValidationResult {
    valid: boolean;
    errors: ValidationIssue[];
}

type AjvLike = {
    addSchema: (schema: object) => void;
    getSchema: (
        schemaRef: string,
    ) =>
        | (((data: unknown) => boolean) & { errors?: ErrorObject[] | null })
        | undefined;
};

const Ajv = AjvModule as unknown as new (
    options?: Record<string, unknown>,
) => AjvLike;

const ajv = new Ajv({
    allErrors: true,
    strict: false,
    allowUnionTypes: true,
});

ajv.addSchema(identitySchema);
ajv.addSchema(authorizationSchema);
ajv.addSchema(communicationSchema);
ajv.addSchema(ledgerSchema);
ajv.addSchema(sessionSchema);
ajv.addSchema(auditSchema);
ajv.addSchema(encryptionSchema);
// PolicyChangeParams schema (a standalone file, not a member of ledgerSchema $defs)
ajv.addSchema(policyChangeRecordSchema as object);

const schemaRefById: Record<SchemaId, string> = {
    // baseline schemas
    principalIdentity: `${identitySchema.$id}#/$defs/principalIdentity`,
    bindingProof: `${identitySchema.$id}#/$defs/bindingProof`,
    agentIdentityDocument: `${identitySchema.$id}#/$defs/agentIdentityDocument`,
    allowlistScope: `${authorizationSchema.$id}#/$defs/allowlistScope`,
    numericLimitScope: `${authorizationSchema.$id}#/$defs/numericLimitScope`,
    scope: `${authorizationSchema.$id}#/$defs/scope`,
    capability: `${authorizationSchema.$id}#/$defs/capability`,
    tokenProof: `${authorizationSchema.$id}#/$defs/tokenProof`,
    capabilityToken: `${authorizationSchema.$id}#/$defs/capabilityToken`,
    envelopeHeader: `${communicationSchema.$id}#/$defs/envelopeHeader`,
    negotiationEnvelope: `${communicationSchema.$id}#/$defs/negotiationEnvelope`,
    actionRecord: `${ledgerSchema.$id}#/$defs/actionRecord`,
    integrityProof: `${ledgerSchema.$id}#/$defs/integrityProof`,
    protocolError: `${ledgerSchema.$id}#/$defs/protocolError`,
    sessionSupersededParams: `${ledgerSchema.$id}#/$defs/sessionSupersededParams`,
    // extension schemas
    rotationProof: `${identitySchema.$id}#/$defs/rotationProof`,
    agentCard: `${identitySchema.$id}#/$defs/agentCard`,
    keyRotationState: `${identitySchema.$id}#/$defs/keyRotationState`,
    resolvedPublicKeys: `${identitySchema.$id}#/$defs/resolvedPublicKeys`,
    temporalScope: `${authorizationSchema.$id}#/$defs/temporalScope`,
    cumulativeLimitScope: `${authorizationSchema.$id}#/$defs/cumulativeLimitScope`,
    meterFieldRef: `${authorizationSchema.$id}#/$defs/meterFieldRef`,
    recurringWindow: `${authorizationSchema.$id}#/$defs/recurringWindow`,
    delegationProof: `${authorizationSchema.$id}#/$defs/delegationProof`,
    handshakeChallenge: `${communicationSchema.$id}#/$defs/handshakeChallenge`,
    handshakeResponse: `${communicationSchema.$id}#/$defs/handshakeResponse`,
    handshakeAckBody: `${communicationSchema.$id}#/$defs/handshakeAckBody`,
    discoveryRequestBody: `${communicationSchema.$id}#/$defs/discoveryRequestBody`,
    discoveryResponseBody: `${communicationSchema.$id}#/$defs/discoveryResponseBody`,
    sessionRecord: `${sessionSchema.$id}#/$defs/sessionRecord`,
    signedAuditQuery: `${auditSchema.$id}#/$defs/signedAuditQuery`,
    auditResourceBinding: `${auditSchema.$id}#/$defs/auditResourceBinding`,
    auditSnapshotBoundary: `${auditSchema.$id}#/$defs/auditSnapshotBoundary`,
    // v0.2 · encryption
    encryptedBody: `${encryptionSchema.$id}#/$defs/encryptedBody`,
    messageReceipt: `${encryptionSchema.$id}#/$defs/messageReceipt`,
    // policy-change-audit
    // standalone schema file, uses the root-level $id directly (no $defs path)
    policyChangeParams: policyChangeRecordSchema.$id,
};

const normalizeErrors = (
    errors: ErrorObject[] | null | undefined,
): ValidationIssue[] =>
    (errors ?? []).map((error) => ({
        instancePath: error.instancePath || '/',
        message: error.message ?? 'validation failed',
        keyword: error.keyword,
    }));

export const validateAgainstSchema = (
    data: unknown,
    schemaId: SchemaId,
): ValidationResult => {
    const validator = ajv.getSchema(schemaRefById[schemaId]);

    /* v8 ignore next 10 -- the SchemaId enum is fully registered, so the validator can never be undefined*/
    if (!validator) {
        return {
            valid: false,
            errors: [
                {
                    instancePath: '/',
                    message: `unknown schema id: ${schemaId}`,
                    keyword: 'schema',
                },
            ],
        };
    }

    const valid = validator(data);

    return {
        valid: Boolean(valid),
        errors: normalizeErrors(validator.errors),
    };
};

// Version-consistency check.
// A Token with specVersion "0.1.0" must not contain temporal_scope / cumulative_limit.
// When it returns { valid: false, reason }, the caller should return INVALID_TOKEN_FORMAT (fail-closed).
// Decoupled from validateAgainstSchema: because the JSON Schema layer's scope.oneOf unconditionally includes 4 types,
// the version semantic constraint must be applied as a post-check by this function after the schema passes.
export interface ScopeVersionCheckResult {
    valid: boolean;
    reason?: string;
}

export const validateScopeVersion = (
    token: CapabilityToken,
): ScopeVersionCheckResult => {
    if (token.specVersion !== '0.1.0') {
        return { valid: true };
    }

    for (const capability of token.capabilities) {
        const scopeType = capability.scope.type;
        if (
            scopeType === 'temporal_scope' ||
            scopeType === 'cumulative_limit'
        ) {
            return {
                valid: false,
                reason: `specVersion "0.1.0" tokens must not contain scope type '${scopeType}'; upgrade to "0.2.0".`,
            };
        }
    }

    return { valid: true };
};
