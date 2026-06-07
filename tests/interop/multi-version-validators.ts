/**
 * Multi-version schema validator routing
 *
 * Purpose: simulate legacy-version validators (v0.1.0 / v0.2.0) inside the conformance harness,
 * to verify cross-version REJECT scenarios (e.g. an xv-03 v0.3.0 envelope must be rejected
 * by a v0.1.0 validator).
 *
 * Implementation path: take the current v0.3.0 schemas as the baseline and generate the v0.1.0/v0.2.0
 * variants via **explicit enum narrowing** (minimal, focused on the reject scenarios known in the fixtures):
 *   - v0.1.0: the specVersion enum contains only ['0.1.0']
 *   - v0.2.0: the specVersion enum is ['0.1.0', '0.2.0']; ActionRecord.action enum does not contain
 *     'SESSION_SUPERSEDED' (the action vocabulary added in v0.3.0)
 *
 * **Scope statement**:
 * This implementation is **targeted enum narrowing**, not a full schema-history archive. **It can only reliably reject
 * the cross-version failure reasons explicitly marked in the current fixtures (specVersion enum / action enum)**.
 * It does **not** guarantee:
 *   - the field constraints of the v0.1.0 schema as of its time (e.g. whether messageType included DISCOVERY_REQUEST)
 *   - the oneOf / anyOf boundaries of the v0.2.0 schema as of its time
 *   - any reject reason not explicitly asserted by a fixture
 *
 * **Uncovered cross-version trust boundaries still await schema-history-archive infrastructure to be filled in.**
 * The caller is obligated: when claiming "complete cross-version coverage", they must make clear that the "coverage set" is
 * the portion of the fixtures' expectedError + assertRejectionMatches that hits, **not** every possible
 * compatibility boundary.
 */

// AJV is not in the root devDependencies; it is used via the hoisted ajv entry point of packages/types.
// Use the default ajv (draft-07) to match the ajv instance configuration of packages/types/src/validation.ts;
// negotiationEnvelope / actionRecord do not depend on the discovery schemas, so the 2020 meta is not needed.
// @ts-expect-error -- uses the hoisted ajv of packages/types (not in this package's dependencies)
import AjvModule, {
    type ErrorObject,
} from '../../packages/types/node_modules/ajv/dist/ajv.js';

type ValidateFn = ((data: unknown) => boolean) & {
    errors?: ErrorObject[] | null;
};
type AjvLike = {
    addSchema: (schema: unknown) => void;
    getSchema: (ref: string) => ValidateFn | undefined;
};
const Ajv = AjvModule as unknown as new (
    options?: Record<string, unknown>,
) => AjvLike;

import authorizationSchemaCurrent from '../../packages/types/src/schemas/authorization.schema.json' with { type: 'json' };
import communicationSchemaCurrent from '../../packages/types/src/schemas/communication.schema.json' with { type: 'json' };
import identitySchemaCurrent from '../../packages/types/src/schemas/identity.schema.json' with { type: 'json' };
import ledgerSchemaCurrent from '../../packages/types/src/schemas/ledger.schema.json' with { type: 'json' };
import auditSchemaCurrent from '../../packages/types/src/schemas/audit.schema.json' with { type: 'json' };
import sessionSchemaCurrent from '../../packages/types/src/schemas/session.schema.json' with { type: 'json' };
import encryptionSchemaCurrent from '../../packages/types/src/schemas/encryption.schema.json' with { type: 'json' };

import type { SchemaId } from '../../packages/types/src/index.js';

export type ValidatorVersion = '0.1.0' | '0.2.0' | '0.3.0';

const SUPPORTED_VALIDATOR_VERSIONS: ReadonlySet<string> = new Set([
    '0.1.0',
    '0.2.0',
    '0.3.0',
]);

/** Type guard + fail-closed runtime check. */
export function isSupportedValidatorVersion(v: string): v is ValidatorVersion {
    return SUPPORTED_VALIDATOR_VERSIONS.has(v);
}

export interface MultiVersionValidationIssue {
    instancePath: string;
    message: string;
    keyword: string;
}

export interface MultiVersionValidationResult {
    valid: boolean;
    errors: MultiVersionValidationIssue[];
}

// Deep-copy + controlled patch helper
function clone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj)) as T;
}

/**
 * Build the v0.1.0 schema variant (specVersion enum is only '0.1.0').
 * Covers xv-03: v0.3.0 envelope → v0.1.0 validator REJECT.
 */
function buildV010CommunicationSchema(): typeof communicationSchemaCurrent {
    const schema = clone(communicationSchemaCurrent);
    const defs = (schema as { $defs?: Record<string, unknown> }).$defs;
    if (defs && typeof defs === 'object') {
        const compat = (defs as Record<string, { enum?: string[] }>)
            .specVersionCompat;
        if (compat && Array.isArray(compat.enum)) {
            compat.enum = ['0.1.0'];
        }
    }
    schema.$id =
        'https://coivitas.ai/schemas/v0.1.0/communication.schema.json';
    return schema;
}

/**
 * Build the v0.2.0 ledger schema variant (remove 'SESSION_SUPERSEDED' from the action enum + disable the
 * SESSION_SUPERSEDED const in the control-plane allOf).
 * Covers xv-06: a v0.3.0 SESSION_SUPERSEDED ActionRecord → v0.2.0 validator REJECT.
 */
function buildV020LedgerSchema(): typeof ledgerSchemaCurrent {
    const schema = clone(ledgerSchemaCurrent);
    // 1) Remove SESSION_SUPERSEDED from actionRecord.action.enum
    const defs = (schema as { $defs?: Record<string, unknown> }).$defs;
    if (defs && typeof defs === 'object') {
        const actionRecord = defs.actionRecord as
            | {
                  properties?: { action?: { enum?: string[] } };
              }
            | undefined;
        if (actionRecord?.properties?.action?.enum) {
            actionRecord.properties.action.enum =
                actionRecord.properties.action.enum.filter(
                    (a) => a !== 'SESSION_SUPERSEDED',
                );
        }
    }
    // 2) Disable the control-plane branch targeting SESSION_SUPERSEDED in the root-level allOf (to avoid double failure)
    const root = schema as { allOf?: Array<unknown> };
    if (Array.isArray(root.allOf)) {
        root.allOf = root.allOf.filter((branch) => {
            const ifClause = (
                branch as {
                    if?: { properties?: { action?: { const?: string } } };
                }
            ).if;
            return ifClause?.properties?.action?.const !== 'SESSION_SUPERSEDED';
        });
    }
    schema.$id = 'https://coivitas.ai/schemas/v0.2.0/ledger.schema.json';
    return schema;
}

interface CompiledValidatorSet {
    negotiationEnvelope: ValidateFn;
    actionRecord: ValidateFn;
}

const validatorCache: Map<ValidatorVersion, CompiledValidatorSet> = new Map();

function getValidatorSet(version: ValidatorVersion): CompiledValidatorSet {
    const cached = validatorCache.get(version);
    if (cached) return cached;

    const ajv = new Ajv({
        strict: false,
        allErrors: true,
        allowUnionTypes: true,
    });

    // v0.1.0: only communication is narrowed (covers xv-03); the remaining schemas still use the current version as the baseline
    // v0.2.0: only ledger is narrowed (covers xv-06); the remaining schemas still use the current version as the baseline
    const communication =
        version === '0.1.0'
            ? buildV010CommunicationSchema()
            : communicationSchemaCurrent;
    const ledger =
        version === '0.2.0' ? buildV020LedgerSchema() : ledgerSchemaCurrent;

    // Cross-schema references: identity / authorization / encryption etc. must be registered together
    // Note: the discovery schemas use the draft 2020-12 meta, which is incompatible with this ajv instance (draft-07);
    // but negotiationEnvelope / actionRecord do not depend on discovery, so it can be omitted.
    ajv.addSchema(authorizationSchemaCurrent);
    ajv.addSchema(identitySchemaCurrent);
    ajv.addSchema(auditSchemaCurrent);
    ajv.addSchema(sessionSchemaCurrent);
    ajv.addSchema(encryptionSchemaCurrent);
    ajv.addSchema(communication);
    ajv.addSchema(ledger);

    const negotiationEnvelopeRef = `${communication.$id}#/$defs/negotiationEnvelope`;
    const actionRecordRef = `${ledger.$id}#/$defs/actionRecord`;

    const negotiationEnvelope = ajv.getSchema(negotiationEnvelopeRef);
    const actionRecord = ajv.getSchema(actionRecordRef);

    if (!negotiationEnvelope || !actionRecord) {
        throw new Error(
            `multi-version validator (${version}) failed to compile: missing schema ref`,
        );
    }

    const set: CompiledValidatorSet = {
        negotiationEnvelope,
        actionRecord,
    };
    validatorCache.set(version, set);
    return set;
}

/**
 * Multi-version validator routing: select the corresponding AJV instance by validatorVersion and validate.
 * Only a subset of schemaIds is supported (negotiationEnvelope / actionRecord).
 * Other schemaIds fall back to the caller's current validator at that version (i.e. the caller handles it themselves).
 *
 * An unknown validatorVersion (typo / unsupported) throws rather than silently falling back to v0.3.0,
 * to avoid the acceptance gate failing open.
 */
export function validateAgainstVersionedSchema(
    data: unknown,
    schemaId: SchemaId,
    // Received as a string to allow runtime typo detection. The fixture JSON passes the string through directly.
    version: string,
): MultiVersionValidationResult | null {
    if (!isSupportedValidatorVersion(version)) {
        throw new Error(
            `multi-version validator: unsupported validatorVersion='${version}'; expected one of ${[...SUPPORTED_VALIDATOR_VERSIONS].join(', ')}`,
        );
    }
    if (schemaId !== 'negotiationEnvelope' && schemaId !== 'actionRecord') {
        // Outside the coverage set: return null to let the caller fall back
        return null;
    }
    const set = getValidatorSet(version);
    const fn =
        schemaId === 'negotiationEnvelope'
            ? set.negotiationEnvelope
            : set.actionRecord;
    const valid = fn(data);
    const errors: MultiVersionValidationIssue[] = (fn.errors ?? []).map(
        (e) => ({
            instancePath: e.instancePath || '/',
            message: e.message ?? 'validation failed',
            keyword: e.keyword,
        }),
    );
    return { valid: Boolean(valid), errors };
}
