import { generateKeyPair } from '@coivitas/crypto';
import type {
    AgentIdentityDocument,
    DID,
    KeyRotationState,
    ResolvedPublicKeys,
    Timestamp,
} from '@coivitas/types';
import {
    SPEC_VERSION,
    SUPPORTED_SPEC_VERSIONS,
    validateAgainstSchema,
} from '@coivitas/types';

import { createBinding, verifyBinding } from './binding.js';
import { createAgentDID, isDidAgent, isDidKey } from './did.js';
import { verifyRotationProof } from './key-rotation.js';
import type {
    CreateAgentIdentityParams,
    CreateAgentIdentityResult,
} from './types.js';

export function buildAgentIdentityDocument(params: {
    agentDid?: DID;
    agentPublicKeyHex: string;
    principalDid: DID;
    bindingProof: AgentIdentityDocument['bindingProof'];
    capabilities?: string[];
    serviceEndpoints?: Array<{ id: string; type: string; url: string }>;
    createdAt?: Timestamp;
    updatedAt?: Timestamp;
}): AgentIdentityDocument {
    const createdAt = (params.createdAt ??
        new Date().toISOString()) as Timestamp;
    const updatedAt = params.updatedAt ?? createdAt;
    const agentDid =
        params.agentDid ?? createAgentDID(params.agentPublicKeyHex);

    // Optional fields: when the caller does not provide them, omit the key entirely rather than writing `undefined`.
    // Reason: an HTTP round-trip (JSON.stringify) drops keys whose value is undefined,
    // so if the local object kept `capabilities: undefined`, `toEqual` would not match the server's response body.
    // Contract: an absent optional field = the key does not exist (aligning with the schema's "not required").

    // version field: the initial version is defined as 1. Hardcode 1 when constructing locally
    // to align with the SQL DEFAULT, avoiding the "no key locally / key present in response" asymmetry
    // when registry.query() injects the version column.
    const document: AgentIdentityDocument = {
        id: agentDid,
        specVersion: SPEC_VERSION,
        principalDid: params.principalDid,
        publicKey: params.agentPublicKeyHex,
        bindingProof: params.bindingProof,
        ...(params.capabilities !== undefined && {
            capabilities: params.capabilities,
        }),
        ...(params.serviceEndpoints !== undefined && {
            serviceEndpoints: params.serviceEndpoints,
        }),
        createdAt,
        updatedAt,
        version: 1,
    };

    return document;
}

export function createAgentIdentity(
    params: CreateAgentIdentityParams,
): CreateAgentIdentityResult {
    const keyPair = generateKeyPair();
    const agentDid = createAgentDID(keyPair.publicKey);
    const createdAt = (params.createdAt ??
        new Date().toISOString()) as Timestamp;
    const bindingProof = createBinding({
        principalDid: params.principalDid,
        agentDid,
        principalPrivateKey: params.principalPrivateKey,
        issuedAt: createdAt,
        expiresAt: null,
    });

    return {
        document: buildAgentIdentityDocument({
            agentDid,
            agentPublicKeyHex: keyPair.publicKey,
            principalDid: params.principalDid,
            bindingProof,
            capabilities: params.capabilities,
            serviceEndpoints: params.serviceEndpoints,
            createdAt,
            updatedAt: createdAt,
        }),
        privateKey: keyPair.privateKey,
    };
}

export function verifyAgentIdentityDocument(document: AgentIdentityDocument): {
    valid: boolean;
    errors: Array<{ field: string; message: string }>;
} {
    const errors: Array<{ field: string; message: string }> = [];
    const schemaResult = validateAgainstSchema(
        document,
        'agentIdentityDocument',
    );

    for (const issue of schemaResult.errors) {
        errors.push({
            field: issue.instancePath,
            message: issue.message,
        });
    }

    if (
        !(SUPPORTED_SPEC_VERSIONS as readonly string[]).includes(
            document.specVersion,
        )
    ) {
        errors.push({
            field: 'specVersion',
            message: `Expected one of ${SUPPORTED_SPEC_VERSIONS.join(', ')}.`,
        });
    }

    if (!isDidAgent(document.id)) {
        errors.push({ field: 'id', message: 'Agent DID format is invalid.' });
    }

    if (!isDidKey(document.principalDid)) {
        errors.push({
            field: 'principalDid',
            message: 'Principal DID format is invalid.',
        });
    }

    // Key-rotation version check:
    // At v=1 (or the default version) the DID is self-certified by the current publicKey.
    // At v>1 the DID is anchored to the first-version public key and must be chain-verified via getDocumentHistory —
    // this function is a stateless validator and does not load history; the caller (the resolver) is responsible for history-chain verification.
    // At v>1, the document must carry a rotationProof and pass triple-signature verification.
    const documentVersion = document.version ?? 1;
    if (documentVersion === 1) {
        if (createAgentDID(document.publicKey) !== document.id) {
            errors.push({
                field: 'publicKey',
                message: 'publicKey does not match document.id.',
            });
        }
    } else {
        // version > 1:
        // 1. rotationProof must exist
        // 2. the rotationProof triple signature must be valid
        // 3. the rotationProof must be bound to the current document (field-binding rules):
        // - proof.agentDid === document.id (prevents cross-agent replay)
        // - proof.newPublicKey === document.publicKey (prevents grafting a valid proof onto a different public key)
        // - proof.oldPublicKey === document.previousPublicKey (if present; prevents skipping an intermediate version)
        // The stateless validator still does not load the history chain (the resolver handles that),
        // but the field-binding checks must be completed here, otherwise IdentityRegistry would accept a tampered document.
        if (!document.rotationProof) {
            errors.push({
                field: 'rotationProof',
                message: 'rotationProof is required when version > 1.',
            });
        } else {
            const proof = document.rotationProof;

            if (proof.agentDid !== document.id) {
                errors.push({
                    field: 'rotationProof.agentDid',
                    message:
                        'rotationProof.agentDid must match document.id.',
                });
            }
            if (proof.newPublicKey !== document.publicKey) {
                errors.push({
                    field: 'rotationProof.newPublicKey',
                    message:
                        'rotationProof.newPublicKey must match document.publicKey.',
                });
            }
            if (
                document.previousPublicKey !== undefined &&
                proof.oldPublicKey !== document.previousPublicKey
            ) {
                errors.push({
                    field: 'rotationProof.oldPublicKey',
                    message:
                        'rotationProof.oldPublicKey must match document.previousPublicKey.',
                });
            }

            if (!verifyRotationProof(proof, document.principalDid)) {
                errors.push({
                    field: 'rotationProof',
                    message:
                        'rotationProof triple-signature verification failed.',
                });
            }
        }
    }

    if (document.bindingProof.agentDid !== document.id) {
        errors.push({
            field: 'bindingProof.agentDid',
            message: 'Binding proof agent DID mismatch.',
        });
    }

    if (document.bindingProof.principalDid !== document.principalDid) {
        errors.push({
            field: 'bindingProof.principalDid',
            message: 'Binding proof principal DID mismatch.',
        });
    }

    if (!verifyBinding(document.bindingProof)) {
        errors.push({
            field: 'bindingProof',
            message: 'Binding proof verification failed.',
        });
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}

export const buildAgentDocument = buildAgentIdentityDocument;

/**
 * Default grace-period duration: 24 hours (milliseconds)
 * Conclusion: the maximum time window during which the old key remains usable during rotation; beyond it only the new key is returned.
 */
export const DEFAULT_GRACE_PERIOD_MS = 24 * 60 * 60 * 1000;

/**
 * Grace-period hard ceiling: 48 hours (milliseconds)
 * Conclusion: the maximum grace period, preventing callers from passing an excessively large value that would degrade security.
 */
export const MAX_GRACE_PERIOD_MS = 48 * 60 * 60 * 1000;

/**
 * Resolve an agent's set of usable public keys
 *
 * Logic:
 *   - ACTIVE/RETIRED → return only current (the current public key)
 *   - ROTATING + grace period not expired + previousPublicKey present → return current + previous
 *   - ROTATING + grace period expired → return only current (the old key is no longer accepted)
 *   - ROTATING + rotationStartedAt is null → degrade, return only current
 *
 * Pure function: accepts already-resolved record data; does not inject a Registry object.
 */
export function resolvePublicKeys(
    record: {
        document: AgentIdentityDocument;
        rotationState: KeyRotationState;
        rotationStartedAt: Timestamp | null;
    },
    opts?: { gracePeriodMs?: number; now?: Timestamp },
): ResolvedPublicKeys {
    const { document, rotationState, rotationStartedAt } = record;
    // Hard-ceiling constraint: prevents callers from passing a value above the ceiling (MAX_GRACE_PERIOD_MS = 48h)
    const gracePeriodMs = Math.min(
        opts?.gracePeriodMs ?? DEFAULT_GRACE_PERIOD_MS,
        MAX_GRACE_PERIOD_MS,
    );
    const nowMs = opts?.now ? new Date(opts.now).getTime() : Date.now();

    // State mapping (v0.2 KeyRotationState → v0.3 ResolvedKeyRotationState):
    // ACTIVE/RETIRED → STABLE (meaning: no rotation in progress, only current is valid)
    // ROTATING → ROTATING (kept as is, the grace-period logic is handled below)
    // The FROZEN output path is left for the full implementation (the current input type has no FROZEN)
    // Non-ROTATING state: return only the current public key, mapped to STABLE
    if (rotationState !== 'ROTATING') {
        return {
            current: document.publicKey,
            rotationState: 'STABLE',
        };
    }

    // ROTATING but rotationStartedAt missing → degrade; the cutoff cannot be computed,
    // so map to STABLE to keep schema-runtime consistency:
    // the schema already strengthened "ROTATING requires [previous, previousValidBefore]",
    // and a missing rotationStartedAt is equivalent to "cannot prove rotation is in progress", equivalent to STABLE semantics.
    if (rotationStartedAt === null) {
        return {
            current: document.publicKey,
            rotationState: 'STABLE',
        };
    }

    // Check whether the grace period has expired (>= semantics: exactly equal to the ceiling counts as expired)
    const rotationStartedMs = new Date(rotationStartedAt).getTime();
    const gracePeriodExpired = nowMs - rotationStartedMs >= gracePeriodMs;

    // Grace period not expired and previousPublicKey present → dual-key mode
    // Return the previousValidBefore field,
    // which the verifier uses as a cutoff to reject tokens forged with the old key after rotation.
    // The version field is still not returned (the caller reads it from AgentRegistryRecord.document.version).
    if (!gracePeriodExpired && document.previousPublicKey !== undefined) {
        return {
            current: document.publicKey,
            previous: document.previousPublicKey,
            previousValidBefore: rotationStartedAt,
            rotationState: 'ROTATING',
        };
    }

    // Grace period expired → rotation is semantically complete, map to STABLE
    // Likewise, without previousPublicKey, return only current (degrade)
    return {
        current: document.publicKey,
        rotationState: 'STABLE',
    };
}
