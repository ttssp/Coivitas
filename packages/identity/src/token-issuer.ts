import { randomUUID } from 'node:crypto';

import { canonicalize, sign } from '@coivitas/crypto';
import { IDENTITY_ENCODING } from './encoding-config.js';
import {
    MAX_DELEGATION_DEPTH,
    ProtocolError,
    SPEC_VERSION_0_2_0,
    SPEC_VERSION,
    type AttenuationDetail,
    type AttenuationResult,
    type Capability,
    type CapabilityToken,
    type DID,
    type DelegationProof,
    type DelegationProofSignedPayload,
    type Scope,
    type Timestamp,
} from '@coivitas/types';

import { isDidAgent, isDidKey, isTimestampExpired } from './did.js';

export interface IssueCapabilityTokenParams {
    issuerDid: DID;
    issuedTo: DID;
    capabilities: Capability[];
    expiresAt: Timestamp;
    revocationUrl: string;
    issuerPrivateKey: string;
    issuedAt?: Timestamp;
}

type CapabilityTokenPayload = Omit<CapabilityToken, 'proof'>;

export function createCapabilityTokenPayload(
    token: CapabilityTokenPayload,
): Uint8Array {
    // Delegation chains: when delegationChain is present it must be included in
    // the top-level signing payload, otherwise the signature does not protect the delegation chain and anyone could tamper with the chain afterward.
    // When absent, the field does not appear in the canonicalized JSON (RFC 8785 aligns with undefined),
    // so a non-delegated token's signed bytes are exactly the same as before.
    const base: Record<string, unknown> = {
        capabilities: token.capabilities,
        expiresAt: token.expiresAt,
        id: token.id,
        issuedAt: token.issuedAt,
        issuedTo: token.issuedTo,
        issuerDid: token.issuerDid,
        principalDid: token.principalDid,
        revocationUrl: token.revocationUrl,
        specVersion: token.specVersion,
    };
    if (token.delegationChain !== undefined) {
        base.delegationChain = token.delegationChain;
    }
    return new TextEncoder().encode(canonicalize(base));
}

export function issueCapabilityToken(
    params: IssueCapabilityTokenParams,
): CapabilityToken {
    const issuedAt = (params.issuedAt ?? new Date().toISOString()) as Timestamp;

    if (!isDidKey(params.issuerDid)) {
        throw new ProtocolError(
            'SIGNATURE_INVALID',
            `Issuer DID must be did:key: ${String(params.issuerDid)}`,
        );
    }

    if (!isDidAgent(params.issuedTo)) {
        throw new ProtocolError(
            'IDENTITY_NOT_FOUND',
            `Issued-to DID must be did:agent: ${String(params.issuedTo)}`,
        );
    }

    if (params.capabilities.length === 0) {
        throw new ProtocolError(
            'SCOPE_EXCEEDED',
            'Capability token must include at least one capability.',
        );
    }

    if (isTimestampExpired(params.expiresAt, issuedAt)) {
        throw new ProtocolError(
            'TOKEN_EXPIRED',
            'Capability token expiry must be in the future.',
        );
    }

    if (!isValidRevocationUrlTemplate(params.revocationUrl)) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'Revocation URL must be an HTTPS URL template containing {id}.',
        );
    }

    const payload: CapabilityTokenPayload = {
        id: `urn:cap:${randomUUID()}`,
        specVersion: SPEC_VERSION,
        issuerDid: params.issuerDid,
        principalDid: params.issuerDid,
        issuedTo: params.issuedTo,
        issuedAt,
        expiresAt: params.expiresAt,
        capabilities: params.capabilities,
        revocationUrl: params.revocationUrl,
    };

    return {
        ...payload,
        proof: {
            type: 'Ed25519Signature2026',
            created: issuedAt,
            verificationMethod: `${params.issuerDid}#key-1`,
            value: sign(
                createCapabilityTokenPayload(payload),
                params.issuerPrivateKey,
                IDENTITY_ENCODING,
            ) as CapabilityToken['proof']['value'],
        },
    };
}

// ─── Helper: scope-dimension match key ───────────────────────────────────────────────────
// Per the scope-extensions spec: same-kind scopes use "type:field"; singleton types use "type".
// The cumulative_limit uniqueness key =
// (meterField.metric, window); the same metric with different windows is a legitimate combination (e.g. holding
// daily + monthly limits simultaneously) and should not be intercepted by the duplicate_dimension pre-check.
// Previously keying on metric alone would reject the multi-window combinations the spec allows.
function scopeMatchKey(scope: Scope): string {
    switch (scope.type) {
        case 'allowlist':
        case 'numeric_limit':
            return `${scope.type}:${scope.field}`;
        case 'temporal_scope':
            return 'temporal_scope';
        case 'cumulative_limit':
            return `cumulative_limit:${scope.meterField.metric}:${scope.window}`;
        default:
            // Unknown type, fail-closed
            return `__unknown__:${(scope as { type: string }).type}`;
    }
}

// ─── Helper: HH:MM → minutes ─────────────────────────────────────────────────────
function parseHHMM(t: string): number {
    const [h, m] = t.split(':').map(Number);
    return (h ?? 0) * 60 + (m ?? 0);
}

// ─── Helper: expand the [start,end) time range into a set of minutes (supports crossing midnight) ─────────────────
function expandToMinuteSet(startMin: number, endMin: number): Set<number> {
    const set = new Set<number>();
    if (startMin <= endMin) {
        for (let m = startMin; m < endMin; m++) set.add(m);
    } else {
        // Crossing midnight: 22:00→06:00
        for (let m = startMin; m < 1440; m++) set.add(m);
        for (let m = 0; m < endMin; m++) set.add(m);
    }
    return set;
}

// ─── Helper: check whether the child time range is a subset of the parent ─────────────────────────────
function isTimeRangeSubset(
    childStart: number,
    childEnd: number,
    parentStart: number,
    parentEnd: number,
): boolean {
    const childSet = expandToMinuteSet(childStart, childEnd);
    const parentSet = expandToMinuteSet(parentStart, parentEnd);
    for (const m of childSet) {
        if (!parentSet.has(m)) return false;
    }
    return true;
}

// ─── Helper: deep equality (used only for meterField comparison) ──────────────────────────────────
function deepEquals(a: unknown, b: unknown): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
}

// ─── Helper: determine whether a child scope is a subset of a parent scope ───────────────────────
// Returns true on success; returns an AttenuationDetail describing the failure reason
function isScopeSubset(child: Scope, parent: Scope): true | AttenuationDetail {
    if (child.type !== parent.type) {
        return { rule: 'scope_type_unknown', scopeType: child.type };
    }
    switch (child.type) {
        case 'allowlist': {
            const p = parent as typeof child;
            if (child.field !== p.field) {
                return { rule: 'allowlist_violation', field: child.field };
            }
            const parentSet = new Set(p.values);
            for (const v of child.values) {
                if (!parentSet.has(v)) {
                    return { rule: 'allowlist_violation', field: child.field };
                }
            }
            return true;
        }
        case 'numeric_limit': {
            const p = parent as typeof child;
            if (child.field !== p.field) {
                return { rule: 'numeric_limit_violation', field: child.field };
            }
            if (child.max > p.max) {
                return { rule: 'numeric_limit_violation', field: child.field };
            }
            return true;
        }
        case 'temporal_scope': {
            const p = parent as typeof child;
            // notBefore: child cannot be earlier than parent
            if (child.notBefore < p.notBefore) {
                return { rule: 'temporal_subset', reason: 'notBefore' };
            }
            // notAfter: child cannot be later than parent
            if (child.notAfter > p.notAfter) {
                return { rule: 'temporal_subset', reason: 'notAfter' };
            }
            // parent has a recurringWindow but child does not → child is not bound by recurring → violates the subset rule
            if (
                p.recurringWindow !== undefined &&
                child.recurringWindow === undefined
            ) {
                return { rule: 'temporal_subset', reason: 'recurringWindow' };
            }
            // recurringWindow: if child has a window it must be a subset of the parent window
            if (child.recurringWindow !== undefined) {
                if (p.recurringWindow === undefined) {
                    // parent unrestricted, child has a window → subset
                    return true;
                }
                // timezone must be identical (scope-extensions)
                if (
                    child.recurringWindow.timezone !==
                    p.recurringWindow.timezone
                ) {
                    return {
                        rule: 'temporal_subset',
                        reason: 'recurringWindow',
                    };
                }
                // Check the daysOfWeek subset
                // Previously the subset check was only entered when child provided daysOfWeek,
                // causing "parent restricted to weekdays + child omits daysOfWeek"
                // to be silently let through — child effectively means "available every day", violating the subset rule.
                // Now add the "parent defines but child omits → fail-closed" branch; all other semantics are unchanged.
                if (
                    p.recurringWindow.daysOfWeek !== undefined &&
                    child.recurringWindow.daysOfWeek === undefined
                ) {
                    return {
                        rule: 'temporal_subset',
                        reason: 'recurringWindow',
                    };
                }
                if (child.recurringWindow.daysOfWeek !== undefined) {
                    if (p.recurringWindow.daysOfWeek !== undefined) {
                        const parentDays = new Set(
                            p.recurringWindow.daysOfWeek,
                        );
                        for (const d of child.recurringWindow.daysOfWeek) {
                            if (!parentDays.has(d)) {
                                return {
                                    rule: 'temporal_subset',
                                    reason: 'recurringWindow',
                                };
                            }
                        }
                    }
                    // parent.daysOfWeek undefined = every day, child specifying days = subset → ok
                }
                // Check the time-range subset (the subset does not require identical timezones; the comparison expands by minutes)
                const cStart = parseHHMM(child.recurringWindow.startTime);
                const cEnd = parseHHMM(child.recurringWindow.endTime);
                const pStart = parseHHMM(p.recurringWindow.startTime);
                const pEnd = parseHHMM(p.recurringWindow.endTime);
                if (!isTimeRangeSubset(cStart, cEnd, pStart, pEnd)) {
                    return {
                        rule: 'temporal_subset',
                        reason: 'recurringWindow',
                    };
                }
            }
            return true;
        }
        case 'cumulative_limit': {
            // child has already been narrowed to CumulativeLimitScope by the switch
            // parent being the same type is the premise of rule 2b (scopeMatchKey matches)
            const p = parent as typeof child;
            const c = child;
            if (!deepEquals(c.meterField, p.meterField)) {
                return { rule: 'cumulative_subset', reason: 'meterField' };
            }
            if (c.max > p.max) {
                return { rule: 'cumulative_subset', reason: 'max' };
            }
            // window must be strictly equal: a limit constraint cannot be guaranteed across different windows
            if (c.window !== p.window) {
                return { rule: 'cumulative_subset', reason: 'window' };
            }
            // Previously `c.currency !== undefined && c.currency !== p.currency`
            // short-circuited and let through when child omitted currency, causing "parent restricts currency=USD + child omits"
            // to attenuate into "any currency" — directly widening the authorization. The scope-extensions spec requires
            // currency to be strictly equal (including the case where both are undefined). Changed here to a normalized
            // null comparison; three compliant boundaries: both undefined → ok; both equal → ok; otherwise → fail.
            if ((c.currency ?? null) !== (p.currency ?? null)) {
                return { rule: 'cumulative_subset', reason: 'currency' };
            }
            return true;
        }
        default:
            return {
                rule: 'scope_type_unknown',
                scopeType: (child as { type: string }).type,
            };
    }
}

// ─── Whether the type is a specVersion 0.2.0-only scope type ──────────────────────────────────────────
function isPhase2ScopeType(type: string): boolean {
    return type === 'temporal_scope' || type === 'cumulative_limit';
}

// ─── validateAttenuation overloads ─────────────────────────────────────────────────
// Legacy callers (no versions) return boolean; version-aware callers return AttenuationResult.
// See the delegation-chain spec and the scope-extensions spec.

export function validateAttenuation(
    parentCapabilities: Capability[],
    childCapabilities: Capability[],
): boolean;
export function validateAttenuation(
    parentCapabilities: Capability[],
    childCapabilities: Capability[],
    versions: { parentSpecVersion: string; childSpecVersion: string },
): AttenuationResult;
export function validateAttenuation(
    parentCapabilities: Capability[],
    childCapabilities: Capability[],
    versions?: { parentSpecVersion: string; childSpecVersion: string },
): boolean | AttenuationResult {
    const phase2Mode = versions !== undefined;

    // ─── F2 fail-closed pre-check 1: empty allowlist ──────────────────────────
    // allowlist.values=[] means "authorizes zero items", a dead token at issuance;
    // the schema layer should intercept it via minItems:1, and the runtime layer provides a second safeguard.
    const emptyAllowlistDetail = (
        side: 'parent' | 'child',
        caps: Capability[],
    ): AttenuationDetail | null => {
        for (const cap of caps) {
            if (
                cap.scope.type === 'allowlist' &&
                cap.scope.values.length === 0
            ) {
                return {
                    rule: 'empty_allowlist',
                    side,
                    action: cap.action,
                    field: cap.scope.field,
                };
            }
        }
        return null;
    };
    const emptyParent = emptyAllowlistDetail('parent', parentCapabilities);
    if (emptyParent !== null) {
        return phase2Mode
            ? { ok: false, mixedVersion: false, detail: emptyParent }
            : false;
    }
    const emptyChild = emptyAllowlistDetail('child', childCapabilities);
    if (emptyChild !== null) {
        return phase2Mode
            ? { ok: false, mixedVersion: false, detail: emptyChild }
            : false;
    }

    // ─── F2 fail-closed pre-check 2: duplicate dimension ──────────────────────────────
    // Two identical scopeMatchKeys under the same action (e.g. two `allowlist:category` entries)
    // indicate ambiguous authorization semantics — Map.set silently overwrites, and a malicious parent token could exploit this to make the child wider than the parent under AND
    // semantics. The schema layer should intercept it via (action, scopeMatchKey) uniqueItems, and
    // the runtime layer provides a second safeguard.
    const duplicateDimensionDetail = (
        side: 'parent' | 'child',
        caps: Capability[],
    ): AttenuationDetail | null => {
        const seenByAction = new Map<string, Set<string>>();
        for (const cap of caps) {
            const key = scopeMatchKey(cap.scope);
            const seen = seenByAction.get(cap.action);
            if (seen === undefined) {
                seenByAction.set(cap.action, new Set([key]));
            } else if (seen.has(key)) {
                return {
                    rule: 'duplicate_dimension',
                    side,
                    action: cap.action,
                    dimension: key,
                };
            } else {
                seen.add(key);
            }
        }
        return null;
    };
    const dupParent = duplicateDimensionDetail('parent', parentCapabilities);
    if (dupParent !== null) {
        return phase2Mode
            ? { ok: false, mixedVersion: false, detail: dupParent }
            : false;
    }
    const dupChild = duplicateDimensionDetail('child', childCapabilities);
    if (dupChild !== null) {
        return phase2Mode
            ? { ok: false, mixedVersion: false, detail: dupChild }
            : false;
    }

    // Index each parent capability: action → scope[]
    const parentActionMap = new Map<string, Scope[]>();
    for (const cap of parentCapabilities) {
        const existing = parentActionMap.get(cap.action) ?? [];
        existing.push(cap.scope);
        parentActionMap.set(cap.action, existing);
    }

    // Rule 1: the child actions must be a subset of the parent actions
    for (const child of childCapabilities) {
        if (!parentActionMap.has(child.action)) {
            const detail: AttenuationDetail = {
                rule: '2a',
                missingDimension: child.action,
            };
            return phase2Mode
                ? { ok: false, mixedVersion: false, detail }
                : false;
        }
    }

    // Build a map of child scope dimensions grouped by action
    const childActionMap = new Map<string, Scope[]>();
    for (const cap of childCapabilities) {
        const existing = childActionMap.get(cap.action) ?? [];
        existing.push(cap.scope);
        childActionMap.set(cap.action, existing);
    }

    for (const [action, childScopes] of childActionMap) {
        const parentScopes = parentActionMap.get(action);
        if (parentScopes === undefined) continue; // already caught by rule 1 above, skip
        // Note: pre-check 2 above already ensured no duplicate scopeMatchKey under the same action,
        // so the Map.set below will not cause a silent overwrite.
        const childDimMap = new Map<string, Scope>();
        for (const s of childScopes) {
            childDimMap.set(scopeMatchKey(s), s);
        }
        const parentDimMap = new Map<string, Scope>();
        for (const s of parentScopes) {
            parentDimMap.set(scopeMatchKey(s), s);
        }

        // Rule 2a: every parent dimension must appear in the child
        for (const [key, parentScope] of parentDimMap) {
            const childScope = childDimMap.get(key);
            if (childScope === undefined) {
                // mixed version: a 0.1.0 parent presenting a 0.2.0-only scope type → fail-closed
                const isMixed =
                    phase2Mode &&
                    versions?.parentSpecVersion === '0.2.0' &&
                    versions?.childSpecVersion === '0.1.0' &&
                    isPhase2ScopeType(parentScope.type);
                const detail: AttenuationDetail = {
                    rule: '2a',
                    missingDimension: key,
                };
                return phase2Mode
                    ? { ok: false, mixedVersion: isMixed, detail }
                    : false;
            }
            // Rule 2b: the child scope must be a subset of the parent scope
            const subsetResult = isScopeSubset(childScope, parentScope);
            if (subsetResult !== true) {
                return phase2Mode
                    ? { ok: false, mixedVersion: false, detail: subsetResult }
                    : false;
            }
        }

        // Rule 2c: the child must not introduce a new dimension the parent lacks
        for (const [key, childScope] of childDimMap) {
            if (!parentDimMap.has(key)) {
                // mixed version: a 0.1.0 parent + 0.2.0 child introducing a 0.2.0-only scope type → fail-closed
                const isMixed =
                    phase2Mode &&
                    versions?.parentSpecVersion === '0.1.0' &&
                    versions?.childSpecVersion === '0.2.0' &&
                    isPhase2ScopeType(childScope.type);
                const detail: AttenuationDetail = {
                    rule: '2c',
                    introducedDimension: key,
                };
                return phase2Mode
                    ? { ok: false, mixedVersion: isMixed, detail }
                    : false;
            }
        }
    }

    return phase2Mode ? { ok: true } : true;
}

// ─── DelegateTokenParams ──────────────────────────────────────────────────────
export interface DelegateTokenParams {
    /** The parent token (currently held by the delegator)*/
    parentToken: CapabilityToken;
    /** The delegator's (parentToken.issuedTo) private key, used to sign the DelegationProof*/
    delegatorPrivateKey: string;
    /** The delegatee DID (must be did:agent:)*/
    delegateeDid: DID;
    /** The attenuated capability set (must be a subset of parentToken.capabilities)*/
    attenuatedCapabilities: Capability[];
    /** The child token's expiry time (≤ parentToken.expiresAt)*/
    expiresAt: Timestamp;
    /** The child token's revocation URL template*/
    revocationUrl: string;
    /** Issuance time (uses the current time when omitted)*/
    issuedAt?: Timestamp;
    /**
     * dc sub-protocol version (dc v0.3 baseline A; independent namespace)
     *
     * Optional; when omitted, DelegationProof.dcVersion is not written (v0.1 compatibility path,
     * where the validator falls back to token.specVersion). Pass it explicitly when the caller
     * explicitly requires declaring the dc protocol version (e.g. a v0.3+ mandatory-metadata scenario); using the `DC_VERSION` constant is recommended.
     *
     * Once DelegationProof.dcVersion is written, the signing payload conditionally includes this field,
     * protected by the delegator's signature (preventing verify-time tampering; constraint 4 CONDITIONAL).
     *
     * @since v0.3.0
     */
    dcVersion?: string;
}

// ─── delegateCapabilityToken ──────────────────────────────────────────────────
// See the delegation-chain spec.
export function delegateCapabilityToken(
    params: DelegateTokenParams,
): CapabilityToken {
    const issuedAt = (params.issuedAt ?? new Date().toISOString()) as Timestamp;
    const { parentToken } = params;

    // 1. delegateeDid must be did:agent:
    if (!isDidAgent(params.delegateeDid)) {
        throw new ProtocolError(
            'IDENTITY_NOT_FOUND',
            `Delegatee DID must be did:agent: ${String(params.delegateeDid)}`,
        );
    }

    // 2. attenuatedCapabilities must not be empty
    if (params.attenuatedCapabilities.length === 0) {
        throw new ProtocolError(
            'SCOPE_EXCEEDED',
            'Delegated capability token must include at least one capability.',
        );
    }

    // 3. expiresAt > issuedAt
    if (isTimestampExpired(params.expiresAt, issuedAt)) {
        throw new ProtocolError(
            'TOKEN_EXPIRED',
            'Child token expiry must be in the future.',
        );
    }

    // 3b. child expiresAt ≤ parent expiresAt
    if (params.expiresAt > parentToken.expiresAt) {
        throw new ProtocolError(
            'TOKEN_EXPIRED',
            'Child token expiry cannot exceed parent token expiry.',
        );
    }

    // 4. revocationUrl format
    if (!isValidRevocationUrlTemplate(params.revocationUrl)) {
        throw new ProtocolError(
            'INTERNAL_ERROR',
            'Revocation URL must be an HTTPS URL template containing {id}.',
        );
    }

    // 5. Attenuation check
    // Previously the 2-argument overload was used, making the mixedVersion guard
    // dead code on the issuance path — an attacker could attenuate a 0.1.0 parent token into a 0.2.0 child token
    // and inject 0.2.0-only scope types (temporal_scope/cumulative_limit),
    // which the 0.1.0 validator cannot see → silently widening authorization.
    // Changed to the 3-argument form: parent uses parentToken.specVersion; child is fixed at 0.2.0
    // (line 642 `specVersion: SPEC_VERSION_0_2_0` is already fixed).
    const attenResult = validateAttenuation(
        parentToken.capabilities,
        params.attenuatedCapabilities,
        {
            parentSpecVersion: parentToken.specVersion,
            childSpecVersion: SPEC_VERSION_0_2_0,
        },
    );
    if (!attenResult.ok) {
        // mixedVersion also uses SCOPE_EXCEEDED (consistent with the original 2-argument overload's error-code contract),
        // with detail.mixedVersion carrying the cross-version injection semantics for easy audit distinction;
        // whether to introduce a dedicated MIXED_VERSION_DELEGATION error code is left for later.
        throw new ProtocolError(
            'SCOPE_EXCEEDED',
            attenResult.mixedVersion
                ? `Mixed-version delegation rejected (parent specVersion=${parentToken.specVersion}, child specVersion=${SPEC_VERSION_0_2_0}); attenuation detail: ${JSON.stringify(attenResult.detail)}`
                : 'Attenuated capabilities must be a subset of parent capabilities.',
        );
    }

    // 6. Depth check: the existing chain length + 1 (this delegation) must not exceed MAX_DELEGATION_DEPTH
    const currentDepth = (parentToken.delegationChain?.length ?? 0) + 1;
    if (currentDepth > MAX_DELEGATION_DEPTH) {
        throw new ProtocolError(
            'SCOPE_EXCEEDED',
            `Delegation chain depth ${currentDepth} exceeds maximum ${MAX_DELEGATION_DEPTH}.`,
        );
    }

    // 7. Construct the DelegationProof
    // delegatorDid = parentToken.issuedTo (the agent holding the parent token)

    // dc v0.3 option A: dcVersion is written into the proof only when the caller passes it explicitly (the v0.1
    // compatibility path's default behavior is unchanged). If written, it is included in the signed payload bytes (constraint 4
    // CONDITIONAL), protected by the delegator's signature.
    const delegatorDid = parentToken.issuedTo;
    const proofPayload: DelegationProofSignedPayload = {
        parentTokenId: parentToken.id,
        delegatorDid,
        delegateeDid: params.delegateeDid,
        parentCapabilities: parentToken.capabilities,
        parentExpiresAt: parentToken.expiresAt,
        attenuatedCapabilities: params.attenuatedCapabilities,
        ...(params.dcVersion !== undefined
            ? { dcVersion: params.dcVersion }
            : {}),
    };
    const proofBytes = new TextEncoder().encode(
        canonicalize(proofPayload as unknown as Record<string, unknown>),
    );
    const delegationProof: DelegationProof = {
        ...proofPayload,
        proof: {
            type: 'Ed25519Signature2026',
            created: issuedAt,
            verificationMethod: `${delegatorDid}#key-1`,
            value: sign(
                proofBytes,
                params.delegatorPrivateKey,
                IDENTITY_ENCODING,
            ) as DelegationProof['proof']['value'],
        },
    };

    // 8. Construct the child token payload
    // issuerDid / principalDid are inherited from the parent token (always the human principal)
    // issuedTo = delegateeDid; specVersion = 0.2.0
    const newChain: DelegationProof[] = [
        ...(parentToken.delegationChain ?? []),
        delegationProof,
    ];
    type ChildPayload = Omit<CapabilityToken, 'proof'>;
    const childPayload: ChildPayload = {
        id: `urn:cap:${randomUUID()}`,
        specVersion: SPEC_VERSION_0_2_0,
        issuerDid: parentToken.issuerDid,
        principalDid: parentToken.principalDid,
        issuedTo: params.delegateeDid,
        issuedAt,
        expiresAt: params.expiresAt,
        capabilities: params.attenuatedCapabilities,
        revocationUrl: params.revocationUrl,
        delegationChain: newChain,
    };

    // 9. Sign the child token (the delegator signs the child token, with verificationMethod pointing at delegatorDid)
    return {
        ...childPayload,
        proof: {
            type: 'Ed25519Signature2026',
            created: issuedAt,
            verificationMethod: `${delegatorDid}#key-1`,
            value: sign(
                createCapabilityTokenPayload(childPayload),
                params.delegatorPrivateKey,
                IDENTITY_ENCODING,
            ) as CapabilityToken['proof']['value'],
        },
    };
}

function isValidRevocationUrlTemplate(url: string): boolean {
    if (!url.includes('{id}')) {
        return false;
    }

    try {
        const parsed = new URL(url.replace('{id}', 'placeholder'));

        return parsed.protocol === 'https:' && parsed.hostname.length > 0;
    } catch {
        return false;
    }
}
