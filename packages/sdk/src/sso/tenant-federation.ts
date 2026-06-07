/**
 * Tenant Federation
 *
 * Responsibilities:
 *   - FederationPort: abstracts database operations (interface injection; supports test mocks)
 *   - TenantFederationAdapter: the production implementation of FederationPort (wraps pg.PoolClient transactions)
 *   - TenantFederationProvider: the core federation business class
 *     - resolveTenant: take the user identity completed by the SAML / OIDC IDP -> resolve it into tenant_id + role
 *     - internally fail-closed in guard 1-3 order (tenant_scope_missing / invalid_type / not_found)
 *     - cross-tenant assertion substitution attack defense (IDP bound to a fixed set of tenant_ids)
 *     - JIT user provisioning (on first login, creates user + identity_link + audit)
 *   - Express handler factory (aligned with the SAML / OIDC pattern):
 *     - createFederationResolveHandler: resolve tenant + role -> return FederationResolution
 *     - createFederationLogoutHandler: record a federation logout audit event
 *
 * Security P0 guards (literally forbidden — grep tests verify the source contains no skip/bypass keywords):
 *   - tenant_id missing -> throw FederationError(TENANT_SCOPE_MISSING)
 *   - tenant_id not a string -> throw FederationError(TENANT_SCOPE_INVALID_TYPE)
 *   - tenant_id not in the tenants table -> throw FederationError(TENANT_NOT_FOUND)
 *   - the IDP's allowed set does not contain assertedTenantId -> throw FederationError(CROSS_TENANT_ASSERTION)
 *   - an existing user but the assertion changes tenant_id -> throw FederationError(IDENTITY_REBIND_REJECTED)
 *   - a stub default 200 is forbidden (fail-closed; all errors -> 4xx/5xx + FederationErrorCode)
 *
 * Hardening points:
 *   - FederationPort injection (does not depend on the concrete TenantFederationProvider class)
 *   - FederationLogoutContext as a standalone type (no partial type assertions allowed)
 *   - every FederationErrorCode corresponds to a fixed sanitizedMessage (not a 256-char truncation)
 *   - federation_mapping idp_signing_cert / idp_jwks_uri JSDoc trust-chain declarations
 *   - keyword grep defense extended to acceptAlgNone / allowAlgNone / skipAlgValidation
 *   - at_hash N/A docstring (the federation layer does not verify JWTs)
 *
 * Keyword grep defense (must not appear in non-comment code lines):
 *   - the original SAML/OIDC 9 keywords: skipSignatureVerify / disableSigCheck / noSigValidation
 *     / skipExpiry / ignoreExp / bypassExpiry / skipIssuer / skipAudience / wildcardClient
 *   - OIDC alg bypass: acceptAlgNone / allowAlgNone / skipAlgValidation / bypassAud / skipNonce
 *   - federation 11 keywords: skipTenantScope / allowCrossTenant / bypassTenantValidation
 *     / trustAllIdp / skipIdpMapping / wildcardTenant
 *     / disableJitGuard / allowIdentityRebind / acceptAnyExternalSubject
 *     / skipFederationAudit / bypassRoleCheck
 *
 * @note at_hash verification: N/A — the federation layer does not verify JWTs;
 *   signature verification is done by saml-provider / oidc-provider. This layer only consumes the already-verified SAMLClaims / OidcUserClaims.
 *
 * @see saml-provider.ts (the source of assertion verification)
 * @see oidc-provider.ts (the source of id_token verification)
 */

import type { SamlUserClaims } from './types.js';
import { parseSamlUserClaims } from './types.js';
import type { OidcUserClaims } from './oidc-provider.js';
import { parseOidcUserClaims } from './oidc-provider.js';

// ── FederationErrorCode (8-entry closed enum; fail-closed system) ─────────────────────

/**
 * Federation error codes (8-entry closed enum; fail-closed system)
 *
 * Conclusion: every federation verification failure maps to a specific error code;
 * error codes correspond to HTTP status codes (mapped in the handler layer);
 * a stub default 200 is forbidden.
 *
 * Hardening: each code must correspond to a fixed sanitizedMessage (full coverage of entries 4-8;
 * avoids leaking PII such as tenant_id / external_subject; no default 256-char fallback allowed).
 */
export const FederationErrorCode = {
    TENANT_SCOPE_MISSING: 'FED_TENANT_SCOPE_MISSING',
    TENANT_SCOPE_INVALID_TYPE: 'FED_TENANT_SCOPE_INVALID_TYPE',
    TENANT_NOT_FOUND: 'FED_TENANT_NOT_FOUND',
    CROSS_TENANT_ASSERTION: 'FED_CROSS_TENANT_ASSERTION',
    IDENTITY_REBIND_REJECTED: 'FED_IDENTITY_REBIND_REJECTED',
    ROLE_INVALID: 'FED_ROLE_INVALID',
    IDP_NOT_REGISTERED: 'FED_IDP_NOT_REGISTERED',
    JIT_PROVISIONING_FAILED: 'FED_JIT_PROVISIONING_FAILED',
} as const;

/** the union type of FederationErrorCode values*/
export type FederationErrorCodeValue =
    (typeof FederationErrorCode)[keyof typeof FederationErrorCode];

/**
 * FederationError: base class for all federation-related errors (fail-closed)
 *
 * Trigger scenarios:
 *   - tenant_id missing -> TENANT_SCOPE_MISSING (P0; fail-closed; must reject)
 *   - tenant_id not a string -> TENANT_SCOPE_INVALID_TYPE (P0; fail-closed)
 *   - tenant_id not in the tenants table -> TENANT_NOT_FOUND (P0; fail-closed)
 *   - the IDP's allowed set does not contain assertedTenantId -> CROSS_TENANT_ASSERTION (P0; cross-tenant attack defense)
 *   - an existing user but the assertion changes tenant_id -> IDENTITY_REBIND_REJECTED (P0)
 *   - invalid role -> ROLE_INVALID
 *   - IDP not registered -> IDP_NOT_REGISTERED
 *   - JIT creation failed -> JIT_PROVISIONING_FAILED
 */
export class FederationError extends Error {
    readonly code: FederationErrorCodeValue;

    constructor(
        message: string,
        code: FederationErrorCodeValue = FederationErrorCode.JIT_PROVISIONING_FAILED,
    ) {
        super(message);
        this.name = 'FederationError';
        this.code = code;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// ── sanitize: fixed-message closure (avoids leaking PII) ────────────────

/**
 * FEDERATION_SANITIZED_MESSAGES: the fixed sanitized message for each FederationErrorCode
 *
 * Conclusion: every FederationErrorCode must have a fixed sanitized message;
 * a default 256-char truncation is forbidden (avoids leaking PII such as tenant_id / external_subject).
 *
 * 8 codes -> 8 fixed strings (full coverage).
 */
const FEDERATION_SANITIZED_MESSAGES: Readonly<
    Record<FederationErrorCodeValue, string>
> = Object.freeze({
    [FederationErrorCode.TENANT_SCOPE_MISSING]:
        'Federation rejected: tenant scope claim is missing from the assertion.',
    [FederationErrorCode.TENANT_SCOPE_INVALID_TYPE]:
        'Federation rejected: tenant scope claim has an invalid type (must be string).',
    [FederationErrorCode.TENANT_NOT_FOUND]:
        'Federation rejected: the specified tenant was not found.',
    [FederationErrorCode.CROSS_TENANT_ASSERTION]:
        'Federation rejected: cross-tenant assertion detected. IDP is not authorized for this tenant.',
    [FederationErrorCode.IDENTITY_REBIND_REJECTED]:
        'Federation rejected: identity rebind detected. Tenant mismatch for existing user.',
    [FederationErrorCode.ROLE_INVALID]:
        'Federation rejected: role claim has an invalid value.',
    [FederationErrorCode.IDP_NOT_REGISTERED]:
        'Federation rejected: the IDP is not registered in federation mapping.',
    [FederationErrorCode.JIT_PROVISIONING_FAILED]:
        'Federation failed: JIT user provisioning encountered an error.',
});

/**
 * sanitizeFederationError: convert a FederationError into safe HTTP response content
 *
 * Conclusion: returns fixed strings that never contain PII;
 * code = FED_* -> fixed sanitized message; non-FederationError -> a fixed generic message.
 *
 * @param err any error object
 * @returns { code: string; message: string } (safe for use in an HTTP response)
 */
export function sanitizeFederationError(err: unknown): {
    code: string;
    message: string;
} {
    if (err instanceof FederationError) {
        return {
            code: err.code,
            message: FEDERATION_SANITIZED_MESSAGES[err.code],
        };
    }
    return {
        code: 'FED_INTERNAL_ERROR',
        message: 'Federation encountered an internal error.',
    };
}

// ── Domain object types (the data models FederationPort depends on) ───────────────────────────────

/**
 * Role enum (the in-tenant role asserted by the IDP; fail-closed: anything other than these three values -> ROLE_INVALID)
 */
export type Role = 'admin' | 'operator' | 'viewer';

/** the set of valid Roles (used for validation; bare casts forbidden)*/
const VALID_ROLES: ReadonlySet<string> = new Set<Role>([
    'admin',
    'operator',
    'viewer',
]);

/**
 * parseRole: parse and validate the role claim (bare casts forbidden)
 *
 * @throws FederationError ROLE_INVALID if the role is invalid
 */
export function parseRole(raw: unknown): Role {
    if (typeof raw !== 'string' || raw.trim() === '') {
        throw new FederationError(
            'Role claim is missing or not a string.',
            FederationErrorCode.ROLE_INVALID,
        );
    }
    const trimmed = raw.trim().toLowerCase();
    if (!VALID_ROLES.has(trimmed)) {
        throw new FederationError(
            `Invalid role claim: "${trimmed.slice(0, 64)}". Must be admin, operator, or viewer.`,
            FederationErrorCode.ROLE_INVALID,
        );
    }
    return trimmed as Role;
}

/**
 * Tenant: the tenants table data model
 */
export interface Tenant {
    readonly id: string;
    readonly name: string;
    readonly createdAt: string;
}

/**
 * IdpMapping: the federation_mapping table data model
 *
 * The JSDoc for the idp_signing_cert / idp_jwks_uri fields must declare
 * "trust-chain entry point; tampering = whole-tenant identity compromise" (explicit security documentation).
 */
export interface IdpMapping {
    readonly id: string;
    /** IDP identifier (SAML EntityID or OIDC issuer)*/
    readonly idpIdentifier: string;
    /** IDP type: saml or oidc*/
    readonly idpType: 'saml' | 'oidc';
    /**
     * the set of allowed tenant_ids (array of UUIDs)
     *
     * Security invariant: this field is the core line of defense against cross-tenant assertion substitution attacks.
     * The tenant_id in the assertion must be in this set; otherwise throw CROSS_TENANT_ASSERTION.
     */
    readonly allowedTenantIds: readonly string[];
    /**
     * IDP signing certificate (SAML; PEM format; optional)
     *
     * Security warning: this field is the entry point of the SAML verification trust chain.
     * Tampering with this field is equivalent to letting an attacker replace the IDP signing certificate,
     * thereby forging arbitrary SAML assertions -> whole-tenant identity compromise.
     * Modifying this field must go through security review and authorization.
     */
    readonly idpSigningCert?: string;
    /**
     * IDP JWKS URI (OIDC; optional)
     *
     * Security warning: this field is the entry point of the OIDC verification trust chain.
     * Tampering with this field is equivalent to letting an attacker replace the JWKS endpoint,
     * thereby forging arbitrary OIDC id_tokens -> whole-tenant identity compromise.
     * Modifying this field must go through security review and authorization.
     */
    readonly idpJwksUri?: string;
    readonly createdAt: string;
    readonly updatedAt: string;
}

/**
 * User: the users table data model (federation-layer view)
 */
export interface User {
    readonly id: string;
    readonly tenantId: string;
    readonly role: Role;
    readonly externalSubject: string;
    readonly idpIdentifier: string;
    readonly createdAt: string;
}

/**
 * FederationAuditEvent: the federation audit event written to the events table
 */
export interface FederationAuditEvent {
    readonly eventType:
        | 'federation.login.new_user'
        | 'federation.login.existing_user'
        | 'federation.login.role_updated'
        | 'federation.logout';
    readonly userId: string;
    readonly tenantId: string;
    readonly idpIdentifier: string;
    readonly externalSubject: string;
    readonly isNewUser: boolean;
    readonly roleUpdated: boolean;
    readonly timestamp: string;
    readonly details?: Readonly<Record<string, string>>;
    /**
     * raceRecovered: true means the audit event comes from the race-recovery path (a JIT concurrent UNIQUE VIOLATION 23505).
     * Only set in the race scenario; the normal path does not set this field.
     */
    readonly raceRecovered?: boolean;
    /**
     * previousRole / newRole: set only when raceRecovered === true and roleUpdated === true.
     * Records the role difference discovered during race recovery (for trust-chain change auditing).
     */
    readonly previousRole?: string;
    readonly newRole?: string;
}

/**
 * FederationResolution: the result returned on a successful resolveTenant
 *
 * Conclusion: the canonical result after federation resolution completes;
 * contains userId / tenantId / role / isNewUser;
 * used by upstream handlers / sessions.
 */
export interface FederationResolution {
    readonly userId: string;
    readonly tenantId: string;
    readonly role: Role;
    readonly isNewUser: boolean;
}

/**
 * FederationLogoutContext: the federation logout context (a standalone type)
 *
 * Hardening: a partial OidcUserClaims / SamlUserClaims hack is not allowed;
 * defines a standalone FederationLogoutContext type that makes the fields required for logout explicit.
 */
export interface FederationLogoutContext {
    readonly userId: string;
    readonly tenantId: string;
    readonly idpIdentifier: string;
    readonly externalSubject: string;
    readonly sessionId?: string;
}

// ── InputClaims (discriminated union; the core input) ─────────────────────

/**
 * SamlFederationInput: the federation input after the SAML IDP completes assertion verification
 *
 * Conclusion: comes from saml-provider.ts's SamlUserClaims (signature / expiry / audience already verified);
 * tenant_id + role are provided by assertion.attributes (the IDP injects them in the attribute statement).
 */
export interface SamlFederationInput {
    readonly type: 'saml';
    readonly claims: SamlUserClaims;
    /** IDP EntityID (used for federation_mapping lookup; usually = claims.idpEntityId)*/
    readonly idpIdentifier: string;
}

/**
 * OidcFederationInput: the federation input after the OIDC IDP completes id_token verification
 *
 * Conclusion: comes from oidc-provider.ts's OidcUserClaims (signature / expiry / issuer / audience already verified);
 * tenant_id + role are provided by id_token.attributes or additional claims.
 */
export interface OidcFederationInput {
    readonly type: 'oidc';
    readonly claims: OidcUserClaims;
    /** OIDC issuer (used for federation_mapping lookup; usually = claims.issuer)*/
    readonly idpIdentifier: string;
}

/** FederationInput: discriminated union (SAML or OIDC)*/
export type FederationInput = SamlFederationInput | OidcFederationInput;

// ── FederationPort (interface injection; test mock + production PostgreSQL) ──────────────────

/**
 * FederationPort: interface abstracting database operations
 *
 * Conclusion: isolates the PostgreSQL implementation via interface injection;
 *   - tests inject a mock (without depending on an actual PostgreSQL installation)
 *   - production injects TenantFederationAdapter (which wraps pg.PoolClient)
 *
 * Hardening: the handler factory must accept a FederationPort injection,
 * with no direct dependency on the TenantFederationProvider concrete class.
 *
 * Security constraints:
 *   - findTenantById: if it returns null, throw TENANT_NOT_FOUND (stubbing a non-existent tenant is not allowed)
 *   - findIdpMapping: if it returns null, throw IDP_NOT_REGISTERED
 *   - findUserByExternalSubject: returning null = first login (JIT provisioning)
 *   - createUser: the users INSERT + federation_identity_links INSERT are in the same transaction; the audit is written outside the tx via safeWriteAuditEvent
 */
export interface FederationPort {
    /**
     * Look up a tenant by tenantId
     *
     * @returns Tenant if it exists; null if it does not (-> TENANT_NOT_FOUND)
     */
    findTenantById(tenantId: string): Promise<Tenant | null>;

    /**
     * Look up a federation_mapping by idpIdentifier
     *
     * @returns IdpMapping (with allowedTenantIds); null if not registered (-> IDP_NOT_REGISTERED)
     */
    findIdpMapping(idpIdentifier: string): Promise<IdpMapping | null>;

    /**
     * Look up an existing user by externalSubject
     *
     * @returns User if it already exists; null = first login (JIT provisioning)
     */
    findUserByExternalSubject(
        externalSubject: string,
        idpIdentifier: string,
    ): Promise<User | null>;

    /**
     * Create a new user (JIT provisioning; called on first login)
     *
     * @returns the successfully created User (with an auto-generated user_id)
     * @throws creation failure -> JIT_PROVISIONING_FAILED
     */
    createUser(input: {
        tenantId: string;
        role: Role;
        externalSubject: string;
        idpIdentifier: string;
    }): Promise<User>;

    /**
     * Update an existing user's role (trusting the IDP as the RBAC authoritative source)
     *
     * @throws JIT_PROVISIONING_FAILED if the update fails
     */
    updateUserRole(userId: string, role: Role): Promise<void>;

    /**
     * Write a federation audit event (events table)
     *
     * Security constraint: every federation operation must write an audit log (accountability);
     * an audit write failure should not block the main flow (but the internal error must be logged).
     */
    writeAuditEvent(event: FederationAuditEvent): Promise<void>;
}

// ── FederationHandlerConfig (handler factory parameters) ───────────────────────────

/**
 * FederationHandlerConfig: the configuration parameters of the handler factory
 *
 * Hardening: the handler factory accepts a FederationPort injection (not a TenantFederationProvider);
 * this lets tests mock the port directly without instantiating the full Provider.
 */
export interface FederationHandlerConfig {
    /**
     * the FederationPort implementation (production = TenantFederationAdapter; tests = mock)
     *
     * The handler factory must accept a FederationPort injection,
     * with no direct dependency on the TenantFederationProvider concrete class.
     */
    readonly port: FederationPort;
}

// ── TenantFederationAdapter (production implementation; wraps pg.PoolClient transactions) ──────────────

/**
 * TenantFederationAdapter: the production implementation of FederationPort
 *
 * Conclusion: used in production; in tests a mock is injected via the FederationHandlerConfig.port parameter;
 * the 3 JIT writes — user + identity_link + audit — are completed within the same pg.PoolClient transaction.
 *
 * Dependencies: pg (the PostgreSQL client); migration 024_sso_federation.sql has created the required tables.
 *
 * Security constraints:
 *   - the 3 JIT provisioning writes (createUser + createFederationIdentityLink + writeAuditEvent)
 *     must be in the same BEGIN/COMMIT transaction; any failure -> ROLLBACK + throw JIT_PROVISIONING_FAILED
 *   - findTenantById uses a parameterized query (SQL injection defense)
 *   - string-concatenated SQL is not allowed (injection defense)
 */
export class TenantFederationAdapter implements FederationPort {
    /**
     * the pg.Pool instance (type-erased to unknown to avoid a direct dependency on pg in the test environment)
     * In production, pass an import('pg').Pool instance.
     */
    private readonly pool: unknown;

    constructor(pool: unknown) {
        if (!pool || typeof (pool as Record<string, unknown>)['connect'] !== 'function') {
            throw new FederationError(
                'TenantFederationAdapter: pool must be a valid pg.Pool instance with a connect() method.',
                FederationErrorCode.JIT_PROVISIONING_FAILED,
            );
        }
        this.pool = pool;
    }

    /**
     * getClient: obtain a PoolClient from the pool (for internal use)
     */
    private async getClient(): Promise<{
        query: (text: string, values?: unknown[]) => Promise<{ rows: unknown[] }>;
        release: () => void;
        query_begin: () => Promise<void>;
        query_commit: () => Promise<void>;
        query_rollback: () => Promise<void>;
    }> {
        // Dynamically call pool.connect(); type-erased to avoid a pg dependency
        const pool = this.pool as {
            connect(): Promise<{
                query(
                    text: string,
                    values?: unknown[],
                ): Promise<{ rows: unknown[] }>;
                release(): void;
            }>;
        };
        const client = await pool.connect();
        // Wrap the transaction helper methods
        return {
            query: client.query.bind(client) as (
                text: string,
                values?: unknown[],
            ) => Promise<{ rows: unknown[] }>,
            release: client.release.bind(client),
            query_begin: async () => {
                await client.query('BEGIN');
            },
            query_commit: async () => {
                await client.query('COMMIT');
            },
            query_rollback: async () => {
                await client.query('ROLLBACK');
            },
        };
    }

    async findTenantById(tenantId: string): Promise<Tenant | null> {
        const client = await this.getClient();
        try {
            const result = await client.query(
                'SELECT id, display_name, created_at FROM managed_service.tenants WHERE id = $1',
                [tenantId],
            );
            const rows = result.rows as Array<{
                id: string;
                display_name: string;
                created_at: string;
            }>;
            if (rows.length === 0) return null;
            const row = rows[0]!;
            return {
                id: row.id,
                name: row.display_name,
                createdAt: row.created_at,
            };
        } finally {
            client.release();
        }
    }

    async findIdpMapping(idpIdentifier: string): Promise<IdpMapping | null> {
        const client = await this.getClient();
        try {
            const result = await client.query(
                `SELECT id, idp_identifier, idp_type, allowed_tenant_ids,
                        idp_signing_cert, idp_jwks_uri, created_at, updated_at
                 FROM managed_service.federation_mapping WHERE idp_identifier = $1`,
                [idpIdentifier],
            );
            const rows = result.rows as Array<{
                id: string;
                idp_identifier: string;
                idp_type: string;
                allowed_tenant_ids: string[];
                idp_signing_cert?: string;
                idp_jwks_uri?: string;
                created_at: string;
                updated_at: string;
            }>;
            if (rows.length === 0) return null;
            const row = rows[0]!;
            return {
                id: row.id,
                idpIdentifier: row.idp_identifier,
                idpType: row.idp_type as 'saml' | 'oidc',
                allowedTenantIds: Object.freeze(row.allowed_tenant_ids ?? []),
                idpSigningCert: row.idp_signing_cert,
                idpJwksUri: row.idp_jwks_uri,
                createdAt: row.created_at,
                updatedAt: row.updated_at,
            };
        } finally {
            client.release();
        }
    }

    async findUserByExternalSubject(
        externalSubject: string,
        idpIdentifier: string,
    ): Promise<User | null> {
        const client = await this.getClient();
        try {
            // Query users by joining through federation_identity_links
            const result = await client.query(
                `SELECT u.id, u.tenant_id, u.role, fil.external_subject, fil.idp_identifier, u.created_at
                 FROM managed_service.users u
                 JOIN managed_service.federation_identity_links fil ON fil.user_id = u.id
                 WHERE fil.external_subject = $1 AND fil.idp_identifier = $2`,
                [externalSubject, idpIdentifier],
            );
            const rows = result.rows as Array<{
                id: string;
                tenant_id: string;
                role: string;
                external_subject: string;
                idp_identifier: string;
                created_at: string;
            }>;
            if (rows.length === 0) return null;
            const row = rows[0]!;
            return {
                id: row.id,
                tenantId: row.tenant_id,
                role: parseRole(row.role),
                externalSubject: row.external_subject,
                idpIdentifier: row.idp_identifier,
                createdAt: row.created_at,
            };
        } finally {
            client.release();
        }
    }

    async createUser(input: {
        tenantId: string;
        role: Role;
        externalSubject: string;
        idpIdentifier: string;
    }): Promise<User> {
        const client = await this.getClient();
        try {
            // The 3 writes complete in the same transaction: users + federation_identity_links + events
            await client.query_begin();

            // 1. Create the users row
            const userResult = await client.query(
                `INSERT INTO managed_service.users (id, tenant_id, role, created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, $2, NOW(), NOW())
                 RETURNING id, tenant_id, role, created_at`,
                [input.tenantId, input.role],
            );
            const userRows = userResult.rows as Array<{
                id: string;
                tenant_id: string;
                role: string;
                created_at: string;
            }>;
            if (userRows.length === 0) {
                throw new FederationError(
                    'JIT provisioning: INSERT INTO managed_service.users returned no rows.',
                    FederationErrorCode.JIT_PROVISIONING_FAILED,
                );
            }
            const userRow = userRows[0]!;

            // 2. Create the federation_identity_links row
            await client.query(
                `INSERT INTO managed_service.federation_identity_links (id, user_id, idp_identifier, external_subject, linked_at)
                 VALUES (gen_random_uuid(), $1, $2, $3, NOW())`,
                [userRow.id, input.idpIdentifier, input.externalSubject],
            );

            // Note: do not write the audit event inside the transaction
            // the audit is written by safeWriteAuditEvent after the tx COMMIT, to avoid double writes
            await client.query_commit();

            return {
                id: userRow.id,
                tenantId: userRow.tenant_id,
                role: parseRole(userRow.role),
                externalSubject: input.externalSubject,
                idpIdentifier: input.idpIdentifier,
                createdAt: userRow.created_at,
            };
        } catch (err: unknown) {
            await client.query_rollback();
            if (err instanceof FederationError) throw err;
            // Patch: preserve the pg SQLSTATE code for the outer 23505 race-recovery check
            // the old wrap lost the pg code -> the outer (err as { code }).code === '23505' in provisionOrUpdateUser would never trigger
            // Design: rethrow the pg error directly (with its .code SQLSTATE) -> the outer L995 catch reads (err as { code }).code and matches 23505;
            // only wrap as a FederationError for non-pg errors (without .code)
            const pgErrCode = (err as { code?: unknown } | null)?.code;
            if (typeof pgErrCode === 'string') {
                // pg error: rethrow directly to preserve the SQLSTATE (needed by the outer race-recovery path)
                throw err;
            }
            throw new FederationError(
                `JIT provisioning transaction failed: ${err instanceof Error ? err.message : String(err)}`,
                FederationErrorCode.JIT_PROVISIONING_FAILED,
            );
        } finally {
            client.release();
        }
    }

    async updateUserRole(userId: string, role: Role): Promise<void> {
        const client = await this.getClient();
        try {
            await client.query(
                'UPDATE managed_service.users SET role = $1, updated_at = NOW() WHERE id = $2',
                [role, userId],
            );
        } catch (err: unknown) {
            if (err instanceof FederationError) throw err;
            throw new FederationError(
                `updateUserRole failed: ${err instanceof Error ? err.message : String(err)}`,
                FederationErrorCode.JIT_PROVISIONING_FAILED,
            );
        } finally {
            client.release();
        }
    }

    async writeAuditEvent(event: FederationAuditEvent): Promise<void> {
        const client = await this.getClient();
        try {
            await client.query(
                `INSERT INTO managed_service.events (id, event_type, payload, created_at)
                 VALUES (gen_random_uuid(), $1, $2, NOW())`,
                [
                    event.eventType,
                    JSON.stringify({
                        userId: event.userId,
                        tenantId: event.tenantId,
                        idpIdentifier: event.idpIdentifier,
                        externalSubject: event.externalSubject,
                        isNewUser: event.isNewUser,
                        roleUpdated: event.roleUpdated,
                        details: event.details,
                        // Race-recovery fields: FederationAuditEvent defines them but they must be written explicitly;
                        // only write them when present (avoids a stray undefined key in the payload).
                        ...(event.raceRecovered !== undefined && {
                            raceRecovered: event.raceRecovered,
                        }),
                        ...(event.previousRole !== undefined && {
                            previousRole: event.previousRole,
                        }),
                        ...(event.newRole !== undefined && { newRole: event.newRole }),
                    }),
                ],
            );
        } finally {
            client.release();
        }
    }
}

// ── TenantFederationProvider (business core; 3 P0 guards + JIT + audit) ────────────

/**
 * TenantFederationProvider: the core federation business class
 *
 * Conclusion: takes the user identity after SAML / OIDC IDP verification;
 * resolves it into tenant_id + role + userId; implements 3 P0 fail-closed guards;
 * includes JIT user provisioning (on first login, creates user + identity_link + audit).
 *
 * Security P0 guards (guards 1-3 execute in order; any failure -> reject and stop):
 *   Guard 1: claims.tenant_id missing -> throw TENANT_SCOPE_MISSING
 *   Guard 2: claims.tenant_id not a string -> throw TENANT_SCOPE_INVALID_TYPE
 *   Guard 3: claims.tenant_id does not exist in the tenants table -> throw TENANT_NOT_FOUND
 *
 * cross-tenant assertion substitution attack defense:
 *   - scenario: an attacker obtains a tenant A assertion via IDP A and tampers with the tenant_id field to tenant B
 *   - defense: validateIdpTenantScope verifies assertedTenantId is in idpMapping.allowedTenantIds
 *   - not in the allowed list -> throw CROSS_TENANT_ASSERTION + audit log
 *
 * JIT user provisioning:
 *   - first login (findUserByExternalSubject = null): create user + identity_link + audit
 *   - existing user (match by externalSubject):
 *     - check that tenant_id matches (mismatch -> throw IDENTITY_REBIND_REJECTED)
 *     - role update allowed (trusting the IDP as the RBAC authoritative source)
 */
export class TenantFederationProvider {
    private readonly port: FederationPort;

    constructor(port: FederationPort) {
        this.port = port;
    }

    /**
     * resolveTenant: resolve SAMLClaims or OidcUserClaims into a FederationResolution
     *
     * Security flow:
     *   1. extractTenantClaim: extract tenant_id (guard 1 + guard 2)
     *   2. look up federation_mapping (IDP_NOT_REGISTERED check)
     *   3. validateIdpTenantScope: CROSS_TENANT_ASSERTION check
     *   4. port.findTenantById: guard 3 (TENANT_NOT_FOUND)
     *   5. extractRoleClaim: ROLE_INVALID check
     *   6. extractExternalSubject: extract the external subject identifier
     *   7. JIT provisioning or update (IDENTITY_REBIND_REJECTED check)
     *
     * @param input FederationInput (discriminated union: saml or oidc)
     * @returns FederationResolution (userId / tenantId / role / isNewUser)
     * @throws FederationError on any guard failure (fail-closed; does not return a partial result)
     */
    async resolveTenant(input: FederationInput): Promise<FederationResolution> {
        const { idpIdentifier } = input;

        // Step 1: extract tenant_id (guard 1 + guard 2)
        const assertedTenantId = this.extractTenantClaim(input);

        // Step 2: look up the IDP mapping (IDP_NOT_REGISTERED check)
        const idpMapping = await this.port.findIdpMapping(idpIdentifier);
        if (idpMapping === null) {
            throw new FederationError(
                `IDP "${idpIdentifier.slice(0, 256)}" is not registered in federation_mapping. ` +
                    'Authentication rejected (fail-closed).',
                FederationErrorCode.IDP_NOT_REGISTERED,
            );
        }

        // Step 3: cross-tenant assertion substitution attack defense
        this.validateIdpTenantScope(idpMapping, assertedTenantId);

        // Step 4: guard 3 — tenant_id must exist in the tenants table
        const tenant = await this.port.findTenantById(assertedTenantId);
        if (tenant === null) {
            throw new FederationError(
                'Tenant not found in tenants table. Authentication rejected (fail-closed).',
                FederationErrorCode.TENANT_NOT_FOUND,
            );
        }

        // Step 5: extract and validate the role
        const role = this.extractRoleClaim(input);

        // Step 6: extract the external subject identifier
        const externalSubject = this.extractExternalSubject(input);

        // Step 7: JIT provisioning or update
        return await this.provisionOrUpdateUser(
            externalSubject,
            idpIdentifier,
            assertedTenantId,
            role,
        );
    }

    /**
     * validateIdpTenantScope: verify whether the IDP is authorized to assert the specified tenant_id
     *
     * Conclusion: the core method of cross-tenant assertion substitution attack defense;
     * scenario: an attacker obtains a tenant A assertion via IDP A and tampers with the tenant_id field to tenant B;
     * defense: each IDP is bound to a fixed set of tenant_ids (federation_mapping.allowed_tenant_ids);
     * assertedTenantId must be in that IDP's allowed set of tenant_ids.
     *
     * @param idpMapping the federation_mapping record (with allowedTenantIds)
     * @param assertedTenantId the tenant_id asserted in the assertion
     * @throws FederationError CROSS_TENANT_ASSERTION if it is not in the allowed list
     */
    validateIdpTenantScope(
        idpMapping: IdpMapping,
        assertedTenantId: string,
    ): void {
        const allowed = idpMapping.allowedTenantIds;
        if (!Array.isArray(allowed) || allowed.length === 0) {
            // Empty allowed set -> fail-closed (the IDP is not authorized for any tenant)
            throw new FederationError(
                'IDP has no allowed tenant_ids configured. ' +
                    'Cross-tenant assertion rejected (fail-closed).',
                FederationErrorCode.CROSS_TENANT_ASSERTION,
            );
        }
        if (!allowed.includes(assertedTenantId)) {
            // Use a fixed message to avoid leaking the assertedTenantId PII
            throw new FederationError(
                'Cross-tenant assertion detected: IDP is not authorized for the asserted tenant_id. ' +
                    'Authentication rejected (fail-closed).',
                FederationErrorCode.CROSS_TENANT_ASSERTION,
            );
        }
    }

    // ── Private helper methods ────────────────────────────────────────────────────────────

    /**
     * extractTenantClaim: extract tenant_id from the FederationInput (guard 1 + guard 2)
     *
     * Guard 1: tenant_id field missing (undefined / null / missing key) -> TENANT_SCOPE_MISSING
     * Guard 2: tenant_id present but not a string -> TENANT_SCOPE_INVALID_TYPE
     *
     * SAML: extracted from claims.attributes['tenant_id']
     * OIDC: extracted from claims.attributes['tenant_id']
     *
     * @throws FederationError TENANT_SCOPE_MISSING if tenant_id is missing
     * @throws FederationError TENANT_SCOPE_INVALID_TYPE if tenant_id is not a string
     */
    private extractTenantClaim(input: FederationInput): string {
        let rawTenantId: unknown;

        if (input.type === 'saml') {
            // SAML: tenant_id is in attributes
            rawTenantId = input.claims.attributes['tenant_id'];
        } else {
            // OIDC: tenant_id is in attributes (or possibly in OIDC custom claims)
            rawTenantId = input.claims.attributes['tenant_id'];
        }

        // Guard 1: missing check (undefined / null / empty string are all treated as missing)
        if (rawTenantId === undefined || rawTenantId === null) {
            throw new FederationError(
                'Federation assertion missing required "tenant_id" claim. ' +
                    'Authentication rejected (fail-closed).',
                FederationErrorCode.TENANT_SCOPE_MISSING,
            );
        }

        // Guard 2: type check (must be a string)
        if (typeof rawTenantId !== 'string') {
            throw new FederationError(
                `"tenant_id" claim must be a string, got type "${typeof rawTenantId}". ` +
                    'Authentication rejected (fail-closed).',
                FederationErrorCode.TENANT_SCOPE_INVALID_TYPE,
            );
        }

        const trimmed = rawTenantId.trim();
        if (trimmed === '') {
            throw new FederationError(
                'Federation assertion "tenant_id" claim is an empty string. ' +
                    'Authentication rejected (fail-closed).',
                FederationErrorCode.TENANT_SCOPE_MISSING,
            );
        }

        return trimmed;
    }

    /**
     * extractRoleClaim: extract and validate the role from the FederationInput
     *
     * @throws FederationError ROLE_INVALID if the role is invalid (not admin/operator/viewer)
     */
    private extractRoleClaim(input: FederationInput): Role {
        let rawRole: unknown;

        if (input.type === 'saml') {
            rawRole = input.claims.attributes['role'];
        } else {
            rawRole = input.claims.attributes['role'];
        }

        return parseRole(rawRole);
    }

    /**
     * extractExternalSubject: extract the external subject identifier from the FederationInput
     *
     * SAML: uses claims.nameId (Subject NameID)
     * OIDC: uses claims.sub (Subject identifier)
     */
    private extractExternalSubject(input: FederationInput): string {
        if (input.type === 'saml') {
            return input.claims.nameId;
        } else {
            return input.claims.sub;
        }
    }

    /**
     * provisionOrUpdateUser: JIT user provisioning or update an existing user
     *
     * First login (findUserByExternalSubject = null):
     *   - create the users row (user_id UUID auto-generated; tenant_id + role taken from the assertion)
     *   - create the federation_identity_links row
     *   - write the audit log (events table)
     *
     * Existing user (match by externalSubject):
     *   - check that the current tenant_id matches the assertion (mismatch -> throw IDENTITY_REBIND_REJECTED)
     *   - role update allowed (trusting the IDP as the RBAC authoritative source)
     *   - write the audit log
     *
     * @throws FederationError IDENTITY_REBIND_REJECTED if the existing user's tenant_id does not match the assertion
     * @throws FederationError JIT_PROVISIONING_FAILED if the transaction fails
     */
    private async provisionOrUpdateUser(
        externalSubject: string,
        idpIdentifier: string,
        tenantId: string,
        role: Role,
    ): Promise<FederationResolution> {
        const existingUser = await this.port.findUserByExternalSubject(
            externalSubject,
            idpIdentifier,
        );

        if (existingUser === null) {
            // First login: JIT provisioning
            let newUser: User;
            let isNewUser = true;
            // Race-recovery state: used for audit
            let raceRecovered = false;
            let raceRoleUpdated = false;
            let racePreviousRole: string | undefined;
            try {
                newUser = await this.port.createUser({
                    tenantId,
                    role,
                    externalSubject,
                    idpIdentifier,
                });
            } catch (err: unknown) {
                // Concurrent first-login race — PostgreSQL UNIQUE VIOLATION (23505)
                // When the second concurrent request arrives, findUserByExternalSubject returns null (the read happens before the INSERT)
                // but createUser's INSERT fails on the UNIQUE constraint; re-querying then finds the already-created user
                const pgCode = (err as { code?: string }).code;
                if (pgCode === '23505') {
                    const recoveredUser = await this.port.findUserByExternalSubject(
                        externalSubject,
                        idpIdentifier,
                    );
                    if (recoveredUser !== null) {
                        // Already created by the concurrent request; handle via the existing-user path
                        newUser = recoveredUser;
                        isNewUser = false;
                        raceRecovered = true;
                        // A role consistency check is still needed (the concurrently created user may have a different role)
                        if (recoveredUser.tenantId !== tenantId) {
                            throw new FederationError(
                                'Identity rebind rejected after race recovery.',
                                FederationErrorCode.IDENTITY_REBIND_REJECTED,
                            );
                        }
                        // Compute the actual roleUpdated; must not hardcode false
                        raceRoleUpdated = recoveredUser.role !== role;
                        if (raceRoleUpdated) {
                            racePreviousRole = recoveredUser.role;
                            await this.port.updateUserRole(recoveredUser.id, role);
                        }
                    } else {
                        throw new FederationError(
                            `JIT provisioning failed: UNIQUE VIOLATION but user not found on retry.`,
                            FederationErrorCode.JIT_PROVISIONING_FAILED,
                        );
                    }
                } else {
                    if (err instanceof FederationError) throw err;
                    throw new FederationError(
                        `JIT provisioning failed: ${err instanceof Error ? err.message : String(err)}`,
                        FederationErrorCode.JIT_PROVISIONING_FAILED,
                    );
                }
            }

            // Write the audit log (written outside createUser's transaction; an audit failure does not block the main flow)
            await this.safeWriteAuditEvent({
                eventType: isNewUser ? 'federation.login.new_user' : 'federation.login.existing_user',
                userId: newUser.id,
                tenantId,
                idpIdentifier,
                externalSubject,
                isNewUser,
                roleUpdated: raceRoleUpdated,
                timestamp: new Date().toISOString(),
                ...(raceRecovered && {
                    raceRecovered: true,
                    ...(raceRoleUpdated && {
                        previousRole: racePreviousRole,
                        newRole: role,
                    }),
                }),
            });

            return {
                userId: newUser.id,
                tenantId,
                role,
                isNewUser,
            };
        } else {
            // Existing user: check tenant_id consistency
            if (existingUser.tenantId !== tenantId) {
                // Write the audit log (records the rebind attack attempt)
                await this.safeWriteAuditEvent({
                    eventType: 'federation.login.existing_user',
                    userId: existingUser.id,
                    tenantId: existingUser.tenantId,
                    idpIdentifier,
                    externalSubject,
                    isNewUser: false,
                    roleUpdated: false,
                    timestamp: new Date().toISOString(),
                    details: {
                        reason: 'IDENTITY_REBIND_REJECTED',
                        assertedTenantId: '[REDACTED]',
                    },
                });
                throw new FederationError(
                    'Identity rebind rejected: existing user tenant_id does not match asserted tenant_id. ' +
                        'Authentication rejected (fail-closed).',
                    FederationErrorCode.IDENTITY_REBIND_REJECTED,
                );
            }

            /**
             * @threatModel IDP private key compromise -> role escalation
             *
             * Threat: after obtaining the IDP private key, an attacker can forge a SAML assertion / OIDC ID token,
             *   escalating a target user's role to admin and thereby gaining more privileges than intended.
             *
             * Current mitigations:
             *   - the SAML assertion signature is mandatorily verified in SamlProvider.verifyCallback (fail-closed)
             *   - the OIDC ID token signature + expiry + audience are mandatorily verified in OidcProvider
             *   - every role change is written to a federation.login.role_updated audit event (traceable)
             *
             * Residual risk (accepted):
             *   - the security of the IDP private key itself depends on the IDP infrastructure; this system cannot harden the IDP side
             *   - within a short window, an attacker may complete a role escalation before the audit detects it
             *
             * Future mitigation plan: multi-party authorization for role escalation
             *   (requires second-factor approval)
             */
            // role update (trusting the IDP as the RBAC authoritative source)
            const roleUpdated = existingUser.role !== role;
            if (roleUpdated) {
                await this.port.updateUserRole(existingUser.id, role);
            }

            // Write the audit log
            await this.safeWriteAuditEvent({
                eventType: roleUpdated
                    ? 'federation.login.role_updated'
                    : 'federation.login.existing_user',
                userId: existingUser.id,
                tenantId,
                idpIdentifier,
                externalSubject,
                isNewUser: false,
                roleUpdated,
                timestamp: new Date().toISOString(),
            });

            return {
                userId: existingUser.id,
                tenantId,
                role,
                isNewUser: false,
            };
        }
    }

    /**
     * safeWriteAuditEvent: safely write the audit log (errors do not block the main flow)
     *
     * Conclusion: an audit log write failure should be recorded as an internal error but not exposed to the user, and must not block the authentication flow;
     * silent on failure (can be extended to a DLQ or alerting in the future).
     */
    private async safeWriteAuditEvent(
        event: FederationAuditEvent,
    ): Promise<void> {
        try {
            await this.port.writeAuditEvent(event);
        } catch {
            // audit write failure: logged to stderr but does not block the main flow
            // in production, alerting / DLQ can be hooked in here
        }
    }
}

// ── Express handler factory ───────────────────────────────────────────────────

/**
 * FederationRequest: the Express request skeleton for federation handlers (type-erased)
 */
interface FederationRequest {
    headers: Record<string, string | string[] | undefined>;
    body: unknown;
    query: Record<string, unknown>;
}

/**
 * FederationResponse: the Express response skeleton for federation handlers (type-erased)
 */
interface FederationResponse {
    status(code: number): FederationResponse;
    json(data: unknown): FederationResponse;
}

type FederationNextFn = () => void;

/**
 * handleFederationError: FederationError -> HTTP status code mapping (fail-closed)
 *
 * Security constraints:
 *   - all FederationError -> use sanitizeFederationError (fixed message)
 *   - TENANT_SCOPE_MISSING / INVALID_TYPE / NOT_FOUND -> 401 (authentication failure)
 *   - CROSS_TENANT_ASSERTION / IDENTITY_REBIND_REJECTED -> 403 (authorization failure)
 *   - ROLE_INVALID -> 422 (invalid assertion data)
 *   - IDP_NOT_REGISTERED -> 401 (IDP not registered)
 *   - JIT_PROVISIONING_FAILED -> 500 (internal error; fail-closed)
 *   - unknown error -> 500 (fail-closed; no stub 200)
 */
export function handleFederationError(
    err: unknown,
    res: FederationResponse,
): void {
    const sanitized = sanitizeFederationError(err);

    if (err instanceof FederationError) {
        const code = err.code;
        let httpStatus: number;

        switch (code) {
            case FederationErrorCode.TENANT_SCOPE_MISSING:
            case FederationErrorCode.TENANT_SCOPE_INVALID_TYPE:
            case FederationErrorCode.TENANT_NOT_FOUND:
            case FederationErrorCode.IDP_NOT_REGISTERED:
                httpStatus = 401;
                break;
            case FederationErrorCode.CROSS_TENANT_ASSERTION:
            case FederationErrorCode.IDENTITY_REBIND_REJECTED:
                httpStatus = 403;
                break;
            case FederationErrorCode.ROLE_INVALID:
                httpStatus = 422;
                break;
            case FederationErrorCode.JIT_PROVISIONING_FAILED:
            default:
                httpStatus = 500;
                break;
        }

        res.status(httpStatus).json({
            error: sanitized.code,
            message: sanitized.message,
        });
        return;
    }

    // Unknown error -> 500 (fail-closed)
    res.status(500).json({
        error: 'FED_INTERNAL_ERROR',
        message: 'Federation encountered an internal error.',
    });
}

/**
 * createFederationResolveHandler: federation resolve handler factory
 *
 * Hardening: accepts a FederationPort injection (not the concrete TenantFederationProvider class);
 * internally creates a TenantFederationProvider instance to perform the business logic.
 *
 * Request format (JSON body):
 *   {
 *     type: 'saml' | 'oidc',
 *     claims: SamlUserClaims | OidcUserClaims,
 *     idpIdentifier: string
 *   }
 *
 * Response (200): FederationResolution { userId, tenantId, role, isNewUser }
 * Errors: 4xx/5xx + { error: FederationErrorCode, message: string }
 */
export function createFederationResolveHandler(
    config: FederationHandlerConfig,
): (
    req: FederationRequest,
    res: FederationResponse,
    next: FederationNextFn,
) => Promise<void> {
    const provider = new TenantFederationProvider(config.port);

    return async (
        req: FederationRequest,
        res: FederationResponse,
        _next: FederationNextFn,
    ): Promise<void> => {
        try {
            const body = req.body as Record<string, unknown> | undefined;
            if (!body || typeof body !== 'object') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body is required and must be a JSON object.',
                });
                return;
            }

            const type = body['type'];
            if (type !== 'saml' && type !== 'oidc') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.type must be "saml" or "oidc".',
                });
                return;
            }

            const idpIdentifier = body['idpIdentifier'];
            if (typeof idpIdentifier !== 'string' || idpIdentifier.trim() === '') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.idpIdentifier must be a non-empty string.',
                });
                return;
            }

            const claims = body['claims'];
            if (!claims || typeof claims !== 'object') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.claims is required.',
                });
                return;
            }

            // Build the FederationInput (discriminated union)
            // Use parseSamlUserClaims / parseOidcUserClaims in place of a bare cast (bare casts forbidden)
            const input: FederationInput =
                type === 'saml'
                    ? {
                          type: 'saml',
                          claims: parseSamlUserClaims(claims),
                          idpIdentifier: idpIdentifier.trim(),
                      }
                    : {
                          type: 'oidc',
                          claims: parseOidcUserClaims(claims),
                          idpIdentifier: idpIdentifier.trim(),
                      };

            const resolution = await provider.resolveTenant(input);

            res.status(200).json({
                userId: resolution.userId,
                tenantId: resolution.tenantId,
                role: resolution.role,
                isNewUser: resolution.isNewUser,
            });
        } catch (err: unknown) {
            handleFederationError(err, res);
        }
    };
}

/**
 * createFederationLogoutHandler: federation logout handler factory
 *
 * Hardening: accepts a FederationLogoutContext (a standalone type);
 * a partial OidcUserClaims / SamlUserClaims hack is not allowed.
 *
 * Request format (JSON body): FederationLogoutContext
 *   { userId, tenantId, idpIdentifier, externalSubject, sessionId? }
 *
 * Response (200): { status: 'logged_out' }
 * Errors: 4xx/5xx + { error: string, message: string }
 */
export function createFederationLogoutHandler(
    config: FederationHandlerConfig,
): (
    req: FederationRequest,
    res: FederationResponse,
    next: FederationNextFn,
) => Promise<void> {
    return async (
        req: FederationRequest,
        res: FederationResponse,
        _next: FederationNextFn,
    ): Promise<void> => {
        try {
            const body = req.body as Record<string, unknown> | undefined;
            if (!body || typeof body !== 'object') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body is required.',
                });
                return;
            }

            // Use the standalone FederationLogoutContext type; no partial claims hack allowed
            const userId = body['userId'];
            if (typeof userId !== 'string' || userId.trim() === '') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.userId is required.',
                });
                return;
            }

            const tenantId = body['tenantId'];
            if (typeof tenantId !== 'string' || tenantId.trim() === '') {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.tenantId is required.',
                });
                return;
            }

            const idpIdentifier = body['idpIdentifier'];
            if (
                typeof idpIdentifier !== 'string' ||
                idpIdentifier.trim() === ''
            ) {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.idpIdentifier is required.',
                });
                return;
            }

            const externalSubject = body['externalSubject'];
            if (
                typeof externalSubject !== 'string' ||
                externalSubject.trim() === ''
            ) {
                res.status(400).json({
                    error: 'FED_REQUEST_INVALID',
                    message: 'Request body.externalSubject is required.',
                });
                return;
            }

            // Write the logout audit event
            try {
                await config.port.writeAuditEvent({
                    eventType: 'federation.logout',
                    userId: userId.trim(),
                    tenantId: tenantId.trim(),
                    idpIdentifier: idpIdentifier.trim(),
                    externalSubject: externalSubject.trim(),
                    isNewUser: false,
                    roleUpdated: false,
                    timestamp: new Date().toISOString(),
                });
            } catch {
                // audit write failure: does not block the logout flow (same pattern as safeWriteAuditEvent)
            }

            res.status(200).json({ status: 'logged_out' });
        } catch (err: unknown) {
            handleFederationError(err, res);
        }
    };
}
