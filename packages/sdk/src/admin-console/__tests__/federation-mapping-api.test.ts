/**
 * federation-mapping-api.test.ts -- FederationMappingAdminClient unit tests
 *
 * Test coverage:
 *   - listMappings: RBAC / tenantId filtering / DB exception
 *   - getMapping: RBAC / not found / DB exception
 *   - createMapping: admin only / input validation / DB exception / success path
 *   - updateMapping: admin only / id validation / allowedTenantIds patch validation / not found / DB exception
 *   - deleteMapping: admin only / confirmId mismatch / not found / DB exception / success path
 *   - fail-closed: DB exception → throw (not swallowed)
 *   - Security P0: non-admin roles cannot write
 *   - Audit: CUD operations write an audit event (cert/jwksUri stored as a sha256 prefix only)
 *   - Cross-tenant isolation: tenant-admin cannot access another tenant's mapping
 *   - Caller union: discriminated union fix / null sentinel unreachable / factory functions
 *
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import {
    FederationMappingAdminClient,
    InMemoryFederationMappingPort,
    FederationMappingError,
    globalAdminCaller,
    tenantScopedCaller,
} from '../federation-mapping-api.js';
import type { IdpMapping } from '../../sso/tenant-federation.js';

// ---------------------------------------------------------------------------
// Type helper: assert the unknown captured by catch as a FederationMappingError (test-only)
// ---------------------------------------------------------------------------

function asFmError(e: unknown): FederationMappingError {
    if (e instanceof FederationMappingError) return e;
    throw new Error(`Expected FederationMappingError, got: ${String(e)}`);
}

// ---------------------------------------------------------------------------
// Test helper: build an IdpMapping fixture
// ---------------------------------------------------------------------------

function makeSamlMapping(overrides: Partial<IdpMapping> = {}): IdpMapping {
    return {
        id: 'map-001',
        idpIdentifier: 'https://saml.idp.example.com',
        idpType: 'saml',
        allowedTenantIds: ['tenant-a', 'tenant-b'],
        idpSigningCert: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
        idpJwksUri: undefined,
        createdAt: '2026-05-01T00:00:00.000Z',
        updatedAt: '2026-05-01T00:00:00.000Z',
        ...overrides,
    };
}

function makeOidcMapping(overrides: Partial<IdpMapping> = {}): IdpMapping {
    return {
        id: 'map-002',
        idpIdentifier: 'https://oidc.idp.example.com',
        idpType: 'oidc',
        allowedTenantIds: ['tenant-c'],
        idpSigningCert: undefined,
        idpJwksUri: 'https://oidc.idp.example.com/.well-known/jwks.json',
        createdAt: '2026-05-01T00:00:00.000Z',
        updatedAt: '2026-05-01T00:00:00.000Z',
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// Helper: compute the hex of the first 16 bytes of sha256 (matching the _sha256Prefix16 logic)
// ---------------------------------------------------------------------------

function sha256Prefix16(value: string): string {
    return createHash('sha256').update(value).digest('hex').slice(0, 32);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FederationMappingAdminClient', () => {
    let port: InMemoryFederationMappingPort;
    let client: FederationMappingAdminClient;

    beforeEach(() => {
        port = new InMemoryFederationMappingPort();
        client = new FederationMappingAdminClient({ port });
    });

    // -----------------------------------------------------------------------
    // listMappings
    // -----------------------------------------------------------------------

    describe('listMappings', () => {
        it('should return all mappings when role is admin', async () => {
            port.seed(makeSamlMapping());
            port.seed(makeOidcMapping());
            const result = await client.listMappings({ role: 'admin', caller: globalAdminCaller() });
            expect(result.mappings).toHaveLength(2);
            expect(result.total).toBe(2);
        });

        it('should allow tenant-admin when tenantId filter matches caller tenantId', async () => {
            port.seed(makeSamlMapping());
            port.seed(makeOidcMapping());
            const result = await client.listMappings({
                role: 'tenant-admin',
                tenantId: 'tenant-a',
                caller: tenantScopedCaller('tenant-a'),
            });
            expect(result.mappings).toHaveLength(1);
            expect(result.mappings[0].idpIdentifier).toBe('https://saml.idp.example.com');
        });

        it('should throw when tenant-admin does not provide tenantId', async () => {
            await expect(
                client.listMappings({ role: 'tenant-admin', caller: tenantScopedCaller('tenant-a') }),
            ).rejects.toThrow(FederationMappingError);
            const err = await client
                .listMappings({ role: 'tenant-admin', caller: tenantScopedCaller('tenant-a') })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should deny viewer role for listMappings', async () => {
            await expect(
                client.listMappings({ role: 'viewer', caller: globalAdminCaller() }),
            ).rejects.toThrow(FederationMappingError);
            const err = await client
                .listMappings({ role: 'viewer', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should throw FEDERATION_MAPPING_ROLE_MISSING when role is empty', async () => {
            const err = await client
                .listMappings({ role: '', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_ROLE_MISSING');
        });

        it('should filter by idpType when provided', async () => {
            port.seed(makeSamlMapping());
            port.seed(makeOidcMapping());
            const result = await client.listMappings({
                role: 'admin',
                idpType: 'saml',
                caller: globalAdminCaller(),
            });
            expect(result.mappings).toHaveLength(1);
            expect(result.mappings[0].idpType).toBe('saml');
        });

        it('should throw FEDERATION_MAPPING_LIST_FAILED when port throws (fail-closed)', async () => {
            port.injectError(new Error('DB connection lost'));
            const err = await client
                .listMappings({ role: 'admin', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_LIST_FAILED');
            expect(err.message).toContain('DB connection lost');
        });

        it('should return empty list when no mappings exist', async () => {
            const result = await client.listMappings({ role: 'admin', caller: globalAdminCaller() });
            expect(result.mappings).toHaveLength(0);
            expect(result.total).toBe(0);
        });
    });

    // -----------------------------------------------------------------------
    // getMapping
    // -----------------------------------------------------------------------

    describe('getMapping', () => {
        it('should return mapping by id for admin role', async () => {
            port.seed(makeSamlMapping());
            const mapping = await client.getMapping({
                role: 'admin',
                id: 'map-001',
                caller: globalAdminCaller(),
            });
            expect(mapping.id).toBe('map-001');
            expect(mapping.idpType).toBe('saml');
        });

        it('should deny viewer from getMapping (P0 SSO trust chain protection)', async () => {
            port.seed(makeSamlMapping());
            const err = await client
                .getMapping({ role: 'viewer', id: 'map-001', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should allow tenant-admin to getMapping for own tenant', async () => {
            port.seed(makeOidcMapping());
            const mapping = await client.getMapping({
                role: 'tenant-admin',
                id: 'map-002',
                caller: tenantScopedCaller('tenant-c'),
            });
            expect(mapping.id).toBe('map-002');
        });

        it('should throw FEDERATION_MAPPING_NOT_FOUND when id does not exist', async () => {
            const err = await client
                .getMapping({ role: 'admin', id: 'nonexistent', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_NOT_FOUND');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when id is empty', async () => {
            const err = await client
                .getMapping({ role: 'admin', id: '', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should throw FEDERATION_MAPPING_GET_FAILED when port throws (fail-closed)', async () => {
            port.injectError(new Error('DB timeout'));
            const err = await client
                .getMapping({ role: 'admin', id: 'map-001', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_GET_FAILED');
        });

        it('should throw FEDERATION_MAPPING_ROLE_MISSING when role is whitespace', async () => {
            const err = await client
                .getMapping({ role: '   ', id: 'map-001', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_ROLE_MISSING');
        });
    });

    // -----------------------------------------------------------------------
    // createMapping
    // -----------------------------------------------------------------------

    describe('createMapping', () => {
        it('should create mapping when role is admin', async () => {
            const mapping = await client.createMapping({
                role: 'admin',
                input: {
                    idpIdentifier: 'https://new.idp.com',
                    idpType: 'oidc',
                    allowedTenantIds: ['tenant-x'],
                    idpJwksUri: 'https://new.idp.com/.well-known/jwks.json',
                },
            });
            expect(mapping.idpIdentifier).toBe('https://new.idp.com');
            expect(mapping.idpType).toBe('oidc');
            expect(mapping.allowedTenantIds).toContain('tenant-x');
        });

        it('should deny tenant-admin from creating mapping (P0 security)', async () => {
            const err = await client
                .createMapping({
                    role: 'tenant-admin',
                    input: {
                        idpIdentifier: 'https://new.idp.com',
                        idpType: 'saml',
                        allowedTenantIds: ['tenant-y'],
                    },
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should deny viewer from creating mapping (P0 security)', async () => {
            const err = await client
                .createMapping({
                    role: 'viewer',
                    input: {
                        idpIdentifier: 'https://new.idp.com',
                        idpType: 'oidc',
                        allowedTenantIds: ['tenant-z'],
                    },
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when idpIdentifier is empty', async () => {
            const err = await client
                .createMapping({
                    role: 'admin',
                    input: {
                        idpIdentifier: '',
                        idpType: 'saml',
                        allowedTenantIds: ['tenant-a'],
                    },
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when allowedTenantIds is empty', async () => {
            const err = await client
                .createMapping({
                    role: 'admin',
                    input: {
                        idpIdentifier: 'https://idp.com',
                        idpType: 'saml',
                        allowedTenantIds: [],
                    },
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should throw FEDERATION_MAPPING_CREATE_FAILED when port throws (fail-closed)', async () => {
            port.injectError(new Error('constraint violation'));
            const err = await client
                .createMapping({
                    role: 'admin',
                    input: {
                        idpIdentifier: 'https://idp.com',
                        idpType: 'saml',
                        allowedTenantIds: ['tenant-a'],
                    },
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_CREATE_FAILED');
        });

        it('should throw FEDERATION_MAPPING_ROLE_MISSING when role is empty', async () => {
            const err = await client
                .createMapping({
                    role: '',
                    input: { idpIdentifier: 'https://x.com', idpType: 'oidc', allowedTenantIds: ['t1'] },
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_ROLE_MISSING');
        });
    });

    // -----------------------------------------------------------------------
    // updateMapping
    // -----------------------------------------------------------------------

    describe('updateMapping', () => {
        it('should update allowedTenantIds when role is admin', async () => {
            port.seed(makeSamlMapping());
            const updated = await client.updateMapping({
                role: 'admin',
                id: 'map-001',
                patch: { allowedTenantIds: ['tenant-a', 'tenant-b', 'tenant-c'] },
            });
            expect(updated.allowedTenantIds).toContain('tenant-c');
        });

        it('should update idpSigningCert when role is admin (P0 trust chain)', async () => {
            port.seed(makeSamlMapping());
            const updated = await client.updateMapping({
                role: 'admin',
                id: 'map-001',
                patch: {
                    idpSigningCert:
                        '-----BEGIN CERTIFICATE-----\nnewCert\n-----END CERTIFICATE-----',
                },
            });
            expect(updated.idpSigningCert).toContain('newCert');
        });

        it('should deny tenant-admin from updating mapping (P0 security)', async () => {
            port.seed(makeSamlMapping());
            const err = await client
                .updateMapping({
                    role: 'tenant-admin',
                    id: 'map-001',
                    patch: { allowedTenantIds: ['tenant-a'] },
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should throw FEDERATION_MAPPING_NOT_FOUND when id does not exist', async () => {
            const err = await client
                .updateMapping({
                    role: 'admin',
                    id: 'nonexistent',
                    patch: { allowedTenantIds: ['tenant-a'] },
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_NOT_FOUND');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when id is empty', async () => {
            const err = await client
                .updateMapping({
                    role: 'admin',
                    id: '',
                    patch: {},
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when allowedTenantIds patch is empty array', async () => {
            port.seed(makeSamlMapping());
            const err = await client
                .updateMapping({
                    role: 'admin',
                    id: 'map-001',
                    patch: { allowedTenantIds: [] },
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should throw FEDERATION_MAPPING_UPDATE_FAILED when port throws (fail-closed)', async () => {
            port.seed(makeSamlMapping());
            port.injectError(new Error('DB write error'));
            const err = await client
                .updateMapping({
                    role: 'admin',
                    id: 'map-001',
                    patch: { allowedTenantIds: ['tenant-a'] },
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_UPDATE_FAILED');
        });
    });

    // -----------------------------------------------------------------------
    // deleteMapping
    // -----------------------------------------------------------------------

    describe('deleteMapping', () => {
        it('should delete mapping when role is admin and confirmId matches', async () => {
            port.seed(makeSamlMapping());
            await expect(
                client.deleteMapping({ role: 'admin', id: 'map-001', confirmId: 'map-001' }),
            ).resolves.toBeUndefined();
            // verify it has been deleted
            const err = await client
                .getMapping({ role: 'admin', id: 'map-001', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_NOT_FOUND');
        });

        it('should deny tenant-admin from deleting mapping (P0 security)', async () => {
            port.seed(makeSamlMapping());
            const err = await client
                .deleteMapping({
                    role: 'tenant-admin',
                    id: 'map-001',
                    confirmId: 'map-001',
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should deny viewer from deleting mapping', async () => {
            const err = await client
                .deleteMapping({
                    role: 'viewer',
                    id: 'map-001',
                    confirmId: 'map-001',
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when confirmId does not match id', async () => {
            port.seed(makeSamlMapping());
            const err = await client
                .deleteMapping({
                    role: 'admin',
                    id: 'map-001',
                    confirmId: 'map-WRONG',
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
            expect(err.message).toContain('confirmId');
        });

        it('should throw FEDERATION_MAPPING_INVALID_INPUT when id is empty', async () => {
            const err = await client
                .deleteMapping({ role: 'admin', id: '', confirmId: '' })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });

        it('should throw FEDERATION_MAPPING_NOT_FOUND when id does not exist', async () => {
            const err = await client
                .deleteMapping({
                    role: 'admin',
                    id: 'nonexistent',
                    confirmId: 'nonexistent',
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_NOT_FOUND');
        });

        it('should throw FEDERATION_MAPPING_DELETE_FAILED when port throws (fail-closed)', async () => {
            port.seed(makeSamlMapping());
            port.injectError(new Error('DB error'));
            const err = await client
                .deleteMapping({
                    role: 'admin',
                    id: 'map-001',
                    confirmId: 'map-001',
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_DELETE_FAILED');
        });

        it('should throw FEDERATION_MAPPING_ROLE_MISSING when role is empty', async () => {
            const err = await client
                .deleteMapping({
                    role: '',
                    id: 'map-001',
                    confirmId: 'map-001',
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_ROLE_MISSING');
        });
    });

    // -----------------------------------------------------------------------
    // Comprehensive Security P0 guard tests
    // -----------------------------------------------------------------------

    describe('P0 security guard: only admin may write', () => {
        it('should reject all write operations for unknown role', async () => {
            const unknownRole = 'superuser';
            const createErr = await client
                .createMapping({
                    role: unknownRole,
                    input: { idpIdentifier: 'x', idpType: 'oidc', allowedTenantIds: ['t1'] },
                })
                .catch(asFmError);
            expect(createErr.code).toBe('FEDERATION_MAPPING_PERMISSION_DENIED');
        });

        it('should preserve cause chain in error (fail-closed error chain)', async () => {
            port.injectError(new Error('original cause'));
            const err = await client
                .listMappings({ role: 'admin', caller: globalAdminCaller() })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect((err as FederationMappingError & { cause?: unknown }).cause).toBeDefined();
        });
    });

    // -----------------------------------------------------------------------
    // Audit events: CUD writes an audit event, cert/jwksUri stored as a sha256 prefix only
    // -----------------------------------------------------------------------

    describe('audit events', () => {
        it('should write federation_mapping.created audit event after createMapping', async () => {
            const cert = '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----';
            await client.createMapping({
                role: 'admin',
                input: {
                    idpIdentifier: 'https://audit-test.idp.com',
                    idpType: 'saml',
                    allowedTenantIds: ['tenant-a'],
                    idpSigningCert: cert,
                },
            });
            const events = port.getAuditEvents();
            expect(events).toHaveLength(1);
            expect(events[0].eventType).toBe('federation_mapping.created');
            expect(events[0].idpIdentifier).toBe('https://audit-test.idp.com');
            // cert stored as a sha256 prefix only, not as plaintext
            expect(events[0].certHashPrefix).toBe(sha256Prefix16(cert));
            expect(events[0].certHashPrefix).toHaveLength(32);
            expect(events[0].certHashPrefix).not.toContain('CERTIFICATE');
        });

        it('should write federation_mapping.updated audit event after updateMapping with new cert', async () => {
            port.seed(makeSamlMapping());
            const newCert = '-----BEGIN CERTIFICATE-----\nnewCert2026\n-----END CERTIFICATE-----';
            await client.updateMapping({
                role: 'admin',
                id: 'map-001',
                patch: { idpSigningCert: newCert },
            });
            const events = port.getAuditEvents();
            expect(events).toHaveLength(1);
            expect(events[0].eventType).toBe('federation_mapping.updated');
            expect(events[0].certHashPrefix).toBe(sha256Prefix16(newCert));
        });

        it('should write federation_mapping.deleted audit event after deleteMapping', async () => {
            port.seed(makeSamlMapping());
            await client.deleteMapping({ role: 'admin', id: 'map-001', confirmId: 'map-001' });
            const events = port.getAuditEvents();
            expect(events).toHaveLength(1);
            expect(events[0].eventType).toBe('federation_mapping.deleted');
            expect(events[0].idpIdentifier).toBe('https://saml.idp.example.com');
            // the delete audit does not contain cert/jwksUri fields
            expect(events[0].certHashPrefix).toBeUndefined();
        });

        it('should write jwksUri hash prefix (not literal URI) in audit event for oidc mapping', async () => {
            const jwksUri = 'https://oidc.idp.example.com/.well-known/jwks.json';
            await client.createMapping({
                role: 'admin',
                input: {
                    idpIdentifier: 'https://oidc.idp.example.com',
                    idpType: 'oidc',
                    allowedTenantIds: ['tenant-c'],
                    idpJwksUri: jwksUri,
                },
            });
            const events = port.getAuditEvents();
            expect(events[0].jwksUriHashPrefix).toBe(sha256Prefix16(jwksUri));
            // does not store the plaintext URI (prevents leaking the internal endpoint)
            expect(events[0].jwksUriHashPrefix).not.toContain('jwks');
        });

        it('should not block primary operation when audit write fails (degraded mode)', async () => {
            // port.writeAuditEvent throws → the primary operation is unaffected
            const originalWriteAudit = port.writeAuditEvent.bind(port);
            let auditWriteCalled = false;
            port.writeAuditEvent = (_event) => {
                auditWriteCalled = true;
                throw new Error('audit storage unavailable');
            };
            const mapping = await client.createMapping({
                role: 'admin',
                input: {
                    idpIdentifier: 'https://degraded-audit.idp.com',
                    idpType: 'oidc',
                    allowedTenantIds: ['tenant-x'],
                },
            });
            // the primary operation succeeds
            expect(mapping.idpIdentifier).toBe('https://degraded-audit.idp.com');
            expect(auditWriteCalled).toBe(true);
            // restore
            port.writeAuditEvent = originalWriteAudit;
        });
    });

    // -----------------------------------------------------------------------
    // Cross-tenant isolation: tenant-admin cannot access another tenant's mapping
    // -----------------------------------------------------------------------

    describe('cross-tenant isolation', () => {
        it('should throw FEDERATION_MAPPING_TENANT_MISMATCH when tenant-admin lists mappings of another tenant', async () => {
            port.seed(makeSamlMapping()); // allowedTenantIds: ['tenant-a', 'tenant-b']
            const err = await client
                .listMappings({
                    role: 'tenant-admin',
                    tenantId: 'tenant-a',
                    caller: tenantScopedCaller('tenant-c'), // differs from tenantId
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_TENANT_MISMATCH');
        });

        it('should throw FEDERATION_MAPPING_TENANT_MISMATCH when tenant-admin gets mapping not in their tenant', async () => {
            // map-001 allowedTenantIds: ['tenant-a', 'tenant-b']; tenant-c is not among them
            port.seed(makeSamlMapping());
            const err = await client
                .getMapping({
                    role: 'tenant-admin',
                    id: 'map-001',
                    caller: tenantScopedCaller('tenant-c'),
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_TENANT_MISMATCH');
        });

        it('should allow tenant-admin to list when caller tenantId matches tenantId filter', async () => {
            port.seed(makeSamlMapping()); // allowedTenantIds: ['tenant-a', 'tenant-b']
            const result = await client.listMappings({
                role: 'tenant-admin',
                tenantId: 'tenant-a',
                caller: tenantScopedCaller('tenant-a'),
            });
            expect(result.mappings).toHaveLength(1);
        });

        it('should allow admin (globalAdminCaller) to access any tenant mapping without mismatch error', async () => {
            port.seed(makeSamlMapping());
            const result = await client.listMappings({
                role: 'admin',
                tenantId: 'tenant-a',
                caller: globalAdminCaller(), // admin is exempt from the cross-tenant check
            });
            expect(result.mappings).toHaveLength(1);
        });

        it('should deny tenant-admin from listing when no tenantId provided (cannot enumerate all)', async () => {
            port.seed(makeSamlMapping());
            port.seed(makeOidcMapping());
            const err = await client
                .listMappings({
                    role: 'tenant-admin',
                    caller: tenantScopedCaller('tenant-a'),
                    // tenantId not provided → tenant-admin cannot enumerate everything
                })
                .catch(asFmError);
            expect(err.code).toBe('FEDERATION_MAPPING_INVALID_INPUT');
        });
    });

    // -----------------------------------------------------------------------
    // Caller discriminated union — factory functions + null sentinel unreachable
    // -----------------------------------------------------------------------

    describe('Caller discriminated union factory functions', () => {
        it('should globalAdminCaller() return Caller with kind === "global-admin"', () => {
            // Conclusion: globalAdminCaller must return { kind: 'global-admin' }, with no tenantId field
            const caller = globalAdminCaller();
            expect(caller.kind).toBe('global-admin');
            expect('tenantId' in caller).toBe(false);
        });

        it('should tenantScopedCaller("t1") return Caller with kind === "tenant-scoped" and tenantId === "t1"', () => {
            // Conclusion: tenantScopedCaller must return { kind: 'tenant-scoped', tenantId }
            const caller = tenantScopedCaller('t1');
            expect(caller.kind).toBe('tenant-scoped');
            if (caller.kind === 'tenant-scoped') {
                expect(caller.tenantId).toBe('t1');
            }
        });

        it('should tenantScopedCaller("") throw Error (fail-closed; empty tenantId forbidden)', () => {
            // Conclusion: empty-string tenantId → throw Error (the null sentinel is unreachable)
            expect(() => tenantScopedCaller('')).toThrow();
        });

        it('should throw FEDERATION_MAPPING_CALLER_INCONSISTENT when role is "tenant-admin" but caller is globalAdminCaller', async () => {
            // Conclusion: tenant-admin role + globalAdminCaller → CALLER_INCONSISTENT (fail-closed)
            // Original null sentinel bypass: callerTenantId=null let the !== null check be circumvented; the type system now forbids it outright
            port.seed(makeSamlMapping());
            const err = await client
                .listMappings({
                    role: 'tenant-admin',
                    tenantId: 'tenant-a',
                    caller: globalAdminCaller(), // role=tenant-admin but caller=global-admin → inconsistent
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_CALLER_INCONSISTENT');
        });

        it('should throw FEDERATION_MAPPING_TENANT_MISMATCH when tenant-admin + tenantScopedCaller has wrong tenantId in getMapping', async () => {
            // Conclusion: tenant-admin + tenantScopedCaller('tenant-c') → not in map-001 allowedTenantIds → MISMATCH
            // This proves the null sentinel bypass is closed: the caller must carry a real tenantId
            port.seed(makeSamlMapping()); // allowedTenantIds: ['tenant-a', 'tenant-b']
            const err = await client
                .getMapping({
                    role: 'tenant-admin',
                    id: 'map-001',
                    caller: tenantScopedCaller('tenant-c'), // tenant-c is not in allowedTenantIds
                })
                .catch(asFmError);
            expect(err).toBeInstanceOf(FederationMappingError);
            expect(err.code).toBe('FEDERATION_MAPPING_TENANT_MISMATCH');
        });
    });
});
