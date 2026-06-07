/**
 * Admin Console RBAC role parsing + permission checks
 *
 * Responsibilities:
 *   - getRoleFromRequest: parse the AdminRole from the X-Role header (fail-closed)
 *   - checkPermission: check whether the role holds the required permission (fail-closed)
 *   - requirePermission: permission assertion (throws AdminRbacError rather than returning a boolean)
 *
 * Design constraints (fail-closed):
 *   - no X-Role header / empty value -> ADMIN_ROLE_MISSING (fail-closed; reject the request)
 *   - unknown role -> ADMIN_ROLE_UNKNOWN (fail-closed; reject the request)
 *   - insufficient permission -> ADMIN_PERMISSION_DENIED (fail-closed; 403 response)
 *   - RBAC never allows default-allow / silent pass / partial-PASS
 *
 */

import type { AdminPermission, AdminRole } from './types.js';
import { AdminRbacError, parseAdminRole, ROLE_PERMISSIONS } from './types.js';

// ── getRoleFromRequest ────────────────────────────────────────────────────────

/**
 * Minimal interface for Express request headers (avoids pulling in @types/express)
 */
export interface MinimalRequest {
    readonly headers: Record<string, string | string[] | undefined>;
}

/**
 * Parse the AdminRole from the X-Role header (fail-closed)
 *
 * Conclusion: extracts X-Role from the HTTP request headers;
 * missing / empty / unknown value -> AdminRbacError (fail-closed; no default role allowed).
 *
 * @param req Express request (or a minimal interface carrying headers)
 * @throws AdminRbacError ADMIN_ROLE_MISSING or ADMIN_ROLE_UNKNOWN
 */
export function getRoleFromRequest(req: MinimalRequest): AdminRole {
    const rawRole = getHeader(req.headers, 'x-role');
    // parseAdminRole is fail-closed: missing / unknown -> AdminRbacError
    return parseAdminRole(rawRole);
}

/**
 * Check whether the role holds the required permission (boolean; does not throw)
 *
 * @param role the parsed AdminRole
 * @param permission the required permission
 * @returns true if the role holds that permission; false otherwise
 */
export function hasPermission(role: AdminRole, permission: AdminPermission): boolean {
    const permissions = ROLE_PERMISSIONS[role];
    // Invariant: every role in ROLE_PERMISSIONS has a corresponding set
    return permissions.has(permission);
}

/**
 * Permission assertion (fail-closed; insufficient permission -> AdminRbacError ADMIN_PERMISSION_DENIED)
 *
 * Conclusion: called at the entry of every admin API handler;
 * an insufficient permission immediately throws AdminRbacError; no partial-PASS allowed.
 *
 * @param role the parsed AdminRole
 * @param permission the required permission
 * @throws AdminRbacError ADMIN_PERMISSION_DENIED
 */
export function requirePermission(role: AdminRole, permission: AdminPermission): void {
    if (!hasPermission(role, permission)) {
        throw new AdminRbacError(
            `Role "${role}" does not have permission "${permission}". ` +
            `Allowed roles for this operation: ${getAllowedRolesFor(permission).join(', ')}.`,
            'ADMIN_PERMISSION_DENIED',
        );
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────────────

/**
 * Return all roles that hold the given permission (used in error messages)
 */
function getAllowedRolesFor(permission: AdminPermission): AdminRole[] {
    const roles: AdminRole[] = [];
    for (const [role, perms] of Object.entries(ROLE_PERMISSIONS) as Array<[AdminRole, ReadonlySet<AdminPermission>]>) {
        if (perms.has(permission)) {
            roles.push(role);
        }
    }
    return roles;
}

/**
 * Get a header value from headers (case-insensitive)
 */
function getHeader(
    headers: Record<string, string | string[] | undefined>,
    name: string,
): string | undefined {
    const lower = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === lower) {
            if (Array.isArray(value)) return value[0];
            return value;
        }
    }
    return undefined;
}
