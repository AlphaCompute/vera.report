/**
 * RBAC role definitions for the VERA admin panel.
 *
 * Roles are stored as a custom claim in the Auth0 ID token
 * under the namespace `https://vera.app/roles`.
 *
 * Two roles exist:
 *   - admin:    full access — evidence, PII, team management
 *   - employee: triage reports, change status — no evidence/PII/team
 */

export const ROLES_CLAIM = 'https://vera.app/roles';

export type VeraRole = 'admin' | 'employee';

const VALID_ROLES: ReadonlySet<string> = new Set<VeraRole>(['admin', 'employee']);

/** Hierarchical level — higher number means more privilege. */
const ROLE_HIERARCHY: Record<VeraRole, number> = {
  employee: 0,
  admin: 1,
};

/**
 * Extract VERA roles from an Auth0 user object.
 * Returns an empty array when the claim is absent or malformed.
 */
export function getRolesFromSession(
  user: Record<string, unknown> | null | undefined,
): VeraRole[] {
  if (!user) return [];
  const raw = user[ROLES_CLAIM];
  if (!Array.isArray(raw)) return [];
  return raw.filter((r): r is VeraRole => typeof r === 'string' && VALID_ROLES.has(r));
}

/**
 * Check whether a set of roles satisfies a required role,
 * respecting the hierarchy (admin >= employee).
 */
export function hasRole(userRoles: VeraRole[], required: VeraRole): boolean {
  const requiredLevel = ROLE_HIERARCHY[required];
  return userRoles.some((r) => ROLE_HIERARCHY[r] >= requiredLevel);
}

/**
 * Convenience: does the user hold the admin role?
 */
export function isAdmin(userRoles: VeraRole[]): boolean {
  return userRoles.includes('admin');
}
