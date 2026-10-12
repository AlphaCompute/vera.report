import { getAllowedAdminDomains, getTenantOrgId } from './tenant';

/**
 * Admin email domains for this deployment. Env-driven via
 * `ADMIN_ALLOWED_DOMAINS` (see lib/tenant.ts); empty when unset, which admits
 * no one. Evaluated at module load — env is fixed per deployment.
 */
export const ALLOWED_ADMIN_DOMAINS = getAllowedAdminDomains();

/**
 * Returns true only if the email belongs to one of the allowed admin domains.
 */
export function isAllowedAdminEmail(email: string | null | undefined): boolean {
  if (!email) return false;
  const normalized = email.toLowerCase();
  return getAllowedAdminDomains().some((domain) => normalized.endsWith(domain));
}

/**
 * Builds an Auth0 Management API (Lucene v3) query that matches users whose
 * email ends with any of the allowed admin domains.
 *
 * Example output: `email:(*@alphacompute.ai OR *@example.org)`
 *
 * Throws when no domains are configured: `email:()` is not a valid query, and
 * an empty allowlist must never widen into an unfiltered user search.
 */
export function buildAdminEmailSearchQuery(): string {
  const domains = getAllowedAdminDomains();
  if (domains.length === 0) throw new Error('ADMIN_ALLOWED_DOMAINS is not configured');
  const clauses = domains.map((d) => `*${d}`).join(' OR ');
  return `email:(${clauses})`;
}

/**
 * Extract the Auth0 Organization id (`org_id`) from a session user object.
 * `org_id` is a standard claim Auth0 injects when a user authenticates in the
 * context of an Organization. Returns null when absent.
 */
export function getOrgIdFromSession(
  user: Record<string, unknown> | null | undefined,
): string | null {
  if (!user) return null;
  const v = user['org_id'];
  return typeof v === 'string' && v ? v : null;
}

/**
 * Multi-tenant Organization scoping (silo model). Returns true when this
 * deployment does not enforce an Organization (`TENANT_ORG_ID` unset) or when
 * the supplied orgId matches the deployment's tenant. Fail-closed once
 * enforcement is enabled: a missing or mismatched org is rejected — this is
 * what stops an admin of one tenant from being accepted by another
 * deployment on the shared Auth0 tenant.
 */
export function isAllowedAdminOrg(orgId: string | null | undefined): boolean {
  const tenant = getTenantOrgId();
  if (!tenant) return true; // Organization scoping not enabled for this deployment
  return typeof orgId === 'string' && orgId === tenant;
}
