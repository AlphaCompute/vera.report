/**
 * Per-deployment tenant configuration (multi-tenant silo model).
 * See docs/pdr/VERA-PDR-001-A1-multi-tenancy.md (Addendum A1).
 *
 * Values are env-driven. Admin domains must be configured explicitly;
 * the optional organization and display name retain single-tenant defaults.
 */

// A plain hostname with at least one dot. Anything else (for example `*`)
// would become a wildcard in the Auth0 user search, so it is dropped.
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/** Normalise a domain fragment: trim, lowercase, ensure a single leading '@'. */
function normalizeDomain(fragment: string): string {
  const t = fragment.trim().toLowerCase().replace(/^@/, '');
  if (!DOMAIN_RE.test(t)) return '';
  return `@${t}`;
}

/**
 * Admin email domains allowed for this deployment.
 * Env: `ADMIN_ALLOWED_DOMAINS` — comma-separated (leading '@' optional).
 * Fails closed: unset, blank or malformed entries yield no domains, so no
 * email is accepted as an admin. Every deployment must set it explicitly.
 */
export function getAllowedAdminDomains(): string[] {
  const raw = process.env.ADMIN_ALLOWED_DOMAINS;
  if (!raw) return [];
  return raw.split(',').map(normalizeDomain).filter(Boolean);
}

/**
 * The Auth0 Organization this deployment serves.
 * Env: `TENANT_ORG_ID`. When unset, Organization scoping is NOT enforced
 * (pre-Organizations / single-tenant behaviour).
 */
export function getTenantOrgId(): string | null {
  return process.env.TENANT_ORG_ID?.trim() || null;
}

/** Human-readable tenant name for branding (consent copy, packet cover letters). */
export function getTenantName(): string {
  return process.env.TENANT_NAME?.trim() || 'Vera';
}
