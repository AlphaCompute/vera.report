import { isAllowedAdminEmail } from './adminAuth';
/**
 * Auth0 Management API client.
 *
 * Uses M2M (client_credentials) grant to obtain an access token
 * for the Auth0 Management API. Token is cached in-memory with
 * a 5-minute safety margin before expiry.
 */

let cachedToken: string | null = null;
let tokenExpiresAt = 0;

/** Build a fixed HTTPS origin from deployment configuration, never request input. */
function managementOrigin(): string {
  const domain = process.env.AUTH0_DOMAIN;
  if (!domain || !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(domain)) {
    throw new Error('AUTH0_DOMAIN must be a hostname');
  }
  return new URL(`https://${domain}`).origin;
}

/**
 * Obtain a Management API access token (cached).
 */
export async function getMgmtToken(): Promise<string> {
  const origin = managementOrigin();
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt) {
    return cachedToken;
  }

  const domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_MGMT_CLIENT_ID;
  const clientSecret = process.env.AUTH0_MGMT_CLIENT_SECRET;

  if (!domain || !clientId || !clientSecret) {
    throw new Error('Missing Auth0 Management API credentials (AUTH0_DOMAIN, AUTH0_MGMT_CLIENT_ID, AUTH0_MGMT_CLIENT_SECRET)');
  }

  const res = await fetch(`${origin}/oauth/token`, {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
      audience: `${origin}/api/v2/`,
      scope: [
        'read:users', 'update:users', 'create:users', 'delete:users',
        'read:roles', 'create:user_tickets',
        // Org-scoped admin management (VERA-PDR-001 A1 / Phase 07) — used only
        // when organization-scoped management is enabled. All requested scopes
        // must be granted; Auth0 rejects the token request otherwise.
        'read:organization_members', 'create:organization_members',
        'read:organization_member_roles', 'create:organization_member_roles',
        'delete:organization_member_roles', 'delete:organization_members',
      ].join(' '),
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Auth0 token request failed (${res.status}): ${body}`);
  }

  const data = await res.json();
  cachedToken = data.access_token;
  // Cache with 5-minute safety margin
  tokenExpiresAt = now + (data.expires_in - 300) * 1000;

  return cachedToken!;
}

/**
 * Authenticated fetch to the Auth0 Management API.
 */
export async function mgmtFetch(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const origin = managementOrigin();
  if (!path.startsWith('/') || path.startsWith('//') || /[\\\x00-\x20#]/.test(path) || path.includes('://')) {
    throw new Error('mgmtFetch: unsafe path');
  }
  const url = new URL(`${origin}/api/v2${path}`);
  // URL parsing normalizes literal and percent-encoded dot segments.
  if (url.origin !== origin || !url.pathname.startsWith('/api/v2/')) {
    throw new Error('mgmtFetch: unsafe path');
  }
  const token = await getMgmtToken();

  return fetch(url, {
    ...options,
    signal: options.signal ?? AbortSignal.timeout(10000),
    // A provider redirect must never carry a privileged request off-origin.
    redirect: 'error',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });
}

/**
 * Org-scoped admin management (VERA-PDR-001 A1, Phase 07).
 *
 * When TENANT_ORG_ID is set, user/role
 * operations target this deployment's Auth0 Organization
 * (`/organizations/{orgId}/members/...`) instead of the tenant-global
 * `/users/{id}/roles`. That keeps one customer's admins from managing another's
 * once a second Organization shares the Auth0 tenant. The legacy rollout flag
 * defaults to enabled for configured Organizations. An explicit value other
 * than true keeps administration disabled until provisioning is complete.
 * The M2M app needs organization_members / organization_member_roles scopes.
 */
export function orgScopedAdmin(): boolean {
  const rollout = process.env.AUTH0_ORG_SCOPED_ADMIN;
  return !!process.env.TENANT_ORG_ID?.trim() && (rollout === undefined || rollout === 'true');
}

function tenantOrgId(): string {
  const org = process.env.TENANT_ORG_ID?.trim();
  if (!org) throw new Error('TENANT_ORG_ID is required for org-scoped admin management');
  return org;
}

/** Role endpoint for a user — org-scoped when enabled, tenant-global otherwise. */
export function memberRolesPath(userId: string): string {
  return orgScopedAdmin()
    ? `/organizations/${encodeURIComponent(tenantOrgId())}/members/${encodeURIComponent(userId)}/roles`
    : `/users/${encodeURIComponent(userId)}/roles`;
}

/**
 * Cached Auth0 role name → role ID mapping.
 */
let roleIdCache: Record<string, string> | null = null;

/**
 * Look up Auth0 role IDs by name. Cached after first call.
 */
export async function getRoleId(roleName: string): Promise<string> {
  if (!roleIdCache) {
    const res = await mgmtFetch('/roles?per_page=50');
    if (!res.ok) {
      throw new Error(`Failed to fetch Auth0 roles: ${res.status}`);
    }
    const roles: { id: string; name: string }[] = await res.json();
    roleIdCache = {};
    for (const r of roles) {
      roleIdCache[r.name] = r.id;
    }
  }
  const id = roleIdCache[roleName];
  if (!id) {
    throw new Error(`Auth0 role "${roleName}" not found. Create it in Auth0 Dashboard → User Management → Roles.`);
  }
  return id;
}

/**
 * Assign a role to a user via Auth0's Roles API.
 */
export async function assignRole(userId: string, roleName: string): Promise<void> {
  const roleId = await getRoleId(roleName);
  const res = await mgmtFetch(memberRolesPath(userId), {
    method: 'POST',
    body: JSON.stringify({ roles: [roleId] }),
  });
  if (!res.ok && res.status !== 204) {
    const body = await res.text();
    throw new Error(`Failed to assign role "${roleName}": ${body}`);
  }
}

/**
 * Remove a role from a user via Auth0's Roles API.
 */
export async function removeRole(userId: string, roleName: string): Promise<void> {
  const roleId = await getRoleId(roleName);
  const res = await mgmtFetch(memberRolesPath(userId), {
    method: 'DELETE',
    body: JSON.stringify({ roles: [roleId] }),
  });
  if (!res.ok && res.status !== 204) {
    const body = await res.text();
    throw new Error(`Failed to remove role "${roleName}": ${body}`);
  }
}

/**
 * Get the roles assigned to a user via Auth0's Roles API.
 */
export async function getUserRoles(userId: string): Promise<string[]> {
  const names: string[] = [];
  for (let page = 0; page < 10; page++) {
    const res = await mgmtFetch(`${memberRolesPath(userId)}?per_page=100&page=${page}`);
    if (!res.ok) throw new Error('Cannot verify user roles');
    const roles: { name: string }[] = await res.json();
    if (!Array.isArray(roles) || roles.some(role => typeof role.name !== 'string')) throw new Error('Invalid roles response');
    names.push(...roles.map(role => role.name));
    if (roles.length < 100) return names;
  }
  throw new Error('Role enumeration limit reached; refusing incomplete role check');
}

/**
 * Add a user to this deployment's Auth0 Organization. No-op unless org-scoped
 * admin management is enabled. Required so an invited user can log in once the
 * frontend enforces the `organization` parameter.
 */
export async function addOrgMember(userId: string): Promise<void> {
  if (!orgScopedAdmin()) return;
  const res = await mgmtFetch(`/organizations/${encodeURIComponent(tenantOrgId())}/members`, {
    method: 'POST',
    body: JSON.stringify({ members: [userId] }),
  });
  if (!res.ok && res.status !== 204) {
    const body = await res.text();
    throw new Error(`Failed to add user to organization: ${body}`);
  }
}

/**
 * List members of this deployment's Auth0 Organization. Returns [] unless
 * org-scoped admin management is enabled (callers then fall back to the
 * email-domain listing).
 */
export async function listOrgMembers(): Promise<{ user_id: string; email: string; name?: string }[]> {
  if (!orgScopedAdmin()) return [];
  const members: { user_id: string; email: string; name?: string }[] = [];
  for (let page = 0; page < 10; page++) {
    const res = await mgmtFetch(`/organizations/${encodeURIComponent(tenantOrgId())}/members?per_page=100&page=${page}`);
    if (!res.ok) throw new Error('Cannot verify organization membership');
    const batch = await res.json();
    if (!Array.isArray(batch)) throw new Error('Invalid organization membership response');
    members.push(...batch);
    if (batch.length < 100) return members;
  }
  throw new Error('Organization enumeration limit reached; refusing incomplete scope check');
}

/**
 * Clear the cached token (useful for testing).
 */
export function clearTokenCache(): void {
  cachedToken = null;
  tokenExpiresAt = 0;
  roleIdCache = null;
}

/** Verify the target, independently of the acting administrator's session. */
export async function assertManagedUser(userId: string): Promise<void> {
  if (process.env.TENANT_ORG_ID?.trim() && !orgScopedAdmin()) {
    throw new Error('Organization-scoped administration must be enabled for this tenant');
  }
  const response = await mgmtFetch(`/users/${encodeURIComponent(userId)}`);
  if (!response.ok) throw new Error('Cannot verify target user');
  const target = await response.json();
  if (target.user_id !== userId || !isAllowedAdminEmail(target.email)) throw new Error('Target user is outside admin scope');
  if (orgScopedAdmin() && !(await listOrgMembers()).some(member => member.user_id === userId)) {
    throw new Error('Target user is outside organization scope');
  }
}

export async function removeManagedUser(userId: string): Promise<Response> {
  await assertManagedUser(userId);
  // Auth0 does not offer an atomic last-admin conditional mutation. Keep admin
  // removal in provider operations rather than race separate counts across replicas.
  if ((await getUserRoles(userId)).includes('admin')) throw new Error('Remove administrators through the identity provider');
  return orgScopedAdmin()
    ? mgmtFetch(`/organizations/${encodeURIComponent(tenantOrgId())}/members`, {
      method: 'DELETE', body: JSON.stringify({ members: [userId] }),
    })
    : mgmtFetch(`/users/${encodeURIComponent(userId)}`, { method: 'DELETE' });
}
