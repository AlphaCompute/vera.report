import { logger } from '../utils/logger';

// Same hostname rule as lib/tenant.ts: malformed entries are ignored.
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/** Resolve a complete recipient set, then verify authoritative profiles before sending. */
export async function getAdminRecipientEmails(
  get: (path: string) => Promise<unknown>,
  orgId?: string,
  roleMode: 'organization' | 'global-in-org' = 'organization',
): Promise<string[]> {
  // Fails closed: no configured domain means no recipient, never a built-in
  // default. Checked before any identity lookups, which would be wasted.
  const domains = (process.env.ADMIN_ALLOWED_DOMAINS || '').split(',')
    .map(domain => domain.trim().toLowerCase().replace(/^@/, ''))
    .filter(domain => DOMAIN_RE.test(domain));
  if (!domains.length) {
    logger.warn('[EMAIL] ADMIN_ALLOWED_DOMAINS is not configured; no admin alert recipients');
    return [];
  }
  const list = async (path: string): Promise<any[]> => {
    const all: any[] = [];
    for (let page = 0; page < 10; page++) {
      const batch = await get(`${path}?per_page=100&page=${page}`);
      if (!Array.isArray(batch) || batch.length > 100) throw new Error('Invalid identity list');
      all.push(...batch);
      if (batch.length < 100) return all;
    }
    throw new Error('Identity enumeration incomplete');
  };
  const roles = await list('/roles');
  if (roles.some(role => !role || typeof role.id !== 'string' || typeof role.name !== 'string')) throw new Error('Invalid role enumeration');
  const admins = roles.filter(role => role.name.toLowerCase() === 'admin');
  if (admins.length !== 1) throw new Error('Admin role unavailable or ambiguous');
  const roleId = encodeURIComponent(admins[0].id);
  let members: any[] = [];
  if (orgId && roleMode === 'organization') {
    const cursors = new Set<string>();
    let from: string | undefined;
    for (let page = 0; ; page++) {
      if (page >= 10) throw new Error('Admin enumeration incomplete');
      const result = await get(`/organizations/${encodeURIComponent(orgId)}/roles/${roleId}/members?take=100${from ? `&from=${encodeURIComponent(from)}` : ''}`) as { members?: unknown; next?: unknown } | null;
      if (!Array.isArray(result?.members) || result.members.length > 100) throw new Error('Invalid member enumeration');
      members.push(...result.members);
      if (result.next === undefined) break;
      if (typeof result.next !== 'string' || !result.next || cursors.has(result.next)) throw new Error('Invalid member cursor');
      cursors.add(result.next);
      from = result.next;
    }
  } else {
    if (roleMode === 'global-in-org' && !orgId) throw new Error('Organization required');
    members = await list(`/roles/${roleId}/users`);
    if (orgId) {
      const organization = await list(`/organizations/${encodeURIComponent(orgId)}/members`);
      if (organization.some(member => typeof member?.user_id !== 'string' || !member.user_id)) throw new Error('Invalid organization membership');
      const ids = new Set(organization.map(member => member.user_id));
      if (members.some(member => typeof member?.user_id !== 'string' || !member.user_id)) throw new Error('Invalid admin membership');
      members = members.filter(member => ids.has(member.user_id));
    }
  }
  if (members.some(member => typeof member?.user_id !== 'string' || !member.user_id)) throw new Error('Invalid admin membership');
  const emails = new Set<string>();
  let filteredDomains = 0;
  for (const id of new Set<string>(members.map(member => member.user_id))) {
    const profile = await get(`/users/${encodeURIComponent(id)}`) as any;
    if (profile?.user_id !== id) throw new Error('Identity profile mismatch');
    if (profile.email_verified !== true || profile.blocked === true) continue;
    const email = typeof profile.email === 'string' ? profile.email.trim().toLowerCase() : '';
    if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) continue;
    if (!domains.includes(email.slice(email.lastIndexOf('@') + 1))) { filteredDomains++; continue; }
    emails.add(email);
  }
  if (filteredDomains) logger.warn('[EMAIL] Admin recipient domain filter excluded profiles', { count: filteredDomains });
  return [...emails];
}
