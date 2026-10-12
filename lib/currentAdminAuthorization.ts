import { isAllowedAdminEmail, isAllowedAdminOrg, getOrgIdFromSession } from './adminAuth';
import { getUserRoles, mgmtFetch, orgScopedAdmin } from './auth0Management';
import type { AdminIdentityWithRoles } from './authMiddleware';
import type { VeraRole } from './roles';

export const ADMIN_AUTHORIZATION_TTL_MS = 30_000;
const MAX_ENTRIES = 512;
type Entry = { userId: string; expiresAt: number; result: Promise<AdminIdentityWithRoles | null> };
const checks = new Map<string, Entry>();

export function invalidateAdminAuthorization(userId?: string): void {
    for (const [key, entry] of checks) if (!userId || entry.userId === userId) checks.delete(key);
}

async function load(userId: string): Promise<AdminIdentityWithRoles | null> {
    const response = await mgmtFetch(`/users/${encodeURIComponent(userId)}`);
    if (response.status === 404) return null;
    if (!response.ok) throw new Error('Current authorization unavailable');
    const user = await response.json();
    if (
        !user ||
        user.user_id !== userId ||
        (user.blocked !== undefined && user.blocked !== false) ||
        user.email_verified !== true ||
        typeof user.email !== 'string' ||
        !isAllowedAdminEmail(user.email)
    )
        return null;
    // In an organization deployment, this reads roles from that membership,
    // never the user's tenant-global role assignments.
    const roles = (await getUserRoles(userId)).filter(
        (role): role is VeraRole => role === 'admin' || role === 'employee',
    );
    if (!roles.length) return null;
    return { userId, email: user.email, name: typeof user.name === 'string' ? user.name : undefined, roles };
}

/** Bound the lifetime of cookie authorization without an IdP call on every poll. */
export async function currentAdminAuthorization(
    user: Record<string, unknown> | undefined,
): Promise<AdminIdentityWithRoles | null> {
    if (
        typeof user?.sub !== 'string' ||
        !user.sub ||
        user.email_verified !== true ||
        typeof user.email !== 'string' ||
        !isAllowedAdminEmail(user.email) ||
        !isAllowedAdminOrg(getOrgIdFromSession(user))
    )
        return null;
    if (process.env.TENANT_ORG_ID?.trim() && !orgScopedAdmin())
        throw new Error('Organization authorization unavailable');
    const key = JSON.stringify([
        user.sub,
        process.env.AUTH0_DOMAIN,
        process.env.TENANT_ORG_ID,
        process.env.AUTH0_ORG_SCOPED_ADMIN,
        process.env.ADMIN_ALLOWED_DOMAINS,
    ]);
    let entry = checks.get(key);
    if (!entry || entry.expiresAt <= Date.now()) {
        if (checks.size >= MAX_ENTRIES) checks.delete(checks.keys().next().value!);
        entry = { userId: user.sub, expiresAt: Date.now() + ADMIN_AUTHORIZATION_TTL_MS, result: load(user.sub) };
        checks.set(key, entry);
    }
    try {
        const current = await entry.result;
        // A slow provider must not extend the validity of an old observation.
        if (entry.expiresAt <= Date.now()) throw new Error('Authorization check expired');
        return current;
    } catch {
        if (checks.get(key) === entry) checks.delete(key);
        // No stale authorization fallback, provider payloads or tokens in errors.
        throw new Error('Current authorization unavailable');
    }
}
