import type { NextApiRequest, NextApiResponse, NextApiHandler } from 'next';
import { auth0 } from './auth0';
import { isAllowedAdminEmail, isAllowedAdminOrg, getOrgIdFromSession } from './adminAuth';
import { hasRole, type VeraRole } from './roles';
import { currentAdminAuthorization } from './currentAdminAuthorization';

export type AdminIdentity = {
  userId: string;
  email: string;
  name?: string;
};

export type AdminIdentityWithRoles = AdminIdentity & {
  roles: VeraRole[];
};

export type AuditedApiHandler = (
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentity,
) => Promise<void | NextApiResponse>;

export type RoleProtectedApiHandler = (
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) => Promise<void | NextApiResponse>;

/**
 * Shared admin gate: allowed email domain plus — when this deployment sets
 * `TENANT_ORG_ID` — Auth0 Organization scoping (silo multi-tenancy). Sends a
 * 403 and returns true when access is denied; returns false to proceed.
 */
function denyNonAdmin(
  session: Awaited<ReturnType<typeof auth0.getSession>>,
  res: NextApiResponse,
): boolean {
  if (session?.user?.email_verified !== true || !isAllowedAdminEmail(session?.user?.email)) {
    res.status(403).json({ error: 'Forbidden: admin access restricted' });
    return true;
  }
  if (!isAllowedAdminOrg(getOrgIdFromSession(session?.user as Record<string, unknown> | undefined))) {
    res.status(403).json({ error: 'Forbidden: organization not allowed' });
    return true;
  }
  return false;
}

async function authorizedAdmin(
  session: Awaited<ReturnType<typeof auth0.getSession>>,
  res: NextApiResponse,
): Promise<AdminIdentityWithRoles | null> {
  if (denyNonAdmin(session, res)) return null;
  try {
    const admin = await currentAdminAuthorization(session?.user);
    if (!admin) res.status(403).json({ error: 'Forbidden: current access revoked' });
    return admin;
  } catch {
    res.setHeader?.('Retry-After', '30');
    res.status(503).json({ error: 'Authorization temporarily unavailable' });
    return null;
  }
}

/**
 * Wraps a Pages Router API route handler with Auth0 session verification
 * and restricts access to allowed admin email domains (see `lib/adminAuth.ts`)
 * and, when enabled, the deployment's Auth0 Organization.
 * Returns 401 if no valid session exists, 403 if email/organization not allowed.
 */
export function withApiAuth(handler: NextApiHandler): NextApiHandler {
  return auth0.withApiAuthRequired(async function authMiddleware(
    req: NextApiRequest,
    res: NextApiResponse
  ) {
    res.setHeader?.('Cache-Control', 'private, no-store');
    res.setHeader?.('Referrer-Policy', 'no-referrer');
    const session = await auth0.getSession(req);
    if (!await authorizedAdmin(session, res)) return;
    return handler(req, res);
  }) as NextApiHandler;
}

/**
 * Like `withApiAuth`, but extracts admin identity from the Auth0 session
 * and passes it to the handler as a third argument for audit logging.
 */
export function withAuditedApiAuth(handler: AuditedApiHandler): NextApiHandler {
  return auth0.withApiAuthRequired(async function auditedAuthMiddleware(
    req: NextApiRequest,
    res: NextApiResponse
  ) {
    res.setHeader?.('Cache-Control', 'private, no-store');
    res.setHeader?.('Referrer-Policy', 'no-referrer');
    const session = await auth0.getSession(req);
    const admin = await authorizedAdmin(session, res);
    if (!admin) return;
    return handler(req, res, { userId: admin.userId, email: admin.email, name: admin.name });
  }) as NextApiHandler;
}

/**
 * Role-based access control wrapper. Checks Auth0 session, domain,
 * and the user's current VERA role through a bounded provider check.
 *
 * Fail-closed: missing current roles or an unavailable provider deny access.
 */
export function withRoleAuth(
  requiredRole: VeraRole,
  handler: RoleProtectedApiHandler,
): NextApiHandler {
  return auth0.withApiAuthRequired(async function roleAuthMiddleware(
    req: NextApiRequest,
    res: NextApiResponse,
  ) {
    res.setHeader?.('Cache-Control', 'private, no-store');
    res.setHeader?.('Referrer-Policy', 'no-referrer');
    const session = await auth0.getSession(req);
    const admin = await authorizedAdmin(session, res);
    if (!admin) return;
    const roles = admin.roles;

    if (!hasRole(roles, requiredRole)) {
      return res.status(403).json({ error: `Forbidden: requires ${requiredRole} role` });
    }

    return handler(req, res, admin);
  }) as NextApiHandler;
}
