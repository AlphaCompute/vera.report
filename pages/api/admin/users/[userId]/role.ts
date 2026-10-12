import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import { invalidateAdminAuthorization } from '@/lib/currentAdminAuthorization';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import {
  assertManagedUser,
  assignRole,
  removeRole,
  getUserRoles,
} from '@/lib/auth0Management';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * PATCH /api/admin/users/:userId/role
 * Change a user's role. Guards against self-demotion and removing the last admin.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  if (req.method !== 'PATCH') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { userId } = req.query;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing userId' });
  }

  const { role } = req.body || {};
  if (!role || !['admin', 'employee'].includes(role)) {
    return res.status(400).json({ success: false, error: 'Role must be "admin" or "employee"' });
  }

  try {
    // Self-demotion guard
    if (userId === admin.userId && role !== 'admin') {
      logAuditEvent({
        adminUserId: admin.userId,
        adminEmail: admin.email,
        action: 'role_change_blocked',
        endpoint: req.url || '',
        method: 'PATCH',
        responseStatus: 403,
        details: {
          resourceId: userId,
          ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
          userAgent: req.headers['user-agent'],
        },
      });
      return res.status(403).json({ success: false, error: 'Cannot demote yourself' });
    }

    await assertManagedUser(userId);
    const currentRoles = await getUserRoles(userId);
    if (currentRoles.includes('admin') && role !== 'admin') {
      return res.status(409).json({ success: false, error: 'Remove administrator roles through the identity provider' });
    }
    const oldRole = currentRoles.includes('admin') ? 'admin' : 'employee';

    if (oldRole !== role) {
      invalidateAdminAuthorization(userId);
      try {
        await assignRole(userId, role);
        await removeRole(userId, oldRole);
      } finally { invalidateAdminAuthorization(userId); }
    }

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'user_role_changed',
      endpoint: req.url || '',
      method: 'PATCH',
      responseStatus: 200,
      details: {
        resourceId: userId,
        newStatus: role,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(200).json({ success: true });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Users API] Role change error:', msg);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

export default withRoleAuth('admin', handler);
