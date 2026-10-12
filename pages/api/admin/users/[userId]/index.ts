import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import { invalidateAdminAuthorization } from '@/lib/currentAdminAuthorization';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { removeManagedUser } from '@/lib/auth0Management';
import { logAuditEvent } from '@/lib/auditClient';

/**
 * DELETE /api/admin/users/:userId
 * Remove a user from Auth0. Guards against self-deletion and last-admin deletion.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  if (req.method !== 'DELETE') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { userId } = req.query;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing userId' });
  }

  try {
    // Self-deletion guard
    if (userId === admin.userId) {
      return res.status(403).json({ success: false, error: 'Cannot delete your own account' });
    }

    const deleteRes = await removeManagedUser(userId).finally(() => invalidateAdminAuthorization(userId));

    if (!deleteRes.ok && deleteRes.status !== 204) {
      const body = await deleteRes.text();
      console.error('[Users API] Delete user failed:', body);
      return res.status(502).json({ success: false, error: 'Failed to delete user' });
    }

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'user_deleted',
      endpoint: req.url || '',
      method: 'DELETE',
      responseStatus: 200,
      details: {
        resourceId: userId as string,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(200).json({ success: true });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Users API] Delete error:', msg);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

export default withRoleAuth('admin', handler);
