import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';

/**
 * GET /api/admin/me
 * Returns the current admin's identity and roles.
 * Both admin and employee roles can access this endpoint.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  return res.status(200).json({
    email: admin.email,
    name: admin.name ?? null,
    roles: admin.roles,
  });
}

export default withRoleAuth('employee', handler);
