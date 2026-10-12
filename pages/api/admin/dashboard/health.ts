import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import { getDb } from '@/lib/mongodb';

/**
 * GET /api/admin/dashboard/health
 * Report backing-store (MongoDB) health.
 */
async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const db = await getDb();
    if (!db) {
      return res.status(503).json({
        success: false,
        data: { status: 'unhealthy', store: 'mongodb' },
        error: 'MongoDB unavailable',
      });
    }

    res.status(200).json({
      success: true,
      data: { status: 'healthy', store: 'mongodb' },
    });
  } catch (error: any) {
    console.error('[Health Check] Error:', error.message);
    res.status(503).json({
      success: false,
      data: { status: 'unhealthy', store: 'mongodb' },
      error: {
        message: `Health check failed: ${error.message}`,
        code: 'HEALTH_CHECK_ERROR',
      },
    });
  }
}

export default withRoleAuth('employee', handler);
