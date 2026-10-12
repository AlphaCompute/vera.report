import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';

/**
 * Admin-gated proxy for the Express /api/monitoring/* endpoints (#453).
 *
 * The monitoring dashboard is admin-only. Its metrics/dataflow/clear handlers
 * live in the Express process, now gated by `requireInternalSecret`, so this
 * Next route — already behind the Auth0 admin check (withRoleAuth) and the
 * `/api/admin/*` middleware — forwards the call with the internal secret. It
 * lives under `/api/admin/*` on purpose so it reuses the existing ALB rule; no
 * new infrastructure is required.
 */
const backendUrl = (): string => process.env.BACKEND_URL || 'http://localhost:3001';
const internalSecret = (): string => process.env.INTERNAL_API_SECRET || '';

const ALLOWED = new Set(['metrics', 'dataflow', 'clear']);

async function handler(req: NextApiRequest, res: NextApiResponse) {
  const secret = internalSecret();
  if (!secret) {
    return res
      .status(500)
      .json({ success: false, error: 'INTERNAL_API_SECRET not configured' });
  }

  const parts = Array.isArray(req.query.path) ? req.query.path : [];
  const sub = parts.join('/');
  if (!ALLOWED.has(sub)) {
    return res.status(404).json({ success: false, error: 'Unknown monitoring endpoint' });
  }

  const qs = req.url && req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  const target = `${backendUrl()}/api/monitoring/${sub}${qs}`;

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: { 'x-internal-secret': secret, 'content-type': 'application/json' },
      body: req.method === 'POST' ? JSON.stringify(req.body ?? {}) : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    const data = await upstream
      .json()
      .catch(() => ({ success: false, error: 'invalid upstream response' }));
    return res.status(upstream.status).json(data);
  } catch {
    return res.status(502).json({ success: false, error: 'monitoring service unreachable' });
  }
}

export default withRoleAuth('admin', handler);
