import type { NextApiRequest, NextApiResponse } from 'next';
import { proxyRateLimitHeaders } from '../../../../src/utils/proxyRateLimit';

/**
 * GET /api/whistleblower/enclave/attestation
 * Proxy to Express — live Nitro PCR0 from the co-located enclave.
 * Used in local development; deployed load balancers route /api/* straight
 * to the Express API, which serves the same response.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const path = '/api/whistleblower/enclave/attestation';
    const response = await fetch(`${backendUrl}${path}`, {
      method: 'GET',
      headers: {
        ...proxyRateLimitHeaders(req, 'GET', path),
        Accept: 'application/json',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(15000),
    });

    // Pass the backend status through unchanged: an absent enclave is already
    // a 200 `{ available: false }` from Express and must stay one here.
    const data = await response.json();
    return res.status(response.status).json(data);
  } catch {
    // The Express backend itself is unreachable — a real fault, not an absent enclave.
    return res.status(502).json({ error: 'backend_unavailable' });
  }
}
