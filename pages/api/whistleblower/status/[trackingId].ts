import { isConfidentialIdentifier, isConfidentialOwnerCode } from '../../../../src/utils/confidentialIdentifiers';
import type { NextApiRequest, NextApiResponse } from 'next';
import { proxyRateLimitHeaders } from '../../../../src/utils/proxyRateLimit';

/**
 * GET /api/whistleblower/status/:trackingId
 * Proxy to Express backend which checks ElizaOS + in-memory store
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { trackingId } = req.query;

    if (!trackingId || typeof trackingId !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing tracking ID',
      });
    }
    // A VERA-OWNER-1 recovery code stays on the device; never forward it to the
    // legacy backend (or any log). Confidential case IDs never name a legacy report.
    if (isConfidentialIdentifier(trackingId) || isConfidentialOwnerCode(req.headers['x-reporter-credential'])) {
      return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    }

    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const path = `/api/whistleblower/status/${encodeURIComponent(trackingId)}`;
    const response = await fetch(
      `${backendUrl}${path}`,
      {
        method: 'GET',
        headers: { ...proxyRateLimitHeaders(req, 'GET', path), 'Content-Type': 'application/json', ...(typeof req.headers['x-reporter-credential'] === 'string' ? { 'X-Reporter-Credential': req.headers['x-reporter-credential'] } : {}) },
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      }
    );

    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (error: any) {
    console.error('[Status Proxy] Request failed');
    return res.status(502).json({
      success: false,
      error: 'Failed to retrieve report status from backend',
    });
  }
}
