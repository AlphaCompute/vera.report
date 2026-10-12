import { isConfidentialIdentifier } from '@/src/utils/confidentialIdentifiers';
import { streamEvidenceResponse } from '@/src/utils/streamEvidenceResponse';
import { EVIDENCE_TRANSFER_TIMEOUT_MS } from '@/src/utils/evidenceLimits';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import { logAuditEventRequired } from '@/lib/auditClient';
import { evidenceResponseHeaders } from '@/src/utils/evidenceResponse';
import { proxyAdminRateLimitHeaders } from '@/src/utils/proxyRateLimit';

/**
 * GET /api/whistleblower/evidence/:trackingId/:filename
 * Proxy to Express backend for evidence retrieval.
 * Requires admin role — contains sensitive whistleblower evidence.
 *
 * Express resolves durable decryption parameters and retrieves/decrypts IPFS evidence.
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const controller = new AbortController();
  res.once('close', () => controller.abort());
  try {
    const { trackingId, filename } = req.query;

    if (!trackingId || typeof trackingId !== 'string') {
      return res.status(400).json({ success: false, error: 'Missing tracking ID' });
    }
    if (isConfidentialIdentifier(trackingId)) return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });

    if (!filename || typeof filename !== 'string') {
      return res.status(400).json({ success: false, error: 'Missing filename' });
    }

    // Forward to Express backend. The internal secret is what authenticates
    // this admin-only request to the backend — Auth0 enforcement happens in
    // withRoleAuth above, and the secret prevents anything else inside the
    // VPC from hitting the backend route directly.
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    const internalSecret = process.env.INTERNAL_API_SECRET;
    if (!internalSecret) {
      console.error('[Evidence Proxy] INTERNAL_API_SECRET not configured');
      return res.status(500).json({ success: false, error: 'Backend not configured' });
    }
    await logAuditEventRequired({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'evidence_access',
      endpoint: req.url || '',
      method: req.method || 'GET',
      responseStatus: 0,
      details: {
        phase: 'attempted',
        resourceId: trackingId,
        filename,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    const path = `/api/whistleblower/evidence/${encodeURIComponent(trackingId)}/${encodeURIComponent(filename)}`;
    const response = await fetch(
      `${backendUrl}${path}`,
      {
        method: 'GET',
        headers: { 'x-internal-secret': internalSecret, ...proxyAdminRateLimitHeaders(admin.userId, 'GET', path) },
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(EVIDENCE_TRANSFER_TIMEOUT_MS)]),
      }
    );

    const statusCode = response.status;

    await logAuditEventRequired({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'evidence_access',
      endpoint: req.url || '',
      method: req.method || 'GET',
      responseStatus: statusCode,
      details: {
        phase: 'response',
        resourceId: trackingId,
        filename,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    if (!response.ok) {
      // Gateways and upstream middleware can return HTML/text errors. Never
      // render those on the admin origin or turn their status into HTTP 200.
      await response.body?.cancel();
      return res.status(statusCode).json({ success: false, error: 'Evidence unavailable' });
    }

    // JSON can be evidence too. Preserve the original bytes, rather than
    // parsing/re-serializing them as an API envelope.
    for (const [name, value] of Object.entries(evidenceResponseHeaders(filename, response.headers.get('content-type')))) {
      res.setHeader(name, value);
    }
    res.status(statusCode);
    await streamEvidenceResponse(response.body, res);
    return;

  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error('[Evidence Proxy] Error:', msg);
    if (res.headersSent || res.destroyed) { res.destroy(); return; }
    return res.status(502).json({
      success: false,
      error: 'Failed to retrieve evidence from backend',
      details: msg
    });
  } finally { controller.abort(); }
}

export default withRoleAuth('admin', handler);

export const config = { api: { responseLimit: false } };
