import type { Response } from 'express';
import { reportPersistenceService } from '../reportPersistence';
import { streamEvidenceResponse } from '../../utils/streamEvidenceResponse';
import { EVIDENCE_TRANSFER_TIMEOUT_MS } from '../../utils/evidenceLimits';
import { proxyRecipientRateLimitHeaders } from '../../utils/proxyRateLimit';

/** Resolve recipient-visible indexes against persisted keys, never caller filenames. */
export async function recipientEvidence(trackingId: string) {
  const rows = await reportPersistenceService.listEvidenceByTrackingIds([trackingId]);
  return rows.filter(row => row.fileKey.startsWith(`${trackingId}/`))
    .sort((a, b) => a.fileKey.localeCompare(b.fileKey))
    .map((row, index) => ({
      index,
      filename: row.fileKey.slice(trackingId.length + 1),
      name: `evidence-${index + 1}${row.fileKey.match(/\.[A-Za-z0-9]{1,8}$/)?.[0].toLowerCase() ?? ''}`,
    }));
}

/** Only called after the recipient's current assignment and consent gates. */
export async function sendRecipientEvidence(
  trackingId: string,
  fileIndex: string,
  res: Response,
  authorize: () => Promise<boolean>,
  capability: string,
): Promise<boolean> {
  if (!/^(0|[1-9]\d*)$/.test(fileIndex)) {
    res.status(400).json({ success: false, error: 'Invalid evidence index' });
    return false;
  }
  const files = await recipientEvidence(trackingId);
  const file = files[Number(fileIndex)];
  if (!file) {
    res.status(404).json({ success: false, error: 'Evidence not found' });
    return false;
  }
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret) {
    res.status(500).json({ success: false, error: 'Evidence access not configured' });
    return false;
  }
  const port = process.env.PORT || '3001';
  if (res.destroyed) return false;
  const disconnected = new AbortController();
  const cancel = () => disconnected.abort();
  res.once('close', cancel);
  let upstream: globalThis.Response | undefined;
  try {
    const path = `/api/whistleblower/evidence/${encodeURIComponent(trackingId)}/${encodeURIComponent(file.filename)}`;
    upstream = await fetch(
      `http://127.0.0.1:${port}${path}`,
      { headers: { 'x-internal-secret': secret, ...proxyRecipientRateLimitHeaders(capability, 'GET', path) }, signal: AbortSignal.any([
        disconnected.signal, AbortSignal.timeout(EVIDENCE_TRANSFER_TIMEOUT_MS),
      ]) },
    );
    if (!upstream.ok) {
      res.status(upstream.status).json({ success: false, error: 'Evidence unavailable' });
      return false;
    }
    // The internal route has finished decrypting before sending headers.
    // Recheck authorization before forwarding any body bytes to the recipient.
    if (!await authorize()) {
      res.status(403).json({ success: false, error: 'Evidence sharing authorization changed' });
      return false;
    }
    if (res.destroyed) return false;
    // Preserve backpressure through the loopback connection: a slow client must
    // not accumulate a full evidence buffer after the internal transfer ends.
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    try { await streamEvidenceResponse(upstream.body, res); }
    catch { res.destroy(); return false; }
    return true;
  } finally {
    res.removeListener('close', cancel);
    if (upstream?.body && !upstream.body.locked) await upstream.body.cancel().catch(() => {});
    disconnected.abort();
  }
}
