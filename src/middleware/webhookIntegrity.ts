import crypto from 'node:crypto';
import type { Request, Response } from 'express';

type SignedRequest = Request & { rawWebhookBody?: Buffer };
export function isSignedWebhook(path: string): boolean {
  return /^\/api\/dissemination\/(?:inbound|receipts)\/webhook\/?$/.test(path);
}
export function captureWebhookBody(req: Request, _res: Response, buffer: Buffer): void {
  if (isSignedWebhook(req.originalUrl.split('?')[0])) (req as SignedRequest).rawWebhookBody = Buffer.from(buffer);
}
export function verifyWebhookSignature(req: Request, res: Response): boolean {
  const secret = process.env.DISSEMINATION_WEBHOOK_SECRET;
  if (!secret) { res.status(503).json({ success: false, error: 'Webhook not configured' }); return false; }
  const signature = req.headers['x-vera-signature'];
  const timestamp = req.headers['x-vera-timestamp'];
  const raw = (req as SignedRequest).rawWebhookBody;
  if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/i.test(signature) || !raw) {
    res.status(401).json({ success: false, error: 'Invalid signature' }); return false;
  }
  const path = req.originalUrl.split('?')[0];
  let expected: Buffer;
  if (timestamp === undefined && path === '/api/dissemination/inbound/webhook') {
    // The previous SES relay already signed its mail timestamp and message ID
    // inside the body. Permit that fresh, replay-deduplicated protocol during
    // rollout; never fall back when an explicit v2 timestamp was supplied.
    const receivedAt = typeof req.body?.receivedAt === 'string' ? Date.parse(req.body.receivedAt) : NaN;
    if (typeof req.body?.messageId !== 'string' || !req.body.messageId ||
        !Number.isFinite(receivedAt) || Math.abs(Date.now() - receivedAt) > 300000) {
      res.status(401).json({ success: false, error: 'Invalid or expired signature' }); return false;
    }
    expected = crypto.createHmac('sha256', secret).update(raw).digest();
  } else {
    if (typeof timestamp !== 'string' || !/^\d{10}$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) {
      res.status(401).json({ success: false, error: 'Invalid or expired signature' }); return false;
    }
    expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${path}.`).update(raw).digest();
  }
  if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), expected)) {
    res.status(401).json({ success: false, error: 'Invalid signature' }); return false;
  }
  return true;
}
/** Stable across retry timestamps; persistence enforces unique receipt/audit keys. */
export function webhookEventKey(req: Request): string {
  return crypto.createHash('sha256').update(req.originalUrl.split('?')[0])
    .update('\0').update((req as SignedRequest).rawWebhookBody!).digest('hex');
}
