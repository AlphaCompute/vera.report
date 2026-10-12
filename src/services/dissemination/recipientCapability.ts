import crypto from 'node:crypto';
import { disseminationPersistence } from './disseminationPersistence';

function key(): Buffer {
  const secret = process.env.RECIPIENT_CAPABILITY_SECRET;
  if (!secret || secret.length < 32 || secret === process.env.DISSEMINATION_WEBHOOK_SECRET || secret === process.env.INTERNAL_API_SECRET) {
    throw new Error('RECIPIENT_CAPABILITY_SECRET must be an independent random secret of at least 32 characters');
  }
  return crypto.createHash('sha256').update('vera-recipient-v3\0' + secret).digest();
}

function referenceKey(): Buffer {
  const secret = process.env.DISSEMINATION_WEBHOOK_SECRET;
  if (!secret) throw new Error('DISSEMINATION_WEBHOOK_SECRET is required for legacy case references');
  return crypto.createHash('sha256').update('vera-recipient-v2\0' + secret).digest();
}

/** Authenticated encryption keeps the reporter bearer credential out of recipient URLs. */
export function sealCapability(kind: string, scope: object): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  cipher.setAAD(Buffer.from(kind));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(scope)), cipher.final()]);
  return ['v3', iv.toString('base64url'), ciphertext.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
}

export function openCapability(kind: string, token: string): unknown {
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'v3') throw new Error('Unsupported capability');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(parts[1], 'base64url'), { authTagLength: 16 });
  decipher.setAAD(Buffer.from(kind));
  decipher.setAuthTag(Buffer.from(parts[3], 'base64url'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(parts[2], 'base64url')), decipher.final()]).toString('utf8'));
}

/** Non-authorizing case reference for recipient documents; never accepted by reporter APIs. */
export function recipientCaseReference(trackingId: string, entityId: string): string {
  return 'CASE-' + crypto.createHmac('sha256', referenceKey()).update(JSON.stringify([trackingId, entityId])).digest('hex').slice(0, 24);
}

export async function issueRecipientCapability(token: string, kind: string): Promise<void> {
  const scope = openCapability(kind, token) as { exp: number };
  if (!Number.isFinite(scope.exp) || scope.exp <= Date.now()) throw new Error('Invalid grant expiry');
  await disseminationPersistence.issueRecipientGrant(crypto.createHash('sha256').update(token).digest('hex'), new Date(scope.exp));
}
export async function recipientCapabilityActive(token: string): Promise<boolean> {
  return disseminationPersistence.recipientGrantActive(crypto.createHash('sha256').update(token).digest('hex'));
}
