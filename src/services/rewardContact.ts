import crypto from 'node:crypto';
import { keyEnvelope } from './keyEnvelope';

// Contact values use per-record AES-GCM keys wrapped with report-bound context.

export interface EncryptedContact {
  /** iv:authTag:ciphertext (all hex), AES-256-GCM under the per-record data key. */
  ciphertext: string;
  /** The per-record data key, envelope-wrapped (KMS in prod). */
  wrappedKey: string;
}

export async function encryptRewardContact(plaintext: string, trackingId: string): Promise<EncryptedContact> {
  const dek = crypto.randomBytes(32);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const ciphertext = `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${enc.toString('hex')}`;
    const wrappedKey = await keyEnvelope.wrap(dek.toString('hex'), { trackingId, purpose: 'reward' });
    return { ciphertext, wrappedKey };
  } finally { dek.fill(0); }
}

// Consumes the owned key. JS strings and crypto-internal copies cannot be erased here.
function decryptWithOwnedKey(ciphertext: string, key: Buffer): string {
  let pending: Buffer | undefined;
  let final: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    const [ivHex, authTagHex, ctHex] = ciphertext.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'), { authTagLength: 16 });
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    pending = decipher.update(Buffer.from(ctHex, 'hex'));
    final = decipher.final();
    plaintext = Buffer.concat([pending, final]);
    return plaintext.toString('utf8');
  } finally {
    key.fill(0);
    pending?.fill(0);
    final?.fill(0);
    plaintext?.fill(0);
  }
}

export async function decryptRewardContact(contact: EncryptedContact, trackingId: string): Promise<string> {
  const dekHex = await keyEnvelope.unwrapEnvelope(contact.wrappedKey, { trackingId, purpose: 'reward' });
  return decryptWithOwnedKey(contact.ciphertext, Buffer.from(dekHex, 'hex'));
}

// Historical direct-key records retain their original derivation until migrated.
function legacyRewardKey(): Buffer {
  const envKey = process.env.REWARD_ENCRYPTION_KEY?.trim();
  if (envKey) return crypto.scryptSync(envKey, 'vera-reward-contact-salt', 32);
  if (process.env.NODE_ENV === 'production') {
    throw new Error('REWARD_ENCRYPTION_KEY must be set to read legacy reward contacts in production');
  }
  return crypto.scryptSync('dev-reward-key-not-for-production', 'vera-reward-contact-salt', 32);
}

export function decryptLegacyRewardContact(encryptedContactValue: string): string {
  return decryptWithOwnedKey(encryptedContactValue, legacyRewardKey());
}
