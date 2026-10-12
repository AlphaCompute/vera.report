import crypto from 'node:crypto';

/**
 * Shared-key AES-256-GCM for legacy report fields and dissemination narratives.
 * Format: iv:authTag:ciphertext (hex). Production requires REWARD_ENCRYPTION_KEY;
 * development retains its deterministic fallback for existing local records.
 * New reward contacts use the per-record envelopes in rewardContact.ts.
 */

const REWARD_KEY_SALT = 'vera-reward-contact-salt';
const DEV_FALLBACK_SOURCE = 'dev-reward-key-not-for-production';

let cachedKey: { source: string; key: Buffer } | null = null;

function getFieldEncryptionKey(): Buffer {
  const envKey = process.env.REWARD_ENCRYPTION_KEY?.trim();
  // Fail closed in production: never fall back to the deterministic dev key — it
  // is public, so encrypting PII/narratives with it is no protection at all.
  if (!envKey && process.env.NODE_ENV === 'production') {
    throw new Error(
      '[REPORT_CRYPTO][CRITICAL] REWARD_ENCRYPTION_KEY is not set in production — ' +
        'refusing to fall back to the insecure dev key. Provision the secret and redeploy.',
    );
  }
  const source = envKey || DEV_FALLBACK_SOURCE;
  if (cachedKey && cachedKey.source === source) {
    return cachedKey.key;
  }
  // Dev fallback source is deterministic so data survives restarts in development.
  const key = crypto.scryptSync(source, REWARD_KEY_SALT, 32);
  cachedKey = { source, key };
  return key;
}

/**
 * Encrypt a sensitive field value using AES-256-GCM.
 * Returns a colon-separated string: iv:authTag:ciphertext (all hex).
 */
export function encryptContactValue(plaintext: string): string {
  const key = getFieldEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypt a value previously encrypted with encryptContactValue().
 */
export function decryptContactValue(encrypted: string): string {
  const [ivHex, authTagHex, ciphertextHex] = encrypted.split(':');
  const key = getFieldEncryptionKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'), { authTagLength: 16 });
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextHex, 'hex')), decipher.final()]).toString('utf8');
}
