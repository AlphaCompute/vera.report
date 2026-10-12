import crypto from 'node:crypto';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';

/**
 * Envelope encryption for the small per-record data keys that protect report
 * narratives and evidence files.
 *
 * The narrative/evidence payloads are already AES-256-GCM encrypted with a
 * random per-record key (the data key / DEK). This service stops that DEK from
 * living next to its ciphertext in plaintext: it wraps the DEK with an AWS KMS
 * customer master key so a database dump alone can no longer decrypt anything —
 * unwrapping requires a KMS `Decrypt` call, gated by the ECS task role's IAM
 * grant and logged in CloudTrail.
 *
 * Wrapped values are self-describing by prefix so mixed states migrate cleanly:
 *   - `enc:kms:v1:<base64 KMS ciphertext blob>`  — KMS-wrapped (production)
 *   - `enc:local:v1:<ivHex>:<authTagHex>:<ctHex>` — local AES fallback (dev/test/self-host)
 *   - anything else                              — a legacy pre-envelope raw key
 *
 * `unwrap` dispatches on the prefix regardless of the current mode, so records
 * written before this change (raw keys) and records written in either mode all
 * keep decrypting. A KMS outage therefore fails closed for KMS-wrapped keys
 * (unwrap throws) rather than silently returning wrong material.
 *
 * The DEK does not survive a full application compromise — the running process
 * can always call KMS to unwrap. The bar this raises is "database compromise
 * alone yields plaintext", plus IAM-separable key access, per-decrypt audit,
 * and CMK rotation.
 */

const KMS_PREFIX = 'enc:kms:v1:';
const KMS_V2_PREFIX = 'enc:kms:v2:';

export function privateKeyContext(context: KeyContext): KeyContext {
  return Object.fromEntries(Object.entries(context).map(([k, v]) => [k, k === 'purpose' ? v : crypto.createHash('sha256').update(JSON.stringify(['vera-context-v2', k, v])).digest('hex')]));
}
const LOCAL_PREFIX = 'enc:local:v1:';

/** Encryption context binds a wrapped key to the record it belongs to. */
export type KeyContext = Record<string, string>;

function canonicalContext(context: KeyContext): string {
  return Object.keys(context)
    .sort()
    .map((k) => `${k}=${context[k]}`)
    .join('&');
}

class KeyEnvelopeService {
  private kms: KMSClient | null = null;
  private cache = new Map<string, { key: string; expiresAt: number }>();
  private readonly cacheTtlMs = 5 * 60 * 1000;
  private readonly cacheMax = 1000;

  private get keyId(): string {
    return process.env.KMS_AT_REST_KEY_ID || '';
  }

  private usesKms(): boolean {
    return !!this.keyId;
  }

  private kmsClient(): KMSClient {
    if (!this.kms) {
      this.kms = new KMSClient({ region: process.env.AWS_REGION || 'us-east-1' });
    }
    return this.kms;
  }

  /**
   * Local fallback master key for environments without KMS. Fails closed in
   * production: a prod deploy must supply KMS_AT_REST_KEY_ID (preferred) or an
   * explicit AT_REST_LOCAL_KEY, never the dev constant.
   */
  private localMasterKey(): Buffer {
    const env = process.env.AT_REST_LOCAL_KEY;
    if (env) return crypto.scryptSync(env, 'vera-at-rest-envelope-salt', 32);
    if (process.env.NODE_ENV === 'production') {
      throw new Error('KMS_AT_REST_KEY_ID or AT_REST_LOCAL_KEY must be set in production');
    }
    return crypto.scryptSync('dev-at-rest-envelope-key', 'vera-at-rest-envelope-salt', 32);
  }

  private requireHostKeyMode(): void {
    if (process.env.ENCLAVE_ENABLED === 'true') {
      // Also refuse standalone callers that do not run application startup
      // validation. A cached plaintext key must never bypass this boundary.
      this.cache.clear();
      throw new Error('Host key envelopes are disabled in enclave mode');
    }
  }

  /**
   * Wrap a plaintext data key (hex string). Idempotent: an already-wrapped
   * value is returned unchanged so double-wrapping is impossible.
   */
  async wrap(plaintextKey: string, context: KeyContext = {}): Promise<string> {
    this.requireHostKeyMode();
    if (plaintextKey.startsWith('enc:')) return plaintextKey;

    if (this.usesKms()) {
      const out = await this.kmsClient().send(
        new EncryptCommand({
          KeyId: this.keyId,
          Plaintext: Buffer.from(plaintextKey, 'utf8'),
          EncryptionContext: privateKeyContext(context),
        }),
      );
      if (!out.CiphertextBlob) throw new Error('KMS Encrypt returned no ciphertext');
      return KMS_V2_PREFIX + Buffer.from(out.CiphertextBlob).toString('base64');
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.localMasterKey(), iv);
    cipher.setAAD(Buffer.from(canonicalContext(context), 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintextKey, 'utf8'), cipher.final()]);
    return `${LOCAL_PREFIX}${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${ct.toString('hex')}`;
  }

  /** Strict reader for records that were introduced with wrapped keys; no raw-key downgrade. */
  async unwrapEnvelope(stored: unknown, context: KeyContext = {}): Promise<string> {
    if (typeof stored !== 'string' || ![KMS_PREFIX, KMS_V2_PREFIX, LOCAL_PREFIX].some(prefix => stored.startsWith(prefix))) {
      throw new Error('Invalid wrapped key envelope');
    }
    return this.unwrap(stored, context);
  }

  /** Legacy records may still contain raw keys; new envelope-only records use unwrapEnvelope. */
  async unwrap(stored: string, context: KeyContext = {}): Promise<string> {
    this.requireHostKeyMode();
    if (stored.startsWith(KMS_PREFIX) || stored.startsWith(KMS_V2_PREFIX)) {
      const prefix = stored.startsWith(KMS_V2_PREFIX) ? KMS_V2_PREFIX : KMS_PREFIX;
      const kmsContext = prefix === KMS_V2_PREFIX ? privateKeyContext(context) : context;
      // Key on ciphertext AND context: a cache hit skips the KMS Decrypt that
      // enforces EncryptionContext, so a blob cached under one record's context
      // must never satisfy an unwrap for a different record.
      const cacheKey = stored + '\0' + JSON.stringify(Object.keys(context).sort().map(k => [k, context[k]]));
      const cached = this.cacheGet(cacheKey);
      if (cached) return cached;

      const blob = Buffer.from(stored.slice(prefix.length), 'base64');
      const out = await this.kmsClient().send(
        new DecryptCommand({ CiphertextBlob: blob, EncryptionContext: kmsContext }),
      );
      if (!out.Plaintext) throw new Error('KMS Decrypt returned no plaintext');
      const key = Buffer.from(out.Plaintext).toString('utf8');
      this.cacheSet(cacheKey, key);
      return key;
    }

    if (stored.startsWith(LOCAL_PREFIX)) {
      const [ivHex, tagHex, ctHex] = stored.slice(LOCAL_PREFIX.length).split(':');
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.localMasterKey(), Buffer.from(ivHex, 'hex'), { authTagLength: 16 });
      decipher.setAAD(Buffer.from(canonicalContext(context), 'utf8'));
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      return Buffer.concat([decipher.update(Buffer.from(ctHex, 'hex')), decipher.final()]).toString('utf8');
    }

    if (stored.startsWith('enc:')) throw new Error('Unsupported key envelope');
    return stored;
  }

  private cacheGet(blob: string): string | null {
    const hit = this.cache.get(blob);
    if (!hit) return null;
    if (hit.expiresAt < Date.now()) {
      this.cache.delete(blob);
      return null;
    }
    return hit.key;
  }

  private cacheSet(blob: string, key: string): void {
    if (this.cache.size >= this.cacheMax) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(blob, { key, expiresAt: Date.now() + this.cacheTtlMs });
  }
}

export const keyEnvelope = new KeyEnvelopeService();
