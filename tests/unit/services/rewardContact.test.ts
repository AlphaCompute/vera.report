/**
 * Reward-contact envelope encryption, using the local key fallback (no KMS in
 * CI/dev). Confirms the value is recoverable, never stored in plaintext, and
 * bound to its report via the encryption context.
 */

import crypto from 'node:crypto';
import { keyEnvelope } from '@services/keyEnvelope';
import { encryptRewardContact, decryptRewardContact, decryptLegacyRewardContact } from '@services/rewardContact';

/** Reproduces the retired direct-key encrypt path (iv:authTag:ciphertext, all hex). */
function legacyEncrypt(plaintext: string): string {
  const envKey = process.env.REWARD_ENCRYPTION_KEY?.trim();
  const key = crypto.scryptSync(envKey || 'dev-reward-key-not-for-production', 'vera-reward-contact-salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${ct.toString('hex')}`;
}

describe('rewardContact', () => {
  const trackingId = 'VRA-ABCDEF0123456789';
  const contact = 'signal:+1-202-555-0134';

  it('round-trips the contact value for the same report', async () => {
    const enc = await encryptRewardContact(contact, trackingId);
    expect(enc.ciphertext).not.toContain(contact);
    expect(enc.wrappedKey).not.toContain(contact);

    const back = await decryptRewardContact(enc, trackingId);
    expect(back).toBe(contact);
  });

  it('fails to decrypt when unwrapped under a different report id', async () => {
    const enc = await encryptRewardContact(contact, trackingId);
    await expect(decryptRewardContact(enc, 'VRA-0000000000000000')).rejects.toThrow();
  });

  it('rejects raw-key substitution in an envelope record', async () => {
    const encrypted = await encryptRewardContact(contact, trackingId);
    const rawKey = await keyEnvelope.unwrap(encrypted.wrappedKey, { trackingId, purpose: 'reward' });
    await expect(decryptRewardContact({ ...encrypted, wrappedKey: rawKey }, trackingId))
      .rejects.toThrow('Invalid wrapped key envelope');
  });

  it('reads a legacy (pre-envelope) contact via the direct-key fallback', () => {
    const legacy = legacyEncrypt(contact);
    expect(decryptLegacyRewardContact(legacy)).toBe(contact);
  });

  it('fails loud on legacy decrypt in production when REWARD_ENCRYPTION_KEY is unset', () => {
    const legacy = legacyEncrypt(contact);
    const prevNodeEnv = process.env.NODE_ENV;
    const prevKey = process.env.REWARD_ENCRYPTION_KEY;
    process.env.NODE_ENV = 'production';
    delete process.env.REWARD_ENCRYPTION_KEY;
    try {
      expect(() => decryptLegacyRewardContact(legacy)).toThrow(/must be set/);
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
      if (prevKey === undefined) delete process.env.REWARD_ENCRYPTION_KEY;
      else process.env.REWARD_ENCRYPTION_KEY = prevKey;
    }
  });
});


describe('owned reward-contact buffers', () => {
  afterEach(() => jest.restoreAllMocks());

  it.each(['current', 'legacy'] as const)('%s decryption clears keys and temporary plaintext on success and bad tags', async format => {
    const trackingId = 'VRA-ABCDEF0123456789';
    const contact = 'synthetic-contact@example.test';
    const encrypted = format === 'current'
      ? await encryptRewardContact(contact, trackingId)
      : { ciphertext: legacyEncrypt(contact), wrappedKey: '' };
    if (format === 'current') {
      const key = await keyEnvelope.unwrap(encrypted.wrappedKey, { trackingId, purpose: 'reward' });
      jest.spyOn(keyEnvelope, 'unwrap').mockResolvedValue(key);
    }
    const create = crypto.createDecipheriv.bind(crypto);
    const owned: Buffer[] = [];
    jest.spyOn(crypto, 'createDecipheriv').mockImplementation(((...args: Parameters<typeof crypto.createDecipheriv>) => {
      const decipher = create(...args);
      // Capture actual native-crypto output without replacing authentication.
      if (Buffer.isBuffer(args[1])) owned.push(args[1]);
      const update = decipher.update.bind(decipher);
      jest.spyOn(decipher, 'update').mockImplementation(((...input: Parameters<typeof decipher.update>) => {
        const result = update(...input);
        if (Buffer.isBuffer(result)) owned.push(result);
        return result;
      }) as typeof decipher.update);
      return decipher;
    }) as typeof crypto.createDecipheriv);
    const read = (ciphertext: string) => format === 'current'
      ? decryptRewardContact({ ...encrypted, ciphertext }, trackingId)
      : Promise.resolve().then(() => decryptLegacyRewardContact(ciphertext));
    expect(await read(encrypted.ciphertext)).toBe(contact);
    expect(owned.length).toBeGreaterThanOrEqual(2);
    expect(owned.every(buffer => buffer.every(byte => byte === 0))).toBe(true);
    owned.length = 0;
    const parts = encrypted.ciphertext.split(':');
    const tag = Buffer.from(parts[1], 'hex');
    tag[0] ^= 1;
    parts[1] = tag.toString('hex');
    await expect(read(parts.join(':'))).rejects.toThrow();
    expect(owned.length).toBeGreaterThanOrEqual(2);
    expect(owned.every(buffer => buffer.every(byte => byte === 0))).toBe(true);
  });

  it.each([false, true])('clears the generated data key (wrapping failure: %s)', async wrappingFails => {
    const create = crypto.createCipheriv.bind(crypto);
    let key: Buffer | undefined;
    jest.spyOn(crypto, 'createCipheriv').mockImplementation(((...args: Parameters<typeof crypto.createCipheriv>) => {
      if (!key && Buffer.isBuffer(args[1])) key = args[1];
      return create(...args);
    }) as typeof crypto.createCipheriv);
    if (wrappingFails) jest.spyOn(keyEnvelope, 'wrap').mockRejectedValueOnce(new Error('synthetic wrapping failure'));
    const result = encryptRewardContact('synthetic-contact', 'VRA-ABCDEF0123456789');
    if (wrappingFails) await expect(result).rejects.toThrow('synthetic wrapping failure');
    else expect(await decryptRewardContact(await result, 'VRA-ABCDEF0123456789')).toBe('synthetic-contact');
    expect(key).toBeDefined();
    expect(key!.every(byte => byte === 0)).toBe(true);
  });
});
