import crypto from 'node:crypto';
import {
  LEGACY_STORAGE_SALT, deriveStorageKey, encryptForStorage, decryptStoredCiphertext,
} from '../../../src/services/evidenceStorageCipher';

// The synchronous derivation every stored record was written with (#1114).
const syncKey = (secret: string, salt?: string) =>
  crypto.scryptSync(secret, salt ? Buffer.from(salt, 'base64') : 'midnight-salt', 32);

// Seal a record exactly as the previous synchronous code did.
function legacySeal(data: Buffer, secret: string, salt?: Buffer) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', crypto.scryptSync(secret, salt ?? 'midnight-salt', 32), iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return { encrypted, iv: iv.toString('base64'), authTag: cipher.getAuthTag().toString('base64'), salt: salt?.toString('base64') };
}

describe('storage-layer key derivation', () => {
  it('matches the synchronous derivation for random per-record salts', async () => {
    for (let i = 0; i < 8; i++) {
      const secret = crypto.randomBytes(32).toString('hex');
      const salt = crypto.randomBytes(16).toString('base64');
      expect((await deriveStorageKey(secret, salt)).equals(syncKey(secret, salt))).toBe(true);
    }
  });

  it('matches the synchronous derivation for legacy records with the fixed salt', async () => {
    expect(LEGACY_STORAGE_SALT).toBe('midnight-salt');
    const secret = crypto.randomBytes(32).toString('hex');
    const expected = crypto.scryptSync(secret, 'midnight-salt', 32);
    expect((await deriveStorageKey(secret)).equals(expected)).toBe(true);
    expect((await deriveStorageKey(secret, '')).equals(expected)).toBe(true);
  });

  it('keeps the scrypt parameters fixed (known-answer vectors, N=16384 r=8 p=1, 32 bytes)', async () => {
    expect((await deriveStorageKey('vera-kat-secret', 'AAECAwQFBgcICQoLDA0ODw==')).toString('hex'))
      .toBe('c2bde31649c83d40be38f7b92eab5ba70858fc4d0e0c45ac80c37cd0c2d12bf1');
    expect((await deriveStorageKey('vera-kat-secret')).toString('hex'))
      .toBe('c1d473345881d01439f6f1aa282a0234e002634429f0e3142af472ded0fad9ad');
  });

  it('does not block the event loop while deriving', async () => {
    let ticked = false;
    setImmediate(() => { ticked = true; });
    await deriveStorageKey('synthetic-secret', crypto.randomBytes(16).toString('base64'));
    expect(ticked).toBe(true);
  });
});

describe('storage-layer encryption', () => {
  it('round-trips and stays readable by the synchronous derivation', async () => {
    const secret = crypto.randomBytes(32).toString('hex');
    const plaintext = crypto.randomBytes(4096);
    const sealed = await encryptForStorage(plaintext, secret);
    expect(sealed.encrypted.equals(plaintext)).toBe(false);
    expect(Buffer.from(sealed.salt, 'base64')).toHaveLength(16);
    expect((await decryptStoredCiphertext(sealed.encrypted, secret, sealed.iv, sealed.authTag, sealed.salt)).equals(plaintext)).toBe(true);
    const decipher = crypto.createDecipheriv('aes-256-gcm', syncKey(secret, sealed.salt), Buffer.from(sealed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(sealed.authTag, 'base64'));
    expect(Buffer.concat([decipher.update(sealed.encrypted), decipher.final()]).equals(plaintext)).toBe(true);
  });

  it('decrypts existing records written by the synchronous code, salted and legacy', async () => {
    const secret = crypto.randomBytes(32).toString('hex');
    const plaintext = Buffer.from('existing evidence ciphertext');
    for (const record of [legacySeal(plaintext, secret, crypto.randomBytes(16)), legacySeal(plaintext, secret)]) {
      const out = await decryptStoredCiphertext(record.encrypted, secret, record.iv, record.authTag, record.salt);
      expect(out.equals(plaintext)).toBe(true);
    }
  });

  it('rejects a wrong key, a wrong salt and an altered tag', async () => {
    const secret = crypto.randomBytes(32).toString('hex');
    const sealed = await encryptForStorage(Buffer.from('synthetic'), secret);
    await expect(decryptStoredCiphertext(sealed.encrypted, 'wrong', sealed.iv, sealed.authTag, sealed.salt)).rejects.toThrow();
    await expect(decryptStoredCiphertext(sealed.encrypted, secret, sealed.iv, sealed.authTag)).rejects.toThrow();
    const tag = Buffer.from(sealed.authTag, 'base64'); tag[0] ^= 1;
    await expect(decryptStoredCiphertext(sealed.encrypted, secret, sealed.iv, tag.toString('base64'), sealed.salt)).rejects.toThrow();
  });
});
