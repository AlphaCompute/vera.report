/**
 * Report field crypto — fail-closed hardening.
 *
 * In production, a missing REWARD_ENCRYPTION_KEY must throw rather than silently
 * fall back to the deterministic public dev key (which would encrypt reward
 * contact PII and report narratives with a known key). Outside production the
 * dev fallback still applies so local data survives restarts.
 */
import {
  encryptContactValue,
  decryptContactValue,
} from '../../../src/services/reportFieldCrypto';

const ORIGINAL_ENV = process.env;
beforeEach(() => {
  process.env = { ...ORIGINAL_ENV };
});
afterEach(() => {
  process.env = ORIGINAL_ENV;
});

describe('reportFieldCrypto fail-closed', () => {
  it('throws in production when REWARD_ENCRYPTION_KEY is missing (no silent dev-key fallback)', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.REWARD_ENCRYPTION_KEY;
    expect(() => encryptContactValue('secret@example.com')).toThrow(/REWARD_ENCRYPTION_KEY/);
  });

  it('encrypts and decrypts round-trip in production when the key is set', () => {
    process.env.NODE_ENV = 'production';
    process.env.REWARD_ENCRYPTION_KEY = 'a'.repeat(64);
    const ct = encryptContactValue('reporter@example.com');
    expect(ct).toMatch(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
    expect(decryptContactValue(ct)).toBe('reporter@example.com');
  });

  it('still uses the deterministic dev fallback outside production', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.REWARD_ENCRYPTION_KEY;
    const ct = encryptContactValue('dev@example.com');
    expect(decryptContactValue(ct)).toBe('dev@example.com');
  });
});
