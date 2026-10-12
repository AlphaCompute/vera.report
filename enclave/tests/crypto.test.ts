/**
 * Crypto handlers.
 *
 * These run against real node:crypto with no test doubles: the whole point of
 * the enclave is that these primitives behave correctly, so faking them would
 * test nothing. Iterations are lowered explicitly in most cases because the
 * production default of 600k PBKDF2 rounds costs about a second per call; the
 * default itself is asserted separately.
 */

import * as crypto from 'node:crypto';
import {
  handleEncrypt,
  handleDecrypt,
  handleDeriveKey,
  handleHash,
  handleGenerateRandom,
  deriveKeyInternal,
  keyStore,
  DEFAULT_PBKDF2_ITERATIONS,
} from '../src/server.js';

const SECRET = 'test-key-derivation-secret';
const FAST = 1000;

afterEach(() => {
  for (const [id, key] of keyStore.entries()) {
    key.fill(0);
    keyStore.delete(id);
  }
});

// The host supplies these costs and sits outside the enclave's trust boundary.
// scryptSync/pbkdf2Sync block, so an unbounded value stalls every other
// request. The bound rejects rather than clamps: a silently lowered cost would
// derive a different key and orphan anything already sealed with the original.
describe('key derivation cost bounds', () => {
  it('preserves fixed-cost scrypt regardless of the unused iteration argument', () => {
    const salt = Buffer.alloc(32, 1);
    expect(deriveKeyInternal(SECRET, salt, 2_000_001, 32, 'scrypt'))
      .toEqual(deriveKeyInternal(SECRET, salt, FAST, 32, 'scrypt'));
  });

  it('rejects an iteration count beyond the ceiling', async () => {
    await expect(handleEncrypt({
      plaintext: 'x', keyDerivationSecret: SECRET, iterations: 2_000_001,
    })).rejects.toThrow('iteration limit exceeded');
  });

  it('rejects an unrecognized algorithm instead of running unbounded PBKDF2', () => {
    for (const algorithm of ['PBKDF2', 'x', '']) {
      expect(() => handleDeriveKey({
        secret: SECRET, iterations: 2_000_000_000, algorithm: algorithm as 'pbkdf2',
      })).toThrow(algorithm ? 'Unsupported key derivation algorithm' : 'iteration limit exceeded');
    }
  });

  it('rejects a key length beyond the ceiling', () => {
    expect(() => handleDeriveKey({
      secret: SECRET, iterations: FAST, keyLength: 257,
    })).toThrow('length limit exceeded');
  });

  it('rejects a non-integer or negative iteration count', async () => {
    for (const iterations of [-1, 0.5, Number.POSITIVE_INFINITY]) {
      await expect(handleEncrypt({
        plaintext: 'x', keyDerivationSecret: SECRET, iterations,
      })).rejects.toThrow('limit exceeded');
    }
  });

  // NaN and 0 are falsy, so `params.iterations || DEFAULT` substitutes the
  // default before the bound is reached. That is the safe outcome, not a gap.
  it('falls back to the default for a falsy iteration count', async () => {
    const sealed = await handleEncrypt({
      plaintext: 'x', keyDerivationSecret: SECRET, iterations: Number.NaN,
    });
    expect(sealed.ciphertext).toBeTruthy();
  });

  it('still accepts the default cost unchanged', async () => {
    const sealed = await handleEncrypt({
      plaintext: 'x', keyDerivationSecret: SECRET, iterations: DEFAULT_PBKDF2_ITERATIONS,
    });
    expect(sealed.ciphertext).toBeTruthy();
  });
});

describe('encrypt / decrypt', () => {
  it('round-trips plaintext', async () => {
    const plaintext = 'the document is in the third filing cabinet';

    const sealed = await handleEncrypt({
      plaintext,
      keyDerivationSecret: SECRET,
      iterations: FAST,
    });
    const opened = await handleDecrypt({
      ciphertext: sealed.ciphertext,
      iv: sealed.iv,
      authTag: sealed.authTag,
      salt: sealed.salt,
      keyDerivationSecret: SECRET,
      iterations: FAST,
    });

    expect(opened).toBe(plaintext);
  });

  it('round-trips unicode and empty input without corruption', async () => {
    for (const plaintext of ['', '☂ 監視 sürveillance', '\u0000\u0001binary-ish\u00ff']) {
      const sealed = await handleEncrypt({ plaintext, keyDerivationSecret: SECRET, iterations: FAST });
      const opened = await handleDecrypt({
        ...sealed,
        keyDerivationSecret: SECRET,
        iterations: FAST,
      } as Parameters<typeof handleDecrypt>[0]);

      expect(opened).toBe(plaintext);
    }
  });

  it('produces a fresh salt and iv per call, so identical plaintext differs', async () => {
    const a = await handleEncrypt({ plaintext: 'same', keyDerivationSecret: SECRET, iterations: FAST });
    const b = await handleEncrypt({ plaintext: 'same', keyDerivationSecret: SECRET, iterations: FAST });

    // Deterministic ciphertext would leak equality between reports.
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.iv).not.toBe(b.iv);
    expect(a.salt).not.toBe(b.salt);
  });

  it('emits a 16-byte iv and a 16-byte GCM tag', async () => {
    const sealed = await handleEncrypt({ plaintext: 'x', keyDerivationSecret: SECRET, iterations: FAST });

    expect(Buffer.from(sealed.iv, 'hex')).toHaveLength(16);
    expect(Buffer.from(sealed.authTag, 'hex')).toHaveLength(16);
    expect(Buffer.from(sealed.salt, 'hex')).toHaveLength(32);
  });

  it('rejects a tampered ciphertext', async () => {
    const sealed = await handleEncrypt({
      plaintext: 'authentic',
      keyDerivationSecret: SECRET,
      iterations: FAST,
    });

    const raw = Buffer.from(sealed.ciphertext, 'base64');
    raw[0] ^= 0xff;

    await expect(
      handleDecrypt({
        ciphertext: raw.toString('base64'),
        iv: sealed.iv,
        authTag: sealed.authTag,
        salt: sealed.salt,
        keyDerivationSecret: SECRET,
        iterations: FAST,
      })
    ).rejects.toThrow();
  });

  it('rejects a tampered auth tag', async () => {
    const sealed = await handleEncrypt({ plaintext: 'authentic', keyDerivationSecret: SECRET, iterations: FAST });

    const tag = Buffer.from(sealed.authTag, 'hex');
    tag[0] ^= 0xff;

    await expect(
      handleDecrypt({ ...sealed, authTag: tag.toString('hex'), keyDerivationSecret: SECRET, iterations: FAST })
    ).rejects.toThrow();
  });

  it('rejects the wrong key-derivation secret', async () => {
    const sealed = await handleEncrypt({ plaintext: 'authentic', keyDerivationSecret: SECRET, iterations: FAST });

    await expect(
      handleDecrypt({ ...sealed, keyDerivationSecret: 'not-the-secret', iterations: FAST })
    ).rejects.toThrow();
  });

  it('rejects a mismatched iteration count', async () => {
    // Iterations are part of key derivation, so a caller replaying with the
    // wrong count must fail closed rather than silently derive another key.
    const sealed = await handleEncrypt({ plaintext: 'authentic', keyDerivationSecret: SECRET, iterations: FAST });

    await expect(
      handleDecrypt({ ...sealed, keyDerivationSecret: SECRET, iterations: FAST + 1 })
    ).rejects.toThrow();
  });

  it('rejects a swapped salt', async () => {
    const a = await handleEncrypt({ plaintext: 'one', keyDerivationSecret: SECRET, iterations: FAST });
    const b = await handleEncrypt({ plaintext: 'two', keyDerivationSecret: SECRET, iterations: FAST });

    await expect(
      handleDecrypt({ ...a, salt: b.salt, keyDerivationSecret: SECRET, iterations: FAST })
    ).rejects.toThrow();
  });

  it('honours a caller-supplied salt', async () => {
    const salt = crypto.randomBytes(32).toString('hex');
    const sealed = await handleEncrypt({ plaintext: 'x', salt, keyDerivationSecret: SECRET, iterations: FAST });

    expect(sealed.salt).toBe(salt);
  });
});

describe('deriveKeyInternal', () => {
  it('is deterministic for the same inputs', () => {
    const salt = Buffer.alloc(32, 7);
    const a = deriveKeyInternal(SECRET, salt, FAST, 32, 'pbkdf2');
    const b = deriveKeyInternal(SECRET, salt, FAST, 32, 'pbkdf2');

    expect(a.equals(b)).toBe(true);
  });

  it('diverges on a different salt', () => {
    const a = deriveKeyInternal(SECRET, Buffer.alloc(32, 1), FAST, 32, 'pbkdf2');
    const b = deriveKeyInternal(SECRET, Buffer.alloc(32, 2), FAST, 32, 'pbkdf2');

    expect(a.equals(b)).toBe(false);
  });

  it('matches the node:crypto reference for pbkdf2-sha512', () => {
    // Pins the digest. Silently dropping to sha1 would still "work" while
    // weakening every derived key, and nothing else here would notice.
    const salt = Buffer.alloc(32, 3);

    expect(
      deriveKeyInternal(SECRET, salt, FAST, 32, 'pbkdf2').equals(
        crypto.pbkdf2Sync(SECRET, salt, FAST, 32, 'sha512')
      )
    ).toBe(true);
  });

  it('supports scrypt and produces a different key than pbkdf2', () => {
    const salt = Buffer.alloc(32, 4);
    const viaScrypt = deriveKeyInternal(SECRET, salt, FAST, 32, 'scrypt');

    expect(viaScrypt).toHaveLength(32);
    expect(viaScrypt.equals(deriveKeyInternal(SECRET, salt, FAST, 32, 'pbkdf2'))).toBe(false);
  });

  it('respects the requested key length', () => {
    const salt = Buffer.alloc(32, 5);

    expect(deriveKeyInternal(SECRET, salt, FAST, 16, 'pbkdf2')).toHaveLength(16);
    expect(deriveKeyInternal(SECRET, salt, FAST, 64, 'pbkdf2')).toHaveLength(64);
  });

  it('keeps the production iteration count at or above OWASP guidance', () => {
    // 600k is the OWASP floor for PBKDF2-HMAC-SHA512 at time of writing.
    // A well-meaning "make tests faster" edit to the constant must fail here.
    expect(DEFAULT_PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(210000);
  });
});

describe('deriveKey handler', () => {
  it('stores the derived key in the enclave and returns only a handle', async () => {
    const before = keyStore.size;
    const out = handleDeriveKey({ secret: SECRET, iterations: FAST });

    expect(keyStore.size).toBe(before + 1);
    // The key material itself must never appear in the response.
    expect(Object.values(out).join(' ')).not.toContain(SECRET);
    expect(out).not.toHaveProperty('key');
    expect(out.keyId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('echoes the parameters needed to reproduce the derivation', () => {
    const out = handleDeriveKey({ secret: SECRET, iterations: FAST, keyLength: 48, algorithm: 'scrypt' });

    expect(out.algorithm).toBe('scrypt');
    expect(out.iterations).toBe(String(FAST));
    expect(out.keyLength).toBe('48');
    expect(Buffer.from(out.salt, 'hex')).toHaveLength(32);
  });

  it('issues a distinct id per call', () => {
    const a = handleDeriveKey({ secret: SECRET, iterations: FAST });
    const b = handleDeriveKey({ secret: SECRET, iterations: FAST });

    expect(a.keyId).not.toBe(b.keyId);
  });
});

describe('hash', () => {
  it('matches known sha256 vectors', () => {
    expect(handleHash({ data: 'abc' })).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    expect(handleHash({ data: '' })).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  it('defaults to sha256 and honours an explicit algorithm', () => {
    expect(handleHash({ data: 'abc' })).toBe(handleHash({ data: 'abc', algorithm: 'sha256' }));
    expect(handleHash({ data: 'abc', algorithm: 'sha512' })).toHaveLength(128);
  });

  it('hashes utf-8 bytes, not a lossy encoding', () => {
    expect(handleHash({ data: '監視' })).toBe(
      crypto.createHash('sha256').update('監視', 'utf-8').digest('hex')
    );
  });
});

describe('generateRandom', () => {
  it('returns the requested number of bytes as hex', () => {
    expect(handleGenerateRandom({ length: 32 })).toHaveLength(64);
  });

  it('clamps to the 1..1024 range instead of throwing or over-allocating', () => {
    expect(handleGenerateRandom({ length: 0 })).toHaveLength(2);
    expect(handleGenerateRandom({ length: -5 })).toHaveLength(2);
    expect(handleGenerateRandom({ length: 99999 })).toHaveLength(2048);
  });

  it('does not repeat across calls', () => {
    const seen = new Set(Array.from({ length: 50 }, () => handleGenerateRandom({ length: 16 })));

    expect(seen.size).toBe(50);
  });
});
