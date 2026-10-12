import { handleDecrypt, handleEncrypt } from '../src/server.js';

it('erases the derived key even when GCM authentication fails', async () => {
  // Keep real encryption/decryption; observe only the KDF output's lifetime.
  const crypto = require('node:crypto') as typeof import('node:crypto');
  const original = crypto.pbkdf2Sync;
  let derived: Buffer | undefined;
  const spy = jest.spyOn(crypto, 'pbkdf2Sync').mockImplementation((...args) => {
    derived = original(...args);
    return derived;
  });
  try {
    const encrypted = await handleEncrypt({ plaintext: 'synthetic', keyDerivationSecret: 'test', iterations: 1000 });
    expect(derived?.every(byte => byte === 0)).toBe(true);
    const tag = Buffer.from(encrypted.authTag, 'hex');
    tag[0] ^= 1;
    await expect(handleDecrypt({ ...encrypted, authTag: tag.toString('hex'), keyDerivationSecret: 'test', iterations: 1000 } as Parameters<typeof handleDecrypt>[0])).rejects.toThrow();
    expect(derived?.every(byte => byte === 0)).toBe(true);
  } finally {
    spy.mockRestore();
  }
});
