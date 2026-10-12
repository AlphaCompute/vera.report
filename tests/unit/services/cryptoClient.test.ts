import crypto from 'node:crypto';
import {
  LocalCryptoClient,
  EnclaveCryptoClient,
  getCryptoClient,
  _resetCryptoClient,
  type CryptoClient,
} from '../../../src/services/cryptoClient';

describe('CryptoClient', () => {
  afterEach(() => {
    _resetCryptoClient();
    delete process.env.ENCLAVE_ENABLED;
  });

  describe('LocalCryptoClient', () => {
    let client: CryptoClient;

    beforeEach(() => {
      client = new LocalCryptoClient();
    });

    it('should encrypt and decrypt data', async () => {
      const plaintext = Buffer.from('sensitive whistleblower evidence');
      const secret = 'test-secret-key';

      const encrypted = await client.encrypt(plaintext, secret);
      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.salt).toBeDefined();

      const decrypted = await client.decrypt(encrypted, secret);
      expect(decrypted.toString()).toBe('sensitive whistleblower evidence');
    });

    it('should produce different ciphertexts for same plaintext', async () => {
      const plaintext = Buffer.from('same data');
      const secret = 'key';

      const enc1 = await client.encrypt(plaintext, secret);
      const enc2 = await client.encrypt(plaintext, secret);

      expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
      expect(enc1.iv).not.toBe(enc2.iv);
      expect(enc1.salt).not.toBe(enc2.salt);
    });

    it('should fail decryption with wrong secret', async () => {
      const plaintext = Buffer.from('secret data');
      const encrypted = await client.encrypt(plaintext, 'correct-key');

      await expect(client.decrypt(encrypted, 'wrong-key')).rejects.toThrow();
    });

    it('should fail decryption with tampered ciphertext', async () => {
      const plaintext = Buffer.from('tamper test');
      const encrypted = await client.encrypt(plaintext, 'key');

      const tampered = { ...encrypted, ciphertext: 'dGFtcGVyZWQ=' };
      await expect(client.decrypt(tampered, 'key')).rejects.toThrow();
    });

    it('should derive key with pbkdf2', async () => {
      const salt = Buffer.from('test-salt-value-here');
      const key = await client.deriveKey('password', salt, {
        algorithm: 'pbkdf2',
        iterations: 1000,
        keyLength: 32,
      });

      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);

      // Same inputs produce same key
      const key2 = await client.deriveKey('password', salt, {
        algorithm: 'pbkdf2',
        iterations: 1000,
        keyLength: 32,
      });
      expect(key.equals(key2)).toBe(true);
    });

    it('should derive key with scrypt', async () => {
      const salt = Buffer.from('test-salt');
      const key = await client.deriveKey('password', salt, {
        algorithm: 'scrypt',
        keyLength: 32,
      });

      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);
    });

    it('should hash data consistently', () => {
      const data = Buffer.from('hash me');
      const hash1 = client.hash(data);
      const hash2 = client.hash(data);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex
    });

    it('should produce different hashes for different data', () => {
      expect(client.hash(Buffer.from('a'))).not.toBe(client.hash(Buffer.from('b')));
    });

    it('should sign data deterministically with same key', () => {
      const data = Buffer.from('sign me');
      const key = Buffer.from('signing-key-32-bytes-long!!!!!!');

      const sig1 = client.sign(data, key);
      const sig2 = client.sign(data, key);

      expect(sig1.equals(sig2)).toBe(true);
    });

    it('should generate random bytes of requested length', () => {
      const bytes16 = client.randomBytes(16);
      const bytes32 = client.randomBytes(32);

      expect(bytes16.length).toBe(16);
      expect(bytes32.length).toBe(32);
      expect(bytes16.equals(client.randomBytes(16))).toBe(false); // statistically
    });

    it('should handle empty buffer encryption', async () => {
      const encrypted = await client.encrypt(Buffer.alloc(0), 'key');
      const decrypted = await client.decrypt(encrypted, 'key');
      expect(decrypted.length).toBe(0);
    });

    it('should handle large data encryption', async () => {
      const largeData = Buffer.alloc(1024 * 1024, 0x42); // 1MB
      const encrypted = await client.encrypt(largeData, 'key');
      const decrypted = await client.decrypt(encrypted, 'key');
      expect(decrypted.equals(largeData)).toBe(true);
    });
  });

  describe('getCryptoClient factory', () => {
    it('should return LocalCryptoClient when ENCLAVE_ENABLED is not set', () => {
      const client = getCryptoClient();
      expect(client).toBeInstanceOf(LocalCryptoClient);
    });

    it('should return LocalCryptoClient when ENCLAVE_ENABLED is false', () => {
      process.env.ENCLAVE_ENABLED = 'false';
      const client = getCryptoClient();
      expect(client).toBeInstanceOf(LocalCryptoClient);
    });

    it('should return EnclaveCryptoClient when ENCLAVE_ENABLED is true', () => {
      process.env.ENCLAVE_ENABLED = 'true';
      const client = getCryptoClient();
      expect(client).toBeInstanceOf(EnclaveCryptoClient);
    });

    it('should return singleton instance', () => {
      const client1 = getCryptoClient();
      const client2 = getCryptoClient();
      expect(client1).toBe(client2);
    });

    it('should return new instance after reset', () => {
      const client1 = getCryptoClient();
      _resetCryptoClient();
      const client2 = getCryptoClient();
      expect(client1).not.toBe(client2);
    });
  });
});

describe('Enclave host-key confinement guard', () => {
  it('rejects all legacy operations that expose or use host keys', async () => {
    const client = new EnclaveCryptoClient();
    await expect(client.encrypt(Buffer.from('evidence'), 'host-secret')).rejects.toThrow('disabled');
    await expect(client.decrypt({ ciphertext: '', iv: '', authTag: '', salt: '' }, 'host-secret')).rejects.toThrow('disabled');
    await expect(client.deriveKey('host-secret', Buffer.alloc(32), { algorithm: 'pbkdf2', iterations: 1000, keyLength: 32 })).rejects.toThrow('cannot be exported');
    expect(() => client.sign(Buffer.from('data'), Buffer.alloc(32))).toThrow('disabled');
  });
});


describe('owned local crypto buffers', () => {
  afterEach(() => jest.restoreAllMocks());

  it.each([false, true])('clears encryption keys (cipher failure: %s) without changing caller plaintext', async fail => {
    const original = crypto.createCipheriv.bind(crypto);
    let key: Buffer | undefined;
    jest.spyOn(crypto, 'createCipheriv').mockImplementation(((...args: Parameters<typeof crypto.createCipheriv>) => {
      if (Buffer.isBuffer(args[1])) key = args[1];
      if (fail) throw new Error('synthetic cipher failure');
      return original(...args);
    }) as typeof crypto.createCipheriv);
    const client = new LocalCryptoClient();
    const plaintext = Buffer.from('synthetic caller-owned plaintext');
    const operation = client.encrypt(plaintext, 'synthetic-secret');
    if (fail) await expect(operation).rejects.toThrow('synthetic cipher failure');
    else expect((await client.decrypt(await operation, 'synthetic-secret')).equals(plaintext)).toBe(true);
    expect(key).toBeDefined();
    expect(key!.every(byte => byte === 0)).toBe(true);
    expect(plaintext.toString()).toBe('synthetic caller-owned plaintext');
  });

  it.each(['valid', 'bad-tag', 'short-tag'] as const)('clears decryption keys and temporary plaintext: %s', async scenario => {
    const client = new LocalCryptoClient();
    const encrypted = await client.encrypt(Buffer.from('synthetic plaintext'), 'synthetic-secret');
    if (scenario === 'bad-tag') {
      const tag = Buffer.from(encrypted.authTag, 'hex'); tag[0] ^= 1;
      encrypted.authTag = tag.toString('hex');
    } else if (scenario === 'short-tag') encrypted.authTag = encrypted.authTag.slice(0, 8);
    const original = crypto.createDecipheriv.bind(crypto);
    const owned: Buffer[] = [];
    jest.spyOn(crypto, 'createDecipheriv').mockImplementation(((...args: Parameters<typeof crypto.createDecipheriv>) => {
      if (Buffer.isBuffer(args[1])) owned.push(args[1]);
      const decipher = original(...args);
      const update = decipher.update.bind(decipher);
      jest.spyOn(decipher, 'update').mockImplementation(((...input: Parameters<typeof decipher.update>) => {
        const result = update(...input);
        if (Buffer.isBuffer(result)) owned.push(result);
        return result;
      }) as typeof decipher.update);
      return decipher;
    }) as typeof crypto.createDecipheriv);
    const operation = client.decrypt(encrypted, 'synthetic-secret');
    if (scenario === 'valid') expect((await operation).toString()).toBe('synthetic plaintext');
    else await expect(operation).rejects.toThrow();
    expect(owned.length).toBe(scenario === 'short-tag' ? 1 : 2);
    expect(owned.every(buffer => buffer.every(byte => byte === 0))).toBe(true);
  });
});
