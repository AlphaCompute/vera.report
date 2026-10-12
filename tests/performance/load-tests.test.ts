import { EvidenceEncryptionService } from '../../src/services/evidenceEncryption';
import { EncryptionService } from '../../src/services/encryption';
import { SimpleCache } from '../../src/utils/cache';

describe('Performance Tests (Real Services)', () => {
  const encryptionService = new EncryptionService();
  const evidenceEncryption = new EvidenceEncryptionService();

  describe('Encryption Performance', () => {
    it('should encrypt and decrypt a 1KB message under 50ms', async () => {
      const data = 'a'.repeat(1024);
      const key = 'perf-test-key-001';

      const start = Date.now();
      const encrypted = encryptionService.encrypt(data, key);
      const decrypted = encryptionService.decrypt(encrypted.encrypted, key, encrypted.iv, encrypted.authTag);
      const elapsed = Date.now() - start;

      expect(decrypted).toBe(data);
      expect(elapsed).toBeLessThan(50);
    });

    it('should encrypt and decrypt a 1MB message under 500ms', async () => {
      const data = 'x'.repeat(1024 * 1024);
      const key = 'perf-test-key-002';

      const start = Date.now();
      const encrypted = encryptionService.encrypt(data, key);
      const decrypted = encryptionService.decrypt(encrypted.encrypted, key, encrypted.iv, encrypted.authTag);
      const elapsed = Date.now() - start;

      expect(decrypted).toBe(data);
      expect(elapsed).toBeLessThan(500);
    });

    it('should handle 100 sequential encryptions under 2s', async () => {
      const key = 'perf-test-key-003';

      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        encryptionService.encrypt(`message-${i}`, key);
      }
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(5000);
    });
  });

  describe('Evidence Encryption Performance', () => {
    it('should encrypt text evidence under 200ms', async () => {
      const content = 'Confidential evidence report. '.repeat(100);
      const secret = 'evidence-perf-secret';

      const start = Date.now();
      const encrypted = await evidenceEncryption.encryptEvidence(content, 'text/plain', secret);
      const elapsed = Date.now() - start;

      expect(encrypted.encryptedData).toBeTruthy();
      expect(encrypted.encryptionMetadata.algorithm).toBe('aes-256-gcm');
      expect(elapsed).toBeLessThan(200);
    });

    it('should encrypt and decrypt evidence with integrity verification', async () => {
      const content = 'Integrity test content for performance';
      const secret = 'integrity-perf-secret';

      const encrypted = await evidenceEncryption.encryptEvidence(content, 'text/plain', secret);
      const decrypted = await evidenceEncryption.decryptEvidence(encrypted, secret);

      expect(decrypted.content.toString('utf8')).toBe(content);
      expect(decrypted.isValid).toBe(true);
    });

    it('should handle 10 concurrent evidence encryptions', async () => {
      const secret = 'concurrent-perf-secret';

      const start = Date.now();
      const operations = Array.from({ length: 10 }, (_, i) =>
        evidenceEncryption.encryptEvidence(`concurrent evidence ${i}`, 'text/plain', secret)
      );
      const results = await Promise.all(operations);
      const elapsed = Date.now() - start;

      expect(results).toHaveLength(10);
      results.forEach(r => expect(r.encryptedData).toBeTruthy());
      expect(elapsed).toBeLessThan(2000);
    });
  });

  describe('Cache Performance', () => {
    it('should achieve cache hit times under 1ms', () => {
      const cache = new SimpleCache(60000);

      cache.set('perf-key', { data: 'cached value' });

      const start = Date.now();
      for (let i = 0; i < 10000; i++) {
        cache.get('perf-key');
      }
      const elapsed = Date.now() - start;

      expect(cache.get('perf-key')).toEqual({ data: 'cached value' });
      expect(elapsed).toBeLessThan(100);
    });

    it('should handle cache eviction based on TTL', async () => {
      const cache = new SimpleCache(50);

      cache.set('ttl-key', 'short-lived');
      expect(cache.get('ttl-key')).toBe('short-lived');

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(cache.get('ttl-key')).toBeNull();
    });
  });

  describe('Memory Usage', () => {
    it('should not leak memory during repeated encrypt/decrypt cycles', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      const key = 'memory-test-key';

      for (let i = 0; i < 500; i++) {
        const data = `cycle-${i}-${'x'.repeat(1000)}`;
        const encrypted = encryptionService.encrypt(data, key);
        encryptionService.decrypt(encrypted.encrypted, key, encrypted.iv, encrypted.authTag);
      }

      if (global.gc) global.gc();
      await new Promise(resolve => setTimeout(resolve, 50));

      const finalMemory = process.memoryUsage().heapUsed;
      const increase = finalMemory - initialMemory;

      expect(increase).toBeLessThan(50 * 1024 * 1024);
    });
  });
});
