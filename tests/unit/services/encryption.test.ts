import { encryptData, decryptData } from '../../../src/services/encryption';

describe('Encryption Service', () => {
  const testData = 'This is sensitive information';
  const testKey = 'test-encryption-key-32-characters!!';

  describe('encryptData', () => {
    it('should encrypt data successfully', () => {
      const encrypted = encryptData(testData, testKey);
      
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(testData);
      expect(encrypted).toContain(':'); // Should contain IV separator
    });

    it('should produce different encrypted values for same data', () => {
      const encrypted1 = encryptData(testData, testKey);
      const encrypted2 = encryptData(testData, testKey);
      
      expect(encrypted1).not.toBe(encrypted2); // Different IVs
    });

    it('should handle empty strings', () => {
      const encrypted = encryptData('', testKey);
      
      expect(encrypted).toBeDefined();
      expect(encrypted).toContain(':');
    });

    it('should handle special characters', () => {
      const specialData = '!@#$%^&*(){}[]|\\:;"<>,.?/~`';
      const encrypted = encryptData(specialData, testKey);
      
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(specialData);
    });

    it('should handle unicode characters', () => {
      const unicodeData = '🚀 Тест データ 测试';
      const encrypted = encryptData(unicodeData, testKey);
      
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(unicodeData);
    });
  });

  describe('decryptData', () => {
    it('should decrypt data successfully', () => {
      const encrypted = encryptData(testData, testKey);
      const decrypted = decryptData(encrypted, testKey);
      
      expect(decrypted).toBe(testData);
    });

    it('should handle empty encrypted strings', () => {
      const encrypted = encryptData('', testKey);
      const decrypted = decryptData(encrypted, testKey);
      
      expect(decrypted).toBe('');
    });

    it('should fail with wrong key', () => {
      const encrypted = encryptData(testData, testKey);
      const wrongKey = 'wrong-key-32-characters-padding!!';
      
      expect(() => decryptData(encrypted, wrongKey)).toThrow();
    });

    it('should fail with invalid encrypted data', () => {
      expect(() => decryptData('invalid:data', testKey)).toThrow();
      expect(() => decryptData('notencrypted', testKey)).toThrow();
    });

    it('should handle round-trip encryption/decryption', () => {
      const testCases = [
        'Simple text',
        '12345',
        'Mixed123!@#',
        '{"json": "data"}',
        'Multi\nLine\nText',
        ''
      ];

      testCases.forEach(data => {
        const encrypted = encryptData(data, testKey);
        const decrypted = decryptData(encrypted, testKey);
        expect(decrypted).toBe(data);
      });
    });
  });

  describe('Edge cases', () => {
    it('should handle very long data', () => {
      const longData = 'x'.repeat(10000);
      const encrypted = encryptData(longData, testKey);
      const decrypted = decryptData(encrypted, testKey);
      
      expect(decrypted).toBe(longData);
      expect(encrypted.length).toBeGreaterThan(longData.length);
    });

    it('should handle binary-like data', () => {
      const binaryData = Buffer.from([0, 1, 2, 3, 255, 254, 253]).toString('utf-8');
      const encrypted = encryptData(binaryData, testKey);
      const decrypted = decryptData(encrypted, testKey);
      
      expect(decrypted).toBe(binaryData);
    });
  });
});