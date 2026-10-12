import { LocalCryptoClient } from '../../../src/services/cryptoClient';
import { pdfFixture } from '../../helpers/pdfFixture';
/**
 * Unit Tests for Evidence Encryption Service
 * Testing encryption, decryption, and privacy protection functionality
 */

import { EvidenceEncryptionService, evidenceEncryptionService, EncryptedEvidence } from '@services/evidenceEncryption';
import { createHash } from 'node:crypto';

describe('EvidenceEncryptionService', () => {
    let service: EvidenceEncryptionService;
    const testSecret = 'test_user_secret_12345';
    const testContent = 'This is sensitive whistleblowing evidence that needs protection';

    beforeEach(() => {
        service = new EvidenceEncryptionService();
    });

    describe('Service Initialization', () => {
        it('should initialize with default configuration', () => {
            const defaultService = new EvidenceEncryptionService();
            expect(defaultService).toBeDefined();
            expect(defaultService.encryptEvidence).toBeDefined();
            expect(defaultService.decryptEvidence).toBeDefined();
        });

        it('should initialize with custom configuration', () => {
            const customService = new EvidenceEncryptionService({
                algorithm: 'aes-256-gcm',
                keyDerivationIterations: 150000,
                saltLength: 64,
                ivLength: 32
            });
            expect(customService).toBeDefined();
        });

        it('should export singleton instance', () => {
            expect(evidenceEncryptionService).toBeDefined();
            expect(evidenceEncryptionService).toBeInstanceOf(EvidenceEncryptionService);
        });
    });

    describe('Text Content Encryption', () => {
        it('should encrypt text content successfully', async () => {
            const encrypted = await service.encryptEvidence(
                testContent,
                'text/plain',
                testSecret
            );

            expect(encrypted).toBeDefined();
            expect(encrypted.encryptedData).toBeDefined();
            expect(encrypted.encryptionMetadata.algorithm).toBe('aes-256-gcm');
            expect(encrypted.encryptionMetadata.salt).toHaveLength(44); // Base64 of 32 bytes
            expect(encrypted.encryptionMetadata.iv).toHaveLength(24); // Base64 of 16 bytes
            expect(encrypted.encryptionMetadata.authTag).toBeDefined();
            expect(encrypted.contentMetadata.originalType).toBe('text/plain');
            expect(encrypted.contentMetadata.size).toBeGreaterThan(0);
            expect(encrypted.contentMetadata.hash).toHaveLength(64); // SHA256 hash
        });

        it('should encrypt different content with different results', async () => {
            const content1 = 'First piece of evidence';
            const content2 = 'Second piece of evidence';

            const encrypted1 = await service.encryptEvidence(content1, 'text/plain', testSecret);
            const encrypted2 = await service.encryptEvidence(content2, 'text/plain', testSecret);

            expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
            expect(encrypted1.encryptionMetadata.salt).not.toBe(encrypted2.encryptionMetadata.salt);
            expect(encrypted1.encryptionMetadata.iv).not.toBe(encrypted2.encryptionMetadata.iv);
        });

        it('should include timestamp in content metadata', async () => {
            const startTime = Date.now();
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            const endTime = Date.now();

            expect(encrypted.contentMetadata.timestamp).toBeGreaterThanOrEqual(startTime);
            expect(encrypted.contentMetadata.timestamp).toBeLessThanOrEqual(endTime);
        });

        it('should generate consistent hash for same content', async () => {
            const hash1 = createHash('sha256').update(testContent).digest('hex');
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            
            expect(encrypted.contentMetadata.hash).toBe(hash1);
        });
    });

    describe('Binary Content Encryption', () => {
        it('should encrypt buffer content successfully', async () => {
            const binaryContent = Buffer.from('Binary evidence data', 'utf8');
            const encrypted = await service.encryptEvidence(
                binaryContent,
                'application/octet-stream',
                testSecret
            );

            expect(encrypted).toBeDefined();
            expect(encrypted.contentMetadata.originalType).toBe('application/octet-stream');
            expect(encrypted.contentMetadata.size).toBe(binaryContent.length);
        });

        it('should handle large binary files', async () => {
            const largeBuffer = Buffer.alloc(10000, 'A');
            const encrypted = await service.encryptEvidence(
                largeBuffer,
                'application/octet-stream',
                testSecret
            );

            expect(encrypted).toBeDefined();
            expect(encrypted.contentMetadata.size).toBe(10000);
            expect(encrypted.encryptedData.length).toBeGreaterThan(0);
        });
    });

    describe('Encryption and Decryption Round Trip', () => {
        it('authenticates legacy ciphertext without inventing its size, digest or privacy properties', async () => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            const legacy = await service.decryptEvidence({ ...encrypted, contentMetadata: { originalType: 'text/plain' } }, testSecret);
            expect(legacy.isValid).toBe(false);
            expect(legacy.content.toString()).toBe(testContent);
            expect(legacy.metadata).toEqual({ fileType: 'text/plain', fileSize: Buffer.byteLength(testContent) });
        });

        it.each([
            { hash: '0'.repeat(64) }, { hash: '' }, { hash: 'not-a-digest' },
            { size: 0 }, { size: -1 }, { size: 1.5 }, { size: Number.NaN },
        ])('rejects recorded integrity metadata %p instead of returning plaintext', async changed => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            await expect(service.decryptEvidence({ ...encrypted, contentMetadata: { ...encrypted.contentMetadata, ...changed } }, testSecret))
                .rejects.toThrow('Evidence decryption failed');
        });

        it.each([0, 4, 8, 12, 15])('rejects a truncated GCM tag of %i bytes', async length => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            encrypted.encryptionMetadata.authTag = Buffer.from(encrypted.encryptionMetadata.authTag, 'base64').subarray(0, length).toString('base64');
            await expect(service.decryptEvidence(encrypted, testSecret)).rejects.toThrow('Evidence decryption failed');
        });

        it('accepts a recorded zero size only for authenticated empty content', async () => {
            const encrypted = await service.encryptEvidence('', 'text/plain', testSecret);
            const result = await service.decryptEvidence(encrypted, testSecret);
            expect(result.isValid).toBe(true);
            expect(result.content.length).toBe(0);
            expect(result.metadata.fileSize).toBe(0);
        });
        it('should successfully decrypt encrypted text content', async () => {
            const originalContent = testContent;
            const encrypted = await service.encryptEvidence(originalContent, 'text/plain', testSecret);
            const decrypted = await service.decryptEvidence(encrypted, testSecret);

            expect(decrypted.isValid).toBe(true);
            expect(decrypted.content.toString('utf8')).toBe(originalContent);
            expect(decrypted.metadata.fileType).toBe('text/plain');
        });

        it('should successfully decrypt encrypted binary content', async () => {
            const originalContent = Buffer.from('Binary test data', 'utf8');
            const encrypted = await service.encryptEvidence(originalContent, 'application/data', testSecret);
            const decrypted = await service.decryptEvidence(encrypted, testSecret);

            expect(decrypted.isValid).toBe(true);
            expect(decrypted.content).toEqual(originalContent);
        });

        it('should fail decryption with wrong secret', async () => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            
            await expect(
                service.decryptEvidence(encrypted, 'wrong_secret')
            ).rejects.toThrow();
        });

        it('should detect content corruption', async () => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            
            // Corrupt the encrypted data
            const corruptedData = encrypted.encryptedData.slice(0, -10) + 'corrupted';
            const corruptedEvidence = { ...encrypted, encryptedData: corruptedData };

            await expect(
                service.decryptEvidence(corruptedEvidence, testSecret)
            ).rejects.toThrow();
        });

        it('should maintain data integrity across multiple encryptions', async () => {
            const testData = [
                'Short text',
                'This is a much longer piece of evidence text that contains sensitive information',
                'Special characters: äöü ñ 中文 🔒',
                ''  // Empty content
            ];

            for (const data of testData) {
                const encrypted = await service.encryptEvidence(data, 'text/plain', testSecret);
                const decrypted = await service.decryptEvidence(encrypted, testSecret);
                
                expect(decrypted.isValid).toBe(true);
                expect(decrypted.content.toString('utf8')).toBe(data);
            }
        });
    });

    describe('Image Metadata Handling', () => {
        it('rejects truncated JPEG metadata instead of encrypting corrupt evidence', async () => {
            await expect(service.encryptEvidence(Buffer.from('ffd8ffe10030abcd', 'hex'), 'image/jpeg', testSecret))
                .rejects.toThrow(/JPEG file is malformed or unsupported/);
        });

        it('rejects a JPEG with no decodable image data instead of storing it', async () => {
            const emptyJpeg = Buffer.from([0xFF, 0xD8, 0xFF, 0xD9]); // markers only, no pixels
            await expect(service.encryptEvidence(emptyJpeg, 'image/jpeg', testSecret))
                .rejects.toThrow('No original file was accepted');
        });

        it('should handle non-image files correctly', async () => {
            const textFile = 'Regular text content';
            const encrypted = await service.encryptEvidence(
                textFile,
                'text/plain',
                testSecret
            );

            expect(encrypted.privacyMetadata.exifRemoved).toBe(false);
        });
    });

    describe('Document Metadata Handling', () => {
        it('should detect document metadata', async () => {
            const pdfContent = Buffer.from(await pdfFixture());
            const encrypted = await service.encryptEvidence(
                pdfContent,
                'application/pdf',
                testSecret
            );

            expect(encrypted.privacyMetadata.deviceInfoCleaned).toBe(false);
        });

        it('rejects invalid PDF input instead of claiming it was sanitized', async () => {
            await expect(service.encryptEvidence(Buffer.from('not a PDF'), 'application/pdf', testSecret))
                .rejects.toThrow();
        });

        it('preserves text that resembles metadata because it is evidence content', async () => {
            const contentWithDevice = 'Evidence text\nCreated with iPhone\nGenerated by Adobe';
            const encrypted = await service.encryptEvidence(
                contentWithDevice,
                'text/plain',
                testSecret
            );
            
            const decrypted = await service.decryptEvidence(encrypted, testSecret);
            const cleanedContent = decrypted.content.toString('utf8');
            
            expect(cleanedContent).toBe(contentWithDevice);
            expect(encrypted.privacyMetadata.metadataStripped).toBe(false);
        });
    });

    describe('Privacy Metadata Tracking', () => {
        it('should track all privacy protection measures', async () => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);

            expect(encrypted.privacyMetadata).toBeDefined();
            expect(encrypted.privacyMetadata.ipObfuscated).toBe(false);
            expect(encrypted.privacyMetadata).toHaveProperty('metadataStripped');
            expect(encrypted.privacyMetadata).toHaveProperty('exifRemoved');
            expect(encrypted.privacyMetadata).toHaveProperty('deviceInfoCleaned');
        });

        it('should generate encryption summary', () => {
            const mockEncrypted: EncryptedEvidence = {
                encryptedData: 'test_data',
                encryptionMetadata: {
                    algorithm: 'aes-256-gcm',
                    salt: 'salt',
                    iv: 'iv',
                    authTag: 'tag',
                    keyVersion: 'v1.0'
                },
                contentMetadata: {
                    originalType: 'text/plain',
                    size: 100,
                    hash: 'hash',
                    timestamp: Date.now()
                },
                privacyMetadata: {
                    metadataStripped: true,
                    exifRemoved: false,
                    deviceInfoCleaned: true,
                    ipObfuscated: true
                }
            };

            const summary = service.getEncryptionSummary(mockEncrypted);
            
            expect(summary).toContain('aes-256-gcm');
            expect(summary).toContain('100 bytes');
            expect(summary).toContain('EXIF=false');
            expect(summary).toContain('Metadata=true');
        });
    });

    describe('Error Handling', () => {
        it('should handle encryption with empty content', async () => {
            const result = await service.encryptEvidence('', 'text/plain', testSecret);
            expect(result).toBeDefined();
            expect(result.contentMetadata.size).toBe(0);
        });

        it('should handle encryption with empty secret', async () => {
            const result = await service.encryptEvidence(testContent, 'text/plain', '');
            expect(result.encryptedData).toBeDefined();
            const decrypted = await service.decryptEvidence(result, '');
            expect(decrypted.content.toString('utf8')).toBe(testContent);
        });

        it('should handle malformed encrypted evidence', async () => {
            const malformedEvidence = {
                encryptedData: 'invalid_base64',
                encryptionMetadata: {
                    algorithm: 'aes-256-gcm',
                    salt: 'invalid',
                    iv: 'invalid',
                    authTag: 'invalid',
                    keyVersion: 'v1.0'
                }
            } as any;

            await expect(
                service.decryptEvidence(malformedEvidence, testSecret)
            ).rejects.toThrow();
        });

        it('should provide meaningful error messages', async () => {
            try {
                await service.encryptEvidence(testContent, 'text/plain', '');
            } catch (error) {
                expect(error.message).toContain('Encryption failed');
            }
        });
    });

    describe('Security Properties', () => {
        it('should use different salts for each encryption', async () => {
            const encrypted1 = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            const encrypted2 = await service.encryptEvidence(testContent, 'text/plain', testSecret);

            expect(encrypted1.encryptionMetadata.salt).not.toBe(encrypted2.encryptionMetadata.salt);
        });

        it('should use different IVs for each encryption', async () => {
            const encrypted1 = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            const encrypted2 = await service.encryptEvidence(testContent, 'text/plain', testSecret);

            expect(encrypted1.encryptionMetadata.iv).not.toBe(encrypted2.encryptionMetadata.iv);
        });

        it('should produce different ciphertext for same content', async () => {
            const encrypted1 = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            const encrypted2 = await service.encryptEvidence(testContent, 'text/plain', testSecret);

            expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
        });

        it('should use strong key derivation', async () => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            
            // Salt should be sufficiently long (32 bytes = 44 characters in base64)
            expect(encrypted.encryptionMetadata.salt.length).toBe(44);
            
            // Should use AES-256-GCM
            expect(encrypted.encryptionMetadata.algorithm).toBe('aes-256-gcm');
            
            // Should have authentication tag
            expect(encrypted.encryptionMetadata.authTag).toBeDefined();
            expect(encrypted.encryptionMetadata.authTag.length).toBeGreaterThan(0);
        });
    });

    describe('Performance', () => {
        it('should encrypt content within reasonable time', async () => {
            const startTime = Date.now();
            await service.encryptEvidence(testContent, 'text/plain', testSecret);
            const endTime = Date.now();
            
            expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
        });

        it('should decrypt content within reasonable time', async () => {
            const encrypted = await service.encryptEvidence(testContent, 'text/plain', testSecret);
            
            const startTime = Date.now();
            await service.decryptEvidence(encrypted, testSecret);
            const endTime = Date.now();
            
            expect(endTime - startTime).toBeLessThan(2000); // Should complete within 2 seconds
        });

        it('should handle multiple concurrent encryptions', async () => {
            const promises = Array(5).fill(null).map((_, i) =>
                service.encryptEvidence(`Content ${i}`, 'text/plain', testSecret)
            );

            const results = await Promise.all(promises);
            
            expect(results).toHaveLength(5);
            results.forEach(result => {
                expect(result).toBeDefined();
                expect(result.encryptedData).toBeDefined();
            });

            // All should have different encrypted data
            const encryptedData = results.map(r => r.encryptedData);
            const uniqueData = new Set(encryptedData);
            expect(uniqueData.size).toBe(5);
        });
    });
});

describe('owned encryption keys', () => {
    afterEach(() => jest.restoreAllMocks());
    it.each([false, true])('clears the derived evidence key (cipher failure: %s)', async fail => {
        const derive = LocalCryptoClient.prototype.deriveKey;
        const keys: Buffer[] = [];
        jest.spyOn(LocalCryptoClient.prototype, 'deriveKey').mockImplementation(async function (this: LocalCryptoClient, ...args) {
            const key = await derive.apply(this, args); keys.push(key); return key;
        });
        const service = new EvidenceEncryptionService({ algorithm: fail ? 'invalid-synthetic-algorithm' : 'aes-256-gcm' });
        const callerContent = Buffer.from('synthetic evidence');
        const operation = service.encryptEvidence(callerContent, 'text/plain', 'synthetic-secret');
        if (fail) await expect(operation).rejects.toThrow('Encryption failed');
        else expect((await service.decryptEvidence(await operation, 'synthetic-secret')).content.toString()).toBe('synthetic evidence');
        expect(keys.length).toBe(fail ? 1 : 2);
        expect(keys.every(key => key.every(byte => byte === 0))).toBe(true);
        expect(callerContent.toString()).toBe('synthetic evidence');
    });
});
