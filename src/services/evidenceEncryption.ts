import { verifyStrippedImage } from './imageVerification';
import { EvidenceValidationError } from '../utils/evidenceValidationError';
import { stripTiffMetadata } from './tiffMetadata';
import { stripPdfMetadata } from './pdfMetadata';
import { isSupportedMedia, stripMediaMetadata } from './mediaMetadata';
import { logger } from '../utils/logger';
import { createHash, createCipheriv, createDecipheriv, randomBytes, CipherGCM, DecipherGCM } from 'node:crypto';
import ExifReader from 'exifreader';
import { getCryptoClient } from './cryptoClient';

interface EncryptionConfig {
    algorithm: string;
    keyDerivationIterations: number;
    saltLength: number;
    ivLength: number;
}

interface EncryptedEvidence {
    encryptedData: string;        // Base64 encoded encrypted content
    encryptionMetadata: {
        algorithm: string;
        salt: string;             // For key derivation
        iv: string;               // Initialization vector
        authTag: string;          // Authentication tag (for AEAD)
        keyVersion: string;       // Key derivation version
    };
    contentMetadata: {
        originalType: string;     // File type before encryption
        size: number;            // Original file size
        hash: string;            // SHA256 hash of original content
        timestamp: number;       // Encryption timestamp
    };
    privacyMetadata: {
        metadataStripped: boolean;
        exifRemoved: boolean;
        deviceInfoCleaned: boolean;
        ipObfuscated: boolean;
    };
}

type DecryptionInput = Pick<EncryptedEvidence, 'encryptedData' | 'encryptionMetadata'> & {
    contentMetadata: { originalType: string; size?: number; hash?: string; timestamp?: number };
    privacyMetadata?: EncryptedEvidence['privacyMetadata'];
};

interface FileMetadata {
    fileName?: string;
    fileType: string;
    fileSize: number;
    mimeType?: string;
    hasExif: boolean;
    hasGPS: boolean;
    deviceInfo?: any;
}

/**
 * Evidence Encryption Service
 * Handles server-side encryption and supported metadata removal
 */
export class EvidenceEncryptionService {
    private config: EncryptionConfig;
    private cryptoClient = getCryptoClient();

    constructor(config?: Partial<EncryptionConfig>) {
        this.config = {
            algorithm: 'aes-256-gcm',
            keyDerivationIterations: 100000,
            saltLength: 32,
            ivLength: 16,
            ...config
        };

        logger.info('[ENCRYPTION] Service initialized with AES-256-GCM');
    }

    /**
     * Remove supported metadata and encrypt the resulting bytes.
     * Strings are encoded as UTF-8. The returned size and hash describe the
     * sanitized plaintext; ciphertext, salt, IV, and authentication tag are base64 encoded.
     * @param options.stripSelection - Legacy field selections; cannot preserve
     * metadata in supported image, PDF, or audio/video formats.
     * @throws {EvidenceValidationError} If sanitization rejects the file.
     * @throws {Error} Other failures are wrapped with an "Encryption failed" prefix.
     */
    async encryptEvidence(
        content: string | Buffer,
        contentType: string,
        userSecret: string,
        options?: {
            fileName?: string;
            additionalMetadata?: Record<string, any>;
            stripSelection?: Record<string, boolean>;
        }
    ): Promise<EncryptedEvidence> {
        logger.info(`🔐 [ENCRYPTION] Starting encryption process for ${contentType} at ${new Date().toISOString()}`);

        let derivedKey: Buffer | undefined;
        try {
            // Step 1: Analyze and strip metadata (respecting user selection)
            const metadata = await this.analyzeFileMetadata(content, contentType, options?.fileName);
            const stripSelection = options?.stripSelection || {};
            const cleanedContent = await this.stripMetadata(content, contentType, metadata, stripSelection);
            
            // Step 2: Generate encryption parameters
            const salt = this.cryptoClient.randomBytes(this.config.saltLength);
            const iv = this.cryptoClient.randomBytes(this.config.ivLength);
            derivedKey = await this.deriveKey(userSecret, salt);
            
            // Step 3: Encrypt the content
            const cipher = createCipheriv(this.config.algorithm, derivedKey, iv) as CipherGCM;
            const contentBuffer = Buffer.isBuffer(cleanedContent) ? cleanedContent : Buffer.from(cleanedContent, 'utf8');

            let encrypted = cipher.update(contentBuffer);
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            const authTag = cipher.getAuthTag();
            
            // Step 4: Create encrypted evidence object
            const encryptedEvidence: EncryptedEvidence = {
                encryptedData: encrypted.toString('base64'),
                encryptionMetadata: {
                    algorithm: this.config.algorithm,
                    salt: salt.toString('base64'),
                    iv: iv.toString('base64'),
                    authTag: authTag.toString('base64'),
                    keyVersion: 'v1.0'
                },
                contentMetadata: {
                    originalType: contentType,
                    size: contentBuffer.length,
                    hash: this.hashContent(contentBuffer),
                    timestamp: Date.now()
                },
                privacyMetadata: {
                    metadataStripped: !contentBuffer.equals(Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8')),
                    // A rebuilt TIFF still has a TIFF header but no EXIF/GPS directories.
                    exifRemoved: metadata.hasExif && (contentType === 'image/tiff' || !this.hasEXIFData(contentBuffer)),
                    deviceInfoCleaned: contentType !== 'application/pdf' && !!metadata.deviceInfo && !contentBuffer.equals(Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8')),
                    ipObfuscated: false // File encryption does not conceal the network source
                }
            };

            logger.info(`✅ [ENCRYPTION] Content encrypted successfully - Size: ${encrypted.length} bytes`);
            logger.info(`🛡️ [PRIVACY] Metadata stripped - EXIF: ${metadata.hasExif}, GPS: ${metadata.hasGPS}`);
            
            return encryptedEvidence;

        } catch (error) {
            if (error instanceof EvidenceValidationError) throw error;
            logger.error(`❌ [ENCRYPTION] Failed at ${new Date().toISOString()}:`, error);
            throw new Error(`Encryption failed: ${error}`);
        } finally { derivedKey?.fill(0); }
    }

    /** Authenticate ciphertext and enforce any recorded plaintext digest and size. */
    async decryptEvidence(
        encryptedEvidence: DecryptionInput,
        userSecret: string
    ): Promise<{
        content: Buffer;
        metadata: Pick<FileMetadata, 'fileType' | 'fileSize'>;
        // False means no plaintext digest was recorded; GCM authentication is still required.
        isValid: boolean;
    }> {
        let derivedKey: Buffer | undefined;
        let partial: Buffer | undefined;
        let decrypted: Buffer | undefined;
        try {
            const { encryptionMetadata, contentMetadata } = encryptedEvidence;
            if (encryptionMetadata.algorithm !== this.config.algorithm) {
                throw new Error('Evidence algorithm mismatch');
            }
            const authTag = Buffer.from(encryptionMetadata.authTag, 'base64');
            if (authTag.length !== 16) throw new Error('Invalid evidence authentication tag');
            const { hash, size } = contentMetadata;
            if (hash !== undefined && !/^[a-f0-9]{64}$/i.test(hash)) {
                throw new Error('Invalid evidence plaintext digest');
            }
            if (size !== undefined && (!Number.isSafeInteger(size) || size < 0)) {
                throw new Error('Invalid evidence plaintext size');
            }
            derivedKey = await this.deriveKey(userSecret, Buffer.from(encryptionMetadata.salt, 'base64'));
            const decipher = createDecipheriv(
                this.config.algorithm, derivedKey, Buffer.from(encryptionMetadata.iv, 'base64')
            ) as DecipherGCM;
            decipher.setAuthTag(authTag);
            partial = decipher.update(Buffer.from(encryptedEvidence.encryptedData, 'base64'));
            decrypted = Buffer.concat([partial, decipher.final()]);
            if (hash !== undefined && this.hashContent(decrypted) !== hash.toLowerCase()) {
                throw new Error('Evidence plaintext digest mismatch');
            }
            if (size !== undefined && decrypted.length !== size) {
                throw new Error('Evidence plaintext size mismatch');
            }
            return {
                content: decrypted,
                metadata: { fileType: contentMetadata.originalType, fileSize: decrypted.length },
                isValid: hash !== undefined,
            };
        } catch (error) {
            decrypted?.fill(0);
            throw Object.assign(new Error('Evidence decryption failed'), { cause: error });
        } finally {
            partial?.fill(0);
            derivedKey?.fill(0);
        }
    }

    /**
     * Analyze file metadata to determine what needs to be stripped
     */
    private async analyzeFileMetadata(
        content: string | Buffer,
        contentType: string,
        fileName?: string
    ): Promise<FileMetadata> {
        const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
        
        const metadata: FileMetadata = {
            fileName,
            fileType: contentType,
            fileSize: buffer.length,
            hasExif: false,
            hasGPS: false
        };

        // Check for EXIF data in images
        if (contentType.startsWith('image/')) {
            metadata.hasExif = this.hasEXIFData(buffer);
            metadata.hasGPS = this.hasGPSData(buffer);
        }

        // Check for document metadata
        if (contentType.includes('pdf') || contentType.includes('document')) {
            metadata.deviceInfo = this.extractDocumentMetadata(buffer);
        }

        return metadata;
    }

    /**
     * Return sanitized bytes for supported images, PDFs, and audio/video.
     * JPEG, PNG, and WebP output must also pass decoder verification. Plain text,
     * CSV, and other unhandled types pass through; strings are encoded as UTF-8.
     * @param stripSelection - Legacy selections, ignored for supported formats.
     * @throws {EvidenceValidationError} If a sanitizer or verifier rejects the file.
     * @throws {Error} For unsupported document types or propagated sanitizer failures.
     */
    private async stripMetadata(
        content: string | Buffer,
        contentType: string,
        metadata: FileMetadata,
        stripSelection: Record<string, boolean> = {}
    ): Promise<Buffer> {
        let buffer = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
        // Media is always sanitized; field selection cannot preserve identifying tags.
        if (isSupportedMedia(contentType)) return stripMediaMetadata(buffer, contentType);
        if (contentType === 'image/tiff') return stripTiffMetadata(buffer);
        if (contentType === 'application/pdf') return stripPdfMetadata(buffer);

        // The PDR requires metadata removal before encryption. A legacy map
        // must not preserve identifying metadata in accepted image formats.
        if (['image/jpeg', 'image/png', 'image/webp'].includes(contentType)) stripSelection = {};

        // Helper to check if a field should be stripped
        // If stripSelection is empty, default to stripping everything (backwards compatible)
        const hasSelections = Object.keys(stripSelection).length > 0;
        const shouldStrip = (fieldId: string): boolean => {
            if (!hasSelections) return true; // Strip by default if no selection provided
            return stripSelection[fieldId] === true;
        };

        // Strip metadata from images (if selected or by default)
        if (contentType.startsWith('image/')) {
            // Check for any EXIF-related fields being stripped
            const stripExif = shouldStrip('camera_make') || shouldStrip('camera_model') ||
                             shouldStrip('software') || shouldStrip('date_taken') ||
                             shouldStrip('gps_location') || shouldStrip('gps_altitude') ||
                             shouldStrip('artist') || shouldStrip('copyright') ||
                             !hasSelections;
            if (stripExif) {
                buffer = this.stripImageMetadata(buffer, contentType);
                await verifyStrippedImage(buffer, contentType);
                logger.info(`🧹 [PRIVACY] Metadata stripped from ${contentType} image`);
            } else {
                logger.debug(`📌 [PRIVACY] Image metadata preserved per user selection`);
            }
        }

        if (contentType.includes('document')) {
            throw new Error('Unsupported document format');
        }

        // Plain text and CSV have no separate metadata container. Their contents
        // are evidence, including words that resemble a device or software tag.

        return buffer;
    }

    /**
     * Check if image contains EXIF/metadata based on format signatures.
     * Supports JPEG, PNG (eXIf/tEXt/iTXt/zTXt chunks), WebP (EXIF/XMP), TIFF.
     */
    private hasEXIFData(buffer: Buffer): boolean {
        if (buffer.length < 12) return false;

        // JPEG: SOI + APP1/APP0
        const hex = buffer.subarray(0, 12).toString('hex');
        if (hex.startsWith('ffd8ff') && (hex.includes('ffe1') || hex.includes('ffe0'))) {
            return true;
        }

        // PNG: look for metadata chunks
        if (buffer.subarray(0, 8).toString('hex') === '89504e470d0a1a0a') {
            return this.pngHasMetadataChunks(buffer);
        }

        // WebP: RIFF....WEBP with EXIF/XMP/ICCP sub-chunks
        if (buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
            buffer.subarray(8, 12).toString('ascii') === 'WEBP') {
            return this.webpHasMetadataChunks(buffer);
        }

        // TIFF: starts with II (little-endian) or MM (big-endian) + magic 42
        if ((buffer[0] === 0x49 && buffer[1] === 0x49 && buffer.readUInt16LE(2) === 42) ||
            (buffer[0] === 0x4D && buffer[1] === 0x4D && buffer.readUInt16BE(2) === 42)) {
            return true; // TIFF files inherently carry IFD metadata
        }

        return false;
    }

    /**
     * Check if EXIF contains GPS data using ExifReader for reliable multi-format detection.
     */
    private hasGPSData(buffer: Buffer): boolean {
        if (!this.hasEXIFData(buffer)) return false;

        try {
            const tags = ExifReader.load(buffer, { expanded: true });
            if (tags.gps && (tags.gps.Latitude !== undefined || tags.gps.Longitude !== undefined)) {
                return true;
            }
        } catch {
            // ExifReader may fail on minimal/synthetic buffers — fall back to raw search
        }

        // Fallback: raw hex scan for GPS IFD pointer tag 0x8825
        const fullHex = buffer.toString('hex');
        return fullHex.includes('8825');
    }

    /** Check if a PNG buffer contains metadata chunks */
    private pngHasMetadataChunks(buffer: Buffer): boolean {
        const metadataTypes = new Set(['tEXt', 'zTXt', 'iTXt', 'eXIf', 'iCCP', 'tIME']);
        let pos = 8; // skip PNG signature
        while (pos + 8 <= buffer.length) {
            const length = buffer.readUInt32BE(pos);
            const type = buffer.subarray(pos + 4, pos + 8).toString('ascii');
            if (metadataTypes.has(type)) return true;
            pos += 12 + length; // length + type(4) + data(length) + crc(4)
        }
        return false;
    }

    /** Check if a WebP buffer contains EXIF/XMP/ICCP sub-chunks */
    private webpHasMetadataChunks(buffer: Buffer): boolean {
        const metadataFourCC = new Set(['EXIF', 'XMP ', 'ICCP']);
        let pos = 12; // skip RIFF header + "WEBP"
        while (pos + 8 <= buffer.length) {
            const fourcc = buffer.subarray(pos, pos + 4).toString('ascii');
            const chunkSize = buffer.readUInt32LE(pos + 4);
            if (metadataFourCC.has(fourcc)) return true;
            pos += 8 + chunkSize + (chunkSize % 2); // pad to even
        }
        return false;
    }

    /**
     * Route to the correct format-specific stripper based on content type.
     */
    private stripImageMetadata(buffer: Buffer, contentType: string): Buffer {
        if (contentType === 'image/jpeg') return this.stripJPEGMetadata(buffer);
        if (contentType === 'image/png') return this.stripPNGMetadata(buffer);
        if (contentType === 'image/webp') return this.stripWebPMetadata(buffer);
        return buffer;
    }

    /**
     * Remove APP0-APP15 and COM segments, except the fixed-size Adobe APP14
     * color-transform segment. Preserve encoded image data and discard bytes
     * after the first end-of-image marker; this does not decode the image.
     * @throws {EvidenceValidationError} For invalid markers, segment lengths,
     * or a missing end-of-image marker.
     */
    private stripJPEGMetadata(buffer: Buffer): Buffer {
        if (buffer.length < 4 || buffer.subarray(0, 2).toString('hex') !== 'ffd8') {
            throw new EvidenceValidationError('JPEG');
        }

        const chunks: Buffer[] = [buffer.subarray(0, 2)];
        let pos = 2;
        while (pos < buffer.length) {
            const start = pos;
            if (buffer[pos++] !== 0xff) throw new EvidenceValidationError('JPEG');
            while (buffer[pos] === 0xff) pos++;
            const marker = buffer[pos++];
            if (marker === undefined || marker === 0) throw new EvidenceValidationError('JPEG');
            if (marker === 0xd9) { chunks.push(buffer.subarray(start, pos)); return Buffer.concat(chunks); }
            if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
                chunks.push(buffer.subarray(start, pos)); continue;
            }
            if (pos + 2 > buffer.length) throw new EvidenceValidationError('JPEG');
            const length = buffer.readUInt16BE(pos);
            if (length < 2 || pos + length > buffer.length) throw new EvidenceValidationError('JPEG');
            const end = pos + length;
            // APP0..APP15 and COM can contain identifying data. Preserve the
            // quantization, frame and Huffman tables needed to decode evidence,
            // and the fixed-size Adobe APP14 colour-transform flags (no free text).
            const adobeTransform = marker === 0xee && length === 14 &&
                buffer.subarray(pos + 2, pos + 7).toString('latin1') === 'Adobe';
            if ((!(marker >= 0xe0 && marker <= 0xef) && marker !== 0xfe) || adobeTransform) {
                chunks.push(buffer.subarray(start, end));
            }
            pos = end;
            if (marker === 0xda) {
                const scanStart = pos;
                // Skip entropy bytes, stuffed FF00 bytes and restart markers.
                while (pos < buffer.length) {
                    if (buffer[pos] !== 0xff) { pos++; continue; }
                    let next = pos + 1;
                    while (buffer[next] === 0xff) next++;
                    if (buffer[next] === 0 || (buffer[next] >= 0xd0 && buffer[next] <= 0xd7)) {
                        pos = next + 1; continue;
                    }
                    break;
                }
                chunks.push(buffer.subarray(scanStart, pos));
            }
        }
        throw new EvidenceValidationError('JPEG');
    }

    /**
     * Strip metadata chunks from PNG images.
     * Keeps known rendering/animation chunks; rejects unknown critical chunks.
     */
    private stripPNGMetadata(buffer: Buffer): Buffer {
        if (buffer.length < 8 || buffer.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') {
            throw new EvidenceValidationError();
        }

        const retainedTypes = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'acTL', 'fcTL', 'fdAT']);
        const chunks: Buffer[] = [buffer.subarray(0, 8)]; // PNG signature
        let pos = 8;

        while (pos + 8 <= buffer.length) {
            const length = buffer.readUInt32BE(pos);
            const type = buffer.subarray(pos + 4, pos + 8).toString('ascii');
            const chunkTotal = 12 + length; // length(4) + type(4) + data(length) + crc(4)

            if (pos + chunkTotal > buffer.length) throw new EvidenceValidationError();
            if (!retainedTypes.has(type) && /^[A-Z]/.test(type)) throw new EvidenceValidationError();

            if (retainedTypes.has(type)) {
                chunks.push(buffer.subarray(pos, pos + chunkTotal));
            }

            pos += chunkTotal;
            if (type === 'IEND') {
                if (length !== 0) throw new EvidenceValidationError();
                return Buffer.concat(chunks); // Discard all trailing bytes.
            }
        }

        throw new EvidenceValidationError();
    }

    /**
     * Strip metadata sub-chunks from WebP images.
     * Removes EXIF, XMP, ICCP chunks and clears corresponding flags in VP8X.
     * Keeps rendering/animation chunks, removes unknown frame sub-chunks, and
     * discards bytes beyond the declared RIFF container without decoding pixels.
     * @throws {EvidenceValidationError} For invalid container/chunk boundaries,
     * no retained chunks, or an animation frame rejected by stripWebPFrame.
     */
    private stripWebPMetadata(buffer: Buffer): Buffer {
        if (buffer.length < 12 ||
            buffer.subarray(0, 4).toString('ascii') !== 'RIFF' ||
            buffer.subarray(8, 12).toString('ascii') !== 'WEBP') {
            throw new EvidenceValidationError('WebP');
        }

        const end = 8 + buffer.readUInt32LE(4);
        if (end < 12 || end > buffer.length) throw new EvidenceValidationError('WebP');
        const retainedFourCC = new Set(['VP8X', 'VP8 ', 'VP8L', 'ALPH', 'ANIM', 'ANMF']);
        const chunks: Buffer[] = [];
        let pos = 12;

        while (pos + 8 <= end) {
            const fourcc = buffer.subarray(pos, pos + 4).toString('ascii');
            const chunkSize = buffer.readUInt32LE(pos + 4);
            const totalChunkSize = 8 + chunkSize + (chunkSize % 2); // pad to even

            if (pos + totalChunkSize > end) throw new EvidenceValidationError('WebP');
            if (retainedFourCC.has(fourcc)) {
                const chunk = buffer.subarray(pos, pos + totalChunkSize);
                // Clear metadata flags in VP8X chunk
                if (fourcc === 'VP8X' && chunk.length >= 10) {
                    const cleaned = Buffer.from(chunk);
                    // Flags byte is at offset 8: bit 5=ICCP, bit 3=EXIF, bit 2=XMP
                    cleaned[8] &= ~0x2c; // clear ICCP(5), EXIF(3), XMP(2); preserve alpha/animation
                    chunks.push(cleaned);
                } else if (fourcc === 'ANMF') {
                    chunks.push(this.stripWebPFrame(chunk.subarray(8, 8 + chunkSize)));
                } else {
                    chunks.push(chunk);
                }
            }

            pos += totalChunkSize;
        }

        if (pos !== end || chunks.length === 0) throw new EvidenceValidationError('WebP');

        // Reconstruct RIFF container
        const payload = Buffer.concat(chunks);
        const riffHeader = Buffer.alloc(12);
        riffHeader.write('RIFF', 0, 'ascii');
        riffHeader.writeUInt32LE(4 + payload.length, 4); // "WEBP" + payload
        riffHeader.write('WEBP', 8, 'ascii');

        return Buffer.concat([riffHeader, payload]);
    }

    /**
     * Rebuild one ANMF animation frame from its 16-byte frame header and only
     * the image sub-chunks (ALPH, VP8, VP8L); unknown sub-chunks can carry data.
     * @param payload - Frame payload without the ANMF chunk header.
     * @returns The complete rebuilt ANMF chunk, including its size header.
     * @throws {EvidenceValidationError} For truncated headers/sub-chunks or no
     * VP8/VP8L image sub-chunk. Pixel data is not decoded here.
     */
    private stripWebPFrame(payload: Buffer): Buffer {
        if (payload.length < 16 + 8) throw new EvidenceValidationError('WebP');
        const parts: Buffer[] = [payload.subarray(0, 16)];
        let image = false;
        for (let pos = 16; pos < payload.length;) {
            if (pos + 8 > payload.length) throw new EvidenceValidationError('WebP');
            const fourcc = payload.subarray(pos, pos + 4).toString('ascii');
            const size = payload.readUInt32LE(pos + 4);
            const total = 8 + size + (size % 2);
            if (pos + total > payload.length) throw new EvidenceValidationError('WebP');
            if (['ALPH', 'VP8 ', 'VP8L'].includes(fourcc)) {
                parts.push(payload.subarray(pos, pos + total));
                image ||= fourcc !== 'ALPH';
            }
            pos += total;
        }
        if (!image) throw new EvidenceValidationError('WebP');
        const body = Buffer.concat(parts);
        const header = Buffer.alloc(8);
        header.write('ANMF', 0, 'ascii');
        header.writeUInt32LE(body.length, 4);
        return Buffer.concat([header, body]);
    }

    /**
     * Extract document metadata for analysis.
     */
    private extractDocumentMetadata(buffer: Buffer): any {
        // Simplified metadata detection
        const text = buffer.toString('ascii').toLowerCase();
        return {
            hasCreator: text.includes('creator') || text.includes('producer'),
            hasModificationDate: text.includes('moddate') || text.includes('creationdate'),
            hasApplicationInfo: text.includes('application') || text.includes('generator')
        };
    }


    /**
     * Derive encryption key from user secret
     */
    private async deriveKey(userSecret: string, salt: Buffer): Promise<Buffer> {
        return this.cryptoClient.deriveKey(userSecret, salt, {
            algorithm: 'pbkdf2',
            iterations: this.config.keyDerivationIterations,
            keyLength: 32,
        });
    }

    /**
     * Hash content for integrity verification
     */
    private hashContent(content: Buffer): string {
        return this.cryptoClient.hash(content);
    }

    /**
     * Generate encryption summary for logging
     */
    /**
     * Strip metadata from a file buffer without encrypting.
     * Used to produce a clean buffer for caching/serving alongside the encrypted version.
     */
    async stripFileMetadata(
        content: Buffer,
        contentType: string,
        stripSelection: Record<string, boolean> = {}
    ): Promise<Buffer> {
        const metadata = await this.analyzeFileMetadata(content, contentType);
        return this.stripMetadata(content, contentType, metadata, stripSelection);
    }

    getEncryptionSummary(encryptedEvidence: EncryptedEvidence): string {
        return `Algorithm: ${encryptedEvidence.encryptionMetadata.algorithm}, ` +
               `Size: ${encryptedEvidence.contentMetadata.size} bytes, ` +
               `Privacy: EXIF=${encryptedEvidence.privacyMetadata.exifRemoved}, ` +
               `Metadata=${encryptedEvidence.privacyMetadata.metadataStripped}`;
    }
}

// Singleton instance
export const evidenceEncryptionService = new EvidenceEncryptionService();

// Export types for other modules
export type {
    EncryptedEvidence,
    FileMetadata,
    EncryptionConfig
};

export default EvidenceEncryptionService;
