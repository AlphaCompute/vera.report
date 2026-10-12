import { EvidenceStorageError } from './evidenceStorageError';
import { MAX_STORED_EVIDENCE_BYTES } from '../utils/evidenceLimits';
import { requireLocalIpfs, storeLocalCiphertext, readLocalCiphertext, unpinLocalCiphertext } from './localIpfs';
import { logger } from '../utils/logger';
import { encryptForStorage, decryptStoredCiphertext } from './evidenceStorageCipher';

// Evidence ciphertext storage on the self-hosted Kubo node (localIpfs.ts), with
// the storage-layer encryption from evidenceStorageCipher.ts. There is no
// third-party fallback: any other IPFS_STORAGE_BACKEND fails closed.

export interface EncryptedDocument {
    encryptedData: Buffer;
    originalCID: string;
    iv: string;
    authTag: string;
    salt: string;
}

export class EvidenceStorageService {
    /**
     * Encrypts and stores a file. The filename and vault id never leave the
     * process: the stored object is the ciphertext alone.
     */
    async uploadEncryptedFile(
        file: Buffer,
        _filename: string,
        _vaultId: string,
        encryptionKey: string,
    ): Promise<EncryptedDocument> {
        try {
            requireLocalIpfs();
            if (file.length > MAX_STORED_EVIDENCE_BYTES) throw new Error('Encrypted evidence exceeds storage limit');
            const { encrypted, iv, authTag, salt } = await encryptForStorage(file, encryptionKey);
            const cid = await storeLocalCiphertext(encrypted);
            return { encryptedData: encrypted, originalCID: cid, iv, authTag, salt };
        } catch (error) {
            // "Failed to upload encrypted file to IPFS" is an IpfsStorageErrors alarm term.
            logger.error('Failed to upload encrypted file to IPFS:', error instanceof Error ? error.message : 'Unknown error');
            throw new EvidenceStorageError('evidence_upload_unavailable', new Error('Failed to upload encrypted file to IPFS'));
        }
    }

    /** Reads stored ciphertext. A local failure never falls back to another backend. */
    async readCiphertext(cid: string): Promise<Buffer> {
        if (!/^[A-Za-z0-9]{20,120}$/.test(cid)) throw new Error('Invalid ciphertext CID');
        requireLocalIpfs();
        return readLocalCiphertext(cid);
    }

    /** Reads and decrypts one stored object. salt is omitted only for legacy records. */
    async retrieveVaultCiphertext(cid: string, key: string, iv: string, tag: string, salt?: string): Promise<Buffer> {
        return decryptStoredCiphertext(await this.readCiphertext(cid), key, iv, tag, salt);
    }

    async unpin(cid: string): Promise<void> {
        try {
            requireLocalIpfs();
            await unpinLocalCiphertext(cid);
        } catch (error) {
            logger.error('Error unpinning local ciphertext:', error instanceof Error ? error.message : 'Unknown error');
            throw new Error('Failed to unpin from IPFS');
        }
    }
}

export const evidenceStorageService = new EvidenceStorageService();
