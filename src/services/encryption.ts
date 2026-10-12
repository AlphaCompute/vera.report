import crypto from 'node:crypto';

export class EncryptionService {
    /**
     * Encrypt data using AES-256-GCM with a random per-record salt.
     * Returns { encrypted, salt, iv, authTag } — all must be stored to decrypt.
     */
    encrypt(data: string, key: string): { encrypted: string; salt: string; iv: string; authTag: string } {
        const salt = crypto.randomBytes(16);
        const keyBuffer = crypto.scryptSync(key, salt, 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return {
            encrypted,
            salt: salt.toString('hex'),
            iv: iv.toString('hex'),
            authTag: cipher.getAuthTag().toString('hex'),
        };
    }

    /**
     * Decrypt data using AES-256-GCM.
     * Pass salt=undefined for legacy records encrypted without a random salt.
     */
    decrypt(encryptedData: string, key: string, iv: string, authTag: string, salt?: string): string {
        // The fixed salt only reads old ciphertext; new encryptions always carry a random salt.
        const scryptSalt = salt ? Buffer.from(salt, 'hex') : 'midnight-salt';
        const keyBuffer = crypto.scryptSync(key, scryptSalt, 32);
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            keyBuffer,
            Buffer.from(iv, 'hex'),
            { authTagLength: 16 },
        );

        decipher.setAuthTag(Buffer.from(authTag, 'hex'));

        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}

export const encryptionService = new EncryptionService();

/**
 * Encrypt and return a self-contained string.
 * New format (4 parts): salt:iv:authTag:ciphertext
 * Legacy format (3 parts): iv:authTag:ciphertext  ← still supported on decrypt
 */
export function encryptData(data: string, key: string): string {
    const result = encryptionService.encrypt(data, key);
    return `${result.salt}:${result.iv}:${result.authTag}:${result.encrypted}`;
}

export function decryptData(encryptedString: string, key: string): string {
    const parts = encryptedString.split(':');

    if (parts.length === 4) {
        // New format: salt:iv:authTag:ciphertext
        return encryptionService.decrypt(parts[3], key, parts[1], parts[2], parts[0]);
    }

    if (parts.length === 3) {
        // Legacy format: iv:authTag:ciphertext (static 'midnight-salt')
        return encryptionService.decrypt(parts[2], key, parts[0], parts[1]);
    }

    throw new Error('Invalid encrypted data format — expected salt:iv:authTag:ciphertext or iv:authTag:ciphertext');
}