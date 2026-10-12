import crypto from 'node:crypto';
import { promisify } from 'node:util';

/**
 * Storage-layer AES-256-GCM for evidence ciphertext written to the self-hosted
 * Kubo node (evidenceStorage.ts). Persisted records carry these parameters as
 * pinataIv / pinataAuthTag / pinataSalt (historical field names, unchanged so
 * existing records keep decrypting). The storage key is derived with
 * scrypt using Node's defaults (N=16384, r=8, p=1) and a 32-byte output. The
 * derivation runs on the libuv thread pool: the synchronous variant blocks the
 * event loop for tens of milliseconds per call (#1114).
 */
const scrypt = promisify(crypto.scrypt) as (password: crypto.BinaryLike, salt: crypto.BinaryLike, keylen: number) => Promise<Buffer>;
const STORAGE_KEY_LENGTH = 32;
/** Read-only compatibility for old ciphertext without a salt; changing this loses access to that data. New writes use random salts. */
export const LEGACY_STORAGE_SALT = 'midnight-salt';

/** salt is the stored base64 per-record salt; absent or empty only on legacy records. */
export function deriveStorageKey(secret: string, salt?: string): Promise<Buffer> {
    return scrypt(secret, salt ? Buffer.from(salt, 'base64') : LEGACY_STORAGE_SALT, STORAGE_KEY_LENGTH);
}

export interface StorageEncryption {
    encrypted: Buffer;
    iv: string;
    authTag: string;
    salt: string;
}

/** AES-256-GCM with a random per-record salt and IV (all base64). */
export async function encryptForStorage(data: Buffer, secret: string): Promise<StorageEncryption> {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const key = await scrypt(secret, salt, STORAGE_KEY_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return {
        encrypted,
        iv: iv.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64'),
        salt: salt.toString('base64'),
    };
}

/** Reverses encryptForStorage. Only full 16-byte GCM tags are accepted. */
export async function decryptStoredCiphertext(ciphertext: Buffer, secret: string, iv: string, authTag: string, salt?: string): Promise<Buffer> {
    const key = await deriveStorageKey(secret, salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'), { authTagLength: 16 });
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
