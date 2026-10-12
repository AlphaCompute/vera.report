import { logger } from '../utils/logger';
import { evidenceStorageService } from './evidenceStorage';

/** Fixed categories for the storage alarms. Storage errors can quote CIDs, gateway
 * URLs or archive keys, so the log line never carries the error itself. */
export type EvidenceReadFailure = 'storage' | 'decrypt' | 'not-found';
export function logEvidenceReadFailure(kind: EvidenceReadFailure): void {
  logger.error(`Evidence read failed: ${kind}`);
}
// The recorded ciphertext is gone: S3 archive NoSuchKey or an HTTP 404.
// Unverified: while s3:ListBucket is conditioned on s3:prefix, S3 may answer a
// missing key with 403 AccessDenied rather than NoSuchKey, so a genuine miss
// can log as 'storage'. AccessDenied stays 'storage' on purpose: it is also
// what a revoked or broken task role returns.
function missing(error: any): boolean {
  return error?.name === 'NoSuchKey' || error?.$metadata?.httpStatusCode === 404 || error?.response?.status === 404;
}
export async function readEvidenceCiphertext(cid: string): Promise<Buffer> {
  try { return await evidenceStorageService.readCiphertext(cid); } catch (error) {
    logEvidenceReadFailure(missing(error) ? 'not-found' : 'storage');
    throw error;
  }
}
/** Both GCM layers and the plaintext integrity check: a wrong key, tag or digest. */
export async function decryptEvidenceOrLog<T>(decrypt: () => T | Promise<T>): Promise<T> {
  try { return await decrypt(); } catch (error) {
    logEvidenceReadFailure('decrypt');
    throw error;
  }
}
