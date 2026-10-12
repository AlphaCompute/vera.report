import crypto from 'node:crypto';
import { EvidenceStorageError } from './evidenceStorageError';
import { EvidenceValidationError } from '../utils/evidenceValidationError';
import { evidenceEncryptionService } from './evidenceEncryption';
import { evidenceStorageService } from './evidenceStorage';
import { reportPersistenceService, type EvidenceDecryptionParams } from './reportPersistence';

/**
 * Sanitize and encrypt all files before uploading any, then upload each file
 * and pass its decryption parameters to writeParams. The intake route must
 * await this before publishing a report or receipt.
 * @param writeParams - Called after each upload; defaults to persistent storage.
 * Callers that stage parameters must persist them before publishing the report.
 * @returns File keys and storage CIDs in input order, or an empty array for no files.
 * @throws {EvidenceValidationError} If any file is rejected, before any upload.
 * @throws {EvidenceStorageError} For encryption, upload, or parameter-write failures.
 * Completed uploads and parameter writes are not rolled back on later failures.
 */
export async function persistSubmissionEvidence(
  trackingId: string,
  files: Express.Multer.File[],
  stripSelection: Record<string, boolean> = {},
  writeParams: (fileKey: string, params: EvidenceDecryptionParams) => Promise<void> =
    (fileKey, params) => reportPersistenceService.saveEvidenceParams(fileKey, params),
): Promise<Array<{ fileKey: string; ipfsHash: string }>> {
  // Sanitize and encrypt every file before uploading any, so a file rejected
  // late cannot leave earlier evidence orphaned at the storage provider. The
  // report-wide evidence cap bounds what is held here.
  const prepared = [];
  for (const [index, file] of files.entries()) {
    // An index distinguishes even byte-identical files with identical names.
    // Filenames can identify a source. Keep only a format-derived extension.
    const extensions: Record<string, string> = {
      'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
      'image/tiff': 'tiff', 'application/pdf': 'pdf', 'text/plain': 'txt', 'text/csv': 'csv',
      'audio/mpeg': 'mp3', 'audio/wav': 'wav', 'audio/x-wav': 'wav',
      'audio/mp4': 'm4a', 'audio/x-m4a': 'm4a', 'audio/aac': 'aac',
      'audio/ogg': 'ogg', 'audio/opus': 'opus', 'audio/flac': 'flac', 'audio/x-flac': 'flac',
      'audio/webm': 'webm', 'video/webm': 'webm', 'video/x-matroska': 'mkv',
      'video/x-msvideo': 'avi', 'video/ogg': 'ogv',
      'video/mp4': 'mp4', 'video/quicktime': 'mov',
    };
    const name = `evidence-${index + 1}.${extensions[file.mimetype] || 'bin'}`;
    const fileKey = `${trackingId}/${name}`;
    const encryptionKey = crypto.randomBytes(32).toString('hex');
    const encrypted = await evidenceEncryptionService.encryptEvidence(
      file.buffer, file.mimetype, encryptionKey,
      { stripSelection },
    ).catch(error => {
      if (error instanceof EvidenceValidationError) throw error;
      throw new EvidenceStorageError('evidence_encryption_unavailable', error);
    });
    prepared.push({ file, name, fileKey, encryptionKey, encrypted });
  }

  const manifest: Array<{ fileKey: string; ipfsHash: string }> = [];
  for (const { file, name, fileKey, encryptionKey, encrypted } of prepared) {
    // Neither provider failure nor a failed key write may fall back to RAM.
    const uploaded = await evidenceStorageService.uploadEncryptedFile(
      Buffer.from(encrypted.encryptedData, 'base64'), name, trackingId, encryptionKey,
    ).catch(error => {
      if (error instanceof EvidenceStorageError) throw error;
      throw new EvidenceStorageError('evidence_upload_unavailable', error);
    });
    if (!uploaded.originalCID) throw new EvidenceStorageError('evidence_upload_unavailable');
    await writeParams(fileKey, {
      encryptionKey,
      originalCID: uploaded.originalCID,
      pinataIv: uploaded.iv,
      pinataAuthTag: uploaded.authTag,
      pinataSalt: uploaded.salt,
      evidenceSalt: encrypted.encryptionMetadata.salt,
      evidenceIv: encrypted.encryptionMetadata.iv,
      evidenceAuthTag: encrypted.encryptionMetadata.authTag,
      contentHash: encrypted.contentMetadata.hash,
      contentSize: encrypted.contentMetadata.size,
      mimetype: file.mimetype,
    }).catch(error => { throw new EvidenceStorageError('evidence_key_write_unavailable', error); });
    manifest.push({ fileKey, ipfsHash: uploaded.originalCID });
  }
  return manifest;
}
