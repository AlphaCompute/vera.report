import { attestedNarrativeConfiguration } from './attestedNarrative';
import crypto from 'node:crypto';
import type { ReportRecord } from './reportPersistence';
import { keyEnvelope } from './keyEnvelope';
import { evidenceEncryptionService } from './evidenceEncryption';
import { decryptContactValue } from './reportFieldCrypto';

/** Shared intake/migration writer. Recipient writes use an explicit versioned
 * binary-DEK envelope; otherwise the historical PBKDF2 envelope is retained.
 * Both formats are read through decryptReportNarrative without cross-format fallback.
 */
export async function encryptReportNarrative(
  trackingId: string,
  plaintext: string,
  signal?: AbortSignal,
): Promise<NonNullable<ReportRecord['encryptedNarrative']>> {
  const attested = attestedNarrativeConfiguration();
  if (attested.writes) return attested.reader!.encrypt(trackingId, plaintext, signal);
  signal?.throwIfAborted();
  const dataKey = crypto.randomBytes(32).toString('hex');
  const encrypted = await evidenceEncryptionService.encryptEvidence(
    plaintext,
    'text/plain',
    dataKey,
    { fileName: 'report.txt' },
  );
  const wrappedKey = await keyEnvelope.wrap(dataKey, { trackingId, purpose: 'narrative' });
  return {
    encryptedData: encrypted.encryptedData,
    encryptionKey: wrappedKey,
    salt: encrypted.encryptionMetadata.salt,
    iv: encrypted.encryptionMetadata.iv,
    authTag: encrypted.encryptionMetadata.authTag,
  };
}

/** Prefer migrated ciphertext; never fall back to stale text after a KMS error. */
export async function decryptReportNarrative(record: ReportRecord, signal?: AbortSignal): Promise<string | undefined> {
  if (!record.encryptedNarrative) return record.encryptedDescription
    ? decryptContactValue(record.encryptedDescription) : undefined;
  if (record.encryptedNarrative.format !== undefined) {
    const reader = attestedNarrativeConfiguration().reader;
    if (!reader || record.encryptedNarrative.format !== 'recipient-narrative:v1') throw new Error('Narrative unavailable');
    return reader.decrypt(record.trackingId, record.encryptedNarrative, signal);
  }
  signal?.throwIfAborted();
  const { encryptedData, encryptionKey, salt, iv, authTag } = record.encryptedNarrative;
  const key = await keyEnvelope.unwrap(encryptionKey, { trackingId: record.trackingId, purpose: 'narrative' });
  const result = await evidenceEncryptionService.decryptEvidence({
    encryptedData,
    encryptionMetadata: { algorithm: 'aes-256-gcm', salt, iv, authTag, keyVersion: 'v1.0' },
    contentMetadata: { originalType: 'text/plain' },
    privacyMetadata: { metadataStripped: false, exifRemoved: false, deviceInfoCleaned: false, ipObfuscated: false },
  }, key);
  return result.content.toString('utf8');
}
