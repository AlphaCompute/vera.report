import crypto from 'node:crypto';
import { zipSync } from 'fflate';
import { MAX_STORED_EVIDENCE_BYTES } from '../../utils/evidenceLimits';
import { reportPersistenceService } from '../reportPersistence';
import { readEvidenceCiphertext, decryptEvidenceOrLog } from '../evidenceRead';
import { evidenceEncryptionService } from '../evidenceEncryption';
import { decryptStoredCiphertext } from '../evidenceStorageCipher';

// Match the supported stored-evidence limit; never silently omit an attachment.
export const MAX_PACKET_EVIDENCE_BYTES = MAX_STORED_EVIDENCE_BYTES;
export type PacketEvidenceFile = { name: string; mimetype: string; content: Buffer };
type EvidenceRow = Awaited<ReturnType<typeof reportPersistenceService.listEvidenceByTrackingIds>>[number];
function ordered(rows: EvidenceRow[]) { return [...rows].sort((a, b) => a.fileKey.localeCompare(b.fileKey)); }
export function evidenceSnapshot(rows: EvidenceRow[]): string {
  return crypto.createHash('sha256').update(JSON.stringify(ordered(rows).map(r =>
    [r.fileKey, r.originalCID, r.contentHash ?? null, r.contentSize ?? null, r.mimetype]))).digest('hex');
}
function checkSize(rows: EvidenceRow[]) {
  if (rows.length > 30 || rows.some(r => r.contentSize !== undefined && (!Number.isSafeInteger(r.contentSize) || r.contentSize < 0)) ||
      rows.reduce((n, r) => n + (r.contentSize ?? 0), 0) > MAX_PACKET_EVIDENCE_BYTES) {
    throw new Error('packet_evidence_size_unsupported');
  }
}
export async function snapshotPacketEvidence(trackingId: string, expectedFiles?: readonly { cid?: string }[]): Promise<string> {
  const rows = await reportPersistenceService.listEvidenceByTrackingIds([trackingId]);
  if (rows.some(row => !row.fileKey.startsWith(`${trackingId}/`))) throw new Error('packet_evidence_changed');
  checkSize(rows);
  if (expectedFiles && (expectedFiles.length !== rows.length || expectedFiles.some((file, i) => file.cid !== ordered(rows)[i].originalCID))) throw new Error('packet_evidence_changed');
  return evidenceSnapshot(rows);
}
export async function loadPacketEvidence(trackingId: string, digest: string): Promise<PacketEvidenceFile[]> {
  const rows = ordered(await reportPersistenceService.listEvidenceByTrackingIds([trackingId]));
  if (rows.some(row => !row.fileKey.startsWith(`${trackingId}/`))) throw new Error('packet_evidence_changed');
  checkSize(rows);
  if (evidenceSnapshot(rows) !== digest) throw new Error('packet_evidence_changed');
  const result: PacketEvidenceFile[] = [];
  let bytes = 0;
  for (const [i, row] of rows.entries()) {
    const params = await reportPersistenceService.getEvidenceParams(row.fileKey);
    if (!params || evidenceSnapshot([{ ...params, fileKey: row.fileKey }]) !== evidenceSnapshot([row])) {
      throw new Error('packet_evidence_changed');
    }
    const ciphertext = await readEvidenceCiphertext(params.originalCID);
    const file = await decryptEvidenceOrLog(async () => {
      const inner = await decryptStoredCiphertext(ciphertext, params.encryptionKey, params.pinataIv, params.pinataAuthTag, params.pinataSalt);
      const plain = await evidenceEncryptionService.decryptEvidence({
        encryptedData: inner.toString('base64'),
        encryptionMetadata: { algorithm: 'aes-256-gcm', salt: params.evidenceSalt, iv: params.evidenceIv, authTag: params.evidenceAuthTag, keyVersion: 'v1.0' },
        contentMetadata: { originalType: params.mimetype, size: params.contentSize, hash: params.contentHash },
      }, params.encryptionKey);
      if (params.contentHash !== undefined && !plain.isValid) throw new Error('packet_evidence_integrity_failed');
      return plain;
    });
    bytes += file.content.length;
    if (bytes > MAX_PACKET_EVIDENCE_BYTES || (params.contentSize !== undefined && file.content.length !== params.contentSize)) throw new Error('packet_evidence_size_unsupported');
    const ext = row.fileKey.match(/\.[A-Za-z0-9]{1,8}$/)?.[0].toLowerCase() ?? '';
    result.push({ name: `evidence-${i + 1}${ext}`, mimetype: params.mimetype, content: file.content });
  }
  return result;
}

/** All exports use the same archive; files stay directly openable after extraction. */
export function renderPacketArchive(pdf: Buffer, files: PacketEvidenceFile[]): Buffer {
  const entries: Record<string, Uint8Array> = {
    'report.pdf': pdf,
    'README.txt': Buffer.from('Open report.pdf for the report. All attached evidence is in the evidence folder.\n' +
      (files.length ? 'Keep the entire folder when sharing or archiving this report.\n' : 'This report has no attached evidence.\n') +
      'Files may contain identifying information. Downloaded copies cannot be recalled.\n'),
  };
  for (const file of files) {
    if (!/^evidence-[1-9][0-9]*(\.[a-z0-9]{1,8})?$/.test(file.name) || entries[`evidence/${file.name}`]) {
      throw new Error('packet_evidence_invalid_filename');
    }
    entries[`evidence/${file.name}`] = file.content;
  }
  // Store without compression: predictable CPU cost for large, already compressed media.
  const archive = zipSync(entries, { level: 0 });
  return Buffer.from(archive.buffer, archive.byteOffset, archive.byteLength);
}

export async function exportPacketArchive(trackingId: string, pdf: Buffer, digest?: string, expectedFiles?: readonly { cid?: string }[]): Promise<Buffer> {
  const snapshot = await snapshotPacketEvidence(trackingId, expectedFiles);
  if (digest && snapshot !== digest) throw new Error('packet_evidence_changed');
  const files = await loadPacketEvidence(trackingId, snapshot);
  const archive = renderPacketArchive(pdf, files);
  if (await snapshotPacketEvidence(trackingId) !== snapshot) throw new Error('packet_evidence_changed');
  return archive;
}
