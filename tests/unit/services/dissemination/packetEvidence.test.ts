import crypto from 'node:crypto';
import { unzipSync } from 'fflate';
import { evidenceSnapshot, loadPacketEvidence, snapshotPacketEvidence, renderPacketArchive, exportPacketArchive } from '../../../../src/services/dissemination/packetEvidence';
import { reportPersistenceService as store } from '../../../../src/services/reportPersistence';
import { evidenceStorageService } from '../../../../src/services/evidenceStorage';
import { evidenceEncryptionService } from '../../../../src/services/evidenceEncryption';
import { logger } from '../../../../src/utils/logger';
jest.mock('../../../../src/services/reportPersistence', () => ({ reportPersistenceService: { listEvidenceByTrackingIds: jest.fn(), getEvidenceParams: jest.fn() } }));
jest.mock('../../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { readCiphertext: jest.fn() } }));
jest.mock('../../../../src/services/evidenceEncryption', () => ({ evidenceEncryptionService: { decryptEvidence: jest.fn() } }));
const content = Buffer.from('synthetic evidence');
let row: any;
beforeEach(() => {
  jest.resetAllMocks();
  const iv = Buffer.alloc(12, 1), salt = Buffer.alloc(16, 2);
  const cipher = crypto.createCipheriv('aes-256-gcm', crypto.scryptSync('fixture-key', salt, 32), iv);
  const encrypted = Buffer.concat([cipher.update('inner encrypted payload'), cipher.final()]);
  row = { fileKey: 'VRA-TEST/private-person.csv', originalCID: 'fixture-cid', encryptionKey: 'fixture-key', pinataIv: iv.toString('base64'), pinataSalt: salt.toString('base64'), pinataAuthTag: cipher.getAuthTag().toString('base64'), evidenceSalt: '', evidenceIv: '', evidenceAuthTag: '', contentHash: 'digest', contentSize: content.length, mimetype: 'text/csv' };
  jest.mocked(store.listEvidenceByTrackingIds).mockResolvedValue([row]);
  jest.mocked(store.getEvidenceParams).mockResolvedValue(row);
  jest.mocked(evidenceStorageService.readCiphertext).mockResolvedValue(encrypted);
  jest.mocked(evidenceEncryptionService.decryptEvidence).mockResolvedValue({ content, isValid: true } as any);
});
it('decrypts included evidence without exposing the original filename or keys', async () => {
  const files = await loadPacketEvidence('VRA-TEST', await snapshotPacketEvidence('VRA-TEST'));
  expect(files).toEqual([{name:'evidence-1.csv', mimetype:'text/csv', content}]);
  expect(JSON.stringify(files)).not.toContain('fixture-key');
});
it('rejects changed evidence before reading bytes', async () => {
  const digest = evidenceSnapshot([row]); row.originalCID = 'replacement';
  await expect(loadPacketEvidence('VRA-TEST', digest)).rejects.toThrow('packet_evidence_changed');
  expect(evidenceStorageService.readCiphertext).not.toHaveBeenCalled();
});
it('fails closed on invalid plaintext integrity', async () => {
  jest.mocked(evidenceEncryptionService.decryptEvidence).mockResolvedValue({content, isValid:false} as any);
  await expect(loadPacketEvidence('VRA-TEST', evidenceSnapshot([row]))).rejects.toThrow('integrity');
});
it.each([-1, 265 * 1024 * 1024])('rejects unsupported size %s before reading bytes', async size => {
  row.contentSize = size;
  await expect(snapshotPacketEvidence('VRA-TEST')).rejects.toThrow('size_unsupported');
  expect(evidenceStorageService.readCiphertext).not.toHaveBeenCalled();
});

it('exports real PNG, PDF and CSV bytes alongside the report', () => {
  const files = [
    { name: 'evidence-1.png', mimetype: 'image/png', content: Buffer.from([137,80,78,71,13,10,26,10]) },
    { name: 'evidence-2.pdf', mimetype: 'application/pdf', content: Buffer.from('%PDF-attachment') },
    { name: 'evidence-3.csv', mimetype: 'text/csv', content: Buffer.from('column\nvalue') },
  ];
  const entries = unzipSync(renderPacketArchive(Buffer.from('%PDF-report'), files));
  expect(Buffer.from(entries['report.pdf']).toString()).toBe('%PDF-report');
  for (const file of files) expect(Buffer.from(entries[`evidence/${file.name}`])).toEqual(file.content);
  expect(Object.keys(entries)).toHaveLength(5);
});
it('supports evidence above the old 20 MiB viewer limit', async () => {
  row.contentSize = 21 * 1024 * 1024;
  await expect(snapshotPacketEvidence('VRA-TEST')).resolves.toMatch(/^[a-f0-9]{64}$/);
});
it('rejects evidence belonging to another report', async () => {
  row.fileKey = 'VRA-OTHER/private.csv';
  await expect(snapshotPacketEvidence('VRA-TEST')).rejects.toThrow('packet_evidence_changed');
});
it('rejects unsafe archive paths and duplicate names', () => {
  const file = { name: '../private.csv', mimetype: 'text/csv', content };
  expect(() => renderPacketArchive(Buffer.from('pdf'), [file])).toThrow('invalid_filename');
  file.name = 'evidence-1.csv';
  expect(() => renderPacketArchive(Buffer.from('pdf'), [file,file])).toThrow('invalid_filename');
});
it('explicitly identifies reports without attachments', () => {
  const entries = unzipSync(renderPacketArchive(Buffer.from('pdf'), []));
  expect(Object.keys(entries)).toEqual(['report.pdf', 'README.txt']);
  expect(Buffer.from(entries['README.txt']).toString()).toContain('no attached evidence');
});

it('exports decrypted evidence end to end and verifies exact archived bytes', async () => {
  const archive = await exportPacketArchive('VRA-TEST', Buffer.from('%PDF-report'));
  const entries = unzipSync(archive);
  expect(Buffer.from(entries['evidence/evidence-1.csv'])).toEqual(content);
  expect(Buffer.from(entries['report.pdf']).toString()).toBe('%PDF-report');
});
it('refuses the entire export if a storage file cannot be retrieved', async () => {
  jest.mocked(evidenceStorageService.readCiphertext).mockRejectedValue(new Error('storage unavailable'));
  await expect(exportPacketArchive('VRA-TEST', Buffer.from('pdf'))).rejects.toThrow('storage unavailable');
});
it.each([
  ['storage', new Error('Local IPFS request failed')],
  ['not-found', Object.assign(new Error('The specified key does not exist. ciphertext/v1/fixture-cid'), { name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } })],
  ['not-found', Object.assign(new Error('Request failed with status code 404'), { response: { status: 404 } })],
])('logs a %s read failure without identifiers', async (kind, error) => {
  const log = jest.spyOn(logger, 'error').mockImplementation(() => undefined);
  jest.mocked(evidenceStorageService.readCiphertext).mockRejectedValue(error);
  await expect(loadPacketEvidence('VRA-TEST', evidenceSnapshot([row]))).rejects.toBe(error);
  expect(log.mock.calls).toEqual([[`Evidence read failed: ${kind}`]]);
});
it.each(['wrong tag', 'integrity'])('logs a decrypt failure (%s) without identifiers', async mode => {
  const log = jest.spyOn(logger, 'error').mockImplementation(() => undefined);
  if (mode === 'wrong tag') row.pinataAuthTag = Buffer.alloc(16).toString('base64');
  else jest.mocked(evidenceEncryptionService.decryptEvidence).mockResolvedValue({ content, isValid: false } as any);
  await expect(loadPacketEvidence('VRA-TEST', evidenceSnapshot([row]))).rejects.toThrow();
  expect(log.mock.calls).toEqual([['Evidence read failed: decrypt']]);
});
it('logs nothing when evidence reads and decrypts', async () => {
  const log = jest.spyOn(logger, 'error').mockImplementation(() => undefined);
  await loadPacketEvidence('VRA-TEST', evidenceSnapshot([row]));
  expect(log).not.toHaveBeenCalled();
});
it('refuses a package if attachments change while it is being built', async () => {
  jest.mocked(store.listEvidenceByTrackingIds).mockResolvedValueOnce([row]).mockResolvedValueOnce([row]).mockResolvedValueOnce([]);
  await expect(exportPacketArchive('VRA-TEST', Buffer.from('pdf'))).rejects.toThrow('packet_evidence_changed');
});

it('refuses a manifest that no longer matches the stored attachment set', async () => {
  await expect(exportPacketArchive('VRA-TEST', Buffer.from('pdf'), undefined, [{cid:'missing-file'}])).rejects.toThrow('packet_evidence_changed');
  await expect(exportPacketArchive('VRA-TEST', Buffer.from('pdf'), undefined, [])).rejects.toThrow('packet_evidence_changed');
});

it('includes legacy attachments without recorded sizes using actual decrypted length', async () => {
  row.contentSize = undefined;
  const entries = unzipSync(await exportPacketArchive('VRA-TEST', Buffer.from('pdf')));
  expect(Buffer.from(entries['evidence/evidence-1.csv'])).toEqual(content);
});
it('keeps files above 20 MiB intact in the exported archive', () => {
  const large = Buffer.alloc(21 * 1024 * 1024, 42);
  const entries = unzipSync(renderPacketArchive(Buffer.from('pdf'), [{name:'evidence-1.mp4', mimetype:'video/mp4', content:large}]));
  const restored = entries['evidence/evidence-1.mp4'];
  expect(restored.byteLength).toBe(large.byteLength);
  expect(crypto.createHash('sha256').update(restored).digest('hex')).toBe(crypto.createHash('sha256').update(large).digest('hex'));
});
