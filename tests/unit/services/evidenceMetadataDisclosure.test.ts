import crypto from 'node:crypto';
import { evidenceStorageService } from '../../../src/services/evidenceStorage';
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';
import { reportPersistenceService } from '../../../src/services/reportPersistence';

jest.mock('../../../src/services/reportPersistence', () => ({ reportPersistenceService: { saveEvidenceParams: jest.fn().mockResolvedValue(undefined) } }));
jest.mock('../../../src/services/evidenceEncryption', () => ({ evidenceEncryptionService: { encryptEvidence: jest.fn(async (bytes: Buffer) => ({ contentMetadata: { hash: crypto.createHash('sha256').update(bytes).digest('hex'), size: bytes.length }, encryptedData: Buffer.from('ciphertext').toString('base64'), encryptionMetadata: { salt: 'salt', iv: 'iv', authTag: 'tag' } })) } }));

const original = process.env;
beforeEach(() => { process.env = { ...original, NODE_ENV: 'test', IPFS_STORAGE_BACKEND: 'local-enclave', ENCLAVE_IPFS_URL: 'http://127.0.0.1:15002' }; });
afterEach(() => { process.env = original; jest.restoreAllMocks(); });
const v0 = 'QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN';

it('sends no original filename, reporter capability or plaintext to storage', async () => {
  const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ cid: v0 })));
  const trackingId = 'VRA-1234567890ABCDEF';
  await evidenceStorageService.uploadEncryptedFile(Buffer.from('private bytes'), 'alice-payroll.pdf', trackingId, crypto.randomBytes(32).toString('hex'));
  expect(fetchSpy).toHaveBeenCalledTimes(1);
  const [url, init] = fetchSpy.mock.calls[0];
  expect(String(url)).toBe('http://127.0.0.1:15002/add');
  const wire = Buffer.from(init!.body as Uint8Array).toString('latin1') + JSON.stringify(init!.headers);
  expect(wire).not.toContain('alice-payroll');
  expect(wire).not.toContain(trackingId);
  expect(wire).not.toContain('private bytes');
  expect(wire).not.toContain('originalFilename');
});

it('stores neutral, distinct evidence names for duplicate source filenames', async () => {
  const upload = jest.spyOn(evidenceStorageService, 'uploadEncryptedFile').mockResolvedValue({ originalCID: 'cid', iv: 'iv', authTag: 'tag', salt: 'salt' } as any);
  const file = { originalname: 'alice-payroll.pdf', mimetype: 'application/pdf', buffer: Buffer.from('evidence') } as Express.Multer.File;
  const entries = await persistSubmissionEvidence('VRA-1234567890ABCDEF', [file, file]);
  expect(entries.map(x => x.fileKey)).toEqual(['VRA-1234567890ABCDEF/evidence-1.pdf', 'VRA-1234567890ABCDEF/evidence-2.pdf']);
  expect(JSON.stringify(jest.mocked(reportPersistenceService.saveEvidenceParams).mock.calls)).not.toContain('alice');
  upload.mockRestore();
});

it.each([['audio/mpeg', 'mp3'], ['audio/wav', 'wav'], ['audio/mp4', 'm4a'], ['audio/aac', 'aac'], ['video/mp4', 'mp4'], ['video/quicktime', 'mov']])('retains a playable neutral extension for %s', async (mimetype, extension) => {
  const upload = jest.spyOn(evidenceStorageService, 'uploadEncryptedFile').mockResolvedValue({ originalCID: 'cid', iv: 'iv', authTag: 'tag', salt: 'salt' } as any);
  try {
    const entries = await persistSubmissionEvidence('VRA-test', [{ originalname: 'private-source-name', mimetype, buffer: Buffer.from('synthetic') } as Express.Multer.File]);
    expect(entries[0].fileKey).toBe(`VRA-test/evidence-1.${extension}`);
  } finally { upload.mockRestore(); }
});

it('classifies storage failures with a fixed code and no backend details', async () => {
  jest.spyOn(global, 'fetch').mockRejectedValue(new Error('PRIVATE_BACKEND_DETAIL'));
  await expect(evidenceStorageService.uploadEncryptedFile(Buffer.from('synthetic'), 'evidence.csv', 'VRA-test', 'synthetic-key'))
    .rejects.toMatchObject({ code: 'evidence_upload_unavailable', message: 'Failed to upload encrypted file to IPFS' });
});
