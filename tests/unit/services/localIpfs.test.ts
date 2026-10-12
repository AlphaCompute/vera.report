import { MAX_STORED_EVIDENCE_BYTES } from '../../../src/utils/evidenceLimits';
import { S3Client } from '@aws-sdk/client-s3';
import { requireLocalIpfs, storeLocalCiphertext, readLocalCiphertext, unpinLocalCiphertext } from '../../../src/services/localIpfs';
import { EvidenceStorageService } from '../../../src/services/evidenceStorage';
const original = process.env;
afterEach(() => { process.env = original; jest.restoreAllMocks(); });
beforeEach(() => { process.env = { ...original, NODE_ENV: 'test', IPFS_STORAGE_BACKEND: 'local-enclave' }; });
const v0 = 'QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN';
test('production requires the ciphertext archive and an explicit proxy origin', () => {
  expect(requireLocalIpfs).not.toThrow();
  process.env.NODE_ENV = 'production';
  expect(requireLocalIpfs).toThrow(/ciphertext archive/);
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'vera-prod-ciphertext';
  expect(requireLocalIpfs).toThrow(/explicit ENCLAVE_IPFS_URL/);
  process.env.ENCLAVE_IPFS_URL = 'http://ipfs.example.com:15002';
  expect(requireLocalIpfs).toThrow(/loopback or ipfs sidecar/);
  for (const url of ['http://127.0.0.1:15002', 'http://ipfs:15002']) {
    process.env.ENCLAVE_IPFS_URL = url;
    expect(requireLocalIpfs).not.toThrow();
  }
  process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT = 'http://127.0.0.1:4566';
  expect(requireLocalIpfs).toThrow(/non-production/);
});
test('any backend other than local-enclave fails closed, including the retired pinata value and unset', async () => {
  const spy = jest.spyOn(global, 'fetch').mockRejectedValue(new Error('must not call'));
  for (const backend of ['pinata', '', undefined]) {
    if (backend === undefined) delete process.env.IPFS_STORAGE_BACKEND; else process.env.IPFS_STORAGE_BACKEND = backend;
    expect(requireLocalIpfs).toThrow('IPFS_STORAGE_BACKEND must be local-enclave');
    const service = new EvidenceStorageService();
    await expect(service.uploadEncryptedFile(Buffer.from('ciphertext'), 'f', 'v', 'key')).rejects.toMatchObject({ code: 'evidence_upload_unavailable' });
    await expect(service.readCiphertext(v0)).rejects.toThrow('IPFS_STORAGE_BACKEND must be local-enclave');
    await expect(service.unpin(v0)).rejects.toThrow('Failed to unpin from IPFS');
  }
  expect(spy).not.toHaveBeenCalled();
});
test('accepts loopback and the ECS link alias, and nothing else', async () => {
  const spy = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ cid: v0 })));
  for (const url of ['http://127.0.0.1:15002', 'http://localhost:15002', 'http://[::1]:15002', 'http://ipfs:15002', 'http://ipfs:15002/']) {
    process.env.ENCLAVE_IPFS_URL = url;
    await expect(storeLocalCiphertext(Buffer.from('ciphertext'))).resolves.toBe(v0);
  }
  expect(spy.mock.calls.map(call => String(call[0]))).toEqual([
    'http://127.0.0.1:15002/add', 'http://localhost:15002/add', 'http://[::1]:15002/add', 'http://ipfs:15002/add', 'http://ipfs:15002/add',
  ]);
  spy.mockClear();
  for (const url of ['https://ipfs:15002', 'http://ipfs.local:15002', 'http://ipfs.:15002', 'http://ipfs-sidecar:15002',
    'http://10.0.0.5:15002', 'http://169.254.170.2', 'http://ipfs:15002/api/v0', 'http://ipfs:15002/?x=1', 'http://u:p@ipfs:15002']) {
    process.env.ENCLAVE_IPFS_URL = url;
    await expect(storeLocalCiphertext(Buffer.from('ciphertext'))).rejects.toThrow(/loopback or ipfs sidecar/);
  }
  expect(spy).not.toHaveBeenCalled();
});
test('unknown backend and unsafe URLs fail without network calls', async () => {
  const spy = jest.spyOn(global, 'fetch').mockRejectedValue(new Error('must not call'));
  process.env.IPFS_STORAGE_BACKEND = 'typo';
  expect(requireLocalIpfs).toThrow(/must be local-enclave/);
  for (const url of ['https://example.com', 'http://user:pass@localhost', 'http://localhost/path']) {
    process.env.ENCLAVE_IPFS_URL = url;
    await expect(storeLocalCiphertext(Buffer.from('ciphertext'))).rejects.toThrow(/loopback/);
    await expect(unpinLocalCiphertext(v0)).rejects.toThrow(/loopback/);
  }
  expect(spy).not.toHaveBeenCalled();
});
test('invalid CIDs and oversized uploads fail before network access', async () => {
  const spy = jest.spyOn(global, 'fetch').mockRejectedValue(new Error('must not call'));
  await expect(readLocalCiphertext('../config')).rejects.toThrow(/CID/);
  await expect(unpinLocalCiphertext('../config')).rejects.toThrow(/CID/);
  await expect(storeLocalCiphertext(Buffer.alloc(MAX_STORED_EVIDENCE_BYTES + 1))).rejects.toThrow(/size/);
  expect(spy).not.toHaveBeenCalled();
});
test('unpin removes the Kubo pin, then every archived version and delete marker of that exact key', async () => {
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'test-archive';
  process.env.ENCLAVE_IPFS_URL = 'http://ipfs:15002';
  const order: string[] = [];
  const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
    order.push(`fetch ${input} ${Buffer.from(init?.body as Uint8Array).toString()}`);
    return new Response(JSON.stringify({ cid: v0, unpinned: true }));
  });
  const key = `ciphertext/v1/${v0}`;
  let listed = 0;
  const send = jest.spyOn(S3Client.prototype, 'send').mockImplementation(async (command: any) => {
    const name = command.constructor.name;
    order.push(name);
    if (name === 'ListObjectVersionsCommand') {
      listed++;
      if (listed === 1) return { IsTruncated: true, NextKeyMarker: key, NextVersionIdMarker: 'v2', Versions: [{ Key: key, VersionId: 'v1' }, { Key: `${key}x`, VersionId: 'other' }] } as never;
      if (listed === 2) return { IsTruncated: false, Versions: [{ Key: key, VersionId: 'v2' }], DeleteMarkers: [{ Key: key, VersionId: 'm1' }] } as never;
      return { IsTruncated: false } as never;
    }
    return { $metadata: { httpStatusCode: 200 } } as never;
  });
  await unpinLocalCiphertext(v0);
  expect(order).toEqual([`fetch http://ipfs:15002/rm ${v0}`, 'ListObjectVersionsCommand', 'ListObjectVersionsCommand', 'DeleteObjectsCommand', 'ListObjectVersionsCommand']);
  const listInput = (send.mock.calls[0][0] as any).input;
  expect(listInput).toMatchObject({ Bucket: 'test-archive', Prefix: key });
  expect((send.mock.calls[1][0] as any).input).toMatchObject({ KeyMarker: key, VersionIdMarker: 'v2' });
  expect((send.mock.calls[2][0] as any).input.Delete.Objects).toEqual([
    { Key: key, VersionId: 'v1' }, { Key: key, VersionId: 'v2' }, { Key: key, VersionId: 'm1' },
  ]);
  expect(fetchSpy).toHaveBeenCalledTimes(1);
});
test('unpin fails when the proxy, a deletion or the final verification fails', async () => {
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'test-archive';
  const key = `ciphertext/v1/${v0}`;
  jest.spyOn(global, 'fetch').mockResolvedValueOnce(new Response('', { status: 502 }));
  const send = jest.spyOn(S3Client.prototype, 'send');
  await expect(unpinLocalCiphertext(v0)).rejects.toThrow(/request failed/);
  expect(send).not.toHaveBeenCalled();
  jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ cid: v0, unpinned: false })));
  send.mockImplementation(async (command: any) => (command.constructor.name === 'DeleteObjectsCommand'
    ? { Errors: [{ Key: key, Code: 'AccessDenied' }] } : { Versions: [{ Key: key, VersionId: 'v1' }] }) as never);
  await expect(unpinLocalCiphertext(v0)).rejects.toThrow(/incomplete/);
  send.mockImplementation(async () => ({ Versions: [{ Key: key, VersionId: 'late' }] }) as never);
  await expect(unpinLocalCiphertext(v0)).rejects.toThrow(/incomplete/);
});
test('unpin without an archive only removes the local pin and EvidenceStorageService routes to it', async () => {
  const spy = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ cid: v0, unpinned: false })));
  const send = jest.spyOn(S3Client.prototype, 'send');
  await new EvidenceStorageService().unpin(v0);
  expect(spy).toHaveBeenCalledTimes(1);
  expect(String(spy.mock.calls[0][0])).toBe('http://127.0.0.1:15002/rm');
  expect(send).not.toHaveBeenCalled();
  spy.mockResolvedValue(new Response(JSON.stringify({ cid: 'b' + 'a'.repeat(40) })));
  await expect(new EvidenceStorageService().unpin(v0)).rejects.toThrow('Failed to unpin from IPFS');
});
test('logs an archive CID mismatch for the IpfsCidMismatch alarm without the CID', async () => {
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'test-archive';
  process.env.ENCLAVE_IPFS_URL = 'http://127.0.0.1:15002';
  const archive = require('../../../src/services/ciphertextArchive');
  const { logger } = require('../../../src/utils/logger');
  jest.spyOn(archive, 'retrieveArchivedCiphertext').mockResolvedValue(Buffer.from('tampered'));
  const error = jest.spyOn(logger, 'error').mockImplementation(() => undefined);
  jest.spyOn(global, 'fetch').mockImplementation(async (url: any) => String(url).endsWith('/cat')
    ? new Response(null, { status: 502 })
    : new Response(JSON.stringify({ cid: 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG' })));
  await expect(readLocalCiphertext(v0)).rejects.toThrow('Archived ciphertext CID mismatch');
  expect(error).toHaveBeenCalledWith('Archived ciphertext CID mismatch');
  expect(JSON.stringify(error.mock.calls)).not.toContain(v0);
});
