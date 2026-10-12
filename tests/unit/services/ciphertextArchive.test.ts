import { Readable } from 'node:stream';
import { S3Client } from '@aws-sdk/client-s3';
import { archiveCiphertext, retrieveArchivedCiphertext, ciphertextArchiveEnabled } from '../../../src/services/ciphertextArchive';
import { storeLocalCiphertext, readLocalCiphertext } from '../../../src/services/localIpfs';
const cid = 'b' + 'a'.repeat(40);
const env = { ...process.env };
beforeEach(() => { process.env = { ...env, NODE_ENV: 'test', IPFS_CIPHERTEXT_ARCHIVE_BUCKET: 'test-archive' }; });
afterEach(() => { process.env = { ...env }; jest.restoreAllMocks(); });
test('waits for archive acknowledgment and rejects failed or unacknowledged writes', async () => {
  jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ cid })));
  const send = jest.spyOn(S3Client.prototype, 'send').mockRejectedValue(new Error('archive down'));
  await expect(storeLocalCiphertext(Buffer.from('ciphertext'))).rejects.toThrow('archive down');
  send.mockResolvedValue({ $metadata: { httpStatusCode: 200 } } as never);
  await expect(storeLocalCiphertext(Buffer.from('ciphertext'))).rejects.toThrow('not acknowledged');
  send.mockResolvedValue({ $metadata: { httpStatusCode: 200 }, ETag: 'etag' } as never);
  await expect(storeLocalCiphertext(Buffer.from('ciphertext'))).resolves.toBe(cid);
  const input = (send.mock.calls[2][0] as any).input;
  expect(input.Key).toBe(`ciphertext/v1/${cid}`);
  expect(input.ContentType).toBe('application/octet-stream');
  expect(input.ChecksumSHA256).toBeDefined();
  expect(input.Metadata).toBeUndefined();
});
test('does not return corrupt archive bytes under a mismatched CID', async () => {
  jest.spyOn(global, 'fetch').mockResolvedValueOnce(new Response('', { status: 502 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ cid: 'b' + 'c'.repeat(40) })));
  jest.spyOn(S3Client.prototype, 'send').mockResolvedValue({ $metadata: { httpStatusCode: 200 }, Body: Readable.from([Buffer.from('altered')]) } as never);
  await expect(readLocalCiphertext(cid)).rejects.toThrow('CID mismatch');
});
test('bounded archive reads reject empty or oversized declared content', async () => {
  const send = jest.spyOn(S3Client.prototype, 'send').mockResolvedValue({ $metadata: { httpStatusCode: 200 }, Body: Readable.from([]) } as never);
  await expect(retrieveArchivedCiphertext(cid)).rejects.toThrow('Empty');
  send.mockResolvedValue({ $metadata: { httpStatusCode: 200 }, ContentLength: Number.MAX_SAFE_INTEGER, Body: Readable.from([]) } as never);
  await expect(retrieveArchivedCiphertext(cid)).rejects.toThrow('Invalid');
});
test('default is unchanged and test endpoints cannot select remote or production destinations', async () => {
  delete process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET;
  expect(ciphertextArchiveEnabled()).toBe(false);
  const send = jest.spyOn(S3Client.prototype, 'send');
  await archiveCiphertext(cid, Buffer.from('ciphertext'));
  expect(send).not.toHaveBeenCalled();
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'test-archive';
  process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT = 'http://example.com';
  expect(ciphertextArchiveEnabled).toThrow('loopback');
  process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT = 'http://127.0.0.1:4566';
  process.env.NODE_ENV = 'production';
  expect(ciphertextArchiveEnabled).toThrow('non-production');
});
test('does not acknowledge the temporary Kubo pin while the archive is still writing', async () => {
  jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ cid })));
  let acknowledge!: (value: any) => void;
  const entered = new Promise<void>(resolve => {
    jest.spyOn(S3Client.prototype, 'send').mockImplementation(() => {
      resolve();
      return new Promise(done => { acknowledge = done; }) as any;
    });
  });
  let settled = false;
  const pending = storeLocalCiphertext(Buffer.from('ciphertext')).then(value => { settled = true; return value; });
  await entered;
  expect(settled).toBe(false);
  acknowledge({ $metadata: { httpStatusCode: 200 }, ETag: 'etag' });
  await expect(pending).resolves.toBe(cid);
});
