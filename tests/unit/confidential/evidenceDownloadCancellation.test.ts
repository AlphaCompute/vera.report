import { EvidenceDownload } from '../../../lib/confidential/evidenceTransfer';

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
};
const flush = () => new Promise<void>(resolve => setImmediate(resolve));
function fixture() {
  const plaintext = new Uint8Array([1, 2, 3]);
  const ciphertext = new Uint8Array([4, 5, 6]);
  const sink = { write: jest.fn().mockResolvedValue(undefined), close: jest.fn().mockResolvedValue(undefined), abort: jest.fn().mockResolvedValue(undefined) };
  const reader = { index: { chunkCount: 1 }, digest: 'digest', size: 3, openChunk: jest.fn().mockResolvedValue(plaintext), dispose: jest.fn() };
  const fetchChunk = jest.fn().mockResolvedValue(ciphertext);
  const download = new EvidenceDownload(sink, async () => ({ reader, fetchChunk } as any));
  return { plaintext, ciphertext, sink, reader, fetchChunk, download };
}

test.each(['fetch', 'decrypt', 'write'] as const)('cancel during final %s never publishes the file', async stage => {
  const f = fixture();
  const pending = deferred<any>();
  if (stage === 'fetch') f.fetchChunk.mockReturnValue(pending.promise);
  if (stage === 'decrypt') f.reader.openChunk.mockReturnValue(pending.promise);
  if (stage === 'write') f.sink.write.mockReturnValue(pending.promise);
  const result = f.download.run().catch(error => error);
  await flush();
  await f.download.cancel();
  pending.resolve(stage === 'fetch' ? f.ciphertext : stage === 'decrypt' ? f.plaintext : undefined);
  expect(await result).toMatchObject({ reason: 'interrupted' });
  expect(f.sink.close).not.toHaveBeenCalled();
  expect(f.sink.abort).toHaveBeenCalledTimes(1);
  expect(f.reader.dispose).toHaveBeenCalledTimes(1);
  expect([...f.ciphertext]).toEqual([0, 0, 0]);
  if (stage !== 'fetch') expect([...f.plaintext]).toEqual([0, 0, 0]);
  if (stage !== 'write') expect(f.sink.write).not.toHaveBeenCalled();
});

test('pause after writing the last chunk preserves progress and resumes without writing twice', async () => {
  const f = fixture();
  const controller = new AbortController();
  f.sink.write.mockImplementation(async () => { controller.abort(); });
  await expect(f.download.run({ signal: controller.signal })).rejects.toMatchObject({ reason: 'interrupted' });
  expect(f.download.progress.bytesDone).toBe(3);
  expect(f.sink.abort).not.toHaveBeenCalled();
  expect(f.sink.close).not.toHaveBeenCalled();
  await f.download.run();
  expect(f.sink.write).toHaveBeenCalledTimes(1);
  expect(f.sink.close).toHaveBeenCalledTimes(1);
});
