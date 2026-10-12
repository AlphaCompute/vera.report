import { extractMetadataIsolated } from '../../../src/services/metadataWorker';
it('extracts metadata in a real worker', async () => {
  const result = await extractMetadataIsolated(Buffer.from('hello'), 'note.txt', 'text/plain', new AbortController().signal);
  expect(result.file).toMatchObject({ name: 'note.txt', size: 5 });
});
it('terminates an in-flight worker on cancellation', async () => {
  const controller = new AbortController();
  const result = extractMetadataIsolated(Buffer.alloc(1024), 'image.png', 'image/png', controller.signal);
  controller.abort();
  await expect(result).rejects.toThrow('Analysis cancelled');
});
