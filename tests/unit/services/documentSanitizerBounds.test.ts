import { PDFDocument } from 'pdf-lib';
import { readdir } from 'node:fs/promises';
import { sanitizeDocument } from '../../../src/services/documentSanitizer';
import { mediaScratchRoot } from '../../../src/services/mediaMetadata';

async function fixture() {
  const doc = await PDFDocument.create();
  doc.addPage([100, 100]).drawText('Evidence', { size: 10, x: 5, y: 40 });
  return Buffer.from(await doc.save());
}

it('refuses simultaneous reconstruction and accepts a retry after completion', async () => {
  const input = await fixture();
  const first = sanitizeDocument(input, 'application/pdf');
  await expect(sanitizeDocument(input, 'application/pdf')).rejects.toThrow('busy');
  await first;
  expect((await PDFDocument.load(await sanitizeDocument(input, 'application/pdf'))).getPageCount()).toBe(1);
});

it('cleans plaintext scratch and releases the slot when native tools are unavailable', async () => {
  const input = await fixture();
  const root = await mediaScratchRoot();
  const before = (await readdir(root)).filter(name => name.startsWith('vera-sanitize-')).sort();
  const path = process.env.PATH;
  try {
    process.env.PATH = '/nonexistent-vera-test-tools';
    await expect(sanitizeDocument(input, 'application/pdf')).rejects.toThrow('Document could not be safely sanitized');
  } finally {
    process.env.PATH = path;
  }
  expect((await readdir(root)).filter(name => name.startsWith('vera-sanitize-')).sort()).toEqual(before);
  expect((await PDFDocument.load(await sanitizeDocument(input, 'application/pdf'))).getPageCount()).toBe(1);
});
