import { PDFDocument, PDFName } from 'pdf-lib';
import { stripPdfMetadata } from '../../../src/services/pdfMetadata';
import { pdfFixture } from '../../helpers/pdfFixture';
import { pdfExpansionFixture } from '../../helpers/pdfExpansionFixture';

it.each([false, true])('rejects 128 MiB expansion before allocation and accepts a retry (object stream=%s)', async objectStream => {
  const input = await pdfExpansionFixture(128, 1, objectStream);
  expect(input.length).toBeLessThan(140000);
  await expect(stripPdfMetadata(input)).rejects.toThrow('No original file');
  const output = await stripPdfMetadata(Buffer.from(await pdfFixture()));
  expect((await PDFDocument.load(output)).getPageCount()).toBe(1);
});

it('bounds cumulative allocation across many individually small streams', async () => {
  await expect(stripPdfMetadata(await pdfExpansionFixture(2, 20))).rejects.toThrow('No original file');
  expect((await stripPdfMetadata(Buffer.from(await pdfFixture()))).length).toBeGreaterThan(0);
});

it('locks all supported expanding decoders to the reviewed allocation hook', () => {
  expect(require('pdf-lib/package.json').version).toBe('1.17.1');
  const DecodeStream = require('pdf-lib/cjs/core/streams/DecodeStream').default;
  for (const name of ['FlateStream', 'LZWStream', 'Ascii85Stream', 'AsciiHexStream', 'RunLengthStream']) {
    const Decoder = require(`pdf-lib/cjs/core/streams/${name}`).default;
    expect(Decoder.prototype.ensureBuffer).toBe(DecodeStream.prototype.ensureBuffer);
  }
});


it.each([false, true])('bounds repeated uncompressed stream copies across the document (same page=%s)', async samePage => {
  const doc = await PDFDocument.create();
  const stream = doc.context.register(doc.context.stream(Buffer.alloc(2 * 1024 * 1024, 32)));
  if (samePage) {
    doc.addPage([100, 100]).node.set(PDFName.of('Contents'), doc.context.obj(Array(12).fill(stream)));
  } else {
    for (let index = 0; index < 12; index++) doc.addPage([100, 100]).node.set(PDFName.of('Contents'), stream);
  }
  const input = Buffer.from(await doc.save());
  expect(input.length).toBeLessThan(3 * 1024 * 1024);
  await expect(stripPdfMetadata(input)).rejects.toThrow('No original file');
  expect((await stripPdfMetadata(Buffer.from(await pdfFixture()))).length).toBeGreaterThan(0);
});
