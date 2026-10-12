import { PDFDocument, PDFName, PDFString, PDFRawStream } from 'pdf-lib';
import sharp from 'sharp';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { stripPdfMetadata } from '../../../src/services/pdfMetadata';

function rendered(input: Uint8Array): Buffer {
  const directory = mkdtempSync(path.join(tmpdir(), 'vera-pdf-widget-'));
  try {
    const file = path.join(directory, 'document.pdf');
    writeFileSync(file, input);
    execFileSync('pdftoppm', ['-singlefile', '-r', '72', '-png', file, file], { timeout: 10000 });
    return readFileSync(file + '.png');
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

it('removes widget identity while retaining field name, value and rendered appearance', async () => {
  const doc = await PDFDocument.create();
  const page = doc.addPage([200, 100]);
  const field = doc.getForm().createTextField('incident_reference');
  field.setText('CASE-123');
  field.addToPage(page, { x: 10, y: 30, width: 150, height: 20 });
  const widget = field.acroField.getWidgets()[0];
  for (const [key, value] of Object.entries({ NM: 'private-widget-id-canary', M: 'D:20010101000000Z', CreationDate: 'D:20000101000000Z', Subj: 'private-widget-subject-canary' })) {
    widget.dict.set(PDFName.of(key), PDFString.of(value));
  }
  const input = await doc.save();
  const output = await stripPdfMetadata(Buffer.from(input));
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  const cleanField = clean.getForm().getTextField('incident_reference');
  expect(cleanField.getText()).toBe('CASE-123');
  const cleanWidget = cleanField.acroField.getWidgets()[0];
  for (const key of ['NM', 'M', 'CreationDate', 'Subj']) expect(cleanWidget.dict.has(PDFName.of(key))).toBe(false);
  expect(rendered(output)).toEqual(rendered(input));
});

it('rejects embedded JPEG identity metadata behind an indirect filter-array name', async () => {
  const jpg = await sharp({ create: { width: 8, height: 8, channels: 3, background: 'red' } })
    .withExif({ IFD0: { Artist: 'private-image-exif-canary' } }).jpeg().toBuffer();
  const doc = await PDFDocument.create();
  const image = await doc.embedJpg(jpg);
  doc.addPage([100, 100]).drawImage(image, { x: 10, y: 10, width: 80, height: 80 });
  const direct = await doc.save();
  const stream = doc.context.lookup(image.ref) as PDFRawStream;
  stream.dict.set(PDFName.of('Filter'), doc.context.obj([doc.context.register(PDFName.of('DCTDecode'))]));
  const indirect = await doc.save();
  // This is a readable PDF, not merely an invalid dictionary that should fail parsing.
  expect(rendered(indirect)).toEqual(rendered(direct));
  await expect(stripPdfMetadata(Buffer.from(indirect))).rejects.toThrow('No original file');
});

it.each(['name', 'indirect-array'])('rejects JPEG metadata behind an abbreviated DCT filter (%s)', async shape => {
  const jpg = await sharp({ create: { width: 8, height: 8, channels: 3, background: 'red' } })
    .withExif({ IFD0: { Artist: 'private-abbreviated-exif-canary' } }).jpeg().toBuffer();
  const doc = await PDFDocument.create();
  const image = await doc.embedJpg(jpg);
  doc.addPage([100, 100]).drawImage(image, { x: 10, y: 10, width: 80, height: 80 });
  const direct = await doc.save();
  const stream = doc.context.lookup(image.ref) as PDFRawStream;
  const alias = PDFName.of('DCT');
  stream.dict.set(PDFName.of('Filter'), shape === 'name' ? alias : doc.context.obj([doc.context.register(alias)]));
  const abbreviated = await doc.save();
  expect(rendered(abbreviated)).toEqual(rendered(direct));
  await expect(stripPdfMetadata(Buffer.from(abbreviated))).rejects.toThrow('No original file');
});

it('preserves a clean JPEG using a direct abbreviated DCT filter', async () => {
  const jpg = await sharp({ create: { width: 8, height: 8, channels: 3, background: 'red' } }).jpeg().toBuffer();
  const doc = await PDFDocument.create();
  const image = await doc.embedJpg(jpg);
  doc.addPage([100, 100]).drawImage(image, { x: 10, y: 10, width: 80, height: 80 });
  await doc.save();
  (doc.context.lookup(image.ref) as PDFRawStream).dict.set(PDFName.of('Filter'), PDFName.of('DCT'));
  const input = await doc.save();
  const output = await stripPdfMetadata(Buffer.from(input));
  expect(rendered(output)).toEqual(rendered(input));
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  const images = clean.context.enumerateIndirectObjects().map(([, object]) => object)
    .filter(object => object instanceof PDFRawStream && object.dict.get(PDFName.of('Subtype')) === PDFName.of('Image')) as PDFRawStream[];
  expect(images).toHaveLength(1);
  expect(Buffer.from(images[0].getContents())).toEqual(jpg);
});
