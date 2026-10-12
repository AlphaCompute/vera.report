import { PDFDocument, PDFName, PDFDict, PDFString, PDFRawStream, decodePDFRawStream, degrees, rgb } from 'pdf-lib';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { stripPdfMetadata } from '../../../src/services/pdfMetadata';
import { pdfFixture, appendIncrementalInfo } from '../../helpers/pdfFixture';

async function readableObjects(input: Uint8Array) {
  const doc = await PDFDocument.load(input, { updateMetadata: false });
  return doc.context.enumerateIndirectObjects().map(([, object]) => object instanceof PDFRawStream ? Buffer.from(decodePDFRawStream(object).decode()).toString('latin1') : object.toString()).join('\n');
}

describe('structural PDF metadata removal', () => {
  it.each([false, true])('removes properties, XMP, annotation identity and unreachable objects (compressed=%s)', async compressed => {
    const input = Buffer.from(await pdfFixture({ compressed }));
    const output = await stripPdfMetadata(input);
    expect(await readableObjects(input)).toContain('identity-canary');
    expect(await readableObjects(output)).not.toContain('identity-canary');
    expect(output.toString('latin1')).not.toContain('identity-canary');
    const clean = await PDFDocument.load(output, { updateMetadata: false });
    expect(clean.getAuthor()).toBeUndefined(); expect(clean.getTitle()).toBeUndefined();
    expect(clean.catalog.has(PDFName.of('Metadata'))).toBe(false);
    expect(clean.context.trailerInfo.ID).toBeUndefined();
    expect(clean.getPageCount()).toBe(1);
  });

  it('discards superseded incremental revision bytes and preserves the latest pages', async () => {
    const input = appendIncrementalInfo(await pdfFixture({ compressed: false }));
    expect((await PDFDocument.load(input, { updateMetadata: false })).getAuthor()).toBe('identity-canary-latest-revision');
    const output = await stripPdfMetadata(input);
    expect(await readableObjects(output)).not.toContain('identity-canary');
    expect(output.toString('latin1')).not.toContain('identity-canary');
  });

  it('preserves interactive form names, values and widget relationships', async () => {
    const output = await stripPdfMetadata(Buffer.from(await pdfFixture({ form: true })));
    const doc = await PDFDocument.load(output, { updateMetadata: false });
    const field = doc.getForm().getTextField('incident_reference');
    expect(field.getText()).toBe('CASE-123');
    expect(field.acroField.getWidgets()).toHaveLength(1);
    expect(field.acroField.getWidgets()[0].dict.has(PDFName.of('AP'))).toBe(true);
  });

  it.each([false, true])('preserves every rendered page and its text (compressed=%s)', async compressed => {
    const directory = mkdtempSync(path.join(tmpdir(), 'vera-pdf-check-'));
    try {
      const doc = await PDFDocument.load(await pdfFixture({ form: true }));
      const rotated = doc.addPage([320, 480]);
      rotated.setRotation(degrees(90));
      rotated.drawText('PAGE TWO: rotated evidence.', { x: 30, y: 420, size: 12 });
      rotated.drawRectangle({ x: 50, y: 80, width: 120, height: 180, color: rgb(0.2, 0.4, 0.8) });
      const cropped = doc.addPage([500, 400]);
      cropped.setCropBox(20, 30, 430, 330);
      cropped.drawText('PAGE THREE: final evidence.', { x: 40, y: 330, size: 12 });
      const jpeg = await require('sharp')({ create: { width: 16, height: 16, channels: 3, background: 'red' } }).jpeg().toBuffer();
      const image = await doc.embedJpg(jpeg);
      cropped.drawImage(image, { x: 40, y: 80, width: 100, height: 100 });
      rotated.drawImage(image, { x: 200, y: 60, width: 60, height: 90 });
      const field = doc.getForm().createTextField('last_page_reference');
      field.setText('FINAL-456'); field.addToPage(cropped, { x: 40, y: 220, width: 220, height: 24 });
      const input = Buffer.from(await doc.save({ useObjectStreams: compressed }));
      const output = await stripPdfMetadata(input);
      const cleanDoc = await PDFDocument.load(output, { updateMetadata: false });
      expect(cleanDoc.getPageCount()).toBe(3);
      expect(cleanDoc.getForm().getTextField('last_page_reference').getText()).toBe('FINAL-456');
      expect(cleanDoc.getAuthor()).toBeUndefined();
      const original = path.join(directory, 'original.pdf'); const clean = path.join(directory, 'clean.pdf');
      writeFileSync(original, input); writeFileSync(clean, output);
      const markers = ['Evidence:', 'PAGE TWO:', 'PAGE THREE:'];
      for (let index = 1; index <= 3; index++) {
        const render = (file: string) => {
          const prefix = file + '-' + index;
          execFileSync('pdftoppm', ['-f', String(index), '-l', String(index), '-singlefile', '-cropbox', '-r', '72', '-png', file, prefix], { timeout: 10000 });
          return readFileSync(prefix + '.png');
        };
        expect({ page: index, pixelsUnchanged: render(clean).equals(render(original)) }).toEqual({ page: index, pixelsUnchanged: true });
        const text = (file: string) => execFileSync('pdftotext', ['-f', String(index), '-l', String(index), file, '-'], { timeout: 10000 }).toString();
        expect(text(clean)).toBe(text(original));
        expect(text(clean)).toContain(markers[index - 1]);
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });

  it.each(['attachment', 'script', 'signature'])('rejects %s instead of silently discarding or invalidating evidence', async kind => {
    const doc = await PDFDocument.load(await pdfFixture());
    if (kind === 'attachment') await doc.attach(Buffer.from('attached evidence'), 'evidence.txt');
    if (kind === 'script') doc.addJavaScript('open', 'app.alert("test")');
    if (kind === 'signature') doc.catalog.set(PDFName.of('Perms'), doc.context.obj({ DocMDP: { Type: 'Sig', ByteRange: [0, 1, 2, 3] } }));
    await expect(stripPdfMetadata(Buffer.from(await doc.save()))).rejects.toThrow('No original file');
  });

  it('preserves metadata-free embedded JPEGs but rejects hidden EXIF in them', async () => {
    const sharp = require('sharp');
    for (const withMetadata of [false, true]) {
      let image = sharp({ create: { width: 8, height: 8, channels: 3, background: 'red' } });
      if (withMetadata) image = image.withExif({ IFD0: { Artist: 'identity-canary-camera' } });
      const jpeg = await image.jpeg().toBuffer();
      const doc = await PDFDocument.create();
      const embedded = await doc.embedJpg(jpeg); doc.addPage([100, 100]).drawImage(embedded, { x: 10, y: 10, width: 80, height: 80 });
      const input = Buffer.from(await doc.save());
      if (withMetadata) await expect(stripPdfMetadata(input)).rejects.toThrow('No original file');
      else expect((await PDFDocument.load(await stripPdfMetadata(input))).getPageCount()).toBe(1);
    }
  });

  it('rejects inline images while retaining BI text inside visible strings', async () => {
    const visible = await PDFDocument.create(); visible.addPage().drawText('BI ID are ordinary words here.');
    expect(await stripPdfMetadata(Buffer.from(await visible.save()))).toBeInstanceOf(Buffer);
    const inline = await PDFDocument.create(); const page = inline.addPage([20, 20]);
    const stream = inline.context.flateStream('q BI /W 1 /H 1 /CS /RGB /BPC 8 ID abc EI Q');
    page.node.set(PDFName.of('Contents'), inline.context.register(stream));
    await expect(stripPdfMetadata(Buffer.from(await inline.save()))).rejects.toThrow('No original file');
  });

  it('accepts exactly the 200-page limit and rejects 201 pages', async () => {
    const pages = async (count: number) => {
      const doc = await PDFDocument.create();
      for (let i = 0; i < count; i++) doc.addPage([200, 200]).drawText(`Page ${i + 1}`, { x: 20, y: 150 });
      return Buffer.from(await doc.save());
    };
    expect((await PDFDocument.load(await stripPdfMetadata(await pages(200)))).getPageCount()).toBe(200);
    await expect(stripPdfMetadata(await pages(201))).rejects.toThrow('No original file');
  });

  it('rejects malformed and oversized input without exposing parser details', async () => {
    await expect(stripPdfMetadata(Buffer.from('%PDF-1.7 identity-canary-malformed'))).rejects.toThrow('No original file');
    await expect(stripPdfMetadata(Buffer.alloc(10 * 1024 * 1024 + 1))).rejects.toThrow('No original file');
  });
});

it('removes widget identity properties while retaining the field name and value', async () => {
  const doc = await PDFDocument.load(await pdfFixture({ form: true }));
  const widget = doc.getForm().getTextField('incident_reference').acroField.getWidgets()[0].dict;
  for (const key of ['M', 'CreationDate', 'NM', 'Subj']) widget.set(PDFName.of(key), PDFString.of('identity-canary-widget'));
  const clean = await PDFDocument.load(await stripPdfMetadata(Buffer.from(await doc.save())), { updateMetadata: false });
  const field = clean.getForm().getTextField('incident_reference');
  expect(field.getText()).toBe('CASE-123');
  for (const key of ['M', 'CreationDate', 'NM', 'Subj']) expect(field.acroField.getWidgets()[0].dict.has(PDFName.of(key))).toBe(false);
});

it('rejects JPEG metadata through an indirect image filter array entry', async () => {
  const jpeg = await require('sharp')({ create: { width: 8, height: 8, channels: 3, background: 'red' } }).withExif({ IFD0: { Artist: 'identity-canary-camera' } }).jpeg().toBuffer();
  const doc = await PDFDocument.create(); const embedded = await doc.embedJpg(jpeg);
  doc.addPage().drawImage(embedded); await doc.flush();
  const image = doc.context.lookup(embedded.ref) as PDFRawStream;
  image.dict.set(PDFName.of('Filter'), doc.context.obj([doc.context.register(PDFName.of('DCTDecode'))]));
  await expect(stripPdfMetadata(Buffer.from(await doc.save()))).rejects.toThrow('No original file');
});
