/**
 * Adversarial PDF assurance (#564): page thumbnails, non-Image JPEG streams,
 * multipage documents, resource caps, deep nesting and annotation identity.
 * Outputs are checked with Poppler (pdftotext/pdftoppm) and a raw byte scan.
 */
import { PDFDocument, PDFName, PDFString, PDFArray, PDFRawStream, StandardFonts, decodePDFRawStream } from 'pdf-lib';
import sharp from 'sharp';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { stripPdfMetadata } from '../../../src/services/pdfMetadata';

jest.setTimeout(60_000);
const CANARY = 'identity-canary';

function poppler<T>(input: Uint8Array, run: (file: string) => T): T {
  const directory = mkdtempSync(path.join(tmpdir(), 'vera-pdf-assurance-'));
  try {
    const file = path.join(directory, 'document.pdf');
    writeFileSync(file, input);
    return run(file);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}
const pageText = (input: Uint8Array, page: number) => poppler(input, file =>
  execFileSync('pdftotext', ['-f', String(page), '-l', String(page), file, '-'], { timeout: 10000 }).toString().trim());
const rendered = (input: Uint8Array) => poppler(input, file => {
  execFileSync('pdftoppm', ['-singlefile', '-r', '72', '-png', file, file], { timeout: 10000 });
  return readFileSync(file + '.png');
});
/** Output is saved with object streams, so scan every decoded object as well as the raw bytes. */
async function expectNoCanary(output: Buffer) {
  expect(output.toString('latin1')).not.toContain(CANARY);
  const doc = await PDFDocument.load(output, { updateMetadata: false });
  const decoded = doc.context.enumerateIndirectObjects().map(([, object]) => object instanceof PDFRawStream
    ? Buffer.from(decodePDFRawStream(object).decode()).toString('latin1') + object.dict.toString() : object.toString()).join('\n');
  expect(decoded).not.toContain(CANARY);
  // PDF strings may be hex-encoded; check that form too.
  expect(decoded.toUpperCase()).not.toContain(Buffer.from(CANARY).toString('hex').toUpperCase());
}
const strip = (input: Uint8Array) => stripPdfMetadata(Buffer.from(input));

async function evidencePage(doc: PDFDocument, text: string) {
  const font = await doc.embedFont(StandardFonts.Helvetica);
  doc.addPage([300, 200]).drawText(text, { x: 20, y: 150, size: 12, font });
}

const exifJpeg = () => sharp({ create: { width: 8, height: 8, channels: 3, background: 'red' } })
  .withExif({ IFD0: { Artist: `${CANARY}-jpeg-exif` }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '51/1 30/1 0/1' } }).jpeg().toBuffer();

it('drops page thumbnails that carry their own JPEG metadata', async () => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Thumbnail evidence page');
  const thumb = doc.context.stream(await exifJpeg(), { Width: 8, Height: 8, ColorSpace: 'DeviceRGB', BitsPerComponent: 8, Filter: 'DCTDecode' });
  doc.getPage(0).node.set(PDFName.of('Thumb'), doc.context.register(thumb));
  const input = await doc.save({ useObjectStreams: false });
  expect(Buffer.from(input).toString('latin1')).toContain(CANARY);

  const output = await strip(input);
  await expectNoCanary(output);
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  expect(clean.getPage(0).node.has(PDFName.of('Thumb'))).toBe(false);
  expect(pageText(output, 1)).toBe('Thumbnail evidence page');
  expect(rendered(output)).toEqual(rendered(input));
});

it('rejects a reachable JPEG stream with metadata even without an Image subtype', async () => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Hidden stream page');
  const hidden = doc.context.stream(await exifJpeg(), { Filter: 'DCTDecode' });
  doc.getPage(0).node.set(PDFName.of('PrivateData'), doc.context.register(hidden));
  await expect(strip(await doc.save())).rejects.toThrow('No original file');
});

it('sanitizes a 50-page document page by page and keeps every page', async () => {
  const doc = await PDFDocument.create();
  for (let page = 1; page <= 50; page++) await evidencePage(doc, `Evidence page ${page} of 50`);
  doc.setAuthor(`${CANARY}-multipage-author`);
  doc.catalog.set(PDFName.of('Metadata'), doc.context.register(doc.context.flateStream(`<x:xmpmeta>${CANARY}-multipage-xmp</x:xmpmeta>`, { Type: 'Metadata', Subtype: 'XML' })));
  const note = doc.context.obj({ Type: 'Annot', Subtype: 'Text', Rect: [0, 0, 10, 10], Contents: PDFString.of('Note on page 37'), T: PDFString.of(`${CANARY}-page-37-author`) });
  doc.getPage(36).node.set(PDFName.of('Annots'), doc.context.obj([doc.context.register(note)]));

  const output = await strip(await doc.save());
  await expectNoCanary(output);
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  expect(clean.getPageCount()).toBe(50);
  for (const page of [1, 13, 37, 50]) expect(pageText(output, page)).toBe(`Evidence page ${page} of 50`);
});

it('accepts 200 pages and rejects 201 pages', async () => {
  const build = async (pages: number) => {
    const doc = await PDFDocument.create();
    for (let page = 0; page < pages; page++) doc.addPage([100, 100]);
    return doc.save();
  };
  const output = await strip(await build(200));
  expect((await PDFDocument.load(output)).getPageCount()).toBe(200);
  await expect(strip(await build(201))).rejects.toThrow('No original file');
});

it('rejects documents with more than 50,000 objects', async () => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Object flood');
  for (let i = 0; i < 50_001; i++) doc.context.register(doc.context.obj(i));
  await expect(strip(await doc.save({ useObjectStreams: true }))).rejects.toThrow('No original file');
});

it('fails closed on pathologically deep nesting and stays available afterwards', async () => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Deep nesting');
  const base = Buffer.from(await doc.save({ useObjectStreams: false }));
  const source = base.toString('latin1');
  const root = /\/Root\s+(\d+)\s+0\s+R/.exec(source)![1];
  const size = Number(/\/Size\s+(\d+)/.exec(source)![1]);
  const previous = /startxref\s+(\d+)\s+%%EOF/.exec(source)![1];
  const depth = 200_000;
  const object = Buffer.from(`\n${size} 0 obj\n${'['.repeat(depth)}${']'.repeat(depth)}\nendobj\n`, 'latin1');
  const xref = base.length + object.length;
  const input = Buffer.concat([base, object, Buffer.from(`xref\n${size} 1\n${String(base.length + 1).padStart(10, '0')} 00000 n \ntrailer\n<< /Size ${size + 1} /Root ${root} 0 R /Prev ${previous} >>\nstartxref\n${xref}\n%%EOF\n`, 'latin1')]);

  await expect(strip(input)).rejects.toThrow();
  expect(pageText(await strip(base), 1)).toBe('Deep nesting');
});

it('removes identity fields from non-Text annotations while keeping their visible content', async () => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Annotated evidence');
  const fields = { T: `${CANARY}-author`, NM: `${CANARY}-id`, Subj: `${CANARY}-subject`, M: 'D:20010101000000Z', CreationDate: 'D:20000101000000Z' };
  const annots = (['FreeText', 'Highlight', 'Ink', 'Stamp', 'Square'] as const).map(subtype => {
    const dict = doc.context.obj({ Type: 'Annot', Subtype: subtype, Rect: [20, 20, 120, 60], Contents: PDFString.of(`Visible ${subtype} remark`) });
    for (const [key, value] of Object.entries(fields)) dict.set(PDFName.of(key), PDFString.of(value));
    return doc.context.register(dict);
  });
  doc.getPage(0).node.set(PDFName.of('Annots'), doc.context.obj(annots));

  const output = await strip(await doc.save());
  await expectNoCanary(output);
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  const kept = (clean.getPage(0).node.Annots() as PDFArray).asArray().map(ref => clean.context.lookup(ref) as any);
  expect(kept).toHaveLength(5);
  for (const annot of kept) {
    for (const key of Object.keys(fields)) expect(annot.has(PDFName.of(key))).toBe(false);
    expect(annot.lookup(PDFName.of('Contents')).decodeText()).toMatch(/^Visible \w+ remark$/);
  }
});

it.each([
  ['FileAttachment annotation', (doc: PDFDocument) => doc.context.obj({ Type: 'Annot', Subtype: 'FileAttachment', Rect: [0, 0, 10, 10] })],
  ['Launch action', (doc: PDFDocument) => doc.context.obj({ Type: 'Annot', Subtype: 'Link', Rect: [0, 0, 10, 10], A: { S: 'Launch', F: PDFString.of('payload.exe') } })],
  ['GoToR action', (doc: PDFDocument) => doc.context.obj({ Type: 'Annot', Subtype: 'Link', Rect: [0, 0, 10, 10], A: { S: 'GoToR', F: PDFString.of('other.pdf'), D: [0, 'Fit'] } })],
])('rejects a %s rather than retaining it', async (_label, annotation) => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Active content');
  doc.getPage(0).node.set(PDFName.of('Annots'), doc.context.obj([doc.context.register(annotation(doc))]));
  await expect(strip(await doc.save())).rejects.toThrow('No original file');
});

it('keeps resources that happen to be named Thumb or Metadata', async () => {
  const doc = await PDFDocument.create();
  const page = doc.addPage([120, 120]);
  const image = await doc.embedPng(await sharp({ create: { width: 8, height: 8, channels: 3, background: 'green' } }).png().toBuffer());
  await doc.flush();
  // Resource names are author-chosen; these collide with removable property names.
  page.node.set(PDFName.of('Resources'), doc.context.obj({ XObject: { Thumb: image.ref, Metadata: image.ref } }));
  page.node.set(PDFName.of('Contents'), doc.context.register(doc.context.flateStream('q 50 0 0 50 5 5 cm /Thumb Do Q q 50 0 0 50 65 65 cm /Metadata Do Q')));
  const input = await doc.save();

  const output = await strip(input);
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  const xobjects = (clean.getPage(0).node.Resources() as any).lookup(PDFName.of('XObject'));
  expect(xobjects.keys().map((k: any) => k.asString()).sort()).toEqual(['/Metadata', '/Thumb']);
  expect(rendered(output)).toEqual(rendered(input));
});

it('removes thread info, optional-content creator/user, OPI and web-capture provenance', async () => {
  const doc = await PDFDocument.create();
  await evidencePage(doc, 'Provenance page');
  const info = (label: string) => ({ Title: PDFString.of(`${CANARY}-${label}-title`), Author: PDFString.of(`${CANARY}-${label}-author`) });
  // A listed thread, and an untyped thread reachable only through a page bead.
  const listed = doc.context.register(doc.context.obj({ I: info('listed-thread') }));
  doc.catalog.set(PDFName.of('Threads'), doc.context.obj([listed]));
  const beadOnly = doc.context.register(doc.context.obj({ I: info('bead-thread') }));
  const bead = doc.context.register(doc.context.obj({ Type: 'Bead', T: beadOnly, R: [0, 0, 100, 100], P: doc.getPage(0).ref }));
  const beadDict = doc.context.lookup(bead) as any;
  beadDict.set(PDFName.of('N'), bead); beadDict.set(PDFName.of('V'), bead);
  (doc.context.lookup(beadOnly) as any).set(PDFName.of('F'), bead);
  doc.getPage(0).node.set(PDFName.of('B'), doc.context.obj([bead]));
  const ocg = doc.context.register(doc.context.obj({ Type: 'OCG', Name: PDFString.of('Evidence layer'),
    Usage: { CreatorInfo: { Creator: PDFString.of(`${CANARY}-ocg-creator`), Subtype: 'Artwork' }, User: { Type: 'Ind', Name: PDFString.of(`${CANARY}-ocg-user`) },
      View: { ViewState: 'ON' }, Print: { PrintState: 'OFF' } } }));
  doc.catalog.set(PDFName.of('OCProperties'), doc.context.obj({ OCGs: [ocg], D: { ON: [ocg] } }));
  doc.catalog.set(PDFName.of('SpiderInfo'), doc.context.obj({ V: 1.2, C: [PDFString.of(`${CANARY}-captured-from-url`)] }));
  doc.catalog.set(PDFName.of('Names'), doc.context.obj({ URLS: { Names: [PDFString.of(`http://${CANARY}.example/page`), bead] }, IDS: { Names: [PDFString.of(`${CANARY}-digest`), bead] } }));
  doc.catalog.set(PDFName.of('PrivateCaptureSet'), doc.context.obj({ Type: 'SpiderContentSet', S: 'SPS', ID: PDFString.of('x'), O: [], SI: { AU: PDFString.of(`http://${CANARY}.example/source`) } }));
  doc.getPage(0).node.set(PDFName.of('OPI'), doc.context.obj({ '2.0': { Type: 'OPI', Version: 2, F: PDFString.of(`C:\\Users\\${CANARY}\\original.tif`) } }));

  const output = await strip(await doc.save({ useObjectStreams: false }));
  await expectNoCanary(output);
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  expect(clean.catalog.has(PDFName.of('SpiderInfo'))).toBe(false);
  const layer = (clean.catalog.lookup(PDFName.of('OCProperties')) as any).lookup(PDFName.of('OCGs')).lookup(0);
  expect(layer.lookup(PDFName.of('Name')).decodeText()).toBe('Evidence layer');
  const usage = layer.lookup(PDFName.of('Usage'));
  expect(usage.has(PDFName.of('CreatorInfo')) || usage.has(PDFName.of('User'))).toBe(false);
  expect(usage.lookup(PDFName.of('View')).lookup(PDFName.of('ViewState')).asString()).toBe('/ON');
  expect(usage.lookup(PDFName.of('Print')).lookup(PDFName.of('PrintState')).asString()).toBe('/OFF');
  expect(pageText(output, 1)).toBe('Provenance page');
});
