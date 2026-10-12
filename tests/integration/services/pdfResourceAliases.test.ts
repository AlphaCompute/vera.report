import { PDFDocument, PDFDict, PDFName, PDFString, PDFRawStream, decodePDFRawStream } from 'pdf-lib';
import { stripPdfMetadata } from '../../../src/services/pdfMetadata';

const CANARY = 'alias-author-canary';
type Layout = 'page' | 'inherited' | 'form';
type Variant = 'javascript' | 'xfa' | 'annotation' | 'link-action' | 'attachment';

// Dictionary insertion order controls which role a shared object is visited in
// first. Neither ordering may change the sanitizer's security decision.
function first(dict: PDFDict, label: string) {
  const key = PDFName.of(label), value = dict.get(key)!;
  const entries = dict.entries();
  for (const [name] of entries) dict.delete(name);
  dict.set(key, value);
  for (const [name, item] of entries) if (name !== key) dict.set(name, item);
}

async function fixture(variant: Variant, layout: Layout, aliasFirst: boolean) {
  const doc = await PDFDocument.create();
  const page = doc.addPage([100, 100]);
  const ref = (value: Record<string, unknown>) => doc.context.register(doc.context.obj(value as any));
  let maps: Record<string, unknown>;
  let catalogProperty: string | undefined;
  if (variant === 'javascript') {
    const action = ref({ S: 'JavaScript', JS: PDFString.of('void 0') });
    const names = ref({ JavaScript: { Names: [PDFString.of('synthetic'), action] } });
    maps = { Shading: action, Properties: names };
    doc.catalog.set(PDFName.of('Names'), names);
    catalogProperty = 'Names';
  } else if (variant === 'xfa') {
    const form = ref({ Fields: [], XFA: doc.context.register(doc.context.stream('<xdp>synthetic</xdp>')) });
    maps = { ExtGState: form };
    doc.catalog.set(PDFName.of('AcroForm'), form);
    catalogProperty = 'AcroForm';
  } else if (variant === 'annotation') {
    // Indirect strings catch stale reachability: deleting /T is insufficient
    // if a prior resource-map visit leaves its string object in the output.
    const author = doc.context.register(PDFString.of(CANARY));
    const annotation = ref({ Type: 'Annot', Subtype: 'Text', Rect: [0, 0, 10, 10],
      T: author, Contents: PDFString.of('Visible note') });
    maps = { XObject: annotation };
    page.node.set(PDFName.of('Annots'), doc.context.obj([annotation]));
  } else if (variant === 'link-action') {
    const action = ref({ S: 'JavaScript', JS: PDFString.of('void 0') });
    maps = { ExtGState: action };
    const link = ref({ Type: 'Annot', Subtype: 'Link', Rect: [0, 0, 10, 10], A: action });
    page.node.set(PDFName.of('Annots'), doc.context.obj([link]));
  } else {
    const payload = doc.context.register(doc.context.stream('synthetic attachment, never executed'));
    const file = ref({ Type: 'Filespec', F: PDFString.of('synthetic.txt'), EF: { F: payload } });
    const names = ref({ EmbeddedFiles: { Names: [PDFString.of('synthetic.txt'), file] } });
    maps = { XObject: file, Properties: names };
    doc.catalog.set(PDFName.of('Names'), names);
    catalogProperty = 'Names';
  }

  const resources = doc.context.obj(maps as any);
  if (layout === 'inherited') {
    page.node.delete(PDFName.of('Resources'));
    page.node.Parent()!.set(PDFName.of('Resources'), resources);
    if (aliasFirst) first(page.node.Parent()!, 'Resources');
  } else if (layout === 'form') {
    const form = doc.context.register(doc.context.flateStream('q Q', {
      Type: 'XObject', Subtype: 'Form', BBox: [0, 0, 100, 100], Resources: resources,
    }));
    page.node.set(PDFName.of('Resources'), doc.context.obj({ XObject: { Form: form } }));
  } else page.node.set(PDFName.of('Resources'), resources);

  if (catalogProperty) first(doc.catalog, aliasFirst ? 'Pages' : catalogProperty);
  else if (layout !== 'inherited') first(page.node, aliasFirst ? 'Resources' : 'Annots');
  return Buffer.from(await doc.save({ useObjectStreams: true }));
}

describe.each<Layout>(['page', 'inherited', 'form'])('PDF aliases in %s resources', layout => {
  describe.each([true, false])('resource map visited first: %s', aliasFirst => {
    it.each<Variant>(['javascript', 'xfa', 'link-action', 'attachment'])('rejects aliased %s', async variant => {
      await expect(stripPdfMetadata(await fixture(variant, layout, aliasFirst))).rejects.toThrow('No original file');
    });

    it('removes an aliased annotation author and its unreachable indirect string', async () => {
      const output = await stripPdfMetadata(await fixture('annotation', layout, aliasFirst));
      const clean = await PDFDocument.load(output, { updateMetadata: false });
      const annotation = clean.getPage(0).node.Annots()!.lookup(0) as PDFDict;
      expect(annotation.has(PDFName.of('T'))).toBe(false);
      expect((annotation.lookup(PDFName.of('Contents')) as PDFString).decodeText()).toBe('Visible note');
      const decoded = clean.context.enumerateIndirectObjects().map(([, object]) => object instanceof PDFRawStream
        ? Buffer.from(decodePDFRawStream(object).decode()).toString('latin1') + object.dict.toString()
        : object.toString()).join('\n');
      expect(decoded).not.toContain(CANARY);
      expect(decoded.toUpperCase()).not.toContain(Buffer.from(CANARY).toString('hex').toUpperCase());
    });
  });
});

it.each(['Sig', 'Filespec', 'EmbeddedFile'])('checks forbidden /Type %s even when reached only as a resource map', async type => {
  const doc = await PDFDocument.create();
  const page = doc.addPage([100, 100]);
  page.node.set(PDFName.of('Resources'), doc.context.obj({ Font: { Type: type } }));
  await expect(stripPdfMetadata(Buffer.from(await doc.save()))).rejects.toThrow('No original file');
});

it('preserves author-chosen Thumb and Metadata resource names', async () => {
  const doc = await PDFDocument.create();
  const page = doc.addPage([100, 100]);
  const form = doc.context.register(doc.context.flateStream('q Q', { Type: 'XObject', Subtype: 'Form', BBox: [0, 0, 10, 10] }));
  page.node.set(PDFName.of('Resources'), doc.context.obj({ XObject: { Thumb: form, Metadata: form } }));
  const clean = await PDFDocument.load(await stripPdfMetadata(Buffer.from(await doc.save())), { updateMetadata: false });
  const objects = clean.getPage(0).node.Resources()!.lookup(PDFName.of('XObject')) as PDFDict;
  expect(objects.keys().map(key => key.decodeText()).sort()).toEqual(['Metadata', 'Thumb']);
});

// Named resources inside each /Resources map still get semantic metadata removal.
// Only map keys are aliases: values must receive semantic metadata removal.
it.each(['Font', 'XObject', 'ExtGState', 'ColorSpace', 'Pattern', 'Shading', 'Properties'])(
  'removes identity properties from a named resource inside /%s', async resourceMap => {
    const doc = await PDFDocument.create();
    const page = doc.addPage([100, 100]);
    const marker = doc.context.register(PDFString.of(CANARY));
    const resource = doc.context.register(doc.context.obj({
      Type: 'Font', Subtype: 'Type1', BaseFont: 'Helvetica',
      Metadata: marker, PieceInfo: marker, OPI: marker, SpiderInfo: marker, IDS: marker, URLS: marker,
    }));
    page.node.set(PDFName.of('Resources'), doc.context.obj({ [resourceMap]: { F1: resource } }));
    const clean = await PDFDocument.load(await stripPdfMetadata(Buffer.from(await doc.save())), { updateMetadata: false });
    const map = clean.getPage(0).node.Resources()!.lookup(PDFName.of(resourceMap)) as PDFDict;
    const target = map.lookup(PDFName.of('F1')) as PDFDict;
    for (const key of ['Metadata', 'PieceInfo', 'OPI', 'SpiderInfo', 'IDS', 'URLS']) {
      expect(target.has(PDFName.of(key))).toBe(false);
    }
    const objects = clean.context.enumerateIndirectObjects().map(([, object]) => object.toString()).join('\n');
    expect(objects).not.toContain(CANARY);
    expect(objects.toUpperCase()).not.toContain(Buffer.from(CANARY).toString('hex').toUpperCase());
  },
);

// Resource-map names only mean "name map" directly under /Resources or /DR. A
// Pattern's own /Shading entry (or a Shading type's keys) is a semantic
// dictionary, so its identity properties must still be removed.
it.each(['page', 'form-dr'])('removes identity properties from a shading dictionary owned by a pattern (%s)', async where => {
  const doc = await PDFDocument.create();
  const page = doc.addPage([100, 100]);
  const marker = doc.context.register(PDFString.of(CANARY));
  const shading = doc.context.obj({ ShadingType: 2, ColorSpace: 'DeviceRGB', Coords: [0, 0, 100, 0],
    Function: { FunctionType: 2, Domain: [0, 1], C0: [0, 0, 0], C1: [1, 1, 1], N: 1 },
    Metadata: marker, PieceInfo: { Editor: { LastModified: marker } } });
  const pattern = doc.context.register(doc.context.obj({ Type: 'Pattern', PatternType: 2, Shading: shading }));
  if (where === 'page') page.node.set(PDFName.of('Resources'), doc.context.obj({ Pattern: { P1: pattern } }));
  else {
    page.node.set(PDFName.of('Resources'), doc.context.obj({}));
    doc.catalog.set(PDFName.of('AcroForm'), doc.context.obj({ Fields: [], DR: { Pattern: { P1: pattern } } }));
  }
  const output = await stripPdfMetadata(Buffer.from(await doc.save()));
  const clean = await PDFDocument.load(output, { updateMetadata: false });
  const objects = clean.context.enumerateIndirectObjects().map(([, object]) => object instanceof PDFRawStream
    ? Buffer.from(decodePDFRawStream(object).decode()).toString('latin1') + object.dict.toString() : object.toString()).join('\n');
  expect(objects).not.toContain(CANARY);
  expect(objects).not.toContain('/PieceInfo');
  expect(objects).toContain('/ShadingType 2');
});
