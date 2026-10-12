import { PDFDocument, PDFName, PDFString, PDFHexString } from 'pdf-lib';

export async function pdfFixture({ compressed = true, metadata = true, form = false } = {}): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([420, 300]);
  page.drawText('Evidence: the delivery was delayed by two days.', { x: 35, y: 250, size: 12 });
  if (form) {
    const field = doc.getForm().createTextField('incident_reference');
    field.setText('CASE-123'); field.addToPage(page, { x: 35, y: 180, width: 220, height: 24 });
  }
  if (metadata) {
    page.node.addContentStream(doc.context.register(doc.context.flateStream('% identity-canary-page-comment\n')));
    doc.setAuthor('identity-canary-author'); doc.setTitle('identity-canary-title'); doc.setCreator('identity-canary-creator'); doc.setProducer('identity-canary-producer');
    const info = doc.context.lookup(doc.context.trailerInfo.Info) as any;
    info.set(PDFName.of('PrivateSource'), PDFString.of('identity-canary-custom-property'));
    const xmp = doc.context.flateStream('<x:xmpmeta>identity-canary-xmp</x:xmpmeta>', { Type: 'Metadata', Subtype: 'XML' });
    doc.catalog.set(PDFName.of('Metadata'), doc.context.register(xmp));
    page.node.set(PDFName.of('PieceInfo'), doc.context.obj({ PrivateEditor: { LastModified: PDFString.of('identity-canary-private-history') } }));
    const note = doc.context.obj({ Type: 'Annot', Subtype: 'Text', Rect: [35, 90, 50, 105], Contents: PDFString.of('Evidence note remains visible.'), T: PDFString.of('identity-canary-annotation-author'), NM: PDFString.of('identity-canary-note-id'), M: PDFString.of('D:20010101000000Z') });
    const notes = page.node.Annots();
    if (notes) notes.push(doc.context.register(note)); else page.node.set(PDFName.of('Annots'), doc.context.obj([doc.context.register(note)]));
    doc.context.trailerInfo.ID = doc.context.obj([PDFHexString.fromText('identity-canary-document-id'), PDFHexString.fromText('identity-canary-document-id')]);
    // Orphaned objects used to survive regex edits and are still serialized by
    // pdf-lib unless the sanitizer performs reachability pruning.
    doc.context.register(doc.context.obj({ OldIdentity: PDFString.of('identity-canary-orphan') }));
  }
  return doc.save({ useObjectStreams: compressed });
}

/** A genuine incremental update retains old Info bytes plus a newer revision. */
export function appendIncrementalInfo(input: Uint8Array): Buffer {
  const original = Buffer.from(input); const source = original.toString('latin1');
  const info = /\/Info\s+(\d+)\s+0\s+R/.exec(source)![1];
  const root = /\/Root\s+(\d+)\s+0\s+R/.exec(source)![1];
  const size = /\/Size\s+(\d+)/.exec(source)![1];
  const previous = /startxref\s+(\d+)\s+%%EOF/.exec(source)![1];
  const object = Buffer.from(`\n${info} 0 obj\n<< /Author (identity-canary-latest-revision) >>\nendobj\n`);
  const offset = original.length + 1;
  const xref = original.length + object.length;
  return Buffer.concat([original, object, Buffer.from(`xref\n${info} 1\n${String(offset).padStart(10, '0')} 00000 n \ntrailer\n<< /Size ${size} /Root ${root} 0 R /Info ${info} 0 R /Prev ${previous} >>\nstartxref\n${xref}\n%%EOF\n`)]);
}
