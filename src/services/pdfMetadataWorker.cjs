const { parentPort, workerData } = require('node:worker_threads');
const { PDFDocument, PDFDict, PDFArray, PDFRef, PDFName, PDFRawStream, decodePDFRawStream } = require('pdf-lib');

// Metadata removal operates on parsed objects, including compressed object
// streams. Unsupported active/embedded content is rejected, never flattened.
const forbidden = new Set(['EmbeddedFiles', 'EF', 'AF', 'XFA', 'JavaScript', 'JS', 'OpenAction', 'AA', 'ByteRange', 'RichMediaContent']);
// Identity-bearing properties removed wherever they occur: XMP, application
// editing data, OPI original-file references and web-capture provenance.
const removed = new Set(['Metadata', 'PieceInfo', 'LastModified', 'OPI', 'SpiderInfo', 'IDS', 'URLS']);
// Removed only on dictionaries of the given /Type: page thumbnails (regenerable
// previews with their own JPEG metadata) and web-capture source URLs.
const removedByType = { Page: new Set(['Thumb']), SpiderContentSet: new Set(['SI']) };
// Optional-content usage keeps view/print/zoom/export state (which drives layer
// visibility) and loses only the creator application and user names.
const usageIdentity = ['CreatorInfo', 'User'];
// Inside a resource dictionary (a /Resources or AcroForm /DR value), keys of these
// entries are resource names chosen by the author, not PDF properties, so a
// resource called /Thumb or /Metadata must not be deleted. The same key names
// elsewhere (e.g. a Pattern's own /Shading) are ordinary semantic dictionaries.
const resourceMaps = new Set(['XObject', 'Font', 'ExtGState', 'ColorSpace', 'Pattern', 'Shading', 'Properties']);
const resourceDictionaries = new Set(['Resources', 'DR']);
// Visit roles. A resource dictionary is semantic (its own keys are fixed names);
// only its resource-map entries are name maps.
const SEMANTIC = 0, NAME_MAP = 1, RESOURCES = 2;
const annotationProperties = new Set(['T', 'M', 'CreationDate', 'NM', 'Subj']);
const annotationSubtypes = new Set(['Text', 'Link', 'FreeText', 'Line', 'Square', 'Circle', 'Polygon', 'PolyLine', 'Highlight', 'Underline', 'Squiggly', 'StrikeOut', 'Stamp', 'Caret', 'Ink', 'Popup', 'Widget', 'PrinterMark', 'TrapNet', 'Watermark', 'Redact']);
const unsupportedSubtypes = new Set(['FileAttachment', 'Sound', 'Movie', 'RichMedia', '3D']);

// Embedded JPEG metadata is a separate container. Retain its exact encoded
// pixels only when it has no private segments or trailing bytes; otherwise
// reject the PDF rather than quietly retain EXIF or change image evidence.
function safeJpeg(bytes) {
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return false;
  let at = 2, entropy = false;
  while (at < bytes.length) {
    if (entropy) {
      if (bytes[at++] !== 0xff) continue;
      const start = at - 1;
      while (bytes[at] === 0xff) at++;
      if (bytes[at] === 0 || (bytes[at] >= 0xd0 && bytes[at] <= 0xd7)) { at++; continue; }
      at = start; entropy = false;
    }
    if (bytes[at++] !== 0xff) return false;
    while (bytes[at] === 0xff) at++;
    const marker = bytes[at++];
    if (marker === 0xd9) return at === bytes.length;
    if (at + 2 > bytes.length) return false;
    const size = bytes[at] * 256 + bytes[at + 1];
    if (size < 2 || at + size > bytes.length) return false;
    const body = bytes.subarray(at + 2, at + size);
    if (marker === 0xfe) return false;
    if (marker >= 0xe0 && marker <= 0xef) {
      const tag = Buffer.from(body.subarray(0, 5)).toString('ascii');
      if (marker === 0xe0) { if (tag !== 'JFIF\0' || body.length !== 14 || body[12] || body[13]) return false; }
      else if (marker === 0xee) { if (tag !== 'Adobe' || body.length !== 12) return false; }
      else return false;
    }
    at += size;
    if (marker === 0xda) entropy = true;
  }
  return false;
}

function assertNoInlineImages(bytes) {
  // Lex content tokens, skipping names, comments, strings and hex strings.
  // Inline image containers need their own metadata analysis; reject them
  // instead of mistaking embedded bytes for ordinary page operators.
  const clean = Buffer.from(bytes);
  const text = clean.toString('latin1');
  const delimiter = c => !c || /[\s()[\]<>/{%}]/.test(c);
  for (let at = 0; at < text.length;) {
    const ch = text[at++];
    if (ch === '%') { const start = at - 1; while (at < text.length && !/[\r\n]/.test(text[at])) at++; clean.fill(32, start, at); continue; }
    if (ch === '(') {
      let depth = 1;
      while (at < text.length && depth) { const next = text[at++]; if (next === '\\') at++; else if (next === '(') depth++; else if (next === ')') depth--; }
      continue;
    }
    if (ch === '<') { if (text[at] === '<') at++; else { while (at < text.length && text[at++] !== '>') {} } continue; }
    if (ch === '/') { while (!delimiter(text[at])) at++; continue; }
    if (delimiter(ch)) continue;
    const start = at - 1; while (!delimiter(text[at])) at++;
    if (text.slice(start, at) === 'BI') throw Error('Inline image requires separate sanitization');
  }
  return clean;
}

/**
 * Return reserialized PDF bytes after removing supported metadata properties,
 * page/form comments, and unreachable objects. Custom properties outside the
 * removal rules can remain; embedded JPEGs are checked without decoding pixels.
 * Accepts 1-200 pages and at most 50,000 indirect objects, with 20 MiB limits
 * on cumulative decoded page/form content and serialized output.
 * @throws {Error} For unsupported content or exceeded limits; parser, decoder,
 * and serialization errors also propagate. The worker entry point converts
 * rejections to an { ok: false } message without exposing error details.
 */
async function sanitize(input) {
  const doc = await PDFDocument.load(input, { updateMetadata: false, throwOnInvalidObject: true });
  if (!doc.getPageCount() || doc.getPageCount() > 200) throw Error('Unsupported page count');
  if (doc.context.enumerateIndirectObjects().length > 50000) throw Error('Too many objects');
  // Bound retained copies across the entire document, including repeated raw
  // stream references that need no decoder allocation and would bypass that budget.
  let contentBytes = 0;
  const boundedContent = stream => {
    const bytes = decodePDFRawStream(stream).decode();
    contentBytes += bytes.length;
    if (contentBytes > 20 * 1024 * 1024) throw Error('Document content too large');
    return bytes;
  };
  for (const page of doc.getPages()) {
    const contents = page.node.Contents();
    const streams = contents instanceof PDFArray ? contents.asArray().map(ref => doc.context.lookup(ref)) : contents ? [contents] : [];
    const decoded = streams.map(stream => { if (!(stream instanceof PDFRawStream)) throw Error('Invalid page stream'); return Buffer.from(boundedContent(stream)); });
    if (decoded.length) page.node.set(PDFName.of('Contents'), doc.context.register(doc.context.flateStream(assertNoInlineImages(Buffer.concat(decoded)))));
  }
  // Removing the trailer reference alone is insufficient: the old Info object
  // would still be written unless unreachable objects are discarded below.
  delete doc.context.trailerInfo.Info;
  delete doc.context.trailerInfo.ID;
  // Article-thread info (/I: Title, Author, …) is removed before the walk so the
  // info dictionary is never reached and is pruned below. Threads need not carry
  // /Type; they are found through the catalog and through page beads.
  const threads = [];
  const catalogThreads = doc.catalog.lookup(PDFName.of('Threads'));
  if (catalogThreads instanceof PDFArray) threads.push(...catalogThreads.asArray());
  for (const page of doc.getPages()) {
    const beads = page.node.lookup(PDFName.of('B'));
    if (beads instanceof PDFArray) for (const bead of beads.asArray()) {
      const beadDict = doc.context.lookup(bead);
      if (beadDict instanceof PDFDict) threads.push(beadDict.get(PDFName.of('T')));
    }
  }
  for (const ref of threads) {
    const thread = ref && doc.context.lookup(ref);
    if (thread instanceof PDFDict) thread.delete(PDFName.of('I'));
  }
  // A dictionary can be both a resource-name map and a semantic object (for
  // example an annotation or AcroForm). A visit in one role must never suppress
  // checks or metadata removal required by a later visit in the other role.
  const reached = [new Set(), new Set(), new Set()];
  const seen = [new Set(), new Set(), new Set()];
  /**
   * Sanitize reachable objects in place and reject unsupported content.
   * @param role - SEMANTIC, NAME_MAP (keys are resource names: preserved, but
   * still checked for forbidden content) or RESOURCES (a /Resources or /DR
   * dictionary whose resource-map entries are name maps). Streams are semantic.
   * @throws {Error} For missing references, unsupported content, or content limits;
   * lookup and stream-decoding errors also propagate.
   */
  function walk(object, role = SEMANTIC) {
    // Streams are always semantic objects, even if a malformed resource map
    // points directly to one. Process their content/budget only once.
    if (object instanceof PDFRawStream) role = SEMANTIC;
    const mode = role;
    const resourceMap = role === NAME_MAP;
    if (object instanceof PDFRef) {
      const key = object.toString();
      if (reached[mode].has(key)) return;
      reached[mode].add(key);
      const target = doc.context.lookup(object);
      if (!target) throw Error('Missing referenced object');
      walk(target, role); return;
    }
    if (!object || seen[mode].has(object)) return;
    seen[mode].add(object);
    if (object instanceof PDFArray) { for (let i = 0; i < object.size(); i++) walk(object.get(i)); return; }
    const dict = object instanceof PDFRawStream ? object.dict : object;
    if (!(dict instanceof PDFDict)) return;
    // Resource names are exempt from property deletion, never from the
    // fail-closed active-content/type checks. Aliasing cannot hide JS, XFA,
    // signatures or file references from those checks.
    const name = key => { const value = dict.lookup(PDFName.of(key)); return value instanceof PDFName ? value.decodeText() : ''; };
    const subtype = name('Subtype');
    if (['JavaScript', 'Launch', 'Rendition', 'GoToE', 'GoToR', 'ImportData', 'SubmitForm', 'ResetForm', 'Hide', 'Named', 'SetOCGState', 'Thread', 'Trans', 'GoTo3DView', 'Sound', 'Movie'].includes(name('S')) || name('Type') === 'Filespec') throw Error('Unsupported action or file reference');
    if (object instanceof PDFRawStream) {
      if (dict.has(PDFName.of('F'))) throw Error('External stream is unsupported');
      if (subtype === 'Form') {
        const bytes = boundedContent(object);
        const replacement = doc.context.flateStream(assertNoInlineImages(bytes));
        object.contents = replacement.contents;
        dict.delete(PDFName.of('DecodeParms'));
        dict.set(PDFName.of('Filter'), PDFName.of('FlateDecode'));
      }
      if (name('Filter') === 'JPXDecode') throw Error('Embedded JPEG2000 metadata requires separate sanitization');
    }
    // Any DCT stream is a JPEG container, whatever its Subtype says.
    if (object instanceof PDFRawStream) {
      const filter = dict.lookup(PDFName.of('Filter'));
      if (filter instanceof PDFName && ['DCTDecode', 'DCT'].includes(filter.decodeText()) && !safeJpeg(object.getContents())) throw Error('Embedded JPEG metadata requires separate sanitization');
      if (filter instanceof PDFArray && filter.asArray().some(ref => {
        const value = doc.context.lookup(ref);
        if (!(value instanceof PDFName)) throw Error('Invalid image filter');
        return ['DCTDecode', 'DCT', 'JPXDecode'].includes(value.decodeText());
      })) throw Error('Unsupported image filter chain');
    }
    if (name('Type') === 'Sig' || name('FT') === 'Sig' || unsupportedSubtypes.has(subtype) || name('Type') === 'EmbeddedFile') throw Error('Unsupported embedded or signed content');
    const typeRemoved = removedByType[name('Type')];
    for (const [key, value] of dict.entries()) {
      const label = key.decodeText();
      if (forbidden.has(label)) throw Error('Unsupported active or attached content');
      // Widget /T is the interactive field name, not an annotation author.
      if (!resourceMap && (removed.has(label) || typeRemoved?.has(label) || ((name('Type') === 'Annot' || annotationSubtypes.has(subtype)) && annotationProperties.has(label) && !(subtype === 'Widget' && label === 'T')))) {
        dict.delete(key); continue;
      }
      if (!resourceMap && label === 'Usage') {
        const usage = dict.lookup(key);
        if (usage instanceof PDFDict) for (const identity of usageIdentity) usage.delete(PDFName.of(identity));
      }
      // Values of a resource-name map are resources, regardless of their names.
      walk(value, role === RESOURCES && resourceMaps.has(label) ? NAME_MAP
        : role !== NAME_MAP && resourceDictionaries.has(label) ? RESOURCES : SEMANTIC);
    }
  }
  walk(doc.context.trailerInfo.Root);
  // Sanitization may remove an edge after a different role already visited its
  // target (e.g. an indirect annotation author). Recompute reachability from the
  // final graph so those stale visits cannot preserve orphaned private objects.
  const retained = new Set();
  const retainedObjects = new Set();
  /**
   * Record references reachable in the sanitized graph for orphan removal.
   * @throws {Error} If a reference cannot be resolved; lookup errors propagate.
   */
  function retain(object) {
    if (object instanceof PDFRef) {
      const key = object.toString();
      if (retained.has(key)) return;
      retained.add(key);
      const target = doc.context.lookup(object);
      if (!target) throw Error('Missing referenced object');
      retain(target); return;
    }
    if (!object || retainedObjects.has(object)) return;
    retainedObjects.add(object);
    if (object instanceof PDFArray) { for (let i = 0; i < object.size(); i++) retain(object.get(i)); return; }
    const dict = object instanceof PDFRawStream ? object.dict : object;
    if (dict instanceof PDFDict) for (const [, value] of dict.entries()) retain(value);
  }
  retain(doc.context.trailerInfo.Root);
  for (const [ref] of doc.context.enumerateIndirectObjects()) if (!retained.has(ref.toString())) doc.context.delete(ref);
  const output = await doc.save({ useObjectStreams: true, addDefaultPage: false, updateFieldAppearances: false, objectsPerTick: 50 });
  if (output.length > 20 * 1024 * 1024) throw Error('Output too large');
  return output;
}

module.exports = { sanitize };
if (parentPort) {
  sanitize(workerData).then(output => {
    parentPort.postMessage({ ok: true, data: output }, [output.buffer]);
    parentPort.close();
  }).catch(() => { parentPort.postMessage({ ok: false }); parentPort.close(); });
}
