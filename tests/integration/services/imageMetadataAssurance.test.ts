/**
 * Adversarial JPEG/PNG/WebP assurance (#564): real encoded images carrying
 * nested metadata canaries go through the production stripper, and the output
 * is checked with independent decoders (libvips via sharp, ExifReader) plus a
 * raw byte scan. Pixels must decode and match; no canary may survive.
 */
import sharp from 'sharp';
import ExifReader from 'exifreader';
import { crc32, deflateSync } from 'node:zlib';
import EvidenceEncryptionService from '../../../src/services/evidenceEncryption';


const service = new EvidenceEncryptionService();
const strip = (input: Buffer, type: string) => service.stripFileMetadata(input, type);
const CANARY = 'identity-canary';

const base = (format: 'jpeg' | 'png' | 'webp', options: sharp.SharpOptions = {}) =>
  sharp({ create: { width: 48, height: 32, channels: 3, background: { r: 180, g: 40, b: 90 } }, ...options })
    .composite([{ input: { create: { width: 16, height: 16, channels: 3, background: { r: 10, g: 200, b: 30 } } }, left: 8, top: 8 }]);

const pixels = (input: Buffer) => sharp(input).raw().toBuffer();

function expectNoCanary(output: Buffer) {
  expect(output.toString('latin1')).not.toContain(CANARY);
  expect(output.toString('utf16le')).not.toContain(CANARY);
}

function jpegSegment(marker: number, body: Buffer): Buffer {
  const header = Buffer.from([0xff, marker, 0, 0]);
  header.writeUInt16BE(body.length + 2, 2);
  return Buffer.concat([header, body]);
}

/** Minimal little-endian EXIF APP1 whose IFD1 carries a real JPEG thumbnail. */
function exifWithThumbnail(thumbnail: Buffer): Buffer {
  const ifd0 = Buffer.alloc(2 + 12 + 4);
  ifd0.writeUInt16LE(1, 0);
  ifd0.writeUInt16LE(0x013b, 2); ifd0.writeUInt16LE(2, 4); // Artist, ASCII
  const artist = Buffer.from(`${CANARY}-exif-artist\0`);
  ifd0.writeUInt32LE(artist.length, 6);
  const artistOffset = 8 + ifd0.length;
  ifd0.writeUInt32LE(artistOffset, 10);
  const ifd1Offset = artistOffset + artist.length;
  ifd0.writeUInt32LE(ifd1Offset, 14);
  const ifd1 = Buffer.alloc(2 + 24 + 4);
  ifd1.writeUInt16LE(2, 0);
  ifd1.writeUInt16LE(0x0201, 2); ifd1.writeUInt16LE(4, 4); ifd1.writeUInt32LE(1, 6);
  ifd1.writeUInt32LE(ifd1Offset + ifd1.length, 10); // JPEGInterchangeFormat
  ifd1.writeUInt16LE(0x0202, 14); ifd1.writeUInt16LE(4, 16); ifd1.writeUInt32LE(1, 18);
  ifd1.writeUInt32LE(thumbnail.length, 22); // JPEGInterchangeFormatLength
  const tiff = Buffer.concat([Buffer.from('II*\0\x08\0\0\0', 'latin1'), ifd0, artist, ifd1, thumbnail]);
  return jpegSegment(0xe1, Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]));
}

function pngChunk(type: string, data: Buffer): Buffer {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'latin1');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

/** Insert chunks immediately after IHDR. */
const withPngChunks = (png: Buffer, chunks: Buffer[]) =>
  Buffer.concat([png.subarray(0, 33), ...chunks, png.subarray(33)]);

function webpChunk(fourcc: string, data: Buffer): Buffer {
  const header = Buffer.alloc(8);
  header.write(fourcc, 0, 'latin1');
  header.writeUInt32LE(data.length, 4);
  return Buffer.concat([header, data, Buffer.alloc(data.length % 2)]);
}

function riff(chunks: Buffer[]): Buffer {
  const payload = Buffer.concat(chunks);
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'latin1'); header.writeUInt32LE(4 + payload.length, 4); header.write('WEBP', 8, 'latin1');
  return Buffer.concat([header, payload]);
}

function webpChunks(webp: Buffer): { fourcc: string; data: Buffer }[] {
  const chunks = [];
  for (let at = 12; at + 8 <= webp.length;) {
    const size = webp.readUInt32LE(at + 4);
    chunks.push({ fourcc: webp.subarray(at, at + 4).toString('latin1'), data: webp.subarray(at + 8, at + 8 + size) });
    at += 8 + size + (size % 2);
  }
  return chunks;
}

describe('JPEG', () => {
  it('removes EXIF with GPS, the IFD1 thumbnail, XMP, ICC, MPF and trailing secondary images', async () => {
    const thumbnail = Buffer.concat([
      Buffer.from([0xff, 0xd8]), jpegSegment(0xfe, Buffer.from(`${CANARY}-thumbnail-comment`)),
      (await sharp({ create: { width: 8, height: 8, channels: 3, background: 'blue' } }).jpeg().toBuffer()).subarray(2),
    ]);
    const tagged = await base('jpeg')
      .withExif({ IFD0: { Make: `${CANARY}-make` }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '51/1 30/1 0/1' } })
      .withXmp(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>${CANARY}-xmp</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>`)
      .jpeg({ quality: 95 }).toBuffer();
    const icc = jpegSegment(0xe2, Buffer.concat([Buffer.from('ICC_PROFILE\0\x01\x01', 'latin1'), Buffer.from(`${CANARY}-icc-profile-description`)]));
    const mpf = jpegSegment(0xe2, Buffer.concat([Buffer.from('MPF\0', 'latin1'), Buffer.from(`${CANARY}-mpf-index`)]));
    const secondary = Buffer.concat([Buffer.from([0xff, 0xd8]), jpegSegment(0xfe, Buffer.from(`${CANARY}-secondary`)), Buffer.from([0xff, 0xd9])]);
    const input = Buffer.concat([tagged.subarray(0, 2), exifWithThumbnail(thumbnail), icc, mpf, tagged.subarray(2), secondary]);

    // The fixture is real to independent parsers, not just bytes that look like metadata.
    // (ExifReader reads one APP1, so check the thumbnail segment on its own.)
    const plain = await base('jpeg').jpeg().toBuffer();
    const thumbnailOnly = ExifReader.load(Buffer.concat([plain.subarray(0, 2), exifWithThumbnail(thumbnail), plain.subarray(2)]), { expanded: true }) as any;
    expect(thumbnailOnly.Thumbnail?.image).toBeDefined();
    expect((ExifReader.load(tagged, { expanded: true }) as any).gps?.Latitude).toBeCloseTo(51.5);
    const tags = await sharp(tagged).metadata();
    expect([tags.exif, tags.xmp].every(Boolean)).toBe(true);

    const output = await strip(input, 'image/jpeg');
    expectNoCanary(output);
    const after = await sharp(output).metadata();
    expect([after.exif, after.xmp, after.icc]).toEqual([undefined, undefined, undefined]);
    expect(() => ExifReader.load(output, { expanded: true })).not.toThrow();
    const reread = ExifReader.load(output, { expanded: true }) as any;
    expect(reread.gps).toBeUndefined();
    expect(reread.Thumbnail).toBeUndefined();
    expect([after.width, after.height]).toEqual([48, 32]);
    // Same entropy-coded data and tables: decoded evidence is identical.
    expect(await pixels(output)).toEqual(await pixels(tagged));
  });

  it('keeps the Adobe colour transform so CMYK evidence decodes to the same pixels', async () => {
    const cmyk = await base('jpeg').toColourspace('cmyk').jpeg({ quality: 95 }).toBuffer();
    expect(cmyk.includes(Buffer.from('Adobe', 'latin1'))).toBe(true);
    const output = await strip(Buffer.concat([cmyk.subarray(0, 2), jpegSegment(0xfe, Buffer.from(`${CANARY}-comment`)), cmyk.subarray(2)]), 'image/jpeg');
    expectNoCanary(output);
    expect(await pixels(output)).toEqual(await pixels(cmyk));
  });

  it('accepts a 50-megapixel phone photo', async () => {
    const photo = await sharp({ create: { width: 8160, height: 6120, channels: 3, background: { r: 90, g: 110, b: 130 } } })
      .withExif({ IFD0: { Make: `${CANARY}-phone` } }).jpeg({ quality: 80 }).toBuffer();
    const output = await strip(photo, 'image/jpeg');
    expectNoCanary(output);
    expect((await sharp(output).metadata()).width).toBe(8160);
  });

  it('rejects a pixel bomb and undecodable image data without returning original bytes', async () => {
    const jpeg = await base('jpeg').jpeg().toBuffer();
    const sof = jpeg.indexOf(Buffer.from([0xff, 0xc0]));
    const bomb = Buffer.from(jpeg);
    bomb.writeUInt16BE(60000, sof + 5); bomb.writeUInt16BE(60000, sof + 7);
    await expect(strip(bomb, 'image/jpeg')).rejects.toThrow('No original file was accepted');

    // A bogus Huffman table is a decoder error, not a recoverable warning.
    const dht = jpeg.indexOf(Buffer.from([0xff, 0xc4]));
    const corrupt = Buffer.from(jpeg);
    corrupt.fill(0xff, dht + 5, dht + 21);
    await expect(strip(corrupt, 'image/jpeg')).rejects.toThrow('No original file was accepted');
  });
});

describe('PNG', () => {
  it('removes tEXt, zTXt, iTXt, tIME, iCCP and eXIf GPS while preserving exact pixels', async () => {
    const png = await base('png').png().toBuffer();
    const exif = (await base('jpeg').withExif({ IFD0: { Artist: `${CANARY}-png-exif` }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '51/1 30/1 0/1' } }).jpeg().toBuffer());
    const app1 = exif.indexOf(Buffer.from('Exif\0\0', 'latin1'));
    const tiff = exif.subarray(app1 + 6, app1 - 2 + exif.readUInt16BE(app1 - 2));
    const input = withPngChunks(png, [
      pngChunk('tEXt', Buffer.from(`Author\0${CANARY}-text`, 'latin1')),
      pngChunk('zTXt', Buffer.concat([Buffer.from('Comment\0\0', 'latin1'), deflateSync(Buffer.from(`${CANARY}-compressed`))])),
      pngChunk('iTXt', Buffer.concat([Buffer.from('XML:com.adobe.xmp\0\0\0\0\0', 'latin1'), Buffer.from(`<x:xmpmeta>${CANARY}-itxt-xmp</x:xmpmeta>`)])),
      pngChunk('tIME', Buffer.from([0x07, 0xea, 9, 27, 12, 0, 0])),
      pngChunk('iCCP', Buffer.concat([Buffer.from(`${CANARY}\0\0`, 'latin1'), deflateSync(Buffer.from('not-a-real-profile'))])),
      pngChunk('eXIf', tiff),
    ]);
    const before = await sharp(input).metadata();
    expect(before.comments?.some(c => c.text.includes(CANARY))).toBe(true);
    expect((ExifReader.load(input, { expanded: true }) as any).gps?.Latitude).toBeCloseTo(51.5);

    const output = await strip(input, 'image/png');
    expectNoCanary(output);
    const after = await sharp(output).metadata();
    expect([after.comments, after.exif, after.icc, after.xmp]).toEqual([undefined, undefined, undefined, undefined]);
    for (const type of ['tEXt', 'zTXt', 'iTXt', 'tIME', 'iCCP', 'eXIf']) expect(output.includes(Buffer.from(type, 'latin1'))).toBe(false);
    expect(await pixels(output)).toEqual(await pixels(png));
  });

  it('rejects a dimension bomb and corrupt compressed image data', async () => {
    const png = await base('png').png().toBuffer();
    const ihdr = Buffer.from(png.subarray(16, 29));
    ihdr.writeUInt32BE(20000, 0); ihdr.writeUInt32BE(20000, 4);
    const bomb = Buffer.concat([png.subarray(0, 8), pngChunk('IHDR', ihdr), png.subarray(33)]);
    await expect(strip(bomb, 'image/png')).rejects.toThrow('No original file was accepted');

    const idat = png.indexOf(Buffer.from('IDAT', 'latin1')) - 4;
    const data = Buffer.from(png.subarray(idat + 8, idat + 8 + png.readUInt32BE(idat)));
    data.fill(0xaa, 2, data.length - 4);
    const corrupt = Buffer.concat([png.subarray(0, idat), pngChunk('IDAT', data), png.subarray(idat + 12 + data.length)]);
    await expect(strip(corrupt, 'image/png')).rejects.toThrow('No original file was accepted');
  });
});

describe('WebP', () => {
  it('removes EXIF, XMP, ICCP and unknown chunks from a real extended WebP and still decodes it', async () => {
    const tagged = await base('webp')
      .withExif({ IFD0: { Artist: `${CANARY}-webp-exif` }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '51/1 30/1 0/1' } })
      .withXmp(`<x:xmpmeta xmlns:x="adobe:ns:meta/">${CANARY}-webp-xmp</x:xmpmeta>`)
      .webp({ lossless: true }).toBuffer();
    const chunks = webpChunks(tagged);
    expect(chunks.map(c => c.fourcc)).toEqual(expect.arrayContaining(['VP8X', 'EXIF', 'XMP ']));
    const vp8x = Buffer.from(chunks[0].data); vp8x[0] |= 0x20; // declare ICCP
    const input = riff([webpChunk('VP8X', vp8x), webpChunk('ICCP', Buffer.from(`${CANARY}-iccp-profile`)),
      ...chunks.slice(1).map(c => webpChunk(c.fourcc, c.data)), webpChunk('ZZZZ', Buffer.from(`${CANARY}-unknown-chunk`))]);
    expect((ExifReader.load(input, { expanded: true }) as any).gps?.Latitude).toBeCloseTo(51.5);

    const output = await strip(input, 'image/webp');
    expectNoCanary(output);
    expect(webpChunks(output).map(c => c.fourcc)).toEqual(['VP8X', 'VP8L']);
    const after = await sharp(output).metadata();
    expect([after.exif, after.xmp, after.icc]).toEqual([undefined, undefined, undefined]);
    expect(await pixels(output)).toEqual(await pixels(await base('webp').webp({ lossless: true }).toBuffer()));
  });

  it('keeps animation frames and flags while removing metadata', async () => {
    const frames = Buffer.alloc(16 * 48 * 4);
    for (let i = 0; i < frames.length; i += 4) frames.set([i % 255, 90, (i >> 6) % 255, 255], i);
    const source = await sharp(frames, { raw: { width: 16, height: 48, channels: 4, pageHeight: 16 } })
      .webp({ lossless: true, loop: 0, delay: [100, 100, 100] }).toBuffer();
    const chunks = webpChunks(source);
    expect(chunks.map(c => c.fourcc)).toContain('ANMF');
    const vp8x = Buffer.from(chunks[0].data); vp8x[0] |= 0x04; // declare XMP
    const input = riff([webpChunk('VP8X', vp8x), ...chunks.slice(1).map(c => webpChunk(c.fourcc, c.data)), webpChunk('XMP ', Buffer.from(`${CANARY}-anim-xmp`))]);

    const output = await strip(input, 'image/webp');
    expectNoCanary(output);
    expect(output[20] & 0x02).toBe(0x02); // animation
    expect(output[20] & 0x04).toBe(0);    // XMP
    expect((await sharp(output, { pages: -1 }).metadata()).pages).toBe(3);
  });

  it('drops unknown sub-chunks inside animation frames and decodes every frame', async () => {
    const frames = Buffer.alloc(16 * 48 * 4);
    for (let i = 0; i < frames.length; i += 4) frames.set([i % 255, 90, (i >> 6) % 255, 255], i);
    const source = await sharp(frames, { raw: { width: 16, height: 48, channels: 4, pageHeight: 16 } })
      .webp({ lossless: true, loop: 0, delay: [100, 100, 100] }).toBuffer();
    const chunks = webpChunks(source);
    const withHidden = chunks.map(c => c.fourcc !== 'ANMF' ? webpChunk(c.fourcc, c.data)
      : webpChunk('ANMF', Buffer.concat([c.data, webpChunk('ZZZZ', Buffer.from(`${CANARY}-frame-subchunk`))])));
    const output = await strip(riff(withHidden), 'image/webp');
    expectNoCanary(output);
    expect((await sharp(output, { pages: -1 }).metadata()).pages).toBe(3);
    expect(await sharp(output, { pages: -1 }).raw().toBuffer()).toEqual(await sharp(source, { pages: -1 }).raw().toBuffer());

    // Corrupting only the last frame must fail verification, not just frame one.
    const last = chunks.map(c => Buffer.from(c.data));
    const lastFrame = last.map((d, i) => chunks[i].fourcc === 'ANMF' ? i : -1).filter(i => i >= 0).pop()!;
    last[lastFrame].fill(0xaa, 16 + 8 + 5);
    await expect(strip(riff(chunks.map((c, i) => webpChunk(c.fourcc, last[i]))), 'image/webp'))
      .rejects.toThrow('No original file was accepted');
  });

  it('rejects a canvas bomb', async () => {
    const tagged = await base('webp').withExif({ IFD0: { Artist: 'x' } }).webp({ lossless: true }).toBuffer();
    const chunks = webpChunks(tagged);
    const vp8x = Buffer.from(chunks[0].data);
    vp8x.writeUIntLE(16382, 4, 3); vp8x.writeUIntLE(16382, 7, 3);
    await expect(strip(riff([webpChunk('VP8X', vp8x), ...chunks.slice(1).map(c => webpChunk(c.fourcc, c.data))]), 'image/webp'))
      .rejects.toThrow('No original file was accepted');
  });
});
