import { crc32 } from 'node:zlib';
import sharp from 'sharp';
import { tiffFixture } from '../../helpers/tiffFixture';
import { PDFDocument } from 'pdf-lib';
import { pdfFixture } from '../../helpers/pdfFixture';
import EvidenceEncryptionService from '../../../src/services/evidenceEncryption';


/**
 * Build a minimal valid JPEG buffer that includes an APP1 (EXIF) segment
 * with a GPS IFD pointer (tag 0x8825) so both hasEXIF and hasGPS detect it.
 */
function buildJpegWithExifAndGps(): Buffer {
  // SOI
  const soi = Buffer.from([0xFF, 0xD8]);

  // APP1 marker (EXIF)
  const exifHeader = Buffer.from('457869660000', 'hex'); // "Exif\0\0"
  // Minimal TIFF header (big-endian) with GPS IFD tag 0x8825
  const tiffHeader = Buffer.from([
    0x4D, 0x4D, // big-endian ("MM")
    0x00, 0x2A, // TIFF magic
    0x00, 0x00, 0x00, 0x08, // offset to first IFD
    // IFD with 1 entry
    0x00, 0x01, // 1 entry
    0x88, 0x25, // tag 0x8825 (GPS IFD) in BE
    0x00, 0x04, // type LONG
    0x00, 0x00, 0x00, 0x01, // count 1
    0x00, 0x00, 0x00, 0x00, // value (offset placeholder)
    0x00, 0x00, 0x00, 0x00, // next IFD offset (none)
  ]);
  const exifPayload = Buffer.concat([exifHeader, tiffHeader]);
  const app1Length = Buffer.alloc(2);
  app1Length.writeUInt16BE(exifPayload.length + 2, 0);
  const app1 = Buffer.concat([Buffer.from([0xFF, 0xE1]), app1Length, exifPayload]);

  // DQT (quantization table) — minimal valid
  const dqt = Buffer.from([
    0xFF, 0xDB, 0x00, 0x43, 0x00,
    ...Array(64).fill(0x01),
  ]);

  // SOF0 (start of frame) — 1x1 pixel, 1 component
  const sof = Buffer.from([
    0xFF, 0xC0, 0x00, 0x0B, 0x08,
    0x00, 0x01, // height 1
    0x00, 0x01, // width 1
    0x01,       // 1 component
    0x01, 0x11, 0x00,
  ]);

  // DHT (Huffman table) — minimal DC table
  const dht = Buffer.from([
    0xFF, 0xC4, 0x00, 0x1F, 0x00,
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
  ]);

  // SOS (start of scan) + minimal scan data + EOI
  const sos = Buffer.from([
    0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
    0x7B, 0x40, // minimal entropy-coded data
    0xFF, 0xD9, // EOI
  ]);

  return Buffer.concat([soi, app1, dqt, sof, dht, sos]);
}

/**
 * Build a minimal JPEG without any EXIF/APP1 segment.
 */
function buildJpegWithoutExif(): Buffer {
  const soi = Buffer.from([0xFF, 0xD8]);
  const dqt = Buffer.from([
    0xFF, 0xDB, 0x00, 0x43, 0x00,
    ...Array(64).fill(0x01),
  ]);
  const sof = Buffer.from([
    0xFF, 0xC0, 0x00, 0x0B, 0x08,
    0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
  ]);
  const dht = Buffer.from([
    0xFF, 0xC4, 0x00, 0x1F, 0x00,
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
  ]);
  const sos = Buffer.from([
    0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
    0x7B, 0x40,
    0xFF, 0xD9,
  ]);
  return Buffer.concat([soi, dqt, sof, dht, sos]);
}

// ─── PNG fixture builders ───

/** Helper: build a single PNG chunk (type + data → length + type + data + CRC) */
function pngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeB = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeB, data])), 0);
  return Buffer.concat([len, typeB, data, crc]);
}

/**
 * Build a minimal PNG with tEXt and eXIf metadata chunks.
 */
function buildPngWithMetadata(): Buffer {
  const sig = Buffer.from('89504e470d0a1a0a', 'hex'); // PNG signature

  // IHDR: 1x1, 8-bit RGB
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(1, 0);  // width
  ihdrData.writeUInt32BE(1, 4);  // height
  ihdrData[8] = 8;               // bit depth
  ihdrData[9] = 2;               // color type (RGB)
  const ihdr = pngChunk('IHDR', ihdrData);

  // tEXt chunk: "Software\0Adobe Photoshop"
  const textData = Buffer.from('Software\0Adobe Photoshop', 'ascii');
  const text = pngChunk('tEXt', textData);

  // eXIf chunk: minimal TIFF header (big-endian) — triggers EXIF detection
  const exifData = Buffer.from([
    0x4D, 0x4D, 0x00, 0x2A,         // MM + magic 42
    0x00, 0x00, 0x00, 0x08,         // offset to IFD
    0x00, 0x00,                     // 0 entries
    0x00, 0x00, 0x00, 0x00,         // next IFD
  ]);
  const exif = pngChunk('eXIf', exifData);

  // Minimal IDAT
  const idatData = Buffer.from([0x08, 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01]);
  const idat = pngChunk('IDAT', idatData);

  // IEND
  const iend = pngChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([sig, ihdr, text, exif, idat, iend]);
}

/**
 * Build a minimal PNG without metadata chunks (only IHDR, IDAT, IEND).
 */
function buildPngWithoutMetadata(): Buffer {
  const sig = Buffer.from('89504e470d0a1a0a', 'hex');
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(1, 0);
  ihdrData.writeUInt32BE(1, 4);
  ihdrData[8] = 8;
  ihdrData[9] = 2;
  const ihdr = pngChunk('IHDR', ihdrData);
  const idatData = Buffer.from([0x08, 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01]);
  const idat = pngChunk('IDAT', idatData);
  const iend = pngChunk('IEND', Buffer.alloc(0));
  return Buffer.concat([sig, ihdr, idat, iend]);
}

// ─── WebP fixture builders ───

/**
 * Build a minimal WebP with VP8X + EXIF chunk.
 */
function buildWebpWithMetadata(): Buffer {
  // VP8X chunk (10 bytes payload): flags byte + canvas size
  const vp8xData = Buffer.alloc(10);
  vp8xData[0] = 0b00001000; // EXIF flag (bit 3) set — note: we also set it here for detection
  // Actually: VP8X flags at byte 0: bit 5=ICCP, bit 4=alpha, bit 3=EXIF, bit 2=XMP, bit 1=anim
  vp8xData[0] = 0x08; // EXIF present
  // Canvas width-1 (24 bits LE) = 0 → 1px
  // Canvas height-1 (24 bits LE) = 0 → 1px
  const vp8x = webpChunk('VP8X', vp8xData);

  const vp8 = webpChunk('VP8L', VP8L_1X1);

  // EXIF chunk with a dummy EXIF payload
  const exifData = Buffer.from([
    0x4D, 0x4D, 0x00, 0x2A,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ]);
  const exif = webpChunk('EXIF', exifData);

  const payload = Buffer.concat([vp8x, vp8, exif]);
  const riff = Buffer.alloc(12);
  riff.write('RIFF', 0, 'ascii');
  riff.writeUInt32LE(4 + payload.length, 4);
  riff.write('WEBP', 8, 'ascii');

  return Buffer.concat([riff, payload]);
}

function webpChunk(fourcc: string, data: Buffer): Buffer {
  const header = Buffer.alloc(8);
  header.write(fourcc, 0, 'ascii');
  header.writeUInt32LE(data.length, 4);
  const pad = data.length % 2 === 1 ? Buffer.alloc(1, 0) : Buffer.alloc(0);
  return Buffer.concat([header, data, pad]);
}

/** A real 1x1 lossless VP8L bitstream, so stripped output must still decode. */
const VP8L_1X1 = Buffer.from('2f0000000007508f2297a7ff8188e87f00', 'hex');

/**
 * Build a minimal WebP without metadata (VP8L only, no VP8X).
 */
function buildWebpWithoutMetadata(): Buffer {
  const vp8 = webpChunk('VP8L', VP8L_1X1);

  const riff = Buffer.alloc(12);
  riff.write('RIFF', 0, 'ascii');
  riff.writeUInt32LE(4 + vp8.length, 4);
  riff.write('WEBP', 8, 'ascii');

  return Buffer.concat([riff, vp8]);
}

// ─── TIFF fixture builders ───

/**
 * Build a minimal TIFF with sensitive tags (Make, Model, Software).
 */
const buildTiffWithMetadata = () => tiffFixture();

/**
 * Build a minimal TIFF without sensitive tags (only required ImageWidth/ImageLength).
 */
const buildTiffWithoutSensitiveMetadata = () => tiffFixture({ metadata: false });

/**
 * Build a text file with device information patterns.
 */
function buildTextWithDeviceInfo(): Buffer {
  return Buffer.from(
    'Incident report\nCreated with iPhone 15 Pro\nGenerated by Notes App\nDevice: MacBook Pro M2\nCamera: Canon EOS R5\nEnd of report',
    'utf8',
  );
}

describe('Metadata Stripping', () => {
  let service: EvidenceEncryptionService;
  const secret = 'test-secret-key';

  beforeEach(() => {
    service = new EvidenceEncryptionService();
  });

  describe('JPEG with EXIF and GPS data', () => {
    it('should detect EXIF and GPS in fixture', async () => {
      const jpeg = buildJpegWithExifAndGps();
      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(true);
      expect(result.privacyMetadata.metadataStripped).toBe(true);
    });

    it('should remove APP1 segment after stripping', async () => {
      const jpeg = buildJpegWithExifAndGps();
      // Verify EXIF marker exists before stripping
      expect(jpeg.toString('hex')).toContain('ffe1');

      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      // After stripping, the APP1 (0xFFE1) segment should be gone
      const outputHex = decrypted.content.toString('hex');
      expect(outputHex.startsWith('ffd8')).toBe(true); // Still valid JPEG
      expect(outputHex).not.toContain('ffe1'); // EXIF segment removed
    });

    it('should remove GPS IFD marker after stripping', async () => {
      const jpeg = buildJpegWithExifAndGps();
      expect(jpeg.toString('hex')).toContain('8825');

      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.toString('hex')).not.toContain('8825');
    });

    it('should preserve image data after stripping', async () => {
      const jpeg = buildJpegWithExifAndGps();
      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      // Must still start with JPEG SOI
      expect(decrypted.content[0]).toBe(0xFF);
      expect(decrypted.content[1]).toBe(0xD8);
      // Must still contain SOS marker (image data)
      expect(decrypted.content.toString('hex')).toContain('ffda');
    });
  });

  describe('JPEG without EXIF', () => {
    it('should not flag EXIF or GPS', async () => {
      const jpeg = buildJpegWithoutExif();
      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(false);
      expect(result.privacyMetadata.metadataStripped).toBe(false);
    });

    it('should return image unchanged', async () => {
      const jpeg = buildJpegWithoutExif();
      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      // Content should be identical (no stripping needed)
      expect(decrypted.content.toString('hex')).toBe(jpeg.toString('hex'));
    });
  });

  describe('PDF document properties through encryption', () => {
    it.each([false, true])('removes parsed metadata and preserves readable pages (compressed=%s)', async compressed => {
      const pdf = Buffer.from(await pdfFixture({ compressed }));
      const result = await service.encryptEvidence(pdf, 'application/pdf', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const doc = await PDFDocument.load(decrypted.content, { updateMetadata: false });
      expect(doc.getAuthor()).toBeUndefined(); expect(doc.getCreator()).toBeUndefined();
      expect(doc.getProducer()).toBeUndefined(); expect(doc.getTitle()).toBeUndefined();
      expect(doc.getPageCount()).toBe(1);
      expect(result.privacyMetadata.metadataStripped).toBe(true);
    });
    it('rejects bytes that only claim to be a PDF', async () => {
      await expect(service.encryptEvidence(Buffer.from('fake PDF'), 'application/pdf', secret)).rejects.toThrow();
    });
  });

  describe('Text file with device information', () => {
    it('preserves "Created with" in text evidence', async () => {
      const text = buildTextWithDeviceInfo();
      const result = await service.encryptEvidence(text, 'text/plain', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content.toString();

      expect(output).toContain('Created with iPhone 15 Pro');
    });

    it('preserves "Generated by" in text evidence', async () => {
      const text = buildTextWithDeviceInfo();
      const result = await service.encryptEvidence(text, 'text/plain', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content.toString();

      expect(output).toContain('Generated by Notes App');
    });

    it('preserves "Device:" in text evidence', async () => {
      const text = buildTextWithDeviceInfo();
      const result = await service.encryptEvidence(text, 'text/plain', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content.toString();

      expect(output).toContain('Device: MacBook Pro M2');
    });

    it('preserves "Camera:" in text evidence', async () => {
      const text = buildTextWithDeviceInfo();
      const result = await service.encryptEvidence(text, 'text/plain', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content.toString();

      expect(output).toContain('Camera: Canon EOS R5');
    });

    it('should preserve non-device text', async () => {
      const text = buildTextWithDeviceInfo();
      const result = await service.encryptEvidence(text, 'text/plain', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content.toString();

      expect(output).toContain('Incident report');
      expect(output).toContain('End of report');
    });
  });

  describe('PNG with metadata chunks', () => {
    it('should detect metadata in PNG with tEXt and eXIf chunks', async () => {
      const png = buildPngWithMetadata();
      const result = await service.encryptEvidence(png, 'image/png', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(true);
      expect(result.privacyMetadata.metadataStripped).toBe(true);
    });

    it('should remove tEXt and eXIf chunks after stripping', async () => {
      const png = buildPngWithMetadata();
      const result = await service.encryptEvidence(png, 'image/png', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content;

      // Walk chunks in the output to verify no metadata chunks remain
      let pos = 8; // skip PNG sig
      const foundTypes: string[] = [];
      while (pos + 8 <= output.length) {
        const length = output.readUInt32BE(pos);
        const type = output.subarray(pos + 4, pos + 8).toString('ascii');
        foundTypes.push(type);
        pos += 12 + length;
      }

      expect(foundTypes).not.toContain('tEXt');
      expect(foundTypes).not.toContain('eXIf');
      expect(foundTypes).toContain('IHDR');
      expect(foundTypes).toContain('IDAT');
      expect(foundTypes).toContain('IEND');
    });

    it('should preserve PNG signature and structure', async () => {
      const png = buildPngWithMetadata();
      const result = await service.encryptEvidence(png, 'image/png', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.subarray(0, 8).toString('hex')).toBe('89504e470d0a1a0a');
    });
  });

  describe('PNG without metadata', () => {
    it('should not flag EXIF', async () => {
      const png = buildPngWithoutMetadata();
      const result = await service.encryptEvidence(png, 'image/png', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(false);
    });

    it('should return image unchanged', async () => {
      const png = buildPngWithoutMetadata();
      const result = await service.encryptEvidence(png, 'image/png', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.toString('hex')).toBe(png.toString('hex'));
    });
  });

  describe('WebP with EXIF chunk', () => {
    it('should detect metadata in WebP with EXIF chunk', async () => {
      const webp = buildWebpWithMetadata();
      const result = await service.encryptEvidence(webp, 'image/webp', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(true);
      expect(result.privacyMetadata.metadataStripped).toBe(true);
    });

    it('should remove EXIF chunk after stripping', async () => {
      const webp = buildWebpWithMetadata();
      const result = await service.encryptEvidence(webp, 'image/webp', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content;

      // Walk RIFF sub-chunks
      let pos = 12;
      const foundFourCC: string[] = [];
      while (pos + 8 <= output.length) {
        const fourcc = output.subarray(pos, pos + 4).toString('ascii');
        const size = output.readUInt32LE(pos + 4);
        foundFourCC.push(fourcc);
        pos += 8 + size + (size % 2);
      }

      expect(foundFourCC).not.toContain('EXIF');
      expect(foundFourCC).toContain('VP8X');
      expect(foundFourCC).toContain('VP8L');
    });

    it('should clear EXIF flag in VP8X after stripping', async () => {
      const webp = buildWebpWithMetadata();
      const result = await service.encryptEvidence(webp, 'image/webp', secret);
      const decrypted = await service.decryptEvidence(result, secret);
      const output = decrypted.content;

      // VP8X is the first chunk after RIFF header (offset 12)
      const vp8xFourCC = output.subarray(12, 16).toString('ascii');
      expect(vp8xFourCC).toBe('VP8X');
      const flags = output[20]; // VP8X flags byte
      expect(flags & 0x08).toBe(0); // EXIF flag cleared
    });

    it('should preserve RIFF/WEBP structure', async () => {
      const webp = buildWebpWithMetadata();
      const result = await service.encryptEvidence(webp, 'image/webp', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.subarray(0, 4).toString('ascii')).toBe('RIFF');
      expect(decrypted.content.subarray(8, 12).toString('ascii')).toBe('WEBP');
    });
  });

  describe('WebP without metadata', () => {
    it('should not flag EXIF', async () => {
      const webp = buildWebpWithoutMetadata();
      const result = await service.encryptEvidence(webp, 'image/webp', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(false);
    });

    it('should return image unchanged', async () => {
      const webp = buildWebpWithoutMetadata();
      const result = await service.encryptEvidence(webp, 'image/webp', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.toString('hex')).toBe(webp.toString('hex'));
    });
  });



  describe('TIFF with sensitive metadata', () => {
    it('should detect metadata in TIFF', async () => {
      const tiff = buildTiffWithMetadata();
      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);

      expect(result.privacyMetadata.exifRemoved).toBe(true);
      expect(result.privacyMetadata.metadataStripped).toBe(true);
    });

    it('should zero Make tag value after stripping', async () => {
      const tiff = buildTiffWithMetadata();
      expect(tiff.toString('ascii')).toContain('Canon');

      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.toString('ascii')).not.toContain('Canon');
    });

    it('should zero Model tag value after stripping', async () => {
      const tiff = buildTiffWithMetadata();
      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.toString('ascii')).not.toContain('EOS R5');
    });

    it('should zero Software tag value after stripping', async () => {
      const tiff = buildTiffWithMetadata();
      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(decrypted.content.toString('ascii')).not.toContain('Lightroom');
    });

    it('should preserve TIFF header', async () => {
      const tiff = buildTiffWithMetadata();
      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect((await sharp(decrypted.content).metadata()).format).toBe('tiff');
    });
  });

  describe('TIFF without sensitive metadata', () => {
    it('reports original TIFF directories as removed after pixel reconstruction', async () => {
      const tiff = buildTiffWithoutSensitiveMetadata();
      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);

      // TIFF always has IFDs; the rebuilt file reuses none of the original ones.
      expect(result.privacyMetadata.exifRemoved).toBe(true);
    });

    it('should preserve non-sensitive tags', async () => {
      const tiff = buildTiffWithoutSensitiveMetadata();
      const result = await service.encryptEvidence(tiff, 'image/tiff', secret);
      const decrypted = await service.decryptEvidence(result, secret);

      expect(await sharp(decrypted.content).raw().toBuffer()).toEqual(await sharp(tiff).raw().toBuffer());
    });
  });

  describe('Selective stripping via stripSelection', () => {
    it('should only strip selected EXIF fields', async () => {
      const jpeg = buildJpegWithExifAndGps();
      const result = await service.encryptEvidence(jpeg, 'image/jpeg', secret, {
        stripSelection: { gps_location: true },
      });

      expect(result.privacyMetadata.exifRemoved).toBe(true);
    });

    it('does not allow an unrelated retention selection to bypass PDF sanitization', async () => {
      const pdf = Buffer.from(await pdfFixture());
      const result = await service.encryptEvidence(pdf, 'application/pdf', secret, { stripSelection: { unrelated_field: true } });
      const decrypted = await service.decryptEvidence(result, secret);
      expect((await PDFDocument.load(decrypted.content, { updateMetadata: false })).getAuthor()).toBeUndefined();
    });
  });
});

// Regression: JPEG metadata stripping previously dropped the decoding tables.
it('preserves JPEG frame, quantization and Huffman segments while stripping APP13 and comments', async () => {
  const service = new EvidenceEncryptionService();
  const jpeg = buildJpegWithoutExif();
  const payload = Buffer.from('source@example.com');
  const segment = (marker: number) => {
    const header = Buffer.from([0xff, marker, 0, payload.length + 2]);
    return Buffer.concat([header, payload]);
  };
  const input = Buffer.concat([jpeg.subarray(0, 2), segment(0xed), segment(0xfe), jpeg.subarray(2), payload]);
  const stripped = await service.stripFileMetadata(input, 'image/jpeg');
  expect(stripped).toEqual(jpeg);
  expect(stripped.toString()).not.toContain('source@example.com');
});

it('clears WebP ICCP/EXIF/XMP flags and retains the alpha flag', async () => {
  const service = new EvidenceEncryptionService();
  const input = buildWebpWithMetadata();
  input[20] = 0x3c;
  const stripped = await service.stripFileMetadata(input, 'image/webp');
  expect(stripped[20] & 0x2c).toBe(0);
  expect(stripped[20] & 0x10).toBe(0x10);
});




it('rejects cyclic TIFF directories without exhausting the call stack', async () => {
  const service = new EvidenceEncryptionService();
  const input = Buffer.from('49492a0008000000000008000000', 'hex');
  await expect(service.stripFileMetadata(input, 'image/tiff')).rejects.toThrow('No original file');
});

it('rejects content spoofing supported image MIME types', async () => {
  const service = new EvidenceEncryptionService();
  for (const type of ['image/jpeg', 'image/png', 'image/webp']) {
    await expect(service.stripFileMetadata(Buffer.from('PRIVATE-NONIMAGE-CANARY'), type)).rejects.toThrow('malformed or unsupported');
  }
});

it('drops unknown PNG ancillary chunks and bytes after IEND', async () => {
  const service = new EvidenceEncryptionService();
  const clean = buildPngWithoutMetadata();
  const data = Buffer.from('PRIVATE-CANARY');
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length); chunk.write('vpAg', 4); data.copy(chunk, 8);
  const input = Buffer.concat([clean.subarray(0, 8), chunk, clean.subarray(8), data]);
  expect(await service.stripFileMetadata(input, 'image/png')).toEqual(clean);
  await expect(service.stripFileMetadata(clean.subarray(0, -1), 'image/png')).rejects.toThrow();
});

it('rejects truncated WebP chunks instead of returning partial evidence', async () => {
  const service = new EvidenceEncryptionService();
  const input = buildWebpWithoutMetadata();
  input.writeUInt32LE(0xffffffff, 16);
  await expect(service.stripFileMetadata(input, 'image/webp')).rejects.toThrow('WebP file is malformed or unsupported');
});
