import sharp from 'sharp';
import { EvidenceValidationError } from '../utils/evidenceValidationError';

const MAX_PIXELS = 40_000_000;
const MAX_PAGES = 50;

/** Rebuild a TIFF from decoded pixels, never from its original directories.
 * Supports 8-bit RGB/greyscale pages. Other sample formats fail closed instead
 * of silently quantizing forensic/scientific evidence. */
export async function stripTiffMetadata(input: Buffer): Promise<Buffer> {
  try {
    if (!input.length || input.length > 10 * 1024 * 1024) throw new Error('Invalid input size');
    const options = { pages: -1, limitInputPixels: MAX_PIXELS, failOn: 'warning' as const };
    const metadata = await sharp(input, options).metadata();
    const pages = metadata.pages || 1;
    if (metadata.format !== 'tiff' || metadata.depth !== 'uchar' ||
        !['srgb', 'rgb', 'b-w'].includes(metadata.space) ||
        pages > MAX_PAGES || !metadata.width || !metadata.height ||
        metadata.width * metadata.height > MAX_PIXELS ||
        (pages > 1 && (metadata.orientation || 1) !== 1)) throw new Error('Unsupported TIFF structure');
    for (let page = 0; page < pages; page++) {
      const info = await sharp(input, { ...options, pages: 1, page }).metadata();
      if (info.depth !== metadata.depth || info.space !== metadata.space || info.width !== metadata.width ||
          info.height !== (metadata.pageHeight || metadata.height) ||
          (pages > 1 && (info.orientation || 1) !== 1)) throw new Error('Inconsistent TIFF pages');
    }
    const decoded = await sharp(input, options).autoOrient().toColourspace('srgb')
      .timeout({ seconds: 15 }).raw().toBuffer({ resolveWithObject: true });
    const { width, height, channels } = decoded.info;
    const pageHeight = pages > 1 ? height / pages : height;
    if (!Number.isInteger(pageHeight) || width * height > MAX_PIXELS) throw new Error('Invalid page geometry');
    // A new raw input has no EXIF, GPS, ICC, XMP, private IFDs, thumbnails or
    // unused original bytes to carry forward. LZW is lossless.
    const output = await sharp(decoded.data, { raw: { width, height, channels, pageHeight } })
      .tiff({ compression: 'lzw', predictor: 'horizontal' }).timeout({ seconds: 15 }).toBuffer();
    if (output.length > 20 * 1024 * 1024) throw new Error('Output too large');
    const result = await sharp(output, options).metadata();
    if ((result.pages || 1) !== pages || result.width !== width || result.height !== height) throw new Error('Pages changed');
    return output;
  } catch (error) {
    // Decoder errors can include reporter metadata. Neither expose those errors
    // nor fall back to the original bytes.
    // Preserve infrastructure failures as retryable, rather than asking the
    // reporter to replace evidence when the machine is out of resources.
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code && ['ENOMEM', 'ENOSPC', 'EMFILE', 'ENFILE', 'EIO'].includes(code)) {
      throw new Error('TIFF sanitizer temporarily unavailable');
    }
    throw new EvidenceValidationError('TIFF', 'Unable to sanitize this TIFF. Use an 8-bit RGB or greyscale TIFF with at most 50 pages and 40 megapixels total. No original file was accepted.');
  }
}
