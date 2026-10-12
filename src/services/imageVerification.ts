import sharp from 'sharp';
import { EvidenceValidationError } from '../utils/evidenceValidationError';

/**
 * Per-frame pixel budgets, from measured peak RSS of this verifier at a 64 px
 * target: baseline JPEG shrink-on-load and streamed PNG decoding add ~0 and ~50 MB at
 * 120 MP (covering 48–108 MP phone sensors), but libwebp decodes a whole frame
 * (~940 MB at 120 MP, ~150 MB at 40 MP), so WebP keeps the TIFF budget.
 * Progressive JPEG may retain full-resolution data; the output size is not a
 * decoder-memory bound.
 */
export const MAX_IMAGE_PIXELS: Record<string, number> = {
  'image/jpeg': 120_000_000, 'image/png': 120_000_000, 'image/webp': 40_000_000,
};
/** WebP animation bounds; APNG only exposes its default image to libvips. */
const MAX_FRAMES = 1000;
const MAX_ANIMATION_PIXELS = 480_000_000;

const FORMATS: Record<string, string> = { 'image/jpeg': 'jpeg', 'image/png': 'png', 'image/webp': 'webp' };
const LABELS: Record<string, 'JPEG' | 'PNG' | 'WebP'> = { 'image/jpeg': 'JPEG', 'image/png': 'PNG', 'image/webp': 'WebP' };

/**
 * Decode a stripped JPEG/PNG/WebP with an independent decoder before it is
 * stored. The byte-level strippers never parse pixels, so this rejects pixel
 * bombs, decoder-reported errors and container/type mismatches instead
 * of accepting evidence nobody can open. Every WebP animation frame is decoded;
 * libvips has no APNG loader, so APNG verifies its default image only.
 * Limits are inclusive: 120 million pixels per JPEG/PNG frame, 40 million per
 * WebP frame, 1,000 frames, and 480 million pixels across frames. Recoverable
 * decoder warnings are accepted. The supplied bytes are not changed.
 * @param contentType - Declared MIME type; other types are skipped.
 * @throws {EvidenceValidationError} For format/limit violations or decoder
 * failures, including timeouts, except the resource errors below.
 * @throws {Error} ENOMEM, ENOSPC, EMFILE, ENFILE, and EIO failures become
 * "Image sanitizer temporarily unavailable"; original decoder errors are hidden.
 */
export async function verifyStrippedImage(output: Buffer, contentType: string): Promise<void> {
  const format = FORMATS[contentType];
  if (!format) return;
  try {
    const maxFrame = MAX_IMAGE_PIXELS[contentType];
    const options = { pages: -1, limitInputPixels: MAX_ANIMATION_PIXELS, failOn: 'error' as const };
    const metadata = await sharp(output, options).metadata();
    const frames = metadata.pages || 1;
    const frameHeight = metadata.pageHeight || metadata.height;
    if (metadata.format !== format || !metadata.width || !frameHeight || frames > MAX_FRAMES ||
        metadata.width * frameHeight > maxFrame ||
        metadata.width * frameHeight * frames > MAX_ANIMATION_PIXELS) throw new Error('Unsupported image structure');
    // Decoding every entropy-coded byte of every frame is what proves the
    // evidence still opens; the thumbnail target keeps memory small.
    await sharp(output, options).resize(64, 64, { fit: 'inside' }).timeout({ seconds: 15 }).raw().toBuffer();
  } catch (error) {
    // Decoder errors can quote reporter-controlled bytes; never surface them.
    // Only errno-coded resource failures are retryable; a decoder that fails to
    // allocate for this file would fail the same way on every retry.
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code && ['ENOMEM', 'ENOSPC', 'EMFILE', 'ENFILE', 'EIO'].includes(code)) {
      throw new Error('Image sanitizer temporarily unavailable');
    }
    const label = LABELS[contentType];
    throw new EvidenceValidationError(label, `Unable to verify this ${label} after removing metadata. Use a valid image of at most ${MAX_IMAGE_PIXELS[contentType] / 1_000_000} megapixels. No original file was accepted.`);
  }
}
