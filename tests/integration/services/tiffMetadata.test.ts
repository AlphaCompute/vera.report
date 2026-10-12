import sharp from 'sharp';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { stripTiffMetadata } from '../../../src/services/tiffMetadata';
import { tiffFixture } from '../../helpers/tiffFixture';

const pixels = (input: Buffer) => sharp(input, { pages: -1 }).autoOrient().toColourspace('srgb').raw().toBuffer();

describe('TIFF reconstruction from pixels', () => {
  it.each([1, 2, 4])('preserves every pixel and page in a %i-page TIFF while removing nested/private/trailing metadata', async pages => {
    const input = tiffFixture({ pages });
    expect(input.toString()).toContain('identity-canary-gps');
    const output = await stripTiffMetadata(input);
    expect(output.toString()).not.toContain('identity-canary');
    expect(output.toString()).not.toContain('Canon');
    expect(output.toString()).not.toContain('Lightroom');
    const metadata = await sharp(output, { pages: -1 }).metadata();
    expect(metadata.pages).toBe(pages);
    expect(metadata.exif).toBeUndefined(); expect(metadata.xmp).toBeUndefined(); expect(metadata.icc).toBeUndefined(); expect(metadata.iptc).toBeUndefined();
    expect(await pixels(output)).toEqual(await pixels(input));
  });

  it('preserves the displayed orientation of a rotated single-page scan', async () => {
    const input = tiffFixture({ orientation: 6 }); const output = await stripTiffMetadata(input);
    expect(await pixels(output)).toEqual(await pixels(input));
    const info = await sharp(output).metadata(); expect(info.width).toBe(2); expect(info.height).toBe(3);
  });

  it('decodes with independent FFmpeg and preserves the original RGB bytes', async () => {
    const input = tiffFixture(); const output = await stripTiffMetadata(input);
    const directory = mkdtempSync(path.join(tmpdir(), 'vera-tiff-check-'));
    try {
      const decode = (data: Buffer, name: string) => {
        const file = path.join(directory, name + '.tiff'); writeFileSync(file, data);
        return execFileSync('ffmpeg', ['-v', 'error', '-i', file, '-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1'], { timeout: 10000 });
      };
      expect(decode(output, 'clean')).toEqual(decode(input, 'original'));
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });

  it('fails closed for high-bit-depth evidence rather than quantizing it', async () => {
    await expect(stripTiffMetadata(tiffFixture({ bits: 16 }))).rejects.toThrow('No original file');
  });

  it('enforces page and pixel limits before decoding large images', async () => {
    await expect(stripTiffMetadata(tiffFixture({ pages: 51, metadata: false }))).rejects.toThrow('No original file');
    const enormous = tiffFixture(); enormous.writeUInt32LE(40_000_001, 18);
    await expect(stripTiffMetadata(enormous)).rejects.toThrow('No original file');
  });

  it('rejects a rotated later page instead of silently changing its presentation', async () => {
    const input = tiffFixture({ pages: 2 });
    const secondIfd = 8 + 2 + 19 * 12 + 4;
    for (let i = 0; i < 19; i++) {
      const entry = secondIfd + 2 + i * 12;
      if (input.readUInt16LE(entry) === 274) input.writeUInt16LE(6, entry + 8);
    }
    await expect(stripTiffMetadata(input)).rejects.toThrow('No original file');
  });

  it('rejects malformed, forged and cyclic input without falling back to its original bytes', async () => {
    for (const input of [Buffer.from('not TIFF'), Buffer.from('49492a0008000000000008000000', 'hex'), tiffFixture().subarray(0, 40)]) {
      await expect(stripTiffMetadata(input)).rejects.toThrow('No original file');
    }
    const png = await sharp({ create: { width: 1, height: 1, channels: 3, background: 'red' } }).png().toBuffer();
    await expect(stripTiffMetadata(png)).rejects.toThrow('No original file');
  });
});

it('does not carry a real thumbnail SubIFD into the reconstructed TIFF', async () => {
  const input = tiffFixture({ pages: 2 });
  const count = input.readUInt16LE(8);
  const nextPointer = 8 + 2 + count * 12;
  const thumbnail = input.readUInt32LE(nextPointer);
  input.writeUInt32LE(0, nextPointer); // The second image becomes a SubIFD, not a main page.
  const entries: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    const entry = Buffer.from(input.subarray(10 + i * 12, 22 + i * 12));
    if (entry.readUInt16LE() === 65000) {
      entry.writeUInt16LE(330); entry.writeUInt16LE(4, 2); entry.writeUInt32LE(1, 4); entry.writeUInt32LE(thumbnail, 8);
    }
    entries.push(entry);
  }
  entries.sort((a, b) => a.readUInt16LE() - b.readUInt16LE());
  entries.forEach((entry, i) => entry.copy(input, 10 + i * 12));
  const before = await sharp(input).metadata();
  expect(before.subifds).toBe(1);
  const output = await stripTiffMetadata(input);
  const after = await sharp(output).metadata();
  expect(after.subifds || 0).toBe(0); expect(after.pages).toBe(1);
  expect(await pixels(output)).toEqual(await pixels(input));
  expect(output.toString()).not.toContain('identity-canary');
});
