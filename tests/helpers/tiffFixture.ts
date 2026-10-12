/** Independent uncompressed TIFF writer: real RGB pixels plus nested EXIF/GPS,
 * unknown private tags and unreferenced trailing bytes. No native encoder is
 * involved in constructing these adversarial fixtures. */
export function tiffFixture({ pages = 1, metadata = true, orientation = 1, bits = 8 } = {}): Buffer {
  const buffer = Buffer.alloc(32 * 1024);
  buffer.write('II'); buffer.writeUInt16LE(42, 2); buffer.writeUInt32LE(8, 4);
  const count = metadata ? 19 : 11;
  const block = 2 + count * 12 + 4;
  let cursor = 8 + pages * block;
  const append = (value: Buffer) => { const at = cursor; value.copy(buffer, at); cursor += value.length; if (cursor % 2) cursor++; return at; };
  const short = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
  const long = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; };
  for (let page = 0; page < pages; page++) {
    const width = 3, height = 2;
    const pixels = Buffer.from(Array.from({ length: width * height * 3 * (bits / 8) }, (_, i) => (i * 13 + page * 71) % 256));
    const pixelOffset = append(pixels);
    const entries: [number, number, number, Buffer][] = [
      [256, 4, 1, long(width)], [257, 4, 1, long(height)],
      [258, 3, 3, Buffer.concat([short(bits), short(bits), short(bits)])],
      [259, 3, 1, short(1)], [262, 3, 1, short(2)],
      [273, 4, 1, long(pixelOffset)], [274, 3, 1, short(orientation)],
      [277, 3, 1, short(3)], [278, 4, 1, long(height)],
      [279, 4, 1, long(pixels.length)], [284, 3, 1, short(1)],
    ];
    if (metadata) {
      const nested = (tag: number, value: string) => {
        const data = Buffer.from(value + '\0'); const offset = append(data);
        const ifd = Buffer.alloc(18); ifd.writeUInt16LE(1); ifd.writeUInt16LE(tag, 2); ifd.writeUInt16LE(2, 4); ifd.writeUInt32LE(data.length, 6); ifd.writeUInt32LE(offset, 10);
        return append(ifd);
      };
      for (const [tag, value] of [[270, 'identity-canary-description'], [271, 'Canon'], [272, 'EOS R5'], [305, 'Lightroom'], [315, 'identity-canary-artist'], [65000, 'identity-canary-private']] as const) {
        const bytes = Buffer.from(value + '\0'); entries.push([tag, 2, bytes.length, bytes]);
      }
      entries.push([34665, 4, 1, long(nested(37510, 'identity-canary-exif'))]);
      entries.push([34853, 4, 1, long(nested(27, 'identity-canary-gps'))]);
    }
    entries.sort((a, b) => a[0] - b[0]);
    const start = 8 + page * block; buffer.writeUInt16LE(entries.length, start);
    entries.forEach(([tag, type, length, value], i) => {
      const at = start + 2 + i * 12;
      buffer.writeUInt16LE(tag, at); buffer.writeUInt16LE(type, at + 2); buffer.writeUInt32LE(length, at + 4);
      if (value.length <= 4) value.copy(buffer, at + 8); else buffer.writeUInt32LE(append(value), at + 8);
    });
    buffer.writeUInt32LE(page + 1 < pages ? start + block : 0, start + 2 + entries.length * 12);
  }
  if (metadata) append(Buffer.from('identity-canary-unreferenced-thumbnail-and-trailing-data'));
  return buffer.subarray(0, cursor);
}
