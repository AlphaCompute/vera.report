import { dataCodewords, encodeCodewords, encodeQr, gfMultiply, penalty, qrSvgPath, reedSolomonRemainder } from '../../../lib/qrCode';

// Reference values from the QR Code specification's worked example
// ("HELLO WORLD", version 1, error correction M) and the standard format tables.
describe('QR encoder', () => {
  test('GF(256) arithmetic uses the QR field polynomial', () => {
    expect(gfMultiply(0x02, 0x80)).toBe(0x1d);
    // 2^8 = x^4 + x^3 + x^2 + 1 and 2^255 = 1 in this field.
    let power = 1;
    for (let i = 0; i < 255; i += 1) { power = gfMultiply(power, 2); if (i === 7) expect(power).toBe(0x1d); }
    expect(power).toBe(1);
    expect(gfMultiply(0x53, 0xca)).toBe(gfMultiply(0xca, 0x53));
    for (let x = 0; x < 256; x += 17) {
      expect(gfMultiply(x, 1)).toBe(x);
      expect(gfMultiply(x, 0)).toBe(0);
    }
  });

  test('HELLO WORLD 1-M data and error correction codewords match the reference', () => {
    const codewords = encodeCodewords('HELLO WORLD', 1, 'M')!;
    expect(codewords.slice(0, 16)).toEqual([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]);
    expect(codewords.slice(16)).toEqual([196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
    expect(reedSolomonRemainder(codewords.slice(0, 16), 10)).toEqual(codewords.slice(16));
  });

  test('capacity tables match the specification', () => {
    expect(dataCodewords(1, 'L')).toBe(19);
    expect(dataCodewords(1, 'M')).toBe(16);
    expect(dataCodewords(1, 'Q')).toBe(13);
    expect(dataCodewords(1, 'H')).toBe(9);
    expect(dataCodewords(4, 'M')).toBe(64);
    expect(dataCodewords(5, 'Q')).toBe(62);
    expect(dataCodewords(7, 'M')).toBe(124);
    expect(dataCodewords(10, 'H')).toBe(122);
  });

  test('draws finder patterns, timing, dark module and format information', () => {
    const qr = encodeQr('HELLO WORLD', 'M');
    expect(qr.version).toBe(1);
    expect(qr.size).toBe(21);
    const m = qr.modules;
    // Finder: dark outer ring, light ring, dark 3x3 core (top-left).
    expect(m[0].slice(0, 7)).toEqual([true, true, true, true, true, true, true]);
    expect(m[1].slice(0, 7)).toEqual([true, false, false, false, false, false, true]);
    expect(m[3].slice(0, 7)).toEqual([true, false, true, true, true, false, true]);
    expect(m[7].slice(0, 8)).toEqual(new Array(8).fill(false));
    for (let i = 8; i < 13; i += 1) { expect(m[6][i]).toBe(i % 2 === 0); expect(m[i][6]).toBe(i % 2 === 0); }
    expect(m[qr.size - 8][8]).toBe(true);
    // Format bits for (M, mask) read back from the first copy match the BCH table.
    const table = [0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0];
    const read = [0, 1, 2, 3, 4, 5, 7, 8].map(y => m[y][8]).concat([7, 5, 4, 3, 2, 1, 0].map(x => m[8][x]));
    const value = read.reduce((acc, bitValue, index) => acc | (Number(bitValue) << index), 0);
    expect(value).toBe(table[qr.mask]);
  });

  test('draws version information from version 7', () => {
    const qr = encodeQr('x'.repeat(120), 'M');
    expect(qr.version).toBe(7);
    // Version 7 information is 0x07C94, stored LSB first in the 6x3 block by the top-right finder.
    let value = 0;
    for (let i = 0; i < 18; i += 1) if (qr.modules[Math.floor(i / 3)][qr.size - 11 + (i % 3)]) value |= 1 << i;
    expect(value).toBe(0x07c94);
  });

  test('a grouped recovery code fits a small alphanumeric symbol', () => {
    const code = '7K3M-9QXA-R2D8-WV4N-J6TC-P1HZ-5GBE-0SKY-M8FQ-3XAW-T7VN-2CJD-H9RB-4PZE';
    const qr = encodeQr(code, 'M');
    expect(qr.version).toBe(4);
    const path = qrSvgPath(qr);
    expect(path).toMatch(/^M\d+,\d+h1v1h-1z/);
    expect(path).not.toContain(code);
    // Byte mode for text outside the alphanumeric set.
    expect(encodeQr(code.toLowerCase(), 'M').version).toBeGreaterThan(4);
  });

  test('picks the lowest-penalty mask and refuses empty or oversized text', () => {
    const qr = encodeQr('HELLO WORLD', 'Q');
    const scores = Array.from({ length: 8 }, (_, mask) => penalty(encodeQr('HELLO WORLD', 'Q', mask).modules));
    expect(penalty(qr.modules)).toBe(Math.min(...scores));
    expect(() => encodeQr('', 'M')).toThrow();
    expect(() => encodeQr('x'.repeat(400), 'M')).toThrow('too long');
  });
});
