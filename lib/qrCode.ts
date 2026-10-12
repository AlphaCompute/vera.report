/** Minimal QR Code (ISO/IEC 18004) encoder for short text, versions 1 to 10.
 * Runs entirely on the device; used to render a recovery code so it never has to
 * pass through a third-party QR service. Alphanumeric mode when the text allows
 * it (upper-case codes with hyphens), byte mode (UTF-8) otherwise.
 * Structure follows the reference algorithm (finder, timing, alignment, format
 * and version information, Reed-Solomon over GF(256)/0x11D, mask penalty rules). */
export type QrErrorCorrection = 'L' | 'M' | 'Q' | 'H';
export type QrMatrix = { version: number; size: number; mask: number; modules: boolean[][] };

const MAX_VERSION = 10;
const ALPHANUMERIC = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
// Index 0 unused; versions 1-10.
const ECC_PER_BLOCK: Record<QrErrorCorrection, number[]> = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
  Q: [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24],
  H: [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28],
};
const BLOCKS: Record<QrErrorCorrection, number[]> = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
  Q: [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8],
  H: [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8],
};
const FORMAT_BITS: Record<QrErrorCorrection, number> = { L: 1, M: 0, Q: 3, H: 2 };

function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const align = Math.floor(version / 7) + 2;
    result -= (25 * align - 10) * align - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}
export function dataCodewords(version: number, ecl: QrErrorCorrection): number {
  return Math.floor(rawDataModules(version) / 8) - ECC_PER_BLOCK[ecl][version] * BLOCKS[ecl][version];
}
function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2, size = version * 4 + 17;
  const step = Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

export function gfMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}
function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i += 1) {
    for (let j = 0; j < result.length; j += 1) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}
export function reedSolomonRemainder(data: readonly number[], degree: number): number[] {
  const divisor = rsDivisor(degree);
  const result = new Array<number>(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ (result.shift() as number);
    result.push(0);
    divisor.forEach((coef, index) => { result[index] ^= gfMultiply(coef, factor); });
  }
  return result;
}

type Bits = number[];
function push(bits: Bits, value: number, length: number): void {
  for (let i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
}
function segmentBits(text: string, version: number): Bits {
  const bits: Bits = [];
  if ([...text].every(char => ALPHANUMERIC.includes(char))) {
    push(bits, 0b0010, 4); push(bits, text.length, version <= 9 ? 9 : 11);
    for (let i = 0; i + 1 < text.length; i += 2) push(bits, ALPHANUMERIC.indexOf(text[i]) * 45 + ALPHANUMERIC.indexOf(text[i + 1]), 11);
    if (text.length % 2) push(bits, ALPHANUMERIC.indexOf(text[text.length - 1]), 6);
  } else {
    const bytes = new TextEncoder().encode(text);
    push(bits, 0b0100, 4); push(bits, bytes.length, version <= 9 ? 8 : 16);
    for (const byte of bytes) push(bits, byte, 8);
  }
  return bits;
}

/** Final interleaved codewords (data + error correction) for one version. */
export function encodeCodewords(text: string, version: number, ecl: QrErrorCorrection): number[] | null {
  const capacity = dataCodewords(version, ecl) * 8;
  const bits = segmentBits(text, version);
  if (bits.length > capacity) return null;
  push(bits, 0, Math.min(4, capacity - bits.length));
  push(bits, 0, (8 - bits.length % 8) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) push(bits, pad, 8);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((acc, bit) => (acc << 1) | bit, 0));

  const blocks = BLOCKS[ecl][version], eccLength = ECC_PER_BLOCK[ecl][version];
  const raw = Math.floor(rawDataModules(version) / 8);
  const shortBlocks = blocks - raw % blocks, shortLength = Math.floor(raw / blocks);
  const all: number[][] = [];
  for (let i = 0, k = 0; i < blocks; i += 1) {
    const block = data.slice(k, k + shortLength - eccLength + (i < shortBlocks ? 0 : 1));
    k += block.length;
    const ecc = reedSolomonRemainder(block, eccLength);
    if (i < shortBlocks) block.push(0);
    all.push(block.concat(ecc));
  }
  const result: number[] = [];
  for (let i = 0; i < all[0].length; i += 1) {
    all.forEach((block, j) => { if (i !== shortLength - eccLength || j >= shortBlocks) result.push(block[i]); });
  }
  return result;
}

function formatInfo(ecl: QrErrorCorrection, mask: number): number {
  const data = (FORMAT_BITS[ecl] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i += 1) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}
function versionInfo(version: number): number {
  let rem = version;
  for (let i = 0; i < 12; i += 1) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
}
const bit = (value: number, index: number) => ((value >>> index) & 1) !== 0;
const MASKS: ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
  (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
];

class Grid {
  readonly modules: boolean[][];
  readonly reserved: boolean[][];
  constructor(readonly size: number) {
    this.modules = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }
  fn(x: number, y: number, dark: boolean): void { this.modules[y][x] = dark; this.reserved[y][x] = true; }
}

function drawFunctionPatterns(grid: Grid, version: number): void {
  const { size } = grid;
  for (let i = 0; i < size; i += 1) { grid.fn(6, i, i % 2 === 0); grid.fn(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const x = cx + dx, y = cy + dy, dist = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) grid.fn(x, y, dist !== 2 && dist !== 4);
      }
    }
  }
  const positions = alignmentPositions(version), last = positions.length - 1;
  positions.forEach((py, i) => positions.forEach((px, j) => {
    if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) grid.fn(px + dx, py + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }));
  drawFormat(grid, 0, 'M'); // reserve; real bits drawn after masking
  if (version >= 7) {
    const bits = versionInfo(version);
    for (let i = 0; i < 18; i += 1) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      grid.fn(a, b, bit(bits, i)); grid.fn(b, a, bit(bits, i));
    }
  }
}
function drawFormat(grid: Grid, mask: number, ecl: QrErrorCorrection): void {
  const bits = formatInfo(ecl, mask), { size } = grid;
  for (let i = 0; i <= 5; i += 1) grid.fn(8, i, bit(bits, i));
  grid.fn(8, 7, bit(bits, 6)); grid.fn(8, 8, bit(bits, 7)); grid.fn(7, 8, bit(bits, 8));
  for (let i = 9; i < 15; i += 1) grid.fn(14 - i, 8, bit(bits, i));
  for (let i = 0; i < 8; i += 1) grid.fn(size - 1 - i, 8, bit(bits, i));
  for (let i = 8; i < 15; i += 1) grid.fn(8, size - 15 + i, bit(bits, i));
  grid.fn(8, size - 8, true);
}
function drawCodewords(grid: Grid, codewords: number[]): void {
  const { size } = grid;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert += 1) {
      for (let j = 0; j < 2; j += 1) {
        const x = right - j, upward = ((right + 1) & 2) === 0, y = upward ? size - 1 - vert : vert;
        if (!grid.reserved[y][x] && i < codewords.length * 8) {
          grid.modules[y][x] = bit(codewords[i >>> 3], 7 - (i & 7));
          i += 1;
        }
      }
    }
  }
}
function applyMask(grid: Grid, mask: number): void {
  for (let y = 0; y < grid.size; y += 1) {
    for (let x = 0; x < grid.size; x += 1) if (!grid.reserved[y][x] && MASKS[mask](x, y)) grid.modules[y][x] = !grid.modules[y][x];
  }
}
export function penalty(modules: boolean[][]): number {
  const size = modules.length;
  let score = 0, dark = 0;
  const lines: boolean[][] = [];
  for (let i = 0; i < size; i += 1) { lines.push(modules[i]); lines.push(modules.map(row => row[i])); }
  const finderA = [true, false, true, true, true, false, true, false, false, false, false];
  const finderB = [false, false, false, false, true, false, true, true, true, false, true];
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= size; i += 1) {
      if (i < size && line[i] === line[i - 1]) { run += 1; continue; }
      if (run >= 5) score += 3 + run - 5;
      run = 1;
    }
    for (let i = 0; i + 11 <= size; i += 1) {
      const window = line.slice(i, i + 11);
      if (window.every((value, k) => value === finderA[k]) || window.every((value, k) => value === finderB[k])) score += 40;
    }
  }
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (modules[y][x]) dark += 1;
      if (x + 1 < size && y + 1 < size) {
        const c = modules[y][x];
        if (modules[y][x + 1] === c && modules[y + 1][x] === c && modules[y + 1][x + 1] === c) score += 3;
      }
    }
  }
  const total = size * size;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return score;
}

/** Whether `encodeQr` can hold this text at the given error correction level. */
export function qrFits(text: string, ecl: QrErrorCorrection = 'M'): boolean {
  if (typeof text !== 'string' || !text) return false;
  for (let version = 1; version <= MAX_VERSION; version += 1) {
    if (segmentBits(text, version).length <= dataCodewords(version, ecl) * 8) return true;
  }
  return false;
}

/** Smallest version that fits, best mask by the standard penalty rules (or the
 * given mask, for tests). */
export function encodeQr(text: string, ecl: QrErrorCorrection = 'M', onlyMask?: number): QrMatrix {
  if (typeof text !== 'string' || !text) throw new Error('Nothing to encode');
  for (let version = 1; version <= MAX_VERSION; version += 1) {
    const codewords = encodeCodewords(text, version, ecl);
    if (!codewords) continue;
    let best: QrMatrix | null = null, bestScore = Infinity;
    for (let mask = 0; mask < 8; mask += 1) {
      if (onlyMask !== undefined && mask !== onlyMask) continue;
      const grid = new Grid(version * 4 + 17);
      drawFunctionPatterns(grid, version);
      drawCodewords(grid, codewords);
      applyMask(grid, mask);
      drawFormat(grid, mask, ecl);
      const score = penalty(grid.modules);
      if (score < bestScore) { bestScore = score; best = { version, size: grid.size, mask, modules: grid.modules }; }
    }
    return best as QrMatrix;
  }
  throw new Error('Text is too long for a QR code');
}

/** One SVG path for all dark modules, with the standard 4-module quiet zone. */
export function qrSvgPath(matrix: QrMatrix, border = 4): string {
  const parts: string[] = [];
  matrix.modules.forEach((row, y) => row.forEach((dark, x) => { if (dark) parts.push(`M${x + border},${y + border}h1v1h-1z`); }));
  return parts.join('');
}
