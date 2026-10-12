import { randomBytes } from 'node:crypto';
import * as nativeCodec from '../../../enclave/src/confidential/base64';
import { decodeBase64 as decodeStateBase64 } from '../../../enclave/src/confidential/caseStateKey';

type Codec = typeof nativeCodec;

// The browser bundle has no Buffer; load a second copy of the module without it.
function loadBrowserCodec(): Codec {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'Buffer')!;
  let codec: Codec | undefined;
  delete (globalThis as { Buffer?: unknown }).Buffer;
  try {
    jest.isolateModules(() => { codec = jest.requireActual('../../../enclave/src/confidential/base64'); });
  } finally { Object.defineProperty(globalThis, 'Buffer', saved); }
  return codec!;
}
const browserCodec = loadBrowserCodec();

// The previous implementation (decode with atob, re-encode, compare), kept as the
// reference for which strings are accepted.
function legacyEncode(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function legacyDecode(value: unknown, max = Number.MAX_SAFE_INTEGER): Uint8Array | null {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4 + 4) return null;
  let bytes: Uint8Array;
  try { bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0)); } catch { return null; }
  if (bytes.length > max || legacyEncode(bytes) !== value) return null;
  return bytes;
}

const TABLE: [string, boolean][] = [
  ['', true],
  ['QQ==', true], ['QR==', false], ['QX==', false], ['QW==', false], ['QQ=', false], ['QQ', false], ['QQ===', false],
  ['QUI=', true], ['QUJ=', false], ['QUK=', false], ['QUI', false], ['QUI==', false],
  ['QUJD', true], ['QUJD=', false], ['QUJD====', false], ['====', false], ['Q===', false], ['QQ=A', false], ['Q=Q=', false],
  ['A', false], ['AA', false], ['AAA', false], ['AAAA', true], ['AAAAA', false],
  ['+/+/', true], ['-_-_', false], ['QUJD-_==', false], ['ab_c', false], ['ab-c', false],
  [' QUJD', false], ['QUJD ', false], ['QU JD', false], ['QUJD\n', false], ['QU\nJD', false], ['QUJD\t', false], ['\r\nQUJD', false],
  ['QUJD\u0000', false], ['QUJé', false], ['QUJＡ', false], ['QU.D', false], ['QU*D', false], ['QUJDQQ==', true],
  ['//8=', true], ['//9=', false], ['/w==', true], ['/x==', false], ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', true],
];

const MUTATIONS = ['-', '_', ' ', '\n', '=', 'A', 'B', '/', '+', '.', 'ÿ'];
function* fuzzInputs(): Generator<string> {
  for (let length = 0; length <= 40; length++) {
    for (let round = 0; round < 6; round++) {
      const wire = Buffer.from(randomBytes(length)).toString('base64');
      yield wire;
      if (!wire.length) continue;
      const at = round % wire.length, insert = MUTATIONS[(length + round) % MUTATIONS.length];
      yield wire.slice(0, at) + insert + wire.slice(at + 1);
      yield wire.slice(0, at) + insert + wire.slice(at);
      yield wire.slice(0, -1);
      yield wire.replace(/=+$/, '');
      yield `${wire}=`;
      // Flip the low bits of the last data character (non-zero trailing bits).
      const data = wire.replace(/=+$/, ''), last = data.length - 1;
      const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.indexOf(data[last]);
      const flipped = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[index ^ (1 + (round % 3))];
      yield data.slice(0, last) + flipped + wire.slice(data.length);
    }
  }
}

describe.each([['native (Buffer)', nativeCodec], ['browser (atob/btoa)', browserCodec]])('canonical base64, %s', (_name, codec) => {
  test.each(TABLE)('%j accepted: %s', (input, accepted) => {
    expect(legacyDecode(input) !== null).toBe(accepted);
    const decoded = codec.decodeCanonicalBase64(input);
    expect(decoded !== null).toBe(accepted);
    if (decoded) expect(Array.from(decoded)).toEqual(Array.from(legacyDecode(input)!));
    expect(codec.canonicalBase64Length(input) >= 0).toBe(accepted);
  });

  test('agrees with the decode/re-encode reference on fuzzed and mutated inputs', () => {
    let checked = 0, rejected = 0;
    for (const input of fuzzInputs()) {
      const expected = legacyDecode(input), actual = codec.decodeCanonicalBase64(input);
      if (expected === null) { expect(actual).toBeNull(); rejected++; } else expect(Array.from(actual!)).toEqual(Array.from(expected));
      checked++;
    }
    expect(rejected).toBeGreaterThan(checked / 3);
  });

  test('size limit matches the reference at the boundary', () => {
    for (let max = 0; max <= 12; max++) {
      for (let length = 0; length <= 14; length++) {
        const wire = Buffer.from(randomBytes(length)).toString('base64');
        expect(codec.decodeCanonicalBase64(wire, max) !== null).toBe(legacyDecode(wire, max) !== null);
        expect(codec.decodeCanonicalBase64(wire, max) !== null).toBe(length <= max);
      }
    }
  });

  test('rejects non-strings', () => {
    for (const value of [undefined, null, 4, {}, ['QQ=='], new Uint8Array(1)]) expect(codec.decodeCanonicalBase64(value)).toBeNull();
  });

  test('round-trips, including across the 0x8000 batch boundary and a full chunk', () => {
    for (const length of [0, 1, 2, 3, 4, 31, 32, 33, 0x7fff, 0x8000, 0x8001, 3 * 0x8000 + 2, 512 * 1024 + 16]) {
      const bytes = new Uint8Array(randomBytes(length));
      const wire = codec.encodeBase64(bytes);
      expect(wire).toBe(Buffer.from(bytes).toString('base64'));
      const decoded = codec.decodeCanonicalBase64(wire, length)!;
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.byteOffset).toBe(0);
      expect(decoded.buffer.byteLength).toBe(length);
      expect(Buffer.from(decoded).equals(Buffer.from(bytes))).toBe(true);
    }
  });

  test('encodes subarray views without reading outside them', () => {
    const backing = new Uint8Array(randomBytes(64)), view = backing.subarray(5, 37);
    expect(codec.encodeBase64(view)).toBe(Buffer.from(view).toString('base64'));
  });
});

test('caseStateKey.decodeBase64 keeps its error and size behaviour', () => {
  expect(Array.from(decodeStateBase64('QQ==', 1))).toEqual([65]);
  for (const [value, max] of [['QR==', 1], ['QQ', 1], ['QUI=', 1], [' QQ==', 1], [5, 1]] as [unknown, number][]) {
    expect(() => decodeStateBase64(value, max)).toThrow('Invalid confidential case state');
  }
});

test('timing: one 512 KiB evidence chunk, previous vs current (logged, not asserted)', () => {
  const wire = Buffer.from(randomBytes(512 * 1024 + 16)).toString('base64');
  const time = (run: () => unknown, rounds: number) => {
    const samples: number[] = [];
    for (let round = 0; round < rounds; round++) { const start = performance.now(); run(); samples.push(performance.now() - start); }
    return samples.sort((a, b) => a - b)[Math.floor(rounds / 2)];
  };
  const legacy = time(() => legacyDecode(wire), 5);
  const native = time(() => nativeCodec.decodeCanonicalBase64(wire), 20);
  const browser = time(() => browserCodec.decodeCanonicalBase64(wire), 20);
  const bytes = nativeCodec.decodeCanonicalBase64(wire)!;
  const legacyEncodeMs = time(() => legacyEncode(bytes), 5);
  const nativeEncodeMs = time(() => nativeCodec.encodeBase64(bytes), 20);
  const browserEncodeMs = time(() => browserCodec.encodeBase64(bytes), 20);
  // tests/setup.ts silences console.log, so write the measurement directly.
  process.stdout.write(`512 KiB chunk median ms: decode legacy ${legacy.toFixed(2)}, native ${native.toFixed(2)}, browser ${browser.toFixed(2)}; ` +
    `encode legacy ${legacyEncodeMs.toFixed(2)}, native ${nativeEncodeMs.toFixed(2)}, browser ${browserEncodeMs.toFixed(2)}\n`);
  expect(bytes.length).toBe(512 * 1024 + 16);
});
