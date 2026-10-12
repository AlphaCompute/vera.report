import { webcrypto } from 'node:crypto';
import { verifySelfRelease } from '../../../enclave/src/cases/selfRelease';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';

// Minimal CBOR encoder for a synthetic NSM document (structure only; no signature needed
// because the document comes from the local NSM device, not over the network).
function encode(value: unknown): Buffer {
  const head = (major: number, n: number) => n < 24 ? Buffer.from([major * 32 + n])
    : n < 256 ? Buffer.from([major * 32 + 24, n]) : Buffer.from([major * 32 + 25, n >> 8, n & 255]);
  if (typeof value === 'number') return head(0, value);
  if (typeof value === 'string') { const data = Buffer.from(value); return Buffer.concat([head(3, data.length), data]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  throw new Error('unsupported');
}
const hex = (n: number) => n.toString(16).padStart(64, '0');
const manifest = (pcr1: string) => canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1, pcr2: '33'.repeat(48) } });
const document = (pcrs: Map<number, Buffer>) => new Uint8Array(encode([encode(new Map([[1, 35]])), new Map(),
  encode(new Map<string, unknown>([['module_id', 'synthetic'], ['pcrs', pcrs]])), Buffer.alloc(96)]));

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

describe('enclave self-release verification', () => {
  const pcrs = new Map([[0, Buffer.alloc(48, 0x11)], [1, Buffer.alloc(48, 0x22)], [2, Buffer.alloc(48, 0x33)]]);
  test('accepts the host manifest only when it matches this enclave\'s own PCRs', async () => {
    const wire = manifest('22'.repeat(48));
    await expect(verifySelfRelease(wire, document(pcrs))).resolves.toBe((await readReleaseManifest(wire)).digest);
  });
  test('a host supplying another release manifest is refused', async () => {
    await expect(verifySelfRelease(manifest('44'.repeat(48)), document(pcrs))).rejects.toThrow('does not match');
    await expect(verifySelfRelease(manifest('22'.repeat(48)), document(new Map([[0, Buffer.alloc(48, 0x11)]])))).rejects.toThrow();
    await expect(verifySelfRelease(manifest('22'.repeat(48)), new Uint8Array([1, 2, 3]))).rejects.toThrow();
  });
});
