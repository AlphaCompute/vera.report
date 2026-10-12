import { readFileSync } from 'node:fs';
import { createTrustedClock, nsmDocumentTimestamp } from '../../../enclave/src/cases/trustedClock';

// Minimal CBOR encoder for synthetic local NSM documents (structure only: the
// document comes from the local NSM device, so no signature is checked).
function encode(value: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([major * 32 + n]);
    if (n < 256) return Buffer.from([major * 32 + 24, n]);
    if (n < 65536) return Buffer.from([major * 32 + 25, n >> 8, n & 255]);
    const out = Buffer.alloc(9); out[0] = major * 32 + 27; out.writeBigUInt64BE(BigInt(n), 1); return out;
  };
  if (typeof value === 'number') return head(0, value);
  if (typeof value === 'string') { const data = Buffer.from(value); return Buffer.concat([head(3, data.length), data]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  throw new Error('unsupported');
}
const document = (timestamp: number | string | null) => {
  const payload = new Map<string, unknown>([['module_id', 'synthetic']]);
  if (timestamp !== null) payload.set('timestamp', timestamp);
  return new Uint8Array(encode([encode(new Map([[1, 35]])), new Map(), encode(payload), Buffer.alloc(96)]));
};

const T0 = Date.UTC(2026, 8, 27, 12);

describe('trusted enclave clock', () => {
  function harness(start = T0) {
    const state = { nsm: start, mono: 1_000, host: start };
    const options = { attest: async () => document(state.nsm), monotonic: () => state.mono, hostClock: () => state.host,
      toleranceMs: 30_000, maxAnchorAgeMs: 600_000, refreshMs: 0 };
    return { state, options };
  }

  test('reads the NSM timestamp and rejects malformed or implausible documents', () => {
    expect(nsmDocumentTimestamp(document(T0))).toBe(T0);
    expect(() => nsmDocumentTimestamp(document(null))).toThrow('Trusted time unavailable');
    expect(() => nsmDocumentTimestamp(document('2026-09-27'))).toThrow();
    expect(() => nsmDocumentTimestamp(document(1_000))).toThrow();
    expect(() => nsmDocumentTimestamp(new Uint8Array([1, 2, 3]))).toThrow();
  });

  test('advances with the monotonic clock from the NSM anchor, not with the host clock', async () => {
    const { state, options } = harness();
    const clock = await createTrustedClock(options);
    expect(clock.now()).toBe(T0);
    state.mono += 5_000; state.host += 25_000; // Host runs ahead within tolerance: ignored.
    expect(clock.now()).toBe(T0 + 5_000);
    state.mono += 1_000; state.host = T0 + 6_000;
    expect(clock.now()).toBe(T0 + 6_000);
  });

  test('refuses when the host clock regresses (or jumps ahead) beyond tolerance', async () => {
    const { state, options } = harness();
    const clock = await createTrustedClock(options);
    state.mono += 60_000; state.host = T0 - 3_600_000; // Rolled back an hour: e.g. to revive an expired grant.
    expect(() => clock.now()).toThrow('Trusted time unavailable');
    state.host = T0 + 60_000 - 29_000;
    expect(clock.now()).toBe(T0 + 60_000);
    state.host = T0 + 60_000 + 86_400_000;
    expect(() => clock.now()).toThrow();
  });

  test('refuses a stale anchor and a regressing NSM re-anchor; never goes backwards', async () => {
    const { state, options } = harness();
    const clock = await createTrustedClock(options);
    state.mono += 700_000; state.host = T0 + 700_000;
    expect(() => clock.now()).toThrow(); // Anchor older than maxAnchorAgeMs.
    state.nsm = T0 + 700_000;
    await clock.refresh();
    expect(clock.now()).toBe(T0 + 700_000);
    state.nsm = T0; // A replayed/older document.
    await expect(clock.refresh()).rejects.toThrow();
    // A slightly earlier (within tolerance) NSM reading re-anchors to hypervisor
    // time but never below a value already returned.
    state.mono += 10_000; state.host = T0 + 710_000;
    expect(clock.now()).toBe(T0 + 710_000);
    state.nsm = T0 + 700_000;
    await clock.refresh();
    expect(clock.now()).toBe(T0 + 710_000);
    state.mono += 20_000;
    expect(clock.now()).toBe(T0 + 720_000);
    state.mono -= 1; // Monotonic regression.
    expect(() => clock.now()).toThrow();
  });

  test('a shift of the NSM and host clocks together (qa/e2e time shift) moves trusted time once re-anchored', async () => {
    const { state, options } = harness();
    let offset = 0;
    const clock = await createTrustedClock({ ...options, attest: async () => document(state.nsm + offset),
      hostClock: () => state.host + offset });
    expect(clock.now()).toBe(T0);
    offset = 31 * 86_400_000;
    expect(() => clock.now()).toThrow('Trusted time unavailable'); // Host ahead of the anchor: fails closed until re-anchored.
    await clock.refresh();
    expect(clock.now()).toBe(T0 + offset);
    state.mono += 1_000; state.host += 1_000;
    expect(clock.now()).toBe(T0 + offset + 1_000);
  });

  test('the time-shift seam is never composed in production', () => {
    const source = readFileSync('enclave/src/confidential-server.ts', 'utf8');
    const production = source.slice(source.indexOf('function productionDependencies'), source.indexOf('export async function composeConfidentialServer'));
    expect(production).toContain('startConfidentialServer');
    expect(production).not.toMatch(/timeShift|offsetMs/);
    expect(source).not.toMatch(/process\.env[^\n]*(SHIFT|SKEW|OFFSET)/i);
  });

  test('fails closed when no NSM document can be obtained', async () => {
    const { options } = harness();
    await expect(createTrustedClock({ ...options, attest: async () => { throw new Error('no nsm'); } })).rejects.toThrow();
  });
});
