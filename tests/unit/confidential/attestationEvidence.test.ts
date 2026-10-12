import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { prepareApplicationAttestation } from '../../../enclave/src/confidential/attestationEvidence';
import type { ApplicationAttestationPolicy } from '../../../enclave/src/confidential/attestationEvidence';

// Independent test encoder, including 64-bit timestamps. Production only
// constructs the fixed COSE Sig_structure; it never re-encodes signed payloads.
function encode(value: unknown): Buffer {
  function head(major: number, n: number): Buffer {
    if (n < 24) return Buffer.from([major * 32 + n]);
    if (n < 256) return Buffer.from([major * 32 + 24, n]);
    if (n < 65536) return Buffer.from([major * 32 + 25, n >> 8, n & 255]);
    const bytes = Buffer.alloc(9); bytes[0] = major * 32 + 27; bytes.writeBigUInt64BE(BigInt(n), 1); return bytes;
  }
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'number') return head(value >= 0 ? 0 : 1, value >= 0 ? value : -1 - value);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  throw new Error('unsupported fixture');
}
const now = 1700000000000, nonce = Buffer.alloc(32, 1), channel = Buffer.from('synthetic public key packets');
const pins = () => new Map([0, 1, 2].map(i => [i, Buffer.alloc(48, i + 1)]));
const policy = (): ApplicationAttestationPolicy => ({ nonce, now, expectedPcrs: pins() });
const pair = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
const header = Buffer.from('a118013822', 'hex'); // Nonminimal key 1 is deliberately preserved.
function fixture(change: (body: Map<string, unknown>) => void = () => {}, protectedBytes: Uint8Array = header) {
  const body = new Map<string, unknown>([
    ['module_id', 'synthetic'], ['timestamp', now], ['digest', 'SHA384'], ['pcrs', pins()],
    ['certificate', Buffer.from([1])], ['cabundle', [Buffer.from([2])]], ['nonce', nonce],
    ['public_key', null], ['user_data', Buffer.concat([Buffer.from('VERA-CONFIDENTIAL-CHANNEL-v1'), createHash('sha256').update(channel).digest()])],
  ]);
  change(body);
  const encoded = encode(body);
  // Sign an indefinite map, not a canonical re-encoding of it.
  const payload = Buffer.concat([Buffer.from([0xbf]), encoded.subarray(1), Buffer.from([0xff])]);
  const signed = encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
  const signature = sign('sha384', signed, { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
  return { document: encode([protectedBytes, new Map(), payload, signature]), signed, signature, payload };
}

test.each([['behind', -(CLOCK_SKEW_MS - 1_000)], ['ahead', CLOCK_SKEW_MS - 1_000]])(
  'accepts a quote from an enclave clock %s of the browser within the tolerated skew', async (_name, offset) => {
    const f = fixture(b => b.set('timestamp', now + (offset as number)));
    await expect(prepareApplicationAttestation(f.document, channel, policy())).resolves.toMatchObject({ timestamp: now + (offset as number) });
  });

test('preserves exact signed headers/payload and prepares real ES384 signature input', async () => {
  const f = fixture(), result = await prepareApplicationAttestation(f.document, channel, policy());
  expect(Buffer.from(result.signedBytes)).toEqual(f.signed);
  expect(verify('sha384', result.signedBytes, { key: pair.publicKey, dsaEncoding: 'ieee-p1363' }, result.signature)).toBe(true);
  // Deliberately invalid certificate bytes are not trusted by this preparatory step.
  expect(result.status).toBe('unverified');
  expect(result.certificate).toEqual(new Uint8Array([1]));
  const tagged = Buffer.concat([Buffer.from([0xd2]), f.document]);
  expect((await prepareApplicationAttestation(tagged, channel, policy())).signedBytes).toEqual(result.signedBytes);
});

test.each<[string, (body: Map<string, unknown>) => void]>([
  ['wrong nonce', b => b.set('nonce', Buffer.alloc(32, 2))],
  ['wrong domain', b => b.set('user_data', Buffer.alloc(58))],
  ['wrong key binding', b => { const data = Buffer.from(b.get('user_data') as Buffer); data[data.length - 1] ^= 1; b.set('user_data', data); }],
  ['stale quote', b => b.set('timestamp', now - 60001 - CLOCK_SKEW_MS)],
  ['future quote', b => b.set('timestamp', now + CLOCK_SKEW_MS + 1)],
  ['non-numeric timestamp', b => b.set('timestamp', String(now))],
  ['wrong PCR', b => (b.get('pcrs') as Map<number, Buffer>).set(1, Buffer.alloc(48, 9))],
  ['debug PCR', b => (b.get('pcrs') as Map<number, Buffer>).set(0, Buffer.alloc(48))],
  ['missing PCR', b => (b.get('pcrs') as Map<number, Buffer>).delete(2)],
  ['invalid PCR index', b => (b.get('pcrs') as Map<number, Buffer>).set(32, Buffer.alloc(48))],
  ['wrong digest', b => b.set('digest', 'SHA256')],
  ['empty identity', b => b.set('module_id', '')],
  ['oversized identity', b => b.set('module_id', 'x'.repeat(1025))],
  ['unexpected recipient key', b => b.set('public_key', Buffer.from([1]))],
  ['missing certificate', b => b.delete('certificate')],
  ['empty certificate', b => b.set('certificate', Buffer.alloc(0))],
  ['empty bundle', b => b.set('cabundle', [])],
  ['oversized bundle', b => b.set('cabundle', Array(11).fill(Buffer.from([1])))],
  ['unknown payload field', b => b.set('extension', 'unknown')],
])('rejects %s before certificate verification', async (_, change) => {
  await expect(prepareApplicationAttestation(fixture(change).document, channel, policy())).rejects.toThrow();
});

test('rejects unsupported COSE headers, shape and signature sizes', async () => {
  const f = fixture();
  for (const document of [
    fixture(() => {}, encode(new Map([[1, -7]]))).document,
    fixture(() => {}, encode(new Map([['1', -35]]))).document,
    encode([header, new Map([[4, Buffer.from([1])]]), f.payload, f.signature]),
    encode([header, new Map(), f.payload, f.signature.subarray(1)]),
    encode([header, new Map(), f.payload]),
  ]) await expect(prepareApplicationAttestation(document, channel, policy())).rejects.toThrow();
});

test('requires independent non-debug PCR0/1/2 pins and a valid clock', async () => {
  const f = fixture();
  for (const change of [
    { expectedPcrs: new Map([[0, Buffer.alloc(48, 1)]]) },
    { expectedPcrs: new Map([...pins(), [0, Buffer.alloc(48)]]) },
    { expectedPcrs: new Map([...pins(), [32, Buffer.alloc(48, 1)]]) },
    { now: NaN }, { now: 0 }, { now: 1.1 }, { now: 8640000000000001 },
    { nonce: Buffer.alloc(31) },
  ]) await expect(prepareApplicationAttestation(f.document, channel, { ...policy(), ...change })).rejects.toThrow();
  await expect(prepareApplicationAttestation(f.document, Buffer.from('substituted key'), policy())).rejects.toThrow();
});

test('snapshots mutable caller policy and input before asynchronous hashing', async () => {
  const f = fixture(), p = policy(), key = Buffer.from(channel);
  p.nonce = Buffer.from(nonce);
  const pending = prepareApplicationAttestation(f.document, key, p);
  f.document.fill(0); key.fill(0); p.nonce.fill(0); p.expectedPcrs.get(0)!.fill(0); p.now = 1;
  const result = await pending;
  expect(result.status).toBe('unverified');
  expect(Buffer.from(result.channelPublicKey)).toEqual(channel);
});
