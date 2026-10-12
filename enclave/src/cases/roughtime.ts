import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/** Minimal Roughtime client (draft-ietf-ntp-roughtime-19 wire format,
 * versions 1 and 0x8000000c) for the enclave's optional external time bound
 * (architecture hole 8).
 *
 * The enclave has no network: the request goes out through the host (storage
 * RPC method `roughtimeExchange`), which is an untrusted relay. That is safe
 * because the answer is authenticated end to end:
 *  - the long-term server key is pinned in the measured configuration and
 *    signs a delegation (online key + validity window);
 *  - the online key signs the response (midpoint, radius, Merkle root);
 *  - the Merkle root commits to the exact request packet, which carries a fresh
 *    32-byte random nonce, and the response echoes that nonce.
 * So the host can delay or drop an answer (bounded by the measured round trip,
 * which widens the accepted interval) but cannot forge or replay one.
 */
export const ROUGHTIME_VERSIONS = [1, 0x8000000c] as const;
const MAGIC = Buffer.from('ROUGHTIM', 'ascii');
const MIN_REQUEST = 1024, MAX_RESPONSE = 4096, MAX_PATH = 32;
const RESPONSE_CONTEXT = Buffer.from('RoughTime v1 response signature\0', 'ascii');
const DELEGATION_CONTEXT = Buffer.from('RoughTime v1 delegation signature\0', 'ascii');
const FAILURE = 'Roughtime response invalid';
function fail(): never { throw new Error(FAILURE); }

/** Tag as the little-endian uint32 of its four ASCII bytes (short names NUL padded). */
export function roughtimeTag(name: string): number {
  const bytes = Buffer.alloc(4);
  bytes.write(name, 'ascii');
  return bytes.readUInt32LE(0);
}
const TAG = Object.fromEntries(['SIG', 'VER', 'SRV', 'NONC', 'TYPE', 'ZZZZ', 'PATH', 'SREP', 'CERT', 'INDX',
  'DELE', 'PUBK', 'MINT', 'MAXT', 'MIDP', 'RADI', 'ROOT', 'VERS'].map(name => [name, roughtimeTag(name)])) as Record<string, number>;

/** Encodes a tag map (values are padded by the caller to multiples of four). */
export function encodeRoughtimeMessage(entries: ReadonlyMap<number, Uint8Array>): Buffer {
  const tags = [...entries.keys()].sort((a, b) => a - b);
  if (!tags.length) fail();
  const header = Buffer.alloc(4 + 8 * tags.length - 4);
  header.writeUInt32LE(tags.length, 0);
  let offset = 0;
  const values: Buffer[] = [];
  tags.forEach((tag, index) => {
    const value = Buffer.from(entries.get(tag)!);
    if (value.length % 4) fail();
    if (index > 0) header.writeUInt32LE(offset, 4 * index);
    header.writeUInt32LE(tag >>> 0, 4 * tags.length + 4 * index);
    values.push(value);
    offset += value.length;
  });
  return Buffer.concat([header, ...values]);
}

/** Strict decoder: ascending unique tags, aligned non-decreasing offsets in range. */
export function decodeRoughtimeMessage(bytes: Uint8Array): Map<number, Buffer> {
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (buffer.length < 4 || buffer.length % 4) fail();
  const count = buffer.readUInt32LE(0);
  if (count < 1 || count > 64) fail();
  const headerLength = 8 * count;
  if (buffer.length < headerLength) fail();
  const valuesLength = buffer.length - headerLength;
  const offsets = [0];
  for (let index = 1; index < count; index++) offsets.push(buffer.readUInt32LE(4 * index));
  offsets.push(valuesLength);
  const result = new Map<number, Buffer>();
  let previousTag = -1;
  for (let index = 0; index < count; index++) {
    const tag = buffer.readUInt32LE(4 * count + 4 * index);
    const start = offsets[index], end = offsets[index + 1];
    if (tag <= previousTag || start % 4 || end % 4 || start > end || end > valuesLength) fail();
    previousTag = tag;
    result.set(tag, buffer.subarray(headerLength + start, headerLength + end));
  }
  return result;
}

function framed(message: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32LE(message.length, 0);
  return Buffer.concat([MAGIC, length, message]);
}
function unframed(packet: Uint8Array): Buffer {
  const buffer = Buffer.from(packet.buffer, packet.byteOffset, packet.byteLength);
  if (buffer.length < 12 || buffer.length > MAX_RESPONSE || !buffer.subarray(0, 8).equals(MAGIC) ||
      buffer.readUInt32LE(8) !== buffer.length - 12) fail();
  return buffer.subarray(12);
}
const u32 = (value: number) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0, 0); return bytes; };
const hash = (...parts: Uint8Array[]) => createHash('sha512').update(Buffer.concat(parts)).digest().subarray(0, 32);

/** SRV value: first 32 bytes of SHA-512(0xff || long-term public key). */
export function roughtimeServerId(publicKey: Uint8Array): Buffer { return hash(Buffer.from([0xff]), publicKey); }

export function ed25519PublicKey(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) fail();
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') }, format: 'jwk' });
}

/** A request packet padded to at least 1024 bytes, with a fresh random nonce. */
export function createRoughtimeRequest(serverPublicKey: Uint8Array, nonce: Uint8Array = randomBytes(32)): { packet: Buffer; nonce: Buffer } {
  if (nonce.length !== 32 || serverPublicKey.length !== 32) fail();
  const entries = new Map<number, Uint8Array>([
    [TAG.VER, Buffer.concat(ROUGHTIME_VERSIONS.map(u32))], [TAG.NONC, Buffer.from(nonce)], [TAG.TYPE, u32(0)],
    [TAG.SRV, roughtimeServerId(serverPublicKey)], [TAG.ZZZZ, Buffer.alloc(0)],
  ]);
  const unpadded = framed(encodeRoughtimeMessage(entries)).length;
  entries.set(TAG.ZZZZ, Buffer.alloc(Math.max(0, MIN_REQUEST - unpadded)));
  return { packet: framed(encodeRoughtimeMessage(entries)), nonce: Buffer.from(nonce) };
}

function field(map: Map<number, Buffer>, tag: number, length?: number): Buffer {
  const value = map.get(tag);
  if (!value || (length !== undefined && value.length !== length)) fail();
  return value;
}
function seconds(value: Buffer): number {
  const big = value.readBigUInt64LE(0);
  if (big > BigInt(Math.floor(Number.MAX_SAFE_INTEGER / 1000))) fail();
  return Number(big);
}

/** Verified time from one response: `midpoint ± radius` (UTC milliseconds). */
export type RoughtimeSample = { midpoint: number; radius: number };

/** Verifies a response against the pinned long-term key and the exact request
 * this enclave sent. Throws on any mismatch; never trusts an unsigned field. */
export function verifyRoughtimeResponse(input: {
  response: Uint8Array; request: Uint8Array; nonce: Uint8Array; publicKey: Uint8Array;
}): RoughtimeSample {
  try {
    const message = decodeRoughtimeMessage(unframed(input.response));
    if (!field(message, TAG.NONC, 32).equals(Buffer.from(input.nonce))) fail();
    if (field(message, TAG.TYPE, 4).readUInt32LE(0) !== 1) fail();
    const certificate = decodeRoughtimeMessage(field(message, TAG.CERT));
    const delegationBytes = field(certificate, TAG.DELE);
    if (!verify(null, Buffer.concat([DELEGATION_CONTEXT, delegationBytes]), ed25519PublicKey(input.publicKey),
      field(certificate, TAG.SIG, 64))) fail();
    const delegation = decodeRoughtimeMessage(delegationBytes);
    const signedBytes = field(message, TAG.SREP);
    if (!verify(null, Buffer.concat([RESPONSE_CONTEXT, signedBytes]), ed25519PublicKey(field(delegation, TAG.PUBK, 32)),
      field(message, TAG.SIG, 64))) fail();
    const signed = decodeRoughtimeMessage(signedBytes);
    if (!(ROUGHTIME_VERSIONS as readonly number[]).includes(field(signed, TAG.VER, 4).readUInt32LE(0))) fail();
    const radius = field(signed, TAG.RADI, 4).readUInt32LE(0), midpoint = seconds(field(signed, TAG.MIDP, 8));
    const minimum = seconds(field(delegation, TAG.MINT, 8)), maximum = seconds(field(delegation, TAG.MAXT, 8));
    // The delegation bounds when its online key may speak: a response outside it is stale.
    if (radius === 0 || midpoint < minimum || midpoint > maximum) fail();
    // The Merkle root must commit to this exact request packet (and thus nonce).
    const path = field(message, TAG.PATH);
    if (path.length % 32 || path.length / 32 > MAX_PATH) fail();
    let index = field(message, TAG.INDX, 4).readUInt32LE(0);
    let node = hash(Buffer.from([0]), input.request);
    for (let offset = 0; offset < path.length; offset += 32) {
      const sibling = path.subarray(offset, offset + 32);
      node = index & 1 ? hash(Buffer.from([1]), sibling, node) : hash(Buffer.from([1]), node, sibling);
      index >>>= 1;
    }
    if (index !== 0 || !node.equals(field(signed, TAG.ROOT, 32))) fail();
    return { midpoint: midpoint * 1000, radius: radius * 1000 };
  } catch { return fail(); }
}

export type RoughtimeServer = { name: string; address: string; publicKey: Uint8Array };
/** Interval that must contain true time at `receivedAt` (monotonic ms). */
export type AuthenticatedTimeBound = { earliest: number; latest: number; receivedAt: number };

/** One sample per pinned server, through the untrusted relay. A server that is
 * unreachable or answers with anything that does not verify yields null. The
 * interval is `midpoint ± radius`, widened by the measured round trip (the
 * answer was produced at some point after the request left). */
export async function sampleRoughtime(servers: readonly RoughtimeServer[],
  exchange: (address: string, packet: Uint8Array) => Promise<Uint8Array | null>,
  monotonic: () => number = () => performance.now()): Promise<(AuthenticatedTimeBound | null)[]> {
  const samples: (AuthenticatedTimeBound | null)[] = [];
  for (const server of servers) {
    try {
      const { packet, nonce } = createRoughtimeRequest(server.publicKey);
      const sentAt = monotonic();
      const response = await exchange(server.address, packet);
      const receivedAt = monotonic();
      if (!response || !(receivedAt >= sentAt)) { samples.push(null); continue; }
      const sample = verifyRoughtimeResponse({ response, request: packet, nonce, publicKey: server.publicKey });
      samples.push({ earliest: sample.midpoint - sample.radius,
        latest: sample.midpoint + sample.radius + Math.ceil(receivedAt - sentAt), receivedAt });
    } catch { samples.push(null); }
  }
  return samples;
}
