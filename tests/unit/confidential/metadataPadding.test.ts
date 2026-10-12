import { createHash, webcrypto } from 'node:crypto';
import { createMessage, decrypt, encrypt, generateKey, readMessage } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import {
  PADDED_PAYLOAD_FORMAT, caseObjectPaddedBytes, caseRecipientKeyId, openOwnerCaseObject, packCaseObjectPayload,
  sealCaseObject, sealChunkedContentKey, unpackCaseObjectPayload,
} from '../../../enclave/src/confidential/caseObject';
import type { ObjectContext } from '../../../enclave/src/confidential/caseObject';
import {
  CHUNKED_OBJECT_FORMAT, CHUNKED_FILE_LIMIT, CHUNK_PLAINTEXT_BYTES, ChunkedObjectError, MAX_CHUNKS_PER_OBJECT,
  MAX_CHUNKS_PER_UPLOAD, PADDED_CHUNKED_OBJECT_FORMAT, bytesEvidenceSource, chunkLayout, isChunkCiphertextLength,
  openOwnerChunkedObject, paddedChunkLayout, parseChunkedIndex, sealChunkedObject, serializeChunkedIndex,
} from '../../../enclave/src/confidential/caseChunks';
import type { ChunkedIndex } from '../../../enclave/src/confidential/caseChunks';
import { chunkCountBucket, padJsonBytes, paddedChunkBudget, powerOfTwoBucket } from '../../../enclave/src/confidential/padding';
import { openCaseMessage, sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import type { MessageParticipants } from '../../../enclave/src/confidential/caseMessage';
import {
  CHANNEL_MIN_PADDED_BYTES, channelPaddedBytes, openChannelRequest, sealChannelRequest, sealChannelResponse,
} from '../../../enclave/src/confidential/channelMessage';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const ctx: ObjectContext = { caseId: hex(1), objectId: hex(2), scope: 'narrative', keyEpoch: 1, objectRevision: 1 };
const evidenceCtx: ObjectContext = { ...ctx, objectId: hex(3), scope: 'evidence' };
let owner: PrivateKey, firm: PrivateKey;

function pattern(size: number, seed = 3): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < size; index++) bytes[index] = (index * 13 + seed + (index >> 9)) & 0xff;
  return bytes;
}
const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
/** Ed25519 signature MPIs drop leading zero bytes, so two ciphertexts of one bucket
 * can differ by a few armored characters; different buckets differ by kilobytes. */
const near = (a: number, b: number) => Math.abs(a - b) <= 8;

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, firm] = await Promise.all(['owner', 'firm'].map(async name => (await generateKey({ type: 'ecc',
    curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
});

describe('bucket functions', () => {
  test('power-of-two buckets have a floor and a cap that is itself a bucket', () => {
    expect(powerOfTwoBucket(0, 4096, 1 << 20)).toBe(4096);
    expect(powerOfTwoBucket(4096, 4096, 1 << 20)).toBe(4096);
    expect(powerOfTwoBucket(4097, 4096, 1 << 20)).toBe(8192);
    expect(powerOfTwoBucket(700_000, 4096, 1 << 20)).toBe(1 << 20);
    expect(powerOfTwoBucket(1_000_000, 4096, 900_000 + 100_000)).toBe(1_000_000);
    expect(() => powerOfTwoBucket(1_000_001, 4096, 1_000_000)).toThrow();
    expect(() => powerOfTwoBucket(1, 3000, 1 << 20)).toThrow();
  });

  test('chunk counts keep three significant bits: few buckets, under 25% overhead, power-of-two limits hold', () => {
    const buckets = new Set<number>();
    for (let count = 1; count <= MAX_CHUNKS_PER_OBJECT; count++) {
      const padded = chunkCountBucket(count);
      buckets.add(padded);
      expect(padded).toBeGreaterThanOrEqual(count);
      expect(padded).toBeLessThan(count * 1.25 + 1);
      expect(chunkCountBucket(padded)).toBe(padded); // Idempotent: a bucket is a fixed point.
      expect(padded).toBeLessThanOrEqual(MAX_CHUNKS_PER_OBJECT);
      if (count > 1) expect(padded).toBeGreaterThanOrEqual(chunkCountBucket(count - 1)); // Monotonic.
    }
    // 1-8 exactly, then four per doubling up to 512: 32 possible counts instead of 512.
    expect(buckets.size).toBe(32);
    expect([9, 10, 11, 17, 33, 65, 129, 257, 385].map(chunkCountBucket)).toEqual([10, 10, 12, 20, 40, 80, 160, 320, 448]);
    expect(MAX_CHUNKS_PER_UPLOAD).toBe(paddedChunkBudget(CHUNKED_FILE_LIMIT / CHUNK_PLAINTEXT_BYTES + 16));
  });

  test('the per-upload chunk budget covers a worst-case split of the upload limit into padded files', () => {
    // Fifteen files of 16 MiB + 1 byte (33 chunks, padded to 40) and the rest of 256 MiB (32 chunks).
    const sizes = [...Array(15).fill(16 * 1024 * 1024 + 1), 16 * 1024 * 1024 - 15];
    expect(sizes.reduce((sum, size) => sum + size, 0)).toBe(CHUNKED_FILE_LIMIT);
    const padded = sizes.reduce((sum, size) => sum + chunkCountBucket(chunkLayout(size).chunkCount), 0);
    expect(padded).toBe(15 * 40 + 32);
    expect(padded).toBeLessThanOrEqual(MAX_CHUNKS_PER_UPLOAD);
  });

  test('JSON space padding parses to the same value and rejects anything else as padding', () => {
    const json = new TextEncoder().encode(JSON.stringify({ a: 1 }));
    const padded = padJsonBytes(json, 64);
    expect(padded.length).toBe(64);
    expect(JSON.parse(new TextDecoder().decode(padded))).toEqual({ a: 1 });
    padded[40] = 0x78;
    expect(() => JSON.parse(new TextDecoder().decode(padded))).toThrow();
    expect(() => padJsonBytes(json, json.length - 1)).toThrow();
  });
});

describe('whole-buffer case objects', () => {
  test.each([0, 1, 100, 3000, 3700, 5000, 70_000, 1_500_000])('%i bytes round-trip through a padded bucket', async size => {
    const plaintext = pattern(size);
    const packed = packCaseObjectPayload(ctx, plaintext);
    expect(packed.length).toBe(caseObjectPaddedBytes(packed.length));
    expect(packed.length & (packed.length - 1)).toBe(0);
    expect(Buffer.from(unpackCaseObjectPayload(packed, ctx)).equals(Buffer.from(plaintext))).toBe(true);
    const sealed = await sealCaseObject(ctx, plaintext, owner);
    expect(Buffer.from(await openOwnerCaseObject(sealed, ctx, owner)).equals(Buffer.from(plaintext))).toBe(true);
  });

  test('storage sees one ciphertext length per bucket, not the payload length', async () => {
    const lengths = await Promise.all([1, 200, 2000, 3500].map(async size =>
      (await sealCaseObject(ctx, pattern(size), owner)).ciphertext.length));
    expect(lengths.every(length => near(length, lengths[0]))).toBe(true);
    const larger = await sealCaseObject(ctx, pattern(5000), owner);
    expect(larger.ciphertext.length).toBeGreaterThan(lengths[0] + 4000);
    // Exact sizes 5,000 and 7,500 land in the same (8 KiB) bucket.
    expect(near((await sealCaseObject(ctx, pattern(7500), owner)).ciphertext.length, larger.ciphertext.length)).toBe(true);
  });

  test('the largest object uses the top bucket and still fits every transport bound', async () => {
    const top = packCaseObjectPayload(ctx, new Uint8Array(8 * 1024 * 1024));
    expect(top.length).toBe(8 * 1024 * 1024 + 4096);
    expect(packCaseObjectPayload(ctx, new Uint8Array(4 * 1024 * 1024)).length).toBe(8 * 1024 * 1024);
  });

  test('tampered, truncated, extended or non-zero padding is rejected', () => {
    const packed = packCaseObjectPayload(ctx, pattern(1500));
    const nonZero = new Uint8Array(packed); nonZero[nonZero.length - 1] = 1;
    expect(() => unpackCaseObjectPayload(nonZero, ctx)).toThrow();
    expect(() => unpackCaseObjectPayload(packed.subarray(0, packed.length - 1), ctx)).toThrow();
    const extended = new Uint8Array(packed.length * 2); extended.set(packed);
    expect(() => unpackCaseObjectPayload(extended, ctx)).toThrow(); // A bucket, but not this payload's bucket.
    // The signed header's length is authoritative. Claiming one byte less turns the
    // last payload byte into non-zero padding; claiming more than the bucket holds
    // (so the bucket no longer matches) is rejected too.
    const size = new DataView(packed.buffer).getUint32(0);
    const header = JSON.parse(new TextDecoder().decode(packed.subarray(4, 4 + size)));
    const withLength = (length: number) => {
      const forged = new TextEncoder().encode(JSON.stringify({ ...header, length }));
      expect(forged.length).toBe(size);
      const bytes = new Uint8Array(packed); bytes.set(forged, 4);
      return bytes;
    };
    const shorter = withLength(1499), beyond = withLength(9999);
    expect(Buffer.from(unpackCaseObjectPayload(withLength(1500), ctx)).equals(Buffer.from(pattern(1500)))).toBe(true);
    expect(() => unpackCaseObjectPayload(shorter, ctx)).toThrow();
    expect(() => unpackCaseObjectPayload(beyond, ctx)).toThrow();
    expect(() => unpackCaseObjectPayload(packed, { ...ctx, objectId: hex(9) })).toThrow();
    expect(header.format).toBe(PADDED_PAYLOAD_FORMAT);
  });

  test('a flipped bit anywhere in the stored ciphertext (including the padding) fails to open', async () => {
    const sealed = await sealCaseObject(ctx, pattern(10), owner);
    const lines = sealed.ciphertext.split('\n');
    // Base64 body lines sit between the armor header and the checksum/footer.
    const body = lines.map((line, index) => ({ line, index })).filter(item => /^[A-Za-z0-9+/]{60,}$/.test(item.line));
    for (const { line, index } of [body[Math.floor(body.length / 2)], body[body.length - 3]]) {
      const flipped = [...lines];
      flipped[index] = line.slice(0, 10) + (line[10] === 'A' ? 'B' : 'A') + line.slice(11);
      await expect(openOwnerCaseObject({ ...sealed, ciphertext: flipped.join('\n') }, ctx, owner)).rejects.toThrow();
    }
  });

  test('objects written before padding (unpadded v1 framing) still open', async () => {
    // Independent re-implementation of the pre-padding writer (commit fad9839e).
    const plaintext = new TextEncoder().encode('SYNTHETIC LEGACY PAYLOAD written before size buckets');
    const header = new TextEncoder().encode(JSON.stringify({ format: 'vera-case-object/v1', context: ctx }));
    const packed = new Uint8Array(4 + header.length + plaintext.length);
    new DataView(packed.buffer).setUint32(0, header.length);
    packed.set(header, 4); packed.set(plaintext, 4 + header.length);
    const key = webcrypto.getRandomValues(new Uint8Array(32));
    const ciphertext = await encrypt({ message: await createMessage({ binary: packed }),
      sessionKey: { algorithm: 'aes256', data: key }, signingKeys: owner, format: 'armored' }) as string;
    const envelope = { format: 'vera-case-object/v1', context: ctx, ciphertextDigest: sha256(ciphertext),
      sessionKey: b64(key), grantDigest: null, recipientKeyId: await caseRecipientKeyId(owner.toPublic()) };
    const ownerEnvelope = await encrypt({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(envelope)) }),
      encryptionKeys: owner.toPublic(), signingKeys: owner, wildcard: true, format: 'armored' }) as string;
    expect(await openOwnerCaseObject({ ciphertext, ownerEnvelope }, ctx, owner)).toEqual(plaintext);
    // The unpadded legacy framing is still bounded and context-bound.
    await expect(openOwnerCaseObject({ ciphertext, ownerEnvelope }, { ...ctx, objectRevision: 2 }, owner)).rejects.toThrow();
  });
});

/** Independent writer for the documented chunked construction, so legacy (v2)
 * objects and deliberately malformed padding can be produced for the reader. */
async function buildChunked(format: string, context: ObjectContext, file: Uint8Array,
  layout: { chunkCount: number; finalBytes: number }, fill = 0) {
  const subtle = webcrypto.subtle;
  const contentKey = webcrypto.getRandomValues(new Uint8Array(32));
  const base = await subtle.importKey('raw', contentKey, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(format),
    info: new TextEncoder().encode('vera chunk key aes-256-gcm') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const aad = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify({ format,
    caseId: context.caseId, objectId: context.objectId, scope: context.scope, keyEpoch: context.keyEpoch,
    objectRevision: context.objectRevision, chunkBytes: CHUNK_PLAINTEXT_BYTES, chunkCount: layout.chunkCount,
    finalBytes: layout.finalBytes }))));
  const headerJson = new TextEncoder().encode(JSON.stringify({ name: 'legacy.bin', type: 'application/octet-stream', size: file.length }));
  const headerPlain = new Uint8Array(1024);
  new DataView(headerPlain.buffer).setUint32(0, headerJson.length); headerPlain.set(headerJson, 4);
  const headerNonce = new Uint8Array(12); headerNonce[0] = 1;
  const header = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: headerNonce, additionalData: aad }, key, headerPlain));
  const parts: Uint8Array[] = [];
  for (let position = 0; position < layout.chunkCount; position++) {
    const final = position === layout.chunkCount - 1;
    const plain = new Uint8Array(final ? layout.finalBytes : CHUNK_PLAINTEXT_BYTES).fill(fill);
    plain.set(file.subarray(position * CHUNK_PLAINTEXT_BYTES, (position + 1) * CHUNK_PLAINTEXT_BYTES));
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setUint32(7, position); nonce[11] = final ? 1 : 0;
    parts.push(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, plain)));
  }
  const index = JSON.stringify({ format, chunkBytes: CHUNK_PLAINTEXT_BYTES, chunkCount: layout.chunkCount,
    finalBytes: layout.finalBytes, header: b64(header), chunks: parts.map(part => sha256(part)) });
  const digest = sha256(index);
  const ownerEnvelope = await sealChunkedContentKey(context, digest, contentKey, owner);
  return { index, digest, ownerEnvelope, parts };
}
async function readAll(reader: Awaited<ReturnType<typeof openOwnerChunkedObject>>, parts: Uint8Array[]): Promise<Buffer> {
  const out: Buffer[] = [];
  for (let position = 0; position < parts.length; position++) out.push(Buffer.from(await reader.openChunk(position, parts[position])));
  return Buffer.concat(out);
}

describe('chunked evidence objects', () => {
  test.each([
    [0, 1, 4096], [5000, 1, 8192], [CHUNK_PLAINTEXT_BYTES, 1, CHUNK_PLAINTEXT_BYTES],
    [CHUNK_PLAINTEXT_BYTES + 1, 2, CHUNK_PLAINTEXT_BYTES], [8 * CHUNK_PLAINTEXT_BYTES + 1, 10, CHUNK_PLAINTEXT_BYTES],
  ])('%i bytes: v3 layout of %i chunks, final %i bytes, round trip with padding chunks', async (size, count, finalBytes) => {
    expect(paddedChunkLayout(size)).toEqual({ chunkCount: count, finalBytes });
    const file = pattern(size);
    const object = await sealChunkedObject(evidenceCtx, bytesEvidenceSource({ name: 'x.bin', type: '', bytes: file }), owner);
    const index = parseChunkedIndex(object.index);
    expect(index).toMatchObject({ format: PADDED_CHUNKED_OBJECT_FORMAT, chunkCount: count, finalBytes });
    const parts = [];
    for (let position = 0; position < count; position++) parts.push(await object.chunk(position));
    // Every stored chunk is an allowed size; multi-chunk objects are all full chunks.
    expect(parts.every(part => isChunkCiphertextLength(part.length))).toBe(true);
    if (count > 1) expect(new Set(parts.map(part => part.length))).toEqual(new Set([CHUNK_PLAINTEXT_BYTES + 16]));
    // Padding chunks are distinct ciphertexts (distinct nonces), so digests never collide.
    expect(new Set(index.chunks).size).toBe(count);
    const reader = await openOwnerChunkedObject(object.index, object.ownerEnvelope, evidenceCtx, object.digest, owner);
    expect(reader.size).toBe(size);
    expect((await readAll(reader, parts)).equals(Buffer.from(file))).toBe(true);
    object.dispose();
  });

  test('storage sees the same layout for files of different sizes within one bucket', async () => {
    const layouts = [8 * CHUNK_PLAINTEXT_BYTES + 1, 9 * CHUNK_PLAINTEXT_BYTES, 10 * CHUNK_PLAINTEXT_BYTES]
      .map(paddedChunkLayout);
    expect(new Set(layouts.map(item => JSON.stringify(item))).size).toBe(1);
    // A tiny and a nearly 4 KiB file are indistinguishable too.
    expect(paddedChunkLayout(1)).toEqual(paddedChunkLayout(4096));
  });

  test('a v3 index must declare a bucketed layout, even before any key is used', () => {
    const header = Buffer.alloc(1024 + 16).toString('base64');
    const valid: ChunkedIndex = { format: PADDED_CHUNKED_OBJECT_FORMAT, chunkBytes: CHUNK_PLAINTEXT_BYTES, chunkCount: 10,
      finalBytes: CHUNK_PLAINTEXT_BYTES, header, chunks: Array.from({ length: 10 }, (_, index) => hex(index + 1)) };
    expect(() => parseChunkedIndex(serializeChunkedIndex(valid))).not.toThrow();
    // Nine chunks is not a bucket, and a partial final chunk is not allowed with several chunks.
    expect(() => parseChunkedIndex(serializeChunkedIndex({ ...valid, chunkCount: 9, chunks: valid.chunks.slice(0, 9) })))
      .toThrow(ChunkedObjectError);
    expect(() => parseChunkedIndex(serializeChunkedIndex({ ...valid, finalBytes: 4096 }))).toThrow(ChunkedObjectError);
    // The same unbucketed layout is still accepted as a legacy v2 index.
    expect(() => parseChunkedIndex(serializeChunkedIndex({ ...valid, format: CHUNKED_OBJECT_FORMAT, chunkCount: 9,
      finalBytes: 4096, chunks: valid.chunks.slice(0, 9) }))).not.toThrow();
  });

  test('legacy v2 objects (padded final chunk, exact count) still open', async () => {
    const file = pattern(2 * CHUNK_PLAINTEXT_BYTES + 5000);
    const layout = chunkLayout(file.length);
    expect(layout).toEqual({ chunkCount: 3, finalBytes: 8192 });
    const legacy = await buildChunked(CHUNKED_OBJECT_FORMAT, evidenceCtx, file, layout);
    const reader = await openOwnerChunkedObject(legacy.index, legacy.ownerEnvelope, evidenceCtx, legacy.digest, owner);
    expect(reader.index.format).toBe(CHUNKED_OBJECT_FORMAT);
    expect((await readAll(reader, legacy.parts)).equals(Buffer.from(file))).toBe(true);
  });

  test('non-zero padding inside a validly encrypted chunk is rejected, in a padding chunk or a data tail', async () => {
    const file = pattern(8 * CHUNK_PLAINTEXT_BYTES + 1);
    const forged = await buildChunked(PADDED_CHUNKED_OBJECT_FORMAT, evidenceCtx, file, paddedChunkLayout(file.length), 7);
    const reader = await openOwnerChunkedObject(forged.index, forged.ownerEnvelope, evidenceCtx, forged.digest, owner);
    // Chunk 0 is all data; chunk 8 holds one data byte then non-zero padding; chunk 9 is padding only.
    await expect(reader.openChunk(0, forged.parts[0])).resolves.toHaveLength(CHUNK_PLAINTEXT_BYTES);
    await expect(reader.openChunk(8, forged.parts[8])).rejects.toThrow(ChunkedObjectError);
    await expect(reader.openChunk(9, forged.parts[9])).rejects.toThrow(ChunkedObjectError);
    // The honest writer's padding chunk opens to nothing.
    const honest = await buildChunked(PADDED_CHUNKED_OBJECT_FORMAT, evidenceCtx, file, paddedChunkLayout(file.length));
    const honestReader = await openOwnerChunkedObject(honest.index, honest.ownerEnvelope, evidenceCtx, honest.digest, owner);
    await expect(honestReader.openChunk(9, honest.parts[9])).resolves.toHaveLength(0);
  });

  test('tampered padding chunks, a relabelled format, or an unpadded v3 layout are rejected', async () => {
    const file = pattern(8 * CHUNK_PLAINTEXT_BYTES + 1);
    const object = await buildChunked(PADDED_CHUNKED_OBJECT_FORMAT, evidenceCtx, file, paddedChunkLayout(file.length));
    const reader = await openOwnerChunkedObject(object.index, object.ownerEnvelope, evidenceCtx, object.digest, owner);
    const tampered = new Uint8Array(object.parts[9]); tampered[5] ^= 1;
    await expect(reader.openChunk(9, tampered)).rejects.toThrow(ChunkedObjectError);
    // Padding chunks cannot be swapped with each other or with data chunks.
    await expect(reader.openChunk(8, object.parts[9])).rejects.toThrow(ChunkedObjectError);
    // Relabelling the index format changes the signed digest and the AAD.
    const relabelled = object.index.replace(PADDED_CHUNKED_OBJECT_FORMAT, CHUNKED_OBJECT_FORMAT);
    await expect(openOwnerChunkedObject(relabelled, object.ownerEnvelope, evidenceCtx, object.digest, owner)).rejects.toThrow();
    // A v3 writer that skipped count padding produces an object no reader accepts.
    const unpadded = await buildChunked(PADDED_CHUNKED_OBJECT_FORMAT, evidenceCtx, file, chunkLayout(file.length));
    await expect(openOwnerChunkedObject(unpadded.index, unpadded.ownerEnvelope, evidenceCtx, unpadded.digest, owner))
      .rejects.toThrow(ChunkedObjectError);
  });
});

describe('case messages', () => {
  let participants: MessageParticipants;
  beforeAll(() => {
    participants = { owner: { caseId: ctx.caseId, ownerFingerprint: owner.getFingerprint(), ownerPublicKey: owner.toPublic() },
      organization: { organizationId: hex(7), publicKey: firm.toPublic() } };
  });
  test('message ciphertext length is a bucket, not the body length, and padding is invisible to readers', async () => {
    const seal = (body: string, sequence = 1) => sealCaseMessage({ sender: 'owner', sequence, sentAt: 1_700_000_000_000, body },
      participants, owner);
    const short = await seal('Hi'), medium = await seal('x'.repeat(3000)), long = await seal('y'.repeat(5000));
    expect(near(medium.length, short.length)).toBe(true);
    expect(long.length).toBeGreaterThan(short.length + 4000);
    expect((await openCaseMessage(medium, participants, firm, { owner: 0, organization: 0 })).body).toBe('x'.repeat(3000));
    const worst = await seal('一'.repeat(10_000)); // 30 KB of UTF-8: the 32 KiB top bucket.
    expect(worst.length).toBeLessThan(48 * 1024);
    expect((await openCaseMessage(worst, participants, owner, { owner: 0, organization: 0 })).body).toHaveLength(10_000);
  });
  test('unpadded messages written before padding still open', async () => {
    const message = { format: 'vera-case-message/v1', caseId: ctx.caseId, organizationId: hex(7),
      recipientKeyId: await caseRecipientKeyId(firm.toPublic()), sender: 'owner', sequence: 3, sentAt: 1_700_000_000_000,
      body: 'SYNTHETIC LEGACY MESSAGE' };
    const wire = await encrypt({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(message)) }),
      encryptionKeys: [owner.toPublic(), firm.toPublic()], signingKeys: owner, wildcard: true, format: 'armored' }) as string;
    expect((await openCaseMessage(wire, participants, firm, { owner: 0, organization: 0 })).body).toBe('SYNTHETIC LEGACY MESSAGE');
  });
});

describe('attested channel', () => {
  let server: PrivateKey;
  beforeAll(async () => {
    server = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'enclave' }], format: 'object' })).privateKey;
  });
  const nonce = '1'.repeat(64);
  test('request and response wire sizes are buckets of at least 16 KiB', async () => {
    const sizes = await Promise.all([1, 500, 6000].map(async size =>
      (await sealChannelRequest(server.toPublic(), nonce, pattern(size))).ciphertext.length));
    expect(sizes.every(size => near(size, sizes[0]))).toBe(true);
    const bigger = await sealChannelRequest(server.toPublic(), nonce, pattern(20_000));
    expect(bigger.ciphertext.length).toBeGreaterThan(sizes[0] + 16_000);
    const request = await openChannelRequest(bigger.ciphertext, nonce, server);
    expect(Buffer.from(request.body).equals(Buffer.from(pattern(20_000)))).toBe(true);
    const replies = await Promise.all([1, 3000].map(async size => {
      const pending = await sealChannelRequest(server.toPublic(), nonce, pattern(1));
      const reply = await sealChannelResponse(await openChannelRequest(pending.ciphertext, nonce, server), pattern(size), server);
      expect(Buffer.from(await pending.openResponse(reply)).equals(Buffer.from(pattern(size)))).toBe(true);
      return reply.length;
    }));
    expect(near(replies[0], replies[1])).toBe(true);
    // The signed plaintext itself is padded: it decrypts to exactly one bucket.
    const pending = await sealChannelRequest(server.toPublic(), nonce, pattern(10));
    const { data } = await decrypt({ message: await readMessage({ armoredMessage: pending.ciphertext }),
      decryptionKeys: server, format: 'binary' });
    expect(data.length).toBe(CHANNEL_MIN_PADDED_BYTES);
    expect(channelPaddedBytes(100, 'request')).toBe(CHANNEL_MIN_PADDED_BYTES);
    // One maximum evidence chunk per response stays inside the response bound.
    expect(channelPaddedBytes(4 * Math.ceil((4 * Math.ceil((CHUNK_PLAINTEXT_BYTES + 16) / 3) + 400) / 3) + 400, 'response'))
      .toBe(1024 * 1024);
  });
  test('an unpadded request from an older client is still accepted', async () => {
    const reply = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'reply' }], format: 'object' });
    const value = { format: 'vera-channel-request/v1', nonce, requestId: hex(5), serverKeyId: await caseRecipientKeyId(server.toPublic()),
      replyPublicKey: b64(reply.publicKey.write()), body: b64(new TextEncoder().encode('SYNTHETIC LEGACY BODY')) };
    const ciphertext = await encrypt({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value)) }),
      encryptionKeys: server.toPublic(), signingKeys: reply.privateKey, wildcard: true, format: 'armored' }) as string;
    const opened = await openChannelRequest(ciphertext, nonce, server);
    expect(new TextDecoder().decode(opened.body)).toBe('SYNTHETIC LEGACY BODY');
  });
});
