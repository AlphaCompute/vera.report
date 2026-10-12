import { createHash, webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseReadAuthorization, OwnerStatement } from '../../../enclave/src/confidential/authorization';
import {
  caseRecipientKeyId, grantCaseObjectEnvelope, openGrantedCaseObject, openOwnerCaseObject,
} from '../../../enclave/src/confidential/caseObject';
import type { ObjectContext } from '../../../enclave/src/confidential/caseObject';
import {
  CHUNKED_FILE_LIMIT, CHUNK_PLAINTEXT_BYTES, ChunkedObjectError, EvidenceChangedError, EvidenceTooLargeError,
  MAX_CHUNKS_PER_OBJECT, bytesEvidenceSource, chunkCiphertextLength, chunkLayout, chunkedIndexDigest, paddedChunkLayout,
  finalChunkBytes, isChunkCiphertextLength, openGrantedChunkedObject, openOwnerChunkedObject, parseChunkedIndex,
  sealChunkedObject, serializeChunkedIndex,
} from '../../../enclave/src/confidential/caseChunks';
import type { SealedChunkedObject } from '../../../enclave/src/confidential/caseChunks';
import * as host from '../../../src/utils/confidentialChunks';
import { CHUNK_REPLY_LIMIT } from '../../../enclave/src/cases/ownerChannel';
import { MAX_CHUNK_CIPHERTEXT_BYTES } from '../../../enclave/src/confidential/caseChunks';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const ctx: ObjectContext = { caseId: hex(1), objectId: hex(2), scope: 'evidence', keyEpoch: 1, objectRevision: 1 };
let owner: PrivateKey, legal: PrivateKey;

function pattern(size: number, seed = 7): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < size; index++) bytes[index] = (index * 31 + seed + (index >> 11)) & 0xff;
  return bytes;
}
async function sealed(bytes: Uint8Array, context = ctx, name = 'PRIVATE-SENTINEL-video.mp4') {
  return sealChunkedObject(context, bytesEvidenceSource({ name, type: 'video/mp4', bytes }), owner);
}
async function chunks(object: SealedChunkedObject): Promise<Uint8Array[]> {
  const result = [];
  for (let position = 0; position < object.chunkDigests.length; position++) result.push(await object.chunk(position));
  return result;
}
async function readAll(reader: Awaited<ReturnType<typeof openOwnerChunkedObject>>, parts: Uint8Array[]): Promise<Uint8Array> {
  const out = new Uint8Array(reader.size);
  let offset = 0;
  for (let position = 0; position < parts.length; position++) {
    const plain = await reader.openChunk(position, parts[position]);
    out.set(plain, offset); offset += plain.length;
  }
  expect(offset).toBe(reader.size);
  return out;
}

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, legal] = await Promise.all(['owner', 'legal'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
});

describe('chunked evidence object format', () => {
  test.each([0, 1, 4096, 4097, CHUNK_PLAINTEXT_BYTES, CHUNK_PLAINTEXT_BYTES + 1, 2 * CHUNK_PLAINTEXT_BYTES + 12_345])(
    'owner round trip of %i bytes with padded chunks', async size => {
      const bytes = pattern(size), object = await sealed(bytes);
      const index = parseChunkedIndex(object.index);
      expect(index.chunkCount).toBe(paddedChunkLayout(size).chunkCount);
      expect(object.digest).toBe(await chunkedIndexDigest(object.index));
      const parts = await chunks(object);
      parts.forEach((part, position) => {
        expect(part.length).toBe(chunkCiphertextLength(index, position));
        expect(isChunkCiphertextLength(part.length)).toBe(true);
        expect(createHash('sha256').update(part).digest('hex')).toBe(index.chunks[position]);
      });
      const reader = await openOwnerChunkedObject(object.index, object.ownerEnvelope, ctx, object.digest, owner);
      expect({ name: reader.name, type: reader.type, size: reader.size }).toEqual({ name: 'PRIVATE-SENTINEL-video.mp4', type: 'video/mp4', size });
      expect(Buffer.from(await readAll(reader, parts)).equals(Buffer.from(bytes))).toBe(true);
    });

  test('storage sees no file name, type or plaintext, and only bucketed sizes', async () => {
    const bytes = new TextEncoder().encode('PRIVATE-SENTINEL-CONTENT '.repeat(500));
    const object = await sealed(bytes);
    expect(object.index).not.toContain('PRIVATE-SENTINEL');
    expect(object.index).not.toContain('video/mp4');
    const [only] = await chunks(object);
    expect(Buffer.from(only).toString('latin1')).not.toContain('PRIVATE-SENTINEL');
    expect(only.length).toBe(16 * 1024 + 16);
    // Two different names produce indexes of identical length (fixed-size header).
    const other = await sealed(bytes, ctx, 'a');
    expect(other.index.length).toBe(object.index.length);
  });

  describe('integrity', () => {
    let object: SealedChunkedObject, parts: Uint8Array[];
    beforeAll(async () => {
      object = await sealed(pattern(2 * CHUNK_PLAINTEXT_BYTES + 500));
      parts = await chunks(object);
    });
    const open = () => openOwnerChunkedObject(object.index, object.ownerEnvelope, ctx, object.digest, owner);

    test('tampered chunk bytes are rejected', async () => {
      const reader = await open();
      const tampered = new Uint8Array(parts[1]); tampered[100] ^= 1;
      await expect(reader.openChunk(1, tampered)).rejects.toThrow(ChunkedObjectError);
      await expect(reader.openChunk(1, parts[1])).resolves.toHaveLength(CHUNK_PLAINTEXT_BYTES);
    });

    test('reordered chunks are rejected', async () => {
      const reader = await open();
      await expect(reader.openChunk(0, parts[1])).rejects.toThrow(ChunkedObjectError);
      await expect(reader.openChunk(1, parts[0])).rejects.toThrow(ChunkedObjectError);
    });

    test('an index with reordered digests cannot be substituted for the signed one', async () => {
      const index = parseChunkedIndex(object.index);
      const swapped = serializeChunkedIndex({ ...index, chunks: [index.chunks[1], index.chunks[0], index.chunks[2]] });
      // The owner envelope binds the original index digest; a forged digest fails there.
      await expect(openOwnerChunkedObject(swapped, object.ownerEnvelope, ctx, await chunkedIndexDigest(swapped), owner))
        .rejects.toThrow(ChunkedObjectError);
      // The signed digest does not match the forged text.
      await expect(openOwnerChunkedObject(swapped, object.ownerEnvelope, ctx, object.digest, owner))
        .rejects.toThrow(ChunkedObjectError);
    });

    test('truncation is rejected: a middle chunk cannot stand in as the final one', async () => {
      const index = parseChunkedIndex(object.index);
      const truncated = serializeChunkedIndex({ ...index, chunkCount: 2, finalBytes: CHUNK_PLAINTEXT_BYTES,
        chunks: index.chunks.slice(0, 2) });
      await expect(openOwnerChunkedObject(truncated, object.ownerEnvelope, ctx, object.digest, owner))
        .rejects.toThrow(ChunkedObjectError);
      const reader = await open();
      // Wrong length for the final position, and a non-final chunk at the end.
      await expect(reader.openChunk(2, parts[1])).rejects.toThrow(ChunkedObjectError);
      await expect(reader.openChunk(2, parts[2].subarray(0, parts[2].length - 1))).rejects.toThrow(ChunkedObjectError);
      await expect(reader.openChunk(3, parts[2])).rejects.toThrow(ChunkedObjectError);
    });

    test('context is bound: another object, scope or epoch cannot open it', async () => {
      for (const context of [{ ...ctx, objectId: hex(9) }, { ...ctx, scope: 'contact' as const }, { ...ctx, keyEpoch: 2 }]) {
        await expect(openOwnerChunkedObject(object.index, object.ownerEnvelope, context, object.digest, owner))
          .rejects.toThrow(ChunkedObjectError);
      }
    });

    test('the chunked key envelope is not accepted by the whole-object reader', async () => {
      await expect(openOwnerCaseObject({ ciphertext: object.index, ownerEnvelope: object.ownerEnvelope }, ctx, owner)).rejects.toThrow();
    });
  });

  test('a granted organization opens the same chunks through its own envelope', async () => {
    const bytes = pattern(CHUNK_PLAINTEXT_BYTES + 99), object = await sealed(bytes);
    const trust = { caseId: ctx.caseId, ownerFingerprint: owner.getFingerprint(), ownerPublicKey: owner.toPublic() };
    const recipientKeyId = await caseRecipientKeyId(legal.toPublic());
    const signed = async (statement: OwnerStatement) => {
      const wire = await signOwnerStatement(statement, owner);
      return { wire, ...await verifyOwnerStatement(wire, trust) };
    };
    const grant = await signed({ kind: 'grant', caseId: ctx.caseId, revision: 2, grantId: hex(3), organizationId: hex(4),
      recipientKeyId, scopes: ['evidence'], keyEpoch: 1, objectRevisionLimit: null, issuedAt: now - 1000, expiresAt: now + 60_000 });
    const release = await signed({ kind: 'release', caseId: ctx.caseId, revision: 1, releaseDigest: hex(5), issuedAt: now - 1000 });
    const manifest = await signed({ kind: 'manifest', caseId: ctx.caseId, revision: 2, objects: [{ objectId: ctx.objectId,
      scope: 'evidence', objectRevision: 1, keyEpoch: 1, ciphertextDigest: object.digest }] });
    const checkpoint = await signed({ kind: 'checkpoint', caseId: ctx.caseId, revision: 2, keyEpoch: 1, previousDigest: null,
      listingDigest: null, manifestDigest: manifest.digest, grantDigests: [grant.digest], releaseDigests: [release.digest], issuedAt: now });
    const auth: CaseReadAuthorization = { trust, grant: grant.wire, release: release.wire, manifest: manifest.wire,
      checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest, request: { organizationId: hex(4), recipientKeyId,
        objectId: ctx.objectId, ciphertextDigest: object.digest, scope: 'evidence', releaseDigest: hex(5), keyEpoch: 1, objectRevision: 1, now } };
    const envelope = await grantCaseObjectEnvelope(object.ownerEnvelope, ctx, owner, legal.toPublic(), auth);
    const reader = await openGrantedChunkedObject(object.index, envelope, ctx, legal, auth);
    expect(Buffer.from(await readAll(reader, await chunks(object))).equals(Buffer.from(bytes))).toBe(true);
    // Expired grant, other recipient and the whole-object reader are all refused.
    await expect(openGrantedChunkedObject(object.index, envelope, ctx, legal, { ...auth, request: { ...auth.request, now: now + 120_000 } }))
      .rejects.toThrow(ChunkedObjectError);
    await expect(openGrantedChunkedObject(object.index, envelope, ctx, owner, auth)).rejects.toThrow(ChunkedObjectError);
    await expect(openGrantedCaseObject({ ciphertext: object.index, recipientEnvelope: envelope }, ctx, legal, auth)).rejects.toThrow();
  });

  describe('limits and validation', () => {
    test('files over 256 MB are refused before any read', async () => {
      const read = jest.fn();
      await expect(sealChunkedObject(ctx, { name: 'big.mov', type: 'video/quicktime', size: CHUNKED_FILE_LIMIT + 1, read }, owner))
        .rejects.toThrow(EvidenceTooLargeError);
      expect(read).not.toHaveBeenCalled();
      expect(chunkLayout(CHUNKED_FILE_LIMIT)).toEqual({ chunkCount: MAX_CHUNKS_PER_OBJECT, finalBytes: CHUNK_PLAINTEXT_BYTES });
    });

    test('index parsing is strict and canonical', async () => {
      const object = await sealed(pattern(10));
      const index = parseChunkedIndex(object.index);
      for (const bad of [
        object.index.replace('{"format"', '{ "format"'),
        serializeChunkedIndex({ ...index, chunkCount: 2 }),
        serializeChunkedIndex({ ...index, finalBytes: 5000 }),
        serializeChunkedIndex({ ...index, chunkBytes: 1024 }),
        serializeChunkedIndex({ ...index, chunks: ['A'.repeat(64)] }),
        serializeChunkedIndex({ ...index, header: index.header.slice(4) }),
        JSON.stringify({ ...index, extra: 1 }),
        serializeChunkedIndex({ ...index, chunkCount: MAX_CHUNKS_PER_OBJECT + 1,
          chunks: Array.from({ length: MAX_CHUNKS_PER_OBJECT + 1 }, (_, n) => hex(n)) }),
      ]) expect(() => parseChunkedIndex(bad)).toThrow(ChunkedObjectError);
      expect(finalChunkBytes(0)).toBe(4096);
      expect(finalChunkBytes(4097)).toBe(8192);
      expect(isChunkCiphertextLength(5000)).toBe(false);
      expect(isChunkCiphertextLength(CHUNK_PLAINTEXT_BYTES + 17)).toBe(false);
    });

    test('a source that changes after encryption is never uploaded', async () => {
      const bytes = pattern(CHUNK_PLAINTEXT_BYTES + 10);
      const object = await sealChunkedObject(ctx, bytesEvidenceSource({ name: 'f', type: '', bytes }), owner);
      bytes[5] ^= 0xff;
      await expect(object.chunk(0)).rejects.toThrow(EvidenceChangedError);
      await expect(object.chunk(1)).resolves.toBeInstanceOf(Uint8Array);
      const shrinking = { name: 'f', type: '', size: 10, read: async () => new Uint8Array(3) };
      await expect(sealChunkedObject(ctx, shrinking, owner)).rejects.toThrow(EvidenceChangedError);
      object.dispose();
      await expect(object.chunk(1)).rejects.toThrow(ChunkedObjectError);
    });
  });

  test('the host mirror of the size rules matches the enclave format exactly', () => {
    expect(host.MAX_CHUNKS_PER_OBJECT).toBe(MAX_CHUNKS_PER_OBJECT);
    expect(host.MAX_CHUNK_BYTES).toBe(MAX_CHUNK_CIPHERTEXT_BYTES);
    for (let plain = 0; plain <= CHUNK_PLAINTEXT_BYTES + 32; plain += plain < 70_000 ? 1 : 4093) {
      expect([plain, host.isChunkSize(plain + 16)]).toEqual([plain, isChunkCiphertextLength(plain + 16)]);
    }
    for (const size of [4096, 8192, 65536, CHUNK_PLAINTEXT_BYTES]) expect(host.isChunkSize(size + 16)).toBe(true);
    // One full chunk, base64 in a JSON reply with its identifiers, fits one channel reply.
    const reply = JSON.stringify({ caseId: hex(1), objectId: hex(2), ciphertextDigest: hex(3), scope: 'evidence', keyEpoch: 1,
      objectRevision: 1, chunkIndex: 511, chunk: Buffer.alloc(MAX_CHUNK_CIPHERTEXT_BYTES).toString('base64') });
    expect(reply.length).toBeLessThanOrEqual(CHUNK_REPLY_LIMIT);
  });
});
