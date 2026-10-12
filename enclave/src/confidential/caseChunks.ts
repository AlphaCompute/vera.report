import type { PrivateKey } from './pgp.ts';
import type { CaseReadAuthorization } from './authorization.ts';
import {
  openGrantedChunkedContentKey, openOwnerChunkedContentKey, sealChunkedContentKey,
} from './caseObject.ts';
import type { ObjectContext } from './caseObject.ts';
import { chunkCountBucket, paddedChunkBudget } from './padding.ts';
import { decodeCanonicalBase64, encodeBase64 } from './base64.ts';

/** Chunked encrypted case objects for large evidence: `vera-case-object/v3`
 * (written now, size-padded) and `vera-case-object/v2` (read-only, older cases).
 *
 * A file is split into fixed 512 KiB plaintext chunks. Each chunk is sealed with
 * AES-256-GCM under a key derived (HKDF-SHA-256) from a fresh random 256-bit
 * content key, following the STREAM construction:
 *   nonce = 7 zero bytes || uint32be(chunk index) || final flag (0x01 on the last chunk)
 *   AAD   = SHA-256(index format, object context, chunk size, chunk count, final size)
 * so every chunk is authenticated on its own, cannot be moved to another
 * position (index in the nonce), another object/case/scope/epoch (context in the
 * AAD), or be dropped from the end (count in the AAD, final flag in the nonce).
 *
 * The canonical index lists the SHA-256 of every chunk ciphertext in order plus
 * an encrypted, fixed-size file header (name, type, exact size). The digest of
 * the index text is what the owner-signed manifest records, so owner authenticity
 * covers every chunk; readers check each chunk digest before decrypting it.
 *
 * Size padding (hole 12). All padding is zero plaintext inside the AEAD, checked
 * on open, and the padded layout is bound by the AAD:
 *  - v2: the last chunk is padded to a power of two between 4 KiB and 512 KiB, so
 *    storage learns the size to 512 KiB (chunk count) plus the final bucket.
 *  - v3: a file of one chunk is padded like v2 (power of two, 4 KiB floor). A
 *    larger file uses only full 512 KiB chunks and its chunk count is rounded up
 *    to keep three significant bits (`chunkCountBucket`, under 25% overhead), with
 *    all-zero padding chunks after the data. The exact size is only in the
 *    encrypted header.
 * The content key travels in the same owner-signed OpenPGP key envelopes as
 * whole-buffer objects, under its own format label (`vera-case-object/v2` for
 * both index formats; the AAD and HKDF salt bind the index format).
 */
export const CHUNKED_OBJECT_FORMAT = 'vera-case-object/v2';
/** Index format of new (count-padded) chunked objects. */
export const PADDED_CHUNKED_OBJECT_FORMAT = 'vera-case-object/v3';
type ChunkedFormat = typeof CHUNKED_OBJECT_FORMAT | typeof PADDED_CHUNKED_OBJECT_FORMAT;
export const CHUNK_PLAINTEXT_BYTES = 512 * 1024;
export const CHUNK_TAG_BYTES = 16;
export const MIN_FINAL_CHUNK_BYTES = 4096;
/** Largest evidence file. */
export const CHUNKED_FILE_LIMIT = 256 * 1024 * 1024;
/** Most evidence bytes per submission or per "add files" commit. */
export const CHUNKED_UPLOAD_LIMIT = 256 * 1024 * 1024;
export const MAX_FILES_PER_UPLOAD = 16;
export const MAX_CHUNKS_PER_OBJECT = CHUNKED_FILE_LIMIT / CHUNK_PLAINTEXT_BYTES;
/** Upper bound on chunks one upload can produce: each file adds at most one
 * partial chunk, and count padding adds under 25% per file. */
export const MAX_CHUNKS_PER_UPLOAD = paddedChunkBudget(CHUNKED_UPLOAD_LIMIT / CHUNK_PLAINTEXT_BYTES + MAX_FILES_PER_UPLOAD);
export const MAX_CHUNK_CIPHERTEXT_BYTES = CHUNK_PLAINTEXT_BYTES + CHUNK_TAG_BYTES;
const HEADER_PLAINTEXT_BYTES = 1024;
const HEADER_WIRE_LENGTH = 4 * Math.ceil((HEADER_PLAINTEXT_BYTES + CHUNK_TAG_BYTES) / 3);
/** Index text bound: 512 digest entries plus the fixed header and framing. */
export const MAX_CHUNKED_INDEX_BYTES = 40 * 1024;
const INDEX_PREFIXES = [CHUNKED_OBJECT_FORMAT, PADDED_CHUNKED_OBJECT_FORMAT].map(format => `{"format":"${format}"`);

export type ChunkedIndex = {
  format: ChunkedFormat; chunkBytes: number; chunkCount: number; finalBytes: number;
  header: string; chunks: string[];
};
export type EvidenceFileHeader = { name: string; type: string; size: number };
/** A file the owner device reads in slices; nothing is loaded whole. */
export type EvidenceSource = EvidenceFileHeader & { read(start: number, end: number): Promise<Uint8Array> };

export class ChunkedObjectError extends Error {
  constructor(message = 'Unable to open confidential evidence') { super(message); }
}
/** The source file no longer matches what was encrypted (edited, moved or unreadable). */
export class EvidenceChangedError extends ChunkedObjectError {
  constructor() { super('A file changed after it was encrypted. Choose it again and resubmit.'); }
}
export class EvidenceTooLargeError extends ChunkedObjectError {
  constructor(message = 'Evidence files must be 256 MB or smaller.') { super(message); }
}
function invalid(): never { throw new ChunkedObjectError(); }

const subtle = () => globalThis.crypto.subtle;
function text(value: string): Uint8Array<ArrayBuffer> { return new TextEncoder().encode(value); }
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
async function sha256(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await subtle().digest('SHA-256', new Uint8Array(bytes))));
}
const encode = encodeBase64;
function decode(value: string): Uint8Array<ArrayBuffer> { return decodeCanonicalBase64(value) ?? invalid(); }
function isId(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }

/** Smallest allowed padded size for a final chunk holding `tail` bytes. */
export function finalChunkBytes(tail: number): number {
  if (!Number.isSafeInteger(tail) || tail < 0 || tail > CHUNK_PLAINTEXT_BYTES) invalid();
  let size = MIN_FINAL_CHUNK_BYTES;
  while (size < tail) size *= 2;
  return size;
}
function isBucket(value: number): boolean {
  if (!Number.isSafeInteger(value) || value < MIN_FINAL_CHUNK_BYTES || value > CHUNK_PLAINTEXT_BYTES) return false;
  return (value & (value - 1)) === 0;
}
/** Every stored chunk is a full chunk or an allowed final bucket, plus the GCM tag. */
export function isChunkCiphertextLength(length: number): boolean {
  return Number.isSafeInteger(length) && isBucket(length - CHUNK_TAG_BYTES);
}
/** v2 (legacy) layout: chunk count and padded final size for `size` bytes. */
export function chunkLayout(size: number): { chunkCount: number; finalBytes: number } {
  if (!Number.isSafeInteger(size) || size < 0) invalid();
  if (size > CHUNKED_FILE_LIMIT) throw new EvidenceTooLargeError();
  const chunkCount = Math.max(1, Math.ceil(size / CHUNK_PLAINTEXT_BYTES));
  return { chunkCount, finalBytes: finalChunkBytes(size - (chunkCount - 1) * CHUNK_PLAINTEXT_BYTES) };
}
/** v3 layout: one power-of-two chunk, or full chunks with a bucketed count. */
export function paddedChunkLayout(size: number): { chunkCount: number; finalBytes: number } {
  const legacy = chunkLayout(size);
  if (legacy.chunkCount === 1) return legacy;
  return { chunkCount: chunkCountBucket(legacy.chunkCount), finalBytes: CHUNK_PLAINTEXT_BYTES };
}
function layoutFor(format: ChunkedFormat, size: number): { chunkCount: number; finalBytes: number } {
  return format === PADDED_CHUNKED_OBJECT_FORMAT ? paddedChunkLayout(size) : chunkLayout(size);
}
/** The layout a v3 index may declare, from its count alone (no file size needed). */
function isPaddedLayout(chunkCount: number, finalBytes: number): boolean {
  return chunkCount === 1 ? isBucket(finalBytes)
    : finalBytes === CHUNK_PLAINTEXT_BYTES && chunkCountBucket(chunkCount) === chunkCount;
}
export function chunkCiphertextLength(index: Pick<ChunkedIndex, 'chunkCount' | 'finalBytes' | 'chunkBytes'>, position: number): number {
  return (position === index.chunkCount - 1 ? index.finalBytes : index.chunkBytes) + CHUNK_TAG_BYTES;
}

export function serializeChunkedIndex(value: ChunkedIndex): string {
  return JSON.stringify({ format: value.format, chunkBytes: value.chunkBytes, chunkCount: value.chunkCount,
    finalBytes: value.finalBytes, header: value.header, chunks: value.chunks });
}
/** Cheap discriminator for stored object text; `parseChunkedIndex` is the check. */
export function isChunkedIndexText(value: unknown): value is string {
  return typeof value === 'string' && INDEX_PREFIXES.some(prefix => value.startsWith(prefix));
}
/** Strict, canonical parse: any other spelling of the same values is rejected, so
 * the index digest identifies exactly one chunk list. Holds no secrets. */
export function parseChunkedIndex(value: unknown): ChunkedIndex {
  if (!isChunkedIndexText(value) || value.length > MAX_CHUNKED_INDEX_BYTES) invalid();
  let parsed: ChunkedIndex;
  try { parsed = JSON.parse(value); } catch { return invalid(); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) ||
      Object.keys(parsed).join(',') !== 'format,chunkBytes,chunkCount,finalBytes,header,chunks' ||
      (parsed.format !== CHUNKED_OBJECT_FORMAT && parsed.format !== PADDED_CHUNKED_OBJECT_FORMAT) ||
      parsed.chunkBytes !== CHUNK_PLAINTEXT_BYTES ||
      !Number.isSafeInteger(parsed.chunkCount) || parsed.chunkCount < 1 || parsed.chunkCount > MAX_CHUNKS_PER_OBJECT ||
      !isBucket(parsed.finalBytes) ||
      (parsed.format === PADDED_CHUNKED_OBJECT_FORMAT && !isPaddedLayout(parsed.chunkCount, parsed.finalBytes)) ||
      typeof parsed.header !== 'string' || parsed.header.length !== HEADER_WIRE_LENGTH ||
      !Array.isArray(parsed.chunks) || parsed.chunks.length !== parsed.chunkCount || !parsed.chunks.every(isId) ||
      serializeChunkedIndex(parsed) !== value) invalid();
  if (decode(parsed.header).length !== HEADER_PLAINTEXT_BYTES + CHUNK_TAG_BYTES) invalid();
  return { format: parsed.format, chunkBytes: parsed.chunkBytes, chunkCount: parsed.chunkCount,
    finalBytes: parsed.finalBytes, header: parsed.header, chunks: [...parsed.chunks] };
}
export async function chunkedIndexDigest(index: string): Promise<string> {
  if (typeof index !== 'string' || index.length > MAX_CHUNKED_INDEX_BYTES) invalid();
  return sha256(text(index));
}

async function aeadKey(contentKey: Uint8Array, format: ChunkedFormat): Promise<CryptoKey> {
  if (!(contentKey instanceof Uint8Array) || contentKey.length !== 32) invalid();
  const base = await subtle().importKey('raw', new Uint8Array(contentKey), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: text(format),
    info: text('vera chunk key aes-256-gcm') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function associatedData(format: ChunkedFormat, context: ObjectContext,
  layout: { chunkCount: number; finalBytes: number }): Promise<Uint8Array<ArrayBuffer>> {
  const descriptor = JSON.stringify({ format, caseId: context.caseId, objectId: context.objectId,
    scope: context.scope, keyEpoch: context.keyEpoch, objectRevision: context.objectRevision,
    chunkBytes: CHUNK_PLAINTEXT_BYTES, chunkCount: layout.chunkCount, finalBytes: layout.finalBytes });
  return new Uint8Array(await subtle().digest('SHA-256', text(descriptor)));
}
function chunkNonce(position: number, final: boolean): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(7, position);
  nonce[11] = final ? 1 : 0;
  return nonce;
}
/** Distinct from every chunk nonce (their first byte is always zero). */
function headerNonce(): Uint8Array<ArrayBuffer> { const nonce = new Uint8Array(12); nonce[0] = 1; return nonce; }

function packHeader(header: EvidenceFileHeader): Uint8Array<ArrayBuffer> {
  const json = text(JSON.stringify({ name: header.name, type: header.type, size: header.size }));
  if (json.length + 4 > HEADER_PLAINTEXT_BYTES) invalid();
  const packed = new Uint8Array(HEADER_PLAINTEXT_BYTES);
  new DataView(packed.buffer).setUint32(0, json.length);
  packed.set(json, 4);
  return packed;
}
function unpackHeader(bytes: Uint8Array): EvidenceFileHeader {
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  if (length + 4 > HEADER_PLAINTEXT_BYTES || bytes.subarray(4 + length).some(byte => byte !== 0)) invalid();
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(4, 4 + length)));
  if (!value || Object.keys(value).join(',') !== 'name,type,size' || typeof value.name !== 'string' ||
      !value.name.length || value.name.length > 255 || typeof value.type !== 'string' || value.type.length > 127 ||
      !Number.isSafeInteger(value.size) || value.size < 0 || value.size > CHUNKED_FILE_LIMIT) invalid();
  return { name: value.name, type: value.type, size: value.size };
}
function checkedHeader(input: EvidenceFileHeader): EvidenceFileHeader {
  if (!input || typeof input.name !== 'string' || !input.name.length || input.name.length > 255 ||
      typeof input.type !== 'string' || input.type.length > 127 || !Number.isSafeInteger(input.size) || input.size < 0) invalid();
  if (input.size > CHUNKED_FILE_LIMIT) throw new EvidenceTooLargeError();
  return { name: input.name, type: input.type, size: input.size };
}

export type SealedChunkedObject = {
  context: ObjectContext; header: EvidenceFileHeader;
  /** Canonical index text; its SHA-256 (`digest`) goes into the owner-signed manifest. */
  index: string; digest: string; chunkDigests: string[];
  ownerEnvelope: string;
  /** Deterministically re-encrypts chunk `position` for upload and checks it still
   * matches the index. Resuming never needs the ciphertext kept in memory, and a
   * changed source is refused before anything leaves the device. */
  chunk(position: number): Promise<Uint8Array>;
  dispose(): void;
};

/** Owner device: encrypt one evidence file as a chunked object. Reads the source
 * one chunk at a time; peak memory is a few chunks regardless of file size. */
export async function sealChunkedObject(context: ObjectContext, source: EvidenceSource,
  owner: PrivateKey): Promise<SealedChunkedObject> {
  const header = checkedHeader(source);
  const expected = { ...context }, read = source.read.bind(source);
  const format = PADDED_CHUNKED_OBJECT_FORMAT, layout = paddedChunkLayout(header.size);
  const contentKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let disposed = false;
  // `disposed` stops re-encryption once the upload is committed or abandoned.
  try {
    const key = await aeadKey(contentKey, format), aad = await associatedData(format, expected, layout);
    const plaintext = async (position: number) => {
      const length = position === layout.chunkCount - 1 ? layout.finalBytes : CHUNK_PLAINTEXT_BYTES;
      const start = Math.min(header.size, position * CHUNK_PLAINTEXT_BYTES);
      const end = Math.min(header.size, start + CHUNK_PLAINTEXT_BYTES);
      // Padding chunks after the data are all zeros; nothing is read for them.
      if (start === end) return new Uint8Array(length);
      let bytes: Uint8Array;
      try { bytes = await read(start, end); } catch { throw new EvidenceChangedError(); }
      if (!(bytes instanceof Uint8Array) || bytes.length !== end - start) throw new EvidenceChangedError();
      if (bytes.length === length) return bytes;
      const padded = new Uint8Array(length);
      padded.set(bytes);
      bytes.fill(0);
      return padded;
    };
    const seal = async (position: number) => {
      const bytes = await plaintext(position);
      try {
        return new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: chunkNonce(position, position === layout.chunkCount - 1),
          additionalData: aad, tagLength: 128 }, key, new Uint8Array(bytes)));
      } finally { bytes.fill(0); }
    };
    const packed = packHeader(header);
    const sealedHeader = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: headerNonce(), additionalData: aad,
      tagLength: 128 }, key, packed));
    packed.fill(0);
    const chunks: string[] = [];
    for (let position = 0; position < layout.chunkCount; position++) chunks.push(await sha256(await seal(position)));
    const index = serializeChunkedIndex({ format, chunkBytes: CHUNK_PLAINTEXT_BYTES,
      chunkCount: layout.chunkCount, finalBytes: layout.finalBytes, header: encode(sealedHeader), chunks });
    const digest = await chunkedIndexDigest(index);
    const ownerEnvelope = await sealChunkedContentKey(expected, digest, contentKey, owner);
    return {
      context: expected, header, index, digest, chunkDigests: [...chunks], ownerEnvelope,
      async chunk(position: number) {
        if (disposed || !Number.isSafeInteger(position) || position < 0 || position >= layout.chunkCount) invalid();
        const bytes = await seal(position);
        if (await sha256(bytes) !== chunks[position]) { bytes.fill(0); throw new EvidenceChangedError(); }
        return bytes;
      },
      dispose() { disposed = true; },
    };
  } catch (error) {
    if (error instanceof ChunkedObjectError) throw error;
    return invalid();
  } finally {
    // Re-encryption uses the derived non-extractable AES key; sharing unwraps the
    // owner envelope. The raw content key is not kept.
    contentKey.fill(0);
  }
}

export type ChunkedObjectReader = EvidenceFileHeader & {
  index: ChunkedIndex; digest: string;
  /** Verify (digest, then AEAD) and decrypt chunk `position`; returns only file
   * bytes (padding removed and checked to be zero; empty for a padding chunk). */
  openChunk(position: number, ciphertext: Uint8Array): Promise<Uint8Array>;
  dispose(): void;
};

async function reader(indexText: string, expectedDigest: string, context: ObjectContext,
  contentKey: Uint8Array): Promise<ChunkedObjectReader> {
  try {
    if (!isId(expectedDigest) || await chunkedIndexDigest(indexText) !== expectedDigest) invalid();
    const index = parseChunkedIndex(indexText);
    const key = await aeadKey(contentKey, index.format), aad = await associatedData(index.format, context, index);
    const opened = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: headerNonce(), additionalData: aad,
      tagLength: 128 }, key, decode(index.header)));
    let header: EvidenceFileHeader;
    try { header = unpackHeader(opened); } finally { opened.fill(0); }
    const layout = layoutFor(index.format, header.size);
    if (layout.chunkCount !== index.chunkCount || layout.finalBytes !== index.finalBytes) invalid();
    let disposed = false;
    return {
      ...header, index, digest: expectedDigest,
      async openChunk(position: number, ciphertext: Uint8Array) {
        if (disposed || !Number.isSafeInteger(position) || position < 0 || position >= index.chunkCount ||
            !(ciphertext instanceof Uint8Array) || ciphertext.length !== chunkCiphertextLength(index, position) ||
            await sha256(ciphertext) !== index.chunks[position]) invalid();
        const final = position === index.chunkCount - 1;
        let plain: Uint8Array;
        try {
          plain = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: chunkNonce(position, final),
            additionalData: aad, tagLength: 128 }, key, new Uint8Array(ciphertext)));
        } catch { return invalid(); }
        // File bytes in this chunk: all of it, a tail, or none (a v3 padding chunk).
        const keep = Math.max(0, Math.min(plain.length, header.size - position * CHUNK_PLAINTEXT_BYTES));
        if (keep === plain.length) return plain;
        try {
          if (plain.subarray(keep).some(byte => byte !== 0)) invalid();
          return plain.slice(0, keep);
        } finally { plain.fill(0); }
      },
      dispose() { disposed = true; },
    };
  } catch (error) {
    if (error instanceof ChunkedObjectError) throw error;
    return invalid();
  } finally { contentKey.fill(0); }
}

/** Owner device: open a chunked object with the owner's own key envelope. */
export async function openOwnerChunkedObject(indexText: string, ownerEnvelope: string, context: ObjectContext,
  expectedDigest: string, owner: PrivateKey): Promise<ChunkedObjectReader> {
  let key: Uint8Array;
  try { key = await openOwnerChunkedContentKey(ownerEnvelope, context, expectedDigest, owner); }
  catch { return invalid(); }
  return reader(indexText, expectedDigest, context, key);
}

/** Recipient device: open a chunked object under current authorization (grant,
 * release, checkpoint and manifest digest are all re-checked). */
export async function openGrantedChunkedObject(indexText: string, recipientEnvelope: string, context: ObjectContext,
  recipient: PrivateKey, authorization: CaseReadAuthorization): Promise<ChunkedObjectReader> {
  let key: Uint8Array;
  try { key = await openGrantedChunkedContentKey(recipientEnvelope, context, recipient, authorization); }
  catch { return invalid(); }
  return reader(indexText, authorization.request.ciphertextDigest, context, key);
}

/** In-memory source (tests and small inputs). */
export function bytesEvidenceSource(file: { name: string; type: string; bytes: Uint8Array }): EvidenceSource {
  const bytes = file.bytes;
  return { name: file.name, type: file.type, size: bytes.length,
    async read(start, end) { return bytes.slice(start, end); } };
}
/** Browser File/Blob source: slices are read on demand, never the whole file. */
export function blobEvidenceSource(file: Blob & { name: string }): EvidenceSource {
  return { name: file.name, type: file.type, size: file.size,
    async read(start, end) { return new Uint8Array(await file.slice(start, end).arrayBuffer()); } };
}
