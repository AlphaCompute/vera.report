/** Host-side mirror of the chunked evidence size rules in
 * enclave/src/confidential/caseChunks.ts (the server build cannot import enclave
 * sources; a unit test keeps the two identical). Sizes only: chunks are opaque
 * AES-GCM ciphertext and the host never interprets their contents. */
export const CHUNK_TAG_BYTES = 16;
export const MIN_FINAL_CHUNK_BYTES = 4096;
export const MAX_CHUNKS_PER_OBJECT = 512;
/** Largest stored chunk: 512 KiB plaintext plus the 16-byte GCM tag. */
export const MAX_CHUNK_BYTES = 512 * 1024 + CHUNK_TAG_BYTES;

/** A full 512 KiB chunk or a power-of-two final bucket (at least 4 KiB), plus the tag. */
export function isChunkSize(size: number): boolean {
  const plain = size - CHUNK_TAG_BYTES;
  return Number.isSafeInteger(size) && plain >= MIN_FINAL_CHUNK_BYTES && plain <= MAX_CHUNK_BYTES - CHUNK_TAG_BYTES &&
    (plain & (plain - 1)) === 0;
}
