/** Size buckets for everything storage or a relay can measure (architecture hole 12).
 *
 * Padding is always added to the plaintext *inside* the authenticated encryption
 * (OpenPGP SEIPD + owner signature, or AES-GCM), so the reader verifies it and
 * strips it; nobody can add, remove or change padding without breaking the
 * ciphertext. Buckets hide the exact size, not the order of magnitude: a relay
 * or storage still learns roughly how large something is, and when it moves.
 */

function invalid(): never { throw new Error('Invalid padded size'); }
function isPowerOfTwo(value: number): boolean { return value > 0 && (value & (value - 1)) === 0; }

/** Smallest power of two that is at least `size` and at least `floor`. When that
 * would exceed `cap`, the result is `cap` (the cap is itself the top bucket).
 * `floor` must be a power of two no larger than `cap`. */
export function powerOfTwoBucket(size: number, floor: number, cap: number): number {
  if (!Number.isSafeInteger(size) || size < 0 || !Number.isSafeInteger(floor) || !isPowerOfTwo(floor) ||
      !Number.isSafeInteger(cap) || cap < floor || size > cap) invalid();
  let bucket = floor;
  while (bucket < size) bucket *= 2;
  return Math.min(bucket, cap);
}

/** Chunk counts keep only their three most significant bits: 1-8 are unchanged,
 * then there are four buckets per doubling (8, 10, 12, 14, 16, 20, 24, 28, 32, 40,
 * ...). A count never grows by 25% or more, and a count at most 2^k never rounds
 * above 2^k, so per-object limits that are powers of two still hold. */
export function chunkCountBucket(count: number): number {
  if (!Number.isSafeInteger(count) || count < 1 || count > 2 ** 30) invalid();
  if (count <= 8) return count;
  const step = 2 ** (Math.floor(Math.log2(count)) - 2);
  return Math.ceil(count / step) * step;
}

/** Upper bound on the total after `chunkCountBucket` rounds each object's count:
 * every object grows by less than 25%, so the sum does too. */
export function paddedChunkBudget(chunks: number): number {
  if (!Number.isSafeInteger(chunks) || chunks < 0) invalid();
  return Math.floor(chunks * 5 / 4);
}

const SPACE = 0x20;
/** JSON text padded with trailing spaces to `size` bytes. Trailing whitespace is
 * valid JSON, so a strict `JSON.parse` of the padded text returns the same value
 * and rejects any non-space padding. Callers pad before signing/encrypting. */
export function padJsonBytes(json: Uint8Array, size: number): Uint8Array<ArrayBuffer> {
  if (!(json instanceof Uint8Array) || !Number.isSafeInteger(size) || size < json.length) invalid();
  const padded = new Uint8Array(size).fill(SPACE);
  padded.set(json);
  return padded;
}
