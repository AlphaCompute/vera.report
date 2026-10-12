/** Strict, canonical standard base64 (RFC 4648 section 4, padded) shared by the
 * enclave and the browser bundle.
 *
 * Canonical means exactly what `btoa` would produce for the decoded bytes:
 * only `A-Z a-z 0-9 + /`, a length that is a multiple of four, `=` padding only
 * at the end and only as much as the final quantum needs, and zero unused bits
 * in the last data character. Everything else is rejected, so one byte string
 * has one accepted encoding.
 *
 * The check is a linear scan of the string rather than a decode and re-encode,
 * which cost about 50 ms per 512 KiB chunk with the (single-threaded) enclave
 * event loop blocked. Node uses its native codec; browsers use `atob`/`btoa`
 * with batched conversion. `Buffer` is read from `globalThis` so bundlers do not
 * inject a polyfill.
 */
type NativeBuffer = {
  from(buffer: ArrayBufferLike, byteOffset: number, length: number): {
    toString(encoding: 'base64'): string;
    write(value: string, encoding: 'base64'): number;
  };
};
const native = (globalThis as { Buffer?: NativeBuffer }).Buffer;
const NON_ALPHABET = /[^A-Za-z0-9+/]/;
const BATCH = 0x8000;

function sextet(code: number): number {
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 71;
  if (code >= 48 && code <= 57) return code + 4;
  if (code === 43) return 62;
  if (code === 47) return 63;
  return -1;
}

/** Decoded length of `value` if it is canonical base64, otherwise -1. */
export function canonicalBase64Length(value: string): number {
  const length = value.length;
  if (length % 4 !== 0) return -1;
  if (length === 0) return 0;
  const padding = value.charCodeAt(length - 1) !== 61 ? 0 : value.charCodeAt(length - 2) !== 61 ? 1 : 2;
  const data = length - padding;
  if (NON_ALPHABET.test(padding ? value.slice(0, data) : value)) return -1;
  if (padding) {
    const last = sextet(value.charCodeAt(data - 1));
    if ((last & (padding === 2 ? 0x0f : 0x03)) !== 0) return -1;
  }
  return (length / 4) * 3 - padding;
}

export function encodeBase64(bytes: Uint8Array): string {
  if (native) return native.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
  let text = '';
  for (let index = 0; index < bytes.length; index += BATCH) {
    text += String.fromCharCode.apply(null, bytes.subarray(index, index + BATCH) as unknown as number[]);
  }
  return btoa(text);
}

/** Bytes of canonical base64 `value` of at most `max` bytes, or null. The result
 * owns its own ArrayBuffer (no pooled or shared memory). */
export function decodeCanonicalBase64(value: unknown, max = Number.MAX_SAFE_INTEGER): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3)) return null;
  const length = canonicalBase64Length(value);
  if (length < 0 || length > max) return null;
  const bytes = new Uint8Array(length);
  if (native) {
    if (native.from(bytes.buffer, 0, length).write(value, 'base64') !== length) return null;
    return bytes;
  }
  const text = atob(value);
  if (text.length !== length) return null;
  for (let index = 0; index < length; index++) bytes[index] = text.charCodeAt(index);
  return bytes;
}
