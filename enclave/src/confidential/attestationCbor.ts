/** Bounded RFC 8949 subset for Nitro evidence, not a general CBOR codec.
 * Parsing grants no trust. Certificate, COSE signature and policy checks follow.
 * Byte strings are copied without re-encoding their contents for signature use. */
export type AttestationCbor = number | string | Uint8Array | null |
  AttestationCbor[] | Map<number | string, AttestationCbor>;

function invalid(): never { throw new Error('Invalid attestation CBOR'); }

export function decodeAttestationCbor(input: Uint8Array, allowCoseTag = false): AttestationCbor {
  if (!(input instanceof Uint8Array) || !input.length || input.length > 16384) invalid();
  // Snapshot input so caller mutations cannot change bytes during later awaits.
  const bytes = new Uint8Array(input);
  let offset = 0, nodes = 0;
  const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  function byte(): number {
    if (offset >= bytes.length) invalid();
    return bytes[offset++];
  }
  function argument(info: number): number | null {
    if (info < 24) return info;
    if (info === 31) return null;
    if (info > 27) invalid();
    let value = 0;
    for (let i = 0; i < 2 ** (info - 24); i++) {
      value = value * 256 + byte();
      if (!Number.isSafeInteger(value)) invalid();
    }
    return value;
  }
  function item(depth: number, root = false): AttestationCbor {
    if (depth > 16 || ++nodes > 2048) invalid();
    const initial = byte(), major = initial >> 5, info = initial & 31;
    if (initial === 0xf6) return null;
    if (major === 7) invalid(); // No floats, booleans, undefined or free breaks.
    const length = argument(info);
    if (major === 6) {
      if (!root || !allowCoseTag || length !== 18) invalid();
      const tagged = item(depth + 1);
      if (!Array.isArray(tagged)) invalid();
      return tagged; // Tag 18 is allowed only once around the COSE array.
    }
    if (major < 2) {
      if (length === null) invalid();
      const value = major === 0 ? length : -1 - length;
      if (!Number.isSafeInteger(value)) invalid();
      return value;
    }
    if (major === 2 || major === 3) {
      if (length !== null) {
        if (length > bytes.length - offset) invalid();
        const value = bytes.slice(offset, offset + length);
        offset += length;
        return major === 2 ? value : utf8.decode(value);
      }
      const parts: Uint8Array[] = [];
      let text = '', total = 0;
      while (bytes[offset] !== 0xff) {
        // Indefinite strings contain only definite chunks of the same type.
        if (offset >= bytes.length || bytes[offset] >> 5 !== major || (bytes[offset] & 31) === 31) invalid();
        const part = item(depth + 1);
        if (major === 3) text += part as string;
        else { const data = part as Uint8Array; parts.push(data); total += data.length; }
      }
      offset++;
      if (major === 3) return text;
      const output = new Uint8Array(total);
      let position = 0;
      for (const part of parts) { output.set(part, position); position += part.length; }
      return output;
    }
    if (major !== 4 && major !== 5) invalid();
    // Every array entry/map pair consumes at least one/two input bytes.
    if (length !== null && length > (bytes.length - offset) / (major === 5 ? 2 : 1)) invalid();
    const list: AttestationCbor[] = [], map = new Map<number | string, AttestationCbor>();
    let count = 0;
    while (length === null ? bytes[offset] !== 0xff : count < length) {
      const value = item(depth + 1);
      if (major === 4) list.push(value);
      else {
        if (typeof value !== 'number' && typeof value !== 'string') invalid();
        if (map.has(value)) invalid(); // Compare decoded keys, including nonminimal encodings.
        map.set(value, item(depth + 1));
      }
      count++;
    }
    if (length === null) offset++;
    return major === 4 ? list : map;
  }
  try {
    const result = item(0, true);
    if (offset !== bytes.length) invalid();
    return result;
  } catch { return invalid(); }
}
