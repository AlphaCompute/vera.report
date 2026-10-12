/**
 * Extract Nitro PCR0 from an AWS NSM attestation document (base64 COSE_Sign1).
 * Display / transparency only — does not verify the AWS certificate chain.
 */

const PCR0_HEX_RE = /^[0-9a-f]{96}$/;

class CborCursor {
  constructor(readonly buf: Buffer, public i = 0) {}
  remaining(): number {
    return this.buf.length - this.i;
  }
  u8(): number {
    if (this.i >= this.buf.length) throw new Error('Unexpected end of CBOR');
    return this.buf[this.i++];
  }
  take(n: number): Buffer {
    if (n < 0 || this.i + n > this.buf.length) throw new Error('Unexpected end of CBOR');
    const slice = this.buf.subarray(this.i, this.i + n);
    this.i += n;
    return slice;
  }
}

function readLength(cur: CborCursor, additional: number): number {
  if (additional < 24) return additional;
  if (additional === 24) return cur.u8();
  if (additional === 25) {
    const b = cur.take(2);
    return (b[0] << 8) | b[1];
  }
  if (additional === 26) {
    return cur.take(4).readUInt32BE(0);
  }
  if (additional === 27) {
    const value = cur.take(8).readBigUInt64BE();
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Unsafe CBOR integer');
    return Number(value);
  }
  throw new Error('Unsupported CBOR length');
}

function decodeItem(cur: CborCursor, depth = 0): unknown {
  if (depth > 16) throw new Error('CBOR nesting too deep');
  const initial = cur.u8();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  switch (major) {
    case 0:
      return readLength(cur, additional);
    case 1:
      return -1 - readLength(cur, additional);
    case 2: {
      if (additional === 31) throw new Error('Indefinite byte strings are unsupported');
      return cur.take(readLength(cur, additional));
    }
    case 3: {
      if (additional === 31) throw new Error('Indefinite text strings are unsupported');
      return cur.take(readLength(cur, additional)).toString('utf8');
    }
    case 4: {
      if (additional === 31) {
        const out: unknown[] = [];
        while (cur.remaining() > 0 && cur.buf[cur.i] !== 0xff) {
          out.push(decodeItem(cur, depth + 1));
        }
        if (cur.u8() !== 0xff) throw new Error('Invalid indefinite array');
        return out;
      }
      const len = readLength(cur, additional);
      const out: unknown[] = [];
      for (let i = 0; i < len; i++) out.push(decodeItem(cur, depth + 1));
      return out;
    }
    case 5: {
      const out = new Map<unknown, unknown>();
      const pushPair = () => {
        const k = decodeItem(cur, depth + 1);
        const v = decodeItem(cur, depth + 1);
        if (out.has(k)) throw new Error('Duplicate CBOR map key');
        out.set(k, v);
      };
      if (additional === 31) {
        while (cur.remaining() > 0 && cur.buf[cur.i] !== 0xff) pushPair();
        if (cur.u8() !== 0xff) throw new Error('Invalid indefinite map');
        return out;
      }
      const len = readLength(cur, additional);
      for (let i = 0; i < len; i++) pushPair();
      return out;
    }
    case 6: {
      readLength(cur, additional); // tag number (e.g. 18 = COSE_Sign1)
      return decodeItem(cur, depth + 1);
    }
    case 7:
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw new Error('Unsupported CBOR simple/float');
    default:
      throw new Error('Unsupported CBOR major type');
  }
}

function decodeCbor(buf: Buffer): unknown {
  if (!buf.length || buf.length > 16384) throw new Error('Invalid CBOR size');
  const cur = new CborCursor(buf);
  const value = decodeItem(cur);
  if (cur.i !== buf.length) throw new Error('Trailing CBOR data');
  return value;
}

function asMap(value: unknown): Map<unknown, unknown> {
  if (!(value instanceof Map)) throw new Error('Expected CBOR map');
  return value;
}

/**
 * Parse a base64 NSM attestation document and return PCR0 as 96 lowercase hex chars.
 */
export function extractPcr0FromAttestationDocument(
  documentBase64: string,
  expectedNonce?: string,
  expectedContext?: string,
): string {
  if (typeof documentBase64 !== 'string' || !documentBase64.length || documentBase64.length > 21848) {
    throw new Error('Invalid attestation document encoding');
  }
  const raw = Buffer.from(documentBase64, 'base64');
  if (!raw.length || raw.length > 16384 || raw.toString('base64') !== documentBase64) {
    throw new Error('Invalid attestation document encoding');
  }

  const cose = decodeCbor(raw);
  if (!Array.isArray(cose) || cose.length !== 4) {
    throw new Error('Invalid COSE envelope');
  }

  const payload = cose[2];
  if (!Buffer.isBuffer(payload) || !payload.length) throw new Error('Missing COSE payload');

  const body = asMap(decodeCbor(payload));
  if (expectedNonce !== undefined) {
    const nonce = body.get('nonce');
    if (!Buffer.isBuffer(nonce) || nonce.toString('hex') !== expectedNonce) throw new Error('Attestation nonce mismatch');
  }
  if (expectedContext !== undefined) {
    // Mirrors verify_identity.py: an identity document carries only the fixed
    // context, never a public key, so it cannot be mistaken for a key grant.
    const userData = body.get('user_data');
    if (!Buffer.isBuffer(userData) || !userData.equals(Buffer.from(expectedContext))) {
      throw new Error('Attestation context mismatch');
    }
    if (body.get('public_key') != null) throw new Error('Unexpected attestation public key');
  }
  const pcrs = asMap(body.get('pcrs'));
  const pcr0 = pcrs.get(0);
  if (!Buffer.isBuffer(pcr0) || pcr0.length !== 48) throw new Error('Invalid PCR0');
  const hex = pcr0.toString('hex');
  if (!PCR0_HEX_RE.test(hex) || !/[1-9a-f]/.test(hex)) throw new Error('Invalid PCR0');
  return hex;
}

function cborUint(n: number): Buffer {
  if (n < 24) return Buffer.from([n]);
  if (n < 256) return Buffer.from([24, n]);
  throw new Error('uint too large for test helper');
}

function cborBstr(b: Buffer): Buffer {
  if (b.length < 24) return Buffer.concat([Buffer.from([0x40 | b.length]), b]);
  if (b.length < 256) return Buffer.concat([Buffer.from([0x58, b.length]), b]);
  if (b.length < 65536) {
    const header = Buffer.alloc(3);
    header[0] = 0x59;
    header.writeUInt16BE(b.length, 1);
    return Buffer.concat([header, b]);
  }
  throw new Error('bytes too long for test helper');
}

function cborTstr(s: string): Buffer {
  const b = Buffer.from(s, 'utf8');
  if (b.length < 24) return Buffer.concat([Buffer.from([0x60 | b.length]), b]);
  if (b.length < 256) return Buffer.concat([Buffer.from([0x78, b.length]), b]);
  throw new Error('text too long for test helper');
}

/** Test helper: build a minimal (unsigned) COSE_Sign1 document carrying PCR0. */
export function synthesizeAttestationDocumentForTests(
  pcr0: Buffer,
  nonce = 'a'.repeat(64),
  timestamp = BigInt(Date.now()),
  userData: Buffer = Buffer.from('VERA-ENCLAVE-IDENTITY-v1'),
): string {
  if (pcr0.length !== 48) throw new Error('PCR0 must be 48 bytes');

  // protected: {1: -35}  (COSE alg header)
  const protectedHeaders = Buffer.concat([Buffer.from([0xa1, 0x01, 0x38, 34])]);
  const pcrsMap = Buffer.concat([
    Buffer.from([0xa3]),
    cborUint(0), cborBstr(pcr0),
    cborUint(1), cborBstr(Buffer.alloc(48, 1)),
    cborUint(2), cborBstr(Buffer.alloc(48, 2)),
  ]);
  const encodedTimestamp = Buffer.alloc(9);
  encodedTimestamp[0] = 0x1b;
  encodedTimestamp.writeBigUInt64BE(timestamp, 1);
  const payload = Buffer.concat([
    Buffer.from([0xa5]),
    cborTstr('timestamp'), encodedTimestamp,
    cborTstr('user_data'), cborBstr(userData),
    cborTstr('nonce'), cborBstr(Buffer.from(nonce, 'hex')),
    cborTstr('digest'), cborTstr('SHA384'),
    cborTstr('pcrs'), pcrsMap,
  ]);
  const cose = Buffer.concat([
    Buffer.from([0x84]),
    cborBstr(protectedHeaders),
    Buffer.from([0xa0]),
    cborBstr(payload),
    cborBstr(Buffer.alloc(96, 0)),
  ]);
  return cose.toString('base64');
}
