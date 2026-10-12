/** Binary AES-256 keys generated for a Nitro recipient. Deliberately distinct
 * from enc:kms:v2, whose decrypted key is a UTF-8 hexadecimal string. */
const PREFIX = 'enc:kms:recipient:v1:';
const MAX_WRAPPED_KEY = 6144;
export function encodeRecipientEnvelope(ciphertext: Buffer): string {
  if (!Buffer.isBuffer(ciphertext) || !ciphertext.length || ciphertext.length > MAX_WRAPPED_KEY) throw new Error('Invalid recipient key envelope');
  return PREFIX + ciphertext.toString('base64');
}
export function decodeRecipientEnvelope(value: unknown): Buffer {
  return decode(value, PREFIX);
}
/** Explicit historical PBKDF2 reader: only v2 KMS wrappers with hashed context. */
export function decodeHistoricalEnvelope(value: unknown): Buffer {
  return decode(value, 'enc:kms:v2:');
}
function decode(value: unknown, prefix: string): Buffer {
  if (typeof value !== 'string' || !value.startsWith(prefix) || value.length > prefix.length + 4 * Math.ceil(MAX_WRAPPED_KEY / 3)) throw new Error('Invalid recipient key envelope');
  const encoded = value.slice(prefix.length);
  const ciphertext = Buffer.from(encoded, 'base64');
  if (!ciphertext.length || ciphertext.length > MAX_WRAPPED_KEY || ciphertext.toString('base64') !== encoded) throw new Error('Invalid recipient key envelope');
  return ciphertext;
}
