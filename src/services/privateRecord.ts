import crypto from 'node:crypto';
import { keyEnvelope } from './keyEnvelope';

/** Storage-only envelope. Record/field binding prevents moving ciphertext between records. */
const PREFIX = 'private:v1:';
export async function sealPrivateValue(value: unknown, record: string, field: string): Promise<string> {
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const aad = JSON.stringify([record, field]);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(aad));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    const wrapped = await keyEnvelope.wrap(key.toString('hex'), { purpose: 'narrative', record, field });
    return PREFIX + JSON.stringify({ key: wrapped, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: encrypted.toString('base64') });
  } finally { key.fill(0); }
}
export async function openPrivateValue(value: unknown, record: string, field: string): Promise<any> {
  // Legacy plaintext stays readable until the compare-and-set migration is complete.
  if (typeof value !== 'string' || !value.startsWith(PREFIX)) return value;
  const stored = JSON.parse(value.slice(PREFIX.length));
  // This envelope was introduced with wrapped keys; it has no raw-key legacy format.
  if (typeof stored.key !== 'string' || !/^enc:(kms:v[12]|local:v1):/.test(stored.key)) throw new Error('Invalid private-record key envelope');
  const key = Buffer.from(await keyEnvelope.unwrap(stored.key, { purpose: 'narrative', record, field }), 'hex');
  let pending: Buffer | undefined;
  let final: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(stored.iv, 'base64'), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(JSON.stringify([record, field])));
    decipher.setAuthTag(Buffer.from(stored.tag, 'base64'));
    pending = decipher.update(Buffer.from(stored.data, 'base64'));
    final = decipher.final();
    plaintext = Buffer.concat([pending, final]);
    return JSON.parse(plaintext.toString('utf8'));
  } finally {
    key.fill(0);
    pending?.fill(0);
    final?.fill(0);
    plaintext?.fill(0);
  }
}
export async function protectFields<T>(doc: T, record: string, fields: string[], mode: 'seal' | 'open'): Promise<T> {
  if (!doc) return doc;
  const result: any = { ...doc };
  for (const field of fields) {
    if (result[field] !== undefined) result[field] = await (mode === 'seal' ? sealPrivateValue : openPrivateValue)(result[field], record, field);
  }
  return result;
}
