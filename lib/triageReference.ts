import crypto from 'node:crypto';

// Employee references are opaque routing handles, never reporter credentials.
// They confer no authority: every use still requires the employee role.
function key(): Buffer {
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret) throw new Error('Internal API secret is required');
  return crypto.createHmac('sha256', secret).update('vera:employee-triage-reference:v1').digest();
}
export function sealTriageReference(trackingId: string): string {
  if (!/^VRA-[A-F0-9]{16}$/.test(trackingId)) throw new Error('Invalid report identifier');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  cipher.setAAD(Buffer.from('employee-triage:v1'));
  const data = Buffer.concat([cipher.update(trackingId, 'utf8'), cipher.final()]);
  return 'TRI-' + Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url');
}
export function openTriageReference(reference: string): string {
  if (!/^TRI-[A-Za-z0-9_-]{64}$/.test(reference)) throw new Error('Invalid triage reference');
  const data = Buffer.from(reference.slice(4), 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key(), data.subarray(0, 12));
  decipher.setAAD(Buffer.from('employee-triage:v1'));
  decipher.setAuthTag(data.subarray(12, 28));
  const value = Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8');
  if (!/^VRA-[A-F0-9]{16}$/.test(value)) throw new Error('Invalid report identifier');
  return value;
}
