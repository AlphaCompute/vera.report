import { passphraseProblem } from './passphraseStrength';
import { generateKey, readPrivateKey } from '../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../enclave/src/confidential/caseObject';
import { applicationOrganizationId } from '../../enclave/src/confidential/applicationOrganization';
import { createFirmKeyBinding } from '../../enclave/src/confidential/firmKeyBinding';
import type { FirmProfile } from '../../enclave/src/confidential/firmKeyBinding';

/** Legal-organization key custody in the firm's browser.
 * The firm private key is generated here and leaves the device only inside an
 * AES-256-GCM export protected by a firm-held secret (a generated recovery code
 * or a long passphrase). VERA never receives the secret or the private key, and
 * there is no platform reset: losing both the export and the secret means the
 * organization needs a new key and new owner grants.
 */
const EXPORT_FORMAT = 'vera-firm-key-export/v1';
const PAYLOAD_FORMAT = 'vera-firm-key-export-payload/v1';
const KDF_ITERATIONS = 600_000;
export const FIRM_RECOVERY_PREFIX = 'VERA-FIRM-1.';
export const FIRM_SECRET_MIN_LENGTH = 16;

export type FirmIdentity = {
  organizationId: string; domain: string; privateKey: PrivateKey; recipientKeyId: string;
};
type ExportMetadata = { organizationId: string; domain: string; recipientKeyId: string };

function invalid(message = 'Unable to open the firm key file'): never { throw new Error(message); }
function base64url(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unbase64url(value: unknown, max: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  const text = value as string;
  const bytes = Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4)),
    char => char.charCodeAt(0));
  if (bytes.length > max || base64url(bytes) !== text) invalid();
  return bytes;
}
export function validFirmDomain(value: string): boolean {
  return typeof value === 'string' && value.length <= 253 &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
}
export function validOrganizationId(value: string): boolean { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function metadata(input: ExportMetadata): ExportMetadata {
  if (!input || !validOrganizationId(input.organizationId) || !validFirmDomain(input.domain) ||
      !/^[a-f0-9]{64}$/.test(input.recipientKeyId)) invalid();
  return { organizationId: input.organizationId, domain: input.domain, recipientKeyId: input.recipientKeyId };
}
function associatedData(meta: ExportMetadata): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify({ format: EXPORT_FORMAT, ...meta }));
}
async function deriveKey(secret: string, salt: Uint8Array<ArrayBuffer>, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const text = typeof secret === 'string' ? secret.trim().normalize('NFC') : '';
  if (text.length < FIRM_SECRET_MIN_LENGTH || text.length > 1024) invalid('Use a recovery code or a passphrase of at least 16 characters');
  // A new export must use a strong secret; existing exports still open.
  if (usage === 'encrypt') { const problem = passphraseProblem(text); if (problem) invalid(problem); }
  const bytes = new TextEncoder().encode(text);
  try {
    const material = await globalThis.crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await globalThis.crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: KDF_ITERATIONS },
      material, { name: 'AES-GCM', length: 256 }, false, [usage]);
  } finally { bytes.fill(0); } // The passphrase copy; the JavaScript string cannot be cleared.
}

/** New firm signing/encryption key. Curve and packet layout match the owner keys. */
export async function generateFirmIdentity(input: { organizationId: string; domain: string }): Promise<FirmIdentity> {
  const domain = input.domain.trim().toLowerCase(), organizationId = input.organizationId.trim().toLowerCase();
  if (!validOrganizationId(organizationId)) invalid('Enter the 64-character organization ID from VERA onboarding');
  if (!validFirmDomain(domain)) invalid('Enter your firm domain, for example counsel.example');
  const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'VERA legal organization' }], format: 'object' });
  return { organizationId, domain, privateKey, recipientKeyId: await caseRecipientKeyId(privateKey.toPublic()) };
}

/** Public intake uses a key-derived ID; assigned legacy IDs remain manual. */
export async function generateApplicationIdentity(domain: string): Promise<FirmIdentity> {
  const firm = await generateFirmIdentity({ organizationId: '0'.repeat(64), domain });
  return { ...firm, organizationId: await applicationOrganizationId(firm.recipientKeyId) };
}

/** Public key binding submitted through the attested channel for approval.
 * A profile, when given, is signed into the same document. */
export async function firmBindingDocument(firm: FirmIdentity, now: number, profile?: FirmProfile): Promise<string> {
  return createFirmKeyBinding({ domain: firm.domain, organizationId: firm.organizationId, issuedAt: now,
    ...(profile ? { profile } : {}) }, firm.privateKey);
}

/** A random 256-bit recovery code for the export (preferred over a passphrase). */
export function generateFirmRecoveryCode(): string {
  return FIRM_RECOVERY_PREFIX + base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/** Encrypted, labeled-private export of the firm key. The JSON line is what
 * `importFirmIdentity` reads; the surrounding text is guidance for people. */
export async function exportFirmIdentity(firm: FirmIdentity, secret: string): Promise<string> {
  const meta = metadata({ organizationId: firm.organizationId, domain: firm.domain, recipientKeyId: firm.recipientKeyId });
  if (await caseRecipientKeyId(firm.privateKey.toPublic()) !== meta.recipientKeyId || !firm.privateKey.isDecrypted()) invalid();
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16)), nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ format: PAYLOAD_FORMAT, ...meta, privateKey: firm.privateKey.armor() }));
  try {
    const key = await deriveKey(secret, salt, 'encrypt');
    const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
      additionalData: associatedData(meta), tagLength: 128 }, key, plaintext));
    const line = JSON.stringify({ format: EXPORT_FORMAT, ...meta, kdf: { name: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS,
      salt: base64url(salt) }, nonce: base64url(nonce), ciphertext: base64url(ciphertext) });
    // Refuse to hand out an export this code cannot open again.
    await importFirmIdentity(line, secret);
    return [
      'VERA legal organization key — PRIVATE. DO NOT SHARE, EMAIL OR UPLOAD.',
      '',
      'This file holds your organization\'s encrypted private key. With the recovery code or',
      'passphrase it can read every case VERA participants share with your organization.',
      'VERA cannot recover or reset it. Store it offline, separately from the code or passphrase.',
      '',
      `Organization ID: ${meta.organizationId}`,
      `Domain: ${meta.domain}`,
      `Key ID: ${meta.recipientKeyId}`,
      '',
      line,
      '',
    ].join('\n');
  } finally { plaintext.fill(0); }
}

/** Envelope inspection is only a file-selection check, never proof of recovery. */
function parseFirmExport(file: string) {
  if (typeof file !== 'string' || file.length > 256 * 1024) invalid();
  const line = file.split('\n').map(item => item.trim()).find(item => item.startsWith(`{"format":"${EXPORT_FORMAT}"`));
  if (!line) invalid();
  const value = JSON.parse(line!);
  if (!value || Object.keys(value).sort().join(',') !== 'ciphertext,domain,format,kdf,nonce,organizationId,recipientKeyId' ||
      !value.kdf || Object.keys(value.kdf).sort().join(',') !== 'iterations,name,salt' ||
      value.kdf.name !== 'PBKDF2-SHA256' || value.kdf.iterations !== KDF_ITERATIONS) invalid();
  const meta = metadata(value);
  unbase64url(value.kdf.salt, 16);
  unbase64url(value.nonce, 12);
  unbase64url(value.ciphertext, 128 * 1024);
  return { value, meta };
}

export function inspectFirmBackup(file: string): ExportMetadata {
  try { return parseFirmExport(file).meta; } catch { return invalid(); }
}

export async function importFirmIdentity(file: string, secret: string): Promise<FirmIdentity> {
  let plaintext: Uint8Array | undefined;
  try {
    const { value, meta } = parseFirmExport(file);
    const key = await deriveKey(secret, unbase64url(value.kdf.salt, 16), 'decrypt');
    plaintext = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: unbase64url(value.nonce, 12),
      additionalData: associatedData(meta), tagLength: 128 }, key, unbase64url(value.ciphertext, 128 * 1024)));
    const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    if (!payload || Object.keys(payload).sort().join(',') !== 'domain,format,organizationId,privateKey,recipientKeyId' ||
        payload.format !== PAYLOAD_FORMAT || payload.organizationId !== meta.organizationId || payload.domain !== meta.domain ||
        payload.recipientKeyId !== meta.recipientKeyId || typeof payload.privateKey !== 'string') invalid();
    const privateKey = await readPrivateKey({ armoredKey: payload.privateKey });
    if (!privateKey.isDecrypted() || await caseRecipientKeyId(privateKey.toPublic()) !== meta.recipientKeyId) invalid();
    return { ...meta, privateKey };
  } catch { return invalid(); } finally { plaintext?.fill(0); }
}
