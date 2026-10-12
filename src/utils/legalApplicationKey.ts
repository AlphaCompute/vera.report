/** Host-only public intake verifier, mirrored from enclave/src/confidential/firmKeyBinding.ts. No private-key or authority signing functions. Conformance tests prevent drift across the independently built runtimes. */
import { createMessage, readKey, readSignature, verify } from 'openpgp';
import type { PublicKey } from 'openpgp';
import { createHash } from 'node:crypto';
import { firmProfile } from './legalApplicationFirmProfile';
import type { FirmProfile } from './legalApplicationFirmProfile';
export type { FirmPracticeArea, FirmProfile } from './legalApplicationFirmProfile';

/** Organization-signed public key submission, sent to VERA for approval.
 * The signature proves possession of the key and binds the organization ID,
 * approved domain and optional public profile. The organization's identity is
 * vouched for by the onboarding authority's signed registration, not by this
 * self-signature. Nothing is published on or fetched from the firm's website.
 * v1 omits the public profile; v2 includes it.
 */
const FORMAT_V1 = 'vera-firm-key-binding/v1';
const FORMAT_V2 = 'vera-firm-key-binding/v2';
// Mirrored from enclave/src/confidential/clockSkew.ts (independent build).
const CLOCK_SKEW_MS = 5 * 60_000;

export type FirmKeyBinding = {
  format: typeof FORMAT_V1 | typeof FORMAT_V2; domain: string; organizationId: string; recipientKeyId: string; issuedAt: number;
  profile?: FirmProfile;
};

export class InvalidFirmKeyBindingError extends Error {
  constructor() { super('Invalid firm key binding'); this.name = 'InvalidFirmKeyBindingError'; }
}
function invalid(): never { throw new InvalidFirmKeyBindingError(); }
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
function domain(value: unknown): string {
  if (typeof value !== 'string' || value.length > 253 || !DOMAIN.test(value)) invalid();
  return value as string;
}

function binding(input: unknown): FirmKeyBinding {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  const v2 = value.format === FORMAT_V2;
  const fields = ['format', 'domain', 'organizationId', 'recipientKeyId', 'issuedAt', ...(v2 ? ['profile'] : [])];
  if (Object.keys(value).length !== fields.length || Object.keys(value).some(key => !fields.includes(key)) ||
      (value.format !== FORMAT_V1 && !v2) || typeof value.organizationId !== 'string' || !/^[a-f0-9]{64}$/.test(value.organizationId) ||
      typeof value.recipientKeyId !== 'string' || !/^[a-f0-9]{64}$/.test(value.recipientKeyId) ||
      !Number.isSafeInteger(value.issuedAt) || (value.issuedAt as number) <= 0) invalid();
  const bound = domain(value.domain);
  const statement: FirmKeyBinding = { format: v2 ? FORMAT_V2 : FORMAT_V1, domain: bound, organizationId: value.organizationId as string,
    recipientKeyId: value.recipientKeyId as string, issuedAt: value.issuedAt as number };
  if (v2) statement.profile = firmProfile(value.profile, bound);
  return statement;
}

/** Verifier: the expected domain and organization come from the reviewed onboarding
 * record; the document is the one the organization submitted through the attested channel. */
export async function verifyFirmKeyBinding(document: string, expected: { domain: string; organizationId: string }): Promise<{
  binding: FirmKeyBinding; publicKey: PublicKey; profile: FirmProfile | null;
}> {
  try {
    if (typeof document !== 'string' || document.length > 64 * 1024) invalid();
    const value = JSON.parse(document);
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 3 ||
        typeof value.publicKey !== 'string' || typeof value.signature !== 'string' || value.signature.length > 16_384) invalid();
    const statement = binding(value.binding);
    if (statement.domain !== domain(expected.domain) || statement.organizationId !== expected.organizationId) invalid();
    const publicKey = await readKey({ armoredKey: value.publicKey });
    if (publicKey.isPrivate() || createHash('sha256').update(publicKey.write()).digest('hex') !== statement.recipientKeyId) invalid();
    const signature = await readSignature({ armoredSignature: value.signature });
    const now = Date.now();
    const created = signature.packets.length === 1 ? signature.packets[0].created?.getTime() : undefined;
    if (created === undefined || !Number.isSafeInteger(created) || created > now + CLOCK_SKEW_MS) invalid();
    // Intake has no attested clock yet. Accept modest positive device skew,
    // including a new key's self-signatures, but never rewind key expiry checks.
    const date = new Date(Math.max(now, created));
    await publicKey.getEncryptionKey(undefined, date); await publicKey.getSigningKey(undefined, date);
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
      signature, verificationKeys: publicKey, date, expectSigned: true, format: 'binary' });
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
    return { binding: statement, publicKey, profile: statement.profile ? { ...statement.profile, practiceAreas: [...statement.profile.practiceAreas] } : null };
  } catch { return invalid(); }
}
