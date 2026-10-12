import { createMessage, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';
import { issuedNotAfter } from './clockSkew.ts';

/** Legal organization setup requirements the enclave enforces before an
 * organization may request access to, or open, a report (architecture: "Firm key
 * custody and onboarding terms").
 *
 * Two statements, each signed by the organization key registered with VERA and
 * bound to that organization and exact key (a key change needs new statements):
 *
 * - `vera-legal-key-custody/v1`: the key holder attests that a second authorized
 *   person holds a copy of the encrypted key file and its recovery code, which
 *   was opened and checked on the key holder's device. This recovery precaution
 *   is optional. The enclave also reports verified enrolled key holders.
 * - `vera-legal-onboarding-terms/v1`: the organization acknowledges the onboarding
 *   terms below, bound to their version and SHA-256 digest. The terms are part of
 *   the measured enclave image, so the host cannot change what was acknowledged.
 *
 * Both are public statements (no key material, no report data). The host stores
 * them with the organization row and can withhold or replay them, never forge
 * them; withholding required terms blocks the organization (fails closed).
 */
export type FirmSetupRequirement = 'custody' | 'terms';
export const FIRM_SETUP_STATEMENT_KINDS: readonly FirmSetupRequirement[] = ['custody', 'terms'];
export const FIRM_SETUP_REQUIREMENTS: readonly FirmSetupRequirement[] = ['terms'];

/** Bump the version whenever the text changes in meaning; every organization then
 * acknowledges again before its next request or report opening. */
export const FIRM_ONBOARDING_TERMS_VERSION = 1;
export const FIRM_ONBOARDING_TERMS: readonly { id: string; title: string; text: string }[] = [
  { id: 'conflicts', title: 'Conflict checks',
    text: 'Run your conflict check on the approved summary before you ask for access. If you need more to check conflicts, ask the reporter privately in your request. Never ask them to put it in the public summary.' },
  { id: 'acceptable-use', title: 'Acceptable use',
    text: 'Use VERA only to offer legal help to the reporter. Do not try to identify or contact a reporter beyond what they choose to share. Access to a report does not by itself make the reporter your client.' },
  { id: 'devices', title: 'Device protection',
    text: 'Open reports only on devices your organization manages, with disk encryption, a screen lock and current updates. Each lawyer uses their own device key and sign-in. Never share the organization key file or a login.' },
  { id: 'downloads', title: 'Download handling',
    text: 'A downloaded file is no longer protected by VERA. Keep it only in your organization\'s protected matter storage and delete working copies you no longer need.' },
  { id: 'departure', title: 'Member departure',
    text: 'When a lawyer leaves, remove their device from Lawyers and devices the same day. Removal stops future access; it cannot recall what they already downloaded.' },
  { id: 'retention', title: 'Retention',
    text: 'Keep and delete report material under your retention policy and professional obligations. Your access lasts until the reporter removes it or it expires.' },
];

export type FirmCustodyStatement = {
  format: 'vera-legal-key-custody/v1'; organizationId: string; recipientKeyId: string;
  method: 'second-custodian-copy'; attestedAt: number;
};
export type FirmTermsStatement = {
  format: 'vera-legal-onboarding-terms/v1'; organizationId: string; recipientKeyId: string;
  termsVersion: number; termsDigest: string; acknowledgedAt: number;
};
export type FirmSetupStatement = FirmCustodyStatement | FirmTermsStatement;
export const FIRM_SETUP_STATEMENT_MAX = 8192;

function invalid(): never { throw new Error('Invalid organization setup statement'); }
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
async function sha256(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Digest of the exact terms text and version the organization acknowledges. */
export async function firmOnboardingTermsDigest(): Promise<string> {
  return sha256(JSON.stringify({ format: 'vera-legal-onboarding-terms-text/v1', version: FIRM_ONBOARDING_TERMS_VERSION,
    terms: FIRM_ONBOARDING_TERMS.map(({ id, title, text }) => ({ id, title, text })) }));
}

function canonical(kind: FirmSetupRequirement, value: unknown): FirmSetupStatement {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const item = value as Record<string, unknown>;
  const fields = Object.keys(item).sort().join(',');
  if (kind === 'custody') {
    if (fields !== 'attestedAt,format,method,organizationId,recipientKeyId' || item.format !== 'vera-legal-key-custody/v1' ||
        item.method !== 'second-custodian-copy' || !hex(item.organizationId) || !hex(item.recipientKeyId) ||
        !positive(item.attestedAt)) invalid();
    return { format: 'vera-legal-key-custody/v1', organizationId: item.organizationId as string,
      recipientKeyId: item.recipientKeyId as string, method: 'second-custodian-copy', attestedAt: item.attestedAt as number };
  }
  if (fields !== 'acknowledgedAt,format,organizationId,recipientKeyId,termsDigest,termsVersion' ||
      item.format !== 'vera-legal-onboarding-terms/v1' || !hex(item.organizationId) || !hex(item.recipientKeyId) ||
      !positive(item.termsVersion) || !hex(item.termsDigest) || !positive(item.acknowledgedAt)) invalid();
  return { format: 'vera-legal-onboarding-terms/v1', organizationId: item.organizationId as string,
    recipientKeyId: item.recipientKeyId as string, termsVersion: item.termsVersion as number,
    termsDigest: item.termsDigest as string, acknowledgedAt: item.acknowledgedAt as number };
}
const kindOf = (statement: FirmSetupStatement): FirmSetupRequirement =>
  statement.format === 'vera-legal-key-custody/v1' ? 'custody' : 'terms';

/** Key holder's device: sign a setup statement with the organization key. */
export async function signFirmSetupStatement(input: FirmSetupStatement, organizationKey: PrivateKey): Promise<string> {
  const statement = canonical(kindOf(input), input);
  if (!organizationKey.isDecrypted() || await caseRecipientKeyId(organizationKey.toPublic()) !== statement.recipientKeyId) invalid();
  if (statement.format === 'vera-legal-onboarding-terms/v1' && (statement.termsVersion !== FIRM_ONBOARDING_TERMS_VERSION ||
      statement.termsDigest !== await firmOnboardingTermsDigest())) invalid();
  const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
    signingKeys: organizationKey, detached: true, format: 'armored' }) as string;
  const document = JSON.stringify({ statement, signature });
  if (document.length > FIRM_SETUP_STATEMENT_MAX) invalid();
  return document;
}

/** Enclave (and portal) check: signed by exactly the registered organization key,
 * for this organization and key, not issued in the future, and for terms, the
 * current version and digest. */
export async function verifyFirmSetupStatement(document: unknown, expected: {
  kind: 'custody'; organizationId: string; recipientKeyId: string; publicKey: PublicKey;
}, now: number): Promise<FirmCustodyStatement>;
export async function verifyFirmSetupStatement(document: unknown, expected: {
  kind: 'terms'; organizationId: string; recipientKeyId: string; publicKey: PublicKey;
}, now: number): Promise<FirmTermsStatement>;
export async function verifyFirmSetupStatement(document: unknown, expected: {
  kind: FirmSetupRequirement; organizationId: string; recipientKeyId: string; publicKey: PublicKey;
}, now: number): Promise<FirmSetupStatement> {
  try {
    if (typeof document !== 'string' || document.length > FIRM_SETUP_STATEMENT_MAX || expected.publicKey.isPrivate()) invalid();
    const value = JSON.parse(document);
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).sort().join(',') !== 'signature,statement' || typeof value.signature !== 'string') invalid();
    const statement = canonical(expected.kind, value.statement);
    const issuedAt = statement.format === 'vera-legal-key-custody/v1' ? statement.attestedAt : statement.acknowledgedAt;
    if (statement.organizationId !== expected.organizationId || statement.recipientKeyId !== expected.recipientKeyId ||
        await caseRecipientKeyId(expected.publicKey) !== expected.recipientKeyId || !issuedNotAfter(issuedAt, now)) invalid();
    if (statement.format === 'vera-legal-onboarding-terms/v1' && (statement.termsVersion !== FIRM_ONBOARDING_TERMS_VERSION ||
        statement.termsDigest !== await firmOnboardingTermsDigest())) invalid();
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
      signature: await readSignature({ armoredSignature: value.signature }), verificationKeys: expected.publicKey,
      expectSigned: true, format: 'binary' });
    const checks = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (checks.length !== 1 || checks[0].status !== 'fulfilled') invalid();
    return statement;
  } catch { return invalid(); }
}
