import {
  FIRM_ONBOARDING_TERMS_VERSION, FIRM_SETUP_REQUIREMENTS, firmOnboardingTermsDigest, signFirmSetupStatement,
} from '../../enclave/src/confidential/firmSetup';
import type { FirmSetupRequirement } from '../../enclave/src/confidential/firmSetup';
import { ConfidentialUnavailableError, base64, channelSessionsFor, trustedTime, unavailable } from './client';
import type { FirmSession } from './firmCase';
export type { FirmSetupRequirement };

/** The organization's enforced setup, as the secure service reports it
 * (`enclave/src/cases/legalSetup.ts`). The service refuses access requests and
 * report opening with `{error:'setup-incomplete', missing}` until terms are met:
 *
 * - `custody` (optional): two enrolled key holders or a signed second-custodian
 *   attestation. This is reported for recovery planning, not required for access;
 * - `terms`: the current onboarding terms acknowledged with the organization key.
 *
 * Statements are signed on this device with the organization key and kept with
 * the organization's record, so every member's device sees the same state and
 * nobody is asked twice. They hold no key material and no report data. */
export type FirmSetupStatus = {
  complete: boolean; missing: FirmSetupRequirement[];
  custody: 'attested' | 'members' | null;
  /** Enrolled key holders the service counted (it stops at 2). */
  holders: number;
  custodyAttestedAt: number | null;
  terms: { version: number; acknowledgedAt: number } | null;
  termsVersion: number;
};

const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

/** `missing` from a `setup-incomplete` reply; null when malformed. */
export function parseSetupMissing(value: unknown): FirmSetupRequirement[] | null {
  if (!Array.isArray(value) || !value.length || value.length > FIRM_SETUP_REQUIREMENTS.length ||
      new Set(value).size !== value.length || !value.every(item => (FIRM_SETUP_REQUIREMENTS as readonly unknown[]).includes(item))) return null;
  return FIRM_SETUP_REQUIREMENTS.filter(item => value.includes(item));
}

/** Strict reply check: anything unexpected is an unavailable service, never "complete". */
export function parseFirmSetupStatus(reply: unknown): FirmSetupStatus {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new ConfidentialUnavailableError();
  const value = reply as Record<string, unknown>;
  if (Object.keys(value).sort().join(',') !== 'complete,custody,custodyAttestedAt,holders,missing,terms,termsVersion') {
    throw new ConfidentialUnavailableError();
  }
  const missing = Array.isArray(value.missing) && value.missing.length === 0 ? [] : parseSetupMissing(value.missing);
  const terms = value.terms as Record<string, unknown> | null;
  if (missing === null || typeof value.complete !== 'boolean' || value.complete !== (missing.length === 0) ||
      !(value.custody === null || value.custody === 'attested' || value.custody === 'members') ||
      !Number.isSafeInteger(value.holders) || (value.holders as number) < 0 || (value.holders as number) > 2 ||
      (value.custody === 'members' && value.holders !== 2) ||
      (value.custodyAttestedAt !== null && !positive(value.custodyAttestedAt)) ||
      (value.custody === 'attested' && value.custodyAttestedAt === null) ||
      !positive(value.termsVersion) ||
      (terms !== null && (typeof terms !== 'object' || Array.isArray(terms) || Object.keys(terms).sort().join(',') !== 'acknowledgedAt,version' ||
        !positive(terms.version) || !positive(terms.acknowledgedAt))) ||
      (terms === null) !== missing.includes('terms')) throw new ConfidentialUnavailableError();
  return { complete: value.complete as boolean, missing, custody: value.custody as FirmSetupStatus['custody'],
    holders: value.holders as number, custodyAttestedAt: value.custodyAttestedAt as number | null,
    terms: terms ? { version: terms.version as number, acknowledgedAt: terms.acknowledgedAt as number } : null,
    termsVersion: value.termsVersion as number };
}

async function call(session: FirmSession, operation: 'legal.setup-status' | 'legal.setup-record', body: () => Promise<unknown>): Promise<unknown> {
  const accessToken = await session.accessToken(); // Sign-in errors surface as themselves.
  try {
    return await channelSessionsFor(session, session.relay, session.releaseManifest).run(async send =>
      send({ operation, accessToken, body: base64(encode(await body())) }, { retry: operation === 'legal.setup-status' }));
  } catch (error) { throw unavailable(error); }
}

export async function readFirmSetup(session: FirmSession, now: number): Promise<FirmSetupStatus> {
  return parseFirmSetupStatus(await call(session, 'legal.setup-status', async () => ({ organizationId: session.firm.organizationId })));
}

/** Signs the statement for `kind` with the organization key on this device and
 * records it. Only call after the person did what it states: checked a second
 * custodian's copy here, or read and acknowledged the terms. */
export async function recordFirmSetup(session: FirmSession, kind: FirmSetupRequirement, now: number): Promise<FirmSetupStatus> {
  const { organizationId, recipientKeyId, privateKey } = session.firm;
  return parseFirmSetupStatus(await call(session, 'legal.setup-record', async () => {
    // Acquire the verified channel before signing, so device skew cannot produce a future statement.
    const issuedAt = trustedTime(now);
    const statement = kind === 'custody'
    ? await signFirmSetupStatement({ format: 'vera-legal-key-custody/v1', organizationId, recipientKeyId,
      method: 'second-custodian-copy', attestedAt: issuedAt }, privateKey)
    : await signFirmSetupStatement({ format: 'vera-legal-onboarding-terms/v1', organizationId, recipientKeyId,
      termsVersion: FIRM_ONBOARDING_TERMS_VERSION, termsDigest: await firmOnboardingTermsDigest(), acknowledgedAt: issuedAt }, privateKey);
    return { organizationId, kind, statement };
  }));
}

const STEP_LABELS: Record<FirmSetupRequirement, string> = {
  custody: 'record a second key holder', terms: 'acknowledge the onboarding terms',
};

/** Plain guidance for a refused request or report (see userFacingError.ts: no
 * identifiers, one short paragraph). */
export function setupIncompleteMessage(missing: readonly FirmSetupRequirement[]): string {
  const steps = (missing.length ? missing : FIRM_SETUP_REQUIREMENTS).map(item => STEP_LABELS[item]);
  const sentence = steps.join(' and ');
  return `Your organization has not finished setup, so it cannot request or open reports yet. ${sentence[0].toUpperCase()}${sentence.slice(1)} under Organization setup on the legal portal home page, then try again.`;
}

/** One line per missing step, with what to do next. */
export function setupNextSteps(missing: readonly FirmSetupRequirement[]): { id: FirmSetupRequirement; title: string; action: string }[] {
  return missing.map(item => item === 'custody'
    ? { id: item, title: 'Second key holder',
      action: 'Check a second authorized person\'s copy of the organization key file and recovery code on this device, or have a second lawyer accept their invitation with their own device key.' }
    : { id: item, title: 'Onboarding terms',
      action: 'Read and acknowledge the onboarding terms. Anyone who holds the organization key can do this once for the whole organization.' });
}
