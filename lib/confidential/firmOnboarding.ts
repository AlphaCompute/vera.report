import type { FirmProfile } from '../../enclave/src/confidential/firmKeyBinding';
import { base64, fetchRelay, ConfidentialUnavailableError, channelFailure, exchange, verifiedSession } from './client';
import type { ChannelRelay } from './client';
import type { FirmIdentity } from './firmKey';
import { CONFIDENTIAL_RELEASE_MANIFEST } from './config';
import { legalAuthConfig, legalAccessToken } from './legalAuth';
import { FIRM_ONBOARDING_TERMS, FIRM_ONBOARDING_TERMS_VERSION } from '../../enclave/src/confidential/firmSetup';
import type { FirmSetupStatus } from './firmSetup';

/** Approval and membership status travel through the attested channel. */
export type DomainCheck =
  | { state: 'verified'; profile: FirmProfile | null; issuedAt: number }
  | { state: 'different-key' }
  | { state: 'unreachable' }
  | { state: 'invalid' };

/** A first public organization key (or a profile refresh of the registered key)
 * travels through the authenticated enclave channel. Replacements go through
 * submitReplacementOrganizationKey with a steward proof and continuity. */
export async function submitOrganizationKey(firm: FirmIdentity, bindingDocument: string): Promise<void> {
  const config = legalAuthConfig();
  if (!config) throw new ConfidentialUnavailableError();
  const relay = fetchRelay();
  const session = await verifiedSession(relay, CONFIDENTIAL_RELEASE_MANIFEST, Date.now());
  const reply = await exchange(relay, session, { operation: 'legal.submit-organization-key',
    accessToken: await legalAccessToken(config), body: base64(new TextEncoder().encode(JSON.stringify({
      organizationId: firm.organizationId, bindingDocument,
    }))) }) as { submitted?: boolean; recipientKeyId?: string };
  if (reply.submitted !== true || reply.recipientKeyId !== firm.recipientKeyId) throw new ConfidentialUnavailableError();
}

export async function checkFirmDomain(firm: Pick<FirmIdentity, 'domain' | 'organizationId' | 'recipientKeyId'>): Promise<DomainCheck> {
  try {
    const config = legalAuthConfig();
    if (!config) return { state: 'unreachable' };
    const { approvedOrganizationProfile } = await import('./firmMemberDevices');
    const { publicKey: key, profile } = await approvedOrganizationProfile(firm, { relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
      accessToken: await legalAccessToken(config), now: Date.now() });
    const { caseRecipientKeyId } = await import('../../enclave/src/confidential/caseObject');
    if (await caseRecipientKeyId(key) !== firm.recipientKeyId) return { state: 'different-key' };
    return { state: 'verified', profile, issuedAt: Date.now() };
  } catch { return { state: 'unreachable' }; }
}

export function domainCheckMessage(check: DomainCheck, domain: string): string {
  if (check.state === 'verified') return `VERA has approved this organization key for ${domain}.`;
  if (check.state === 'different-key') return 'A different organization key is registered. Submit this key for approval before using it.';
  return 'Your organization key is awaiting approval, or its status could not be checked. Keep your saved backup.';
}

export type MembershipStatus =
  | { state: 'not-enrolled' }
  /** A membership existed but expired or was ended. A new invitation renews it. */
  | { state: 'lapsed' }
  | { state: 'enrolled'; leaseExpiresAt: number; members: number | null; keyMatches: boolean };

/** The signed-in member's own enrollment. Requires only the sign-in token. */
export async function readMembershipStatus(input: { relay: ChannelRelay; releaseManifest: string; accessToken: string;
  firm: Pick<FirmIdentity, 'organizationId' | 'recipientKeyId'>; now: number }): Promise<MembershipStatus> {
  let reply: unknown;
  try {
    const channel = await verifiedSession(input.relay, input.releaseManifest, input.now);
    reply = await exchange(input.relay, channel, { operation: 'legal.membership', accessToken: input.accessToken });
  } catch (error) { throw channelFailure(error); }
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new ConfidentialUnavailableError();
  const value = reply as Record<string, unknown>;
  const fields = Object.keys(value).sort().join(',');
  if (fields === 'enrolled,lapsed' && value.enrolled === false && typeof value.lapsed === 'boolean') {
    return { state: value.lapsed ? 'lapsed' : 'not-enrolled' };
  }
  const hex = (item: unknown) => typeof item === 'string' && /^[a-f0-9]{64}$/.test(item);
  if (fields !== 'enrolled,lapsed,leaseExpiresAt,members,organizationId,recipientKeyId' || value.enrolled !== true ||
      value.lapsed !== false || !hex(value.organizationId) || !hex(value.recipientKeyId) ||
      !Number.isSafeInteger(value.leaseExpiresAt) || (value.leaseExpiresAt as number) <= 0 ||
      (value.members !== null && (!Number.isSafeInteger(value.members) || (value.members as number) < 1))) {
    throw new ConfidentialUnavailableError();
  }
  return { state: 'enrolled', leaseExpiresAt: value.leaseExpiresAt as number, members: value.members as number | null,
    keyMatches: value.organizationId === input.firm.organizationId && value.recipientKeyId === input.firm.recipientKeyId };
}

const DAY_MS = 86_400_000;
/** Warn this long before a membership lease (seven days at most) ends. */
export const MEMBERSHIP_WARNING_MS = 2 * DAY_MS;

export function membershipEndDate(value: number): string {
  return new Date(value).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
}

/** Where the signed-in member's lease stands at `now`. A lease the server still
 * reported as enrolled counts as ended once its end time passes on this device. */
export type MembershipLease =
  | { state: 'unknown' }
  | { state: 'not-enrolled' }
  | { state: 'other-key' }
  | { state: 'active'; endsAt: number }
  | { state: 'ending-soon'; endsAt: number; daysLeft: number }
  | { state: 'ended'; endedAt: number | null };

export function membershipLease(status: MembershipStatus | null, now: number): MembershipLease {
  if (status === null) return { state: 'unknown' };
  if (status.state === 'not-enrolled') return { state: 'not-enrolled' };
  if (status.state === 'lapsed') return { state: 'ended', endedAt: null };
  if (!status.keyMatches) return { state: 'other-key' };
  const left = status.leaseExpiresAt - now;
  if (left <= 0) return { state: 'ended', endedAt: status.leaseExpiresAt };
  if (left <= MEMBERSHIP_WARNING_MS) return { state: 'ending-soon', endsAt: status.leaseExpiresAt, daysLeft: Math.ceil(left / DAY_MS) };
  return { state: 'active', endsAt: status.leaseExpiresAt };
}

export type PortalView = 'checking' | 'reports' | 'not-enrolled' | 'other-key' | 'ended';

/** What the legal portal shows below the setup panel. Reports (and the directory and shared-request
 * calls behind them) mount only once membership is confirmed, or once the membership check itself
 * failed (their own errors then explain the problem), never while the check is still pending, so a
 * lawyer who is not enrolled never sees request errors flash before the blocked panel. */
export function portalView(membership: { status: MembershipStatus | null; error: string | null }, now: number): PortalView {
  if (membership.status === null) return membership.error === null ? 'checking' : 'reports';
  const lease = membershipLease(membership.status, now);
  if (lease.state === 'not-enrolled' || lease.state === 'other-key' || lease.state === 'ended') return lease.state;
  return 'reports';
}

/** The portal-wide notice for a membership that ends soon or has ended; null otherwise. */
export function membershipNotice(status: MembershipStatus | null, now: number):
  { tone: 'attention' | 'negative'; title: string; message: string } | null {
  const lease = membershipLease(status, now);
  if (lease.state === 'ending-soon') {
    return { tone: 'attention', title: lease.daysLeft <= 1 ? 'Your membership ends within a day' : `Your membership ends in ${lease.daysLeft} days`,
      message: `Your membership ends on ${membershipEndDate(lease.endsAt)}. Reopen your saved approved device to renew access. If you are the first key holder without a device approval, ask VERA onboarding for a new invitation.` };
  }
  if (lease.state === 'ended') {
    return { tone: 'negative', title: 'Your membership has ended',
      message: `${lease.endedAt === null ? 'Your membership has ended' : `Your membership ended on ${membershipEndDate(lease.endedAt)}`}, so reports are not available. Reopen your saved approved device to renew access, or ask your organization for help. First key holders without a device approval need a new VERA invitation.` };
  }
  return null;
}

export type ChecklistStep = { id: 'key' | 'custody' | 'terms' | 'domain' | 'invitation' | 'lawyers'; label: string; done: boolean; detail: string;
  /** Optional steps never hold back `complete`. */
  optional?: boolean };

/** What the organization must cover before it works with reports (architecture:
 * "Onboarding should cover conflict checks, acceptable use, device protection,
 * download handling, member departure and retention"). The text, its version and
 * digest live in the measured enclave module so the service enforces exactly what
 * was acknowledged (`enclave/src/confidential/firmSetup.ts`). */
export { FIRM_ONBOARDING_TERMS, FIRM_ONBOARDING_TERMS_VERSION };

/** Onboarding acknowledgments kept on this device. Holds no key material, no
 * report data and no reporter link: only when the second key copy was checked
 * (for which organization key) and when the terms were acknowledged. */
export type OnboardingRecord = {
  /** A second custodian's copy of this organization key was opened and checked here. */
  custody: { recipientKeyId: string; verifiedAt: number } | null;
  terms: { version: number; acceptedAt: number } | null;
};
export const EMPTY_ONBOARDING_RECORD: OnboardingRecord = { custody: null, terms: null };
type KeyValueStore = Pick<Storage, 'getItem' | 'setItem'>;
const onboardingStorageKey = (organizationId: string) => `vera-legal-onboarding:${organizationId}`;
const hex64 = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const time = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

/** Reads the record, treating anything malformed as "not done". */
export function readOnboardingRecord(store: KeyValueStore | null, organizationId: string): OnboardingRecord {
  try {
    const raw = store?.getItem(onboardingStorageKey(organizationId));
    if (!raw || raw.length > 1024) return EMPTY_ONBOARDING_RECORD;
    const value = JSON.parse(raw) as Partial<OnboardingRecord>;
    const custody = value.custody && hex64(value.custody.recipientKeyId) && time(value.custody.verifiedAt)
      ? { recipientKeyId: value.custody.recipientKeyId, verifiedAt: value.custody.verifiedAt } : null;
    const terms = value.terms && Number.isSafeInteger(value.terms.version) && time(value.terms.acceptedAt)
      ? { version: value.terms.version, acceptedAt: value.terms.acceptedAt } : null;
    return { custody, terms };
  } catch { return EMPTY_ONBOARDING_RECORD; }
}

/** Merges `patch` into the stored record and returns the result. A storage
 * failure still returns the merged record, so the step shows as done for now. */
export function recordOnboarding(store: KeyValueStore | null, organizationId: string,
  patch: Partial<OnboardingRecord>): OnboardingRecord {
  const next = { ...readOnboardingRecord(store, organizationId), ...patch };
  try { store?.setItem(onboardingStorageKey(organizationId), JSON.stringify(next)); } catch { /* Shown as done until reload. */ }
  return next;
}

/** The organization's setup as the secure service enforces it (see firmSetup.ts).
 * `status: null` while it is being read (or could not be read: `error`). */
export type ServerSetup = { status: FirmSetupStatus | null; error?: string | null };
const ENFORCED = 'VERA will not send requests or open reports for your organization until this is done.';

/** The required terms and optional custody once the service's setup status applies (the member is
 * enrolled with this key). Done only when VERA has the signed statement or counted
 * the key holders; a step finished only on this device says so. */
function enforcedSteps(setup: ServerSetup, local: { copyChecked: boolean; termsAccepted: boolean }): ChecklistStep[] {
  const { status } = setup;
  const pending = setup.error ?? 'Checking with VERA…';
  const custody: ChecklistStep = { id: 'custody', label: 'Second key holder (optional)', optional: true, done: !!status && status.custody !== null,
    detail: !status ? pending
      : status.custody === 'members' ? 'At least two enrolled people hold your organization key on their own devices.'
        : status.custody === 'attested' ? `A second key holder's copy was checked and recorded with VERA${status.custodyAttestedAt ? ` on ${membershipEndDate(status.custodyAttestedAt)}` : ''}.`
          : local.copyChecked ? "A second key holder's copy was checked on this device but is not recorded with VERA yet. This is optional."
            : 'For extra recovery protection, you can keep a backup with a second authorized person and check their copy here, or add a second lawyer. You can request and open reports without this step. VERA cannot recover a lost key.' };
  const terms: ChecklistStep = { id: 'terms', label: 'Onboarding terms acknowledged', done: !!status && status.terms !== null,
    detail: !status ? pending
      : status.terms ? `Your organization acknowledged the onboarding terms on ${membershipEndDate(status.terms.acknowledgedAt)}. Every member's device sees this.`
        : local.termsAccepted ? `Acknowledged on this device but not recorded with VERA yet. ${ENFORCED}`
          : `Read and acknowledge how your organization must handle reports. Anyone who holds the organization key can do this once for everyone. ${ENFORCED}` };
  return [custody, terms];
}

/** Steps this device finished locally that VERA does not have yet, so the portal
 * can sign and record them once the member is enrolled (no second prompt). */
export function pendingSetupSync(status: FirmSetupStatus, record: OnboardingRecord, recipientKeyId: string): ('custody' | 'terms')[] {
  const pending: ('custody' | 'terms')[] = [];
  if (status.custody === null && record.custody?.recipientKeyId === recipientKeyId) pending.push('custody');
  if (status.missing.includes('terms') && record.terms !== null && record.terms.version >= FIRM_ONBOARDING_TERMS_VERSION) pending.push('terms');
  return pending;
}

/** The onboarding steps with live state. `null` means "not checked yet". Adding lawyers is
 * optional: a sole practitioner is a complete organization, and counts as done once enrolled.
 * A second key holder is an optional recovery precaution.
 *
 * Without `setup` (before enrollment, on the setup page) custody and terms are this
 * device's own record. With `setup` they are what the service enforces. */
export function onboardingChecklist(input: { keySaved: boolean; domain: string; domainCheck: DomainCheck | null;
  membership: MembershipStatus | null; now?: number; recipientKeyId: string; record: OnboardingRecord;
  setup?: ServerSetup }): { steps: ChecklistStep[]; complete: boolean } {
  const { domainCheck, record } = input;
  // A lease that ran out on this device is an ended membership, not an accepted invitation.
  const membership: MembershipStatus | null = input.membership?.state === 'enrolled' && input.now !== undefined &&
    input.membership.leaseExpiresAt <= input.now ? { state: 'lapsed' } : input.membership;
  const enrolled = membership?.state === 'enrolled' && membership.keyMatches;
  const lawyers = membership?.state === 'enrolled' ? membership.members : null;
  const copyChecked = record.custody?.recipientKeyId === input.recipientKeyId;
  const secondPerson = enrolled && lawyers !== null && lawyers >= 2;
  const termsAccepted = record.terms !== null && record.terms.version >= FIRM_ONBOARDING_TERMS_VERSION;
  const enforced = input.setup ? enforcedSteps(input.setup, { copyChecked, termsAccepted }) : null;
  const steps: ChecklistStep[] = [
    { id: 'key', label: 'Organization key saved', done: input.keySaved,
      detail: input.keySaved ? 'Your key file and its recovery code are saved and checked.'
        : 'Download the key file, then reopen it with its recovery code to check both copies.' },
    ...(enforced ?? [{ id: 'custody' as const, label: 'Second key holder (optional)', optional: true, done: copyChecked || secondPerson,
      detail: copyChecked ? 'A second key holder\'s copy of the key file and recovery code was checked on this device.'
        : secondPerson ? `${lawyers} people hold your organization key on their own devices.`
          : 'For extra recovery protection, you can check a second authorized person\'s backup here or add a second lawyer. This is optional. VERA cannot recover a lost key.' },
    { id: 'terms' as const, label: 'Onboarding terms acknowledged', done: termsAccepted,
      detail: termsAccepted ? 'You acknowledged how your organization handles conflicts, devices, downloads, departures and retention.'
        : 'Read and acknowledge how your organization must handle reports before you ask for access.' }]),
    { id: 'domain', label: 'Organization key approved', done: domainCheck?.state === 'verified',
      detail: domainCheck === null ? `Checking ${input.domain}…` : domainCheckMessage(domainCheck, input.domain) },
    { id: 'invitation', label: 'Invitation accepted', done: enrolled,
      detail: membership === null ? 'Checking your membership…'
        : membership.state === 'enrolled' && !membership.keyMatches
          ? 'Your account is enrolled with a different organization key. Unlock that key, or ask VERA onboarding for a new invitation.'
          : membership.state === 'enrolled'
            ? `Your membership is active until ${membershipEndDate(membership.leaseExpiresAt)}. Reopen your saved approved device to renew access. First key holders without a device approval need a new VERA invitation.`
            : membership.state === 'lapsed'
              ? 'Your membership has ended. Ask VERA onboarding for a new invitation, then open its link.'
              : 'Open the private invitation link from VERA onboarding while signed in, then accept it here.' },
    { id: 'lawyers', label: 'Lawyers added (optional)', optional: true, done: enrolled && lawyers !== null && lawyers >= 1,
      detail: !enrolled ? 'Available after you accept your invitation.'
        : lawyers === null ? 'The number of enrolled lawyers is not available right now.'
          : lawyers >= 2 ? `${lawyers} people are enrolled for your organization.`
            : 'Only you so far. Add lawyers any time: give each lawyer their own key and invitation; do not share the organization key file.' },
  ];
  return { steps, complete: steps.every(step => step.done || step.optional === true) };
}
