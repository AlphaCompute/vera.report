import type { AccessGrant, CaseManifest, CaseScope } from '../../enclave/src/confidential/authorization';
import { MAX_GRANT_LIFETIME_MS, grantActiveAt, grantCoversObject } from '../../enclave/src/confidential/grantPolicy';
import type { AccessRequestDetails, LegalAccessRequest } from '../../enclave/src/confidential/accessRequest';
import { FEE_BASES, RESPONSE_TIMES } from '../../enclave/src/confidential/requestDetails';
import { FIRM_PRACTICE_AREAS } from '../../enclave/src/confidential/firmProfile';
import type { FirmProfile } from '../../enclave/src/confidential/firmProfile';
import type { OwnerGrantDecision } from '../../enclave/src/confidential/ownerGrant';

/** Pure decision and wording helpers for access sharing. No I/O and no
 * persistence: the pages own state; these functions only map an explicit
 * choice to a grant decision and signed facts to plain English. */

const DAY = 86_400_000;
export const DURATIONS = [
  { id: 'until-revoked', label: 'Until I revoke it', ms: null },
  { id: '30-days', label: '30 days', ms: 30 * DAY },
  { id: '90-days', label: '90 days', ms: 90 * DAY },
  { id: '1-year', label: '1 year', ms: 365 * DAY },
] as const;
export type DurationId = typeof DURATIONS[number]['id'];
/** Days before an end date when both sides are told access is about to end. */
export const EXPIRY_WARNING_DAYS = 14;

export type EvidenceEntry = { objectId: string; objectRevision: number; ordinal: number };
/** Evidence files in the signed manifest, in the order they were added. */
export function evidenceEntries(manifest: Pick<CaseManifest, 'objects'> | null): EvidenceEntry[] {
  return (manifest?.objects ?? []).filter(item => item.scope === 'evidence')
    .map((item, index) => ({ objectId: item.objectId, objectRevision: item.objectRevision, ordinal: index + 1 }));
}
/** Name for a file whose encrypted name this device has not seen. */
export function fileLabel(entry: EvidenceEntry, names?: ReadonlyMap<string, string>): string {
  const name = names?.get(entry.objectId);
  const when = entry.objectRevision === 1 ? 'sent with your report' : 'added later';
  return name ? `${name} (${when})` : `File ${entry.ordinal} (${when})`;
}

export type AccessChoice = {
  report: boolean;
  evidence: 'all' | 'some' | 'none';
  /** Object IDs of the evidence files to share when `evidence` is `some`. */
  selected: string[];
  future: boolean;
  duration: DurationId;
};

/** Starting point for the chooser: what the organization asked for, current
 * material only, lasting until revoked. For a renewal only what the organization's current access covers is
 * pre-selected; files added since then need an explicit tick. */
export function defaultChoice(request: Pick<LegalAccessRequest, 'scopes'>, evidence: EvidenceEntry[],
  current: readonly AccessGrant[] = []): AccessChoice {
  const main = current.filter(grant => grant.scopes.some(scope => scope !== 'contact' && scope !== 'identity'));
  if (main.length) {
    // Exactly the files the current access covers: files outside its revision
    // limit (added later) or excluded are not pre-selected.
    const evidenceGrants = main.filter(grant => grant.scopes.includes('evidence'));
    const selected = evidence.filter(item => evidenceGrants.some(grant => grantCoversObject(grant,
      { objectId: item.objectId, scope: 'evidence', objectRevision: item.objectRevision }))).map(item => item.objectId);
    return { report: main.some(grant => grant.scopes.includes('narrative')) && request.scopes.includes('narrative'),
      evidence: !evidenceGrants.length || !request.scopes.includes('evidence') || !selected.length ? 'none'
        : selected.length === evidence.length ? 'all' : 'some',
      selected, future: request.scopes.includes('evidence') &&
        main.some(grant => grant.scopes.includes('evidence') && grant.objectRevisionLimit === null),
      duration: 'until-revoked' };
  }
  // Current material only by default; files added later need an explicit choice.
  return { report: request.scopes.includes('narrative'),
    evidence: request.scopes.includes('evidence') && evidence.length ? 'all' : 'none',
    selected: evidence.map(item => item.objectId), future: false, duration: 'until-revoked' };
}

/** "Change what they can read" for an organization that already has access:
 * report and evidence can be added or removed. Contact and identity are never part of it. */
export function changeParts(_grants: readonly AccessGrant[]): RequestedParts {
  return { report: true, evidence: true, messages: false };
}
const CHANGE_SCOPES: CaseScope[] = ['narrative', 'evidence'];

/** Chooser start for a change: exactly what the organization can read now. */
export function changeChoice(grants: readonly AccessGrant[], evidence: EvidenceEntry[]): AccessChoice {
  return defaultChoice({ scopes: CHANGE_SCOPES }, evidence, grants);
}

/** The end of an organization's current report access (`null` = until revoked). */
export function currentAccessEnd(grants: readonly AccessGrant[]): number | null {
  const main = grants.filter(grant => !isContactOnly(grant));
  if (!main.length || main.some(grant => grant.expiresAt === null)) return null;
  return Math.max(...main.map(grant => grant.expiresAt as number));
}

/** Explicit change -> a replacement grant decision for an organization that
 * already has access. The end date is kept (renewing changes it); a fresh grant
 * ID keeps the replacement distinct from the grant it replaces. */
export function changeDecisionFromChoice(choice: AccessChoice, grants: readonly AccessGrant[], evidence: EvidenceEntry[],
  currentRevision: number, now: number, grantId: string = randomGrantId()): OwnerGrantDecision {
  const expiresAt = currentAccessEnd(grants);
  if (expiresAt !== null && expiresAt <= now) throw new AccessChoiceError('This access has ended. Renew it first, then change what they can read.');
  const decision = decisionFromChoice({ ...choice, duration: 'until-revoked' },
    { requestId: grantId, scopes: CHANGE_SCOPES, objectRevisionLimit: null }, evidence, currentRevision, now);
  return { ...decision, expiresAt };
}
function randomGrantId(): string {
  return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
}

/** Which parts of the case a request asked for (contact/identity never count). */
export type RequestedParts = { report: boolean; evidence: boolean; messages: boolean };
export function requestedParts(scopes: readonly CaseScope[]): RequestedParts {
  return { report: scopes.includes('narrative'), evidence: scopes.includes('evidence'), messages: false };
}

/** One sentence restating the chooser before the reporter presses Allow. */
export function choiceSummary(choice: AccessChoice, asks: RequestedParts, evidence: readonly EvidenceEntry[], name: string): string {
  const parts: string[] = [];
  if (choice.report && asks.report) parts.push('your report');
  if (asks.evidence && choice.evidence !== 'none') {
    const count = choice.evidence === 'all' ? evidence.length : evidence.filter(entry => choice.selected.includes(entry.objectId)).length;
    parts.push(choice.evidence === 'all' ? (evidence.length ? 'all your evidence files' : 'evidence files')
      : `${count} evidence file${count === 1 ? '' : 's'}`);
    if (choice.future) parts.push('files you add later');
  } else if (asks.evidence && !evidence.length && choice.future) parts.push('files you add later');
  if (!parts.length) return 'Nothing is selected yet.';
  const duration = DURATIONS.find(entry => entry.id === choice.duration);
  const until = !duration || duration.ms === null ? 'until you revoke access' : `for ${duration.label}`;
  return `${name} will be able to read ${parts.join(', ')}, ${until}.`;
}

export class AccessChoiceError extends Error {}

/** Explicit chooser state -> signed grant decision. Contact and identity are
 * never part of this decision; they have their own action. Legacy messaging scopes are not renewed. */
export function decisionFromChoice(choice: AccessChoice, request: Pick<LegalAccessRequest, 'requestId' | 'scopes' | 'objectRevisionLimit'>,
  evidence: EvidenceEntry[], currentRevision: number, now: number): OwnerGrantDecision {
  const scopes: CaseScope[] = [];
  if (choice.report && request.scopes.includes('narrative')) scopes.push('narrative');
  // With no files yet, "share files I add later" alone shares evidence.
  const sharesEvidence = request.scopes.includes('evidence') &&
    (choice.evidence !== 'none' || (!evidence.length && choice.future));
  if (sharesEvidence) scopes.push('evidence');
  if (!scopes.length) throw new AccessChoiceError('Choose your report, some evidence, or both.');
  let excludedObjectIds: string[] | undefined;
  if (sharesEvidence && choice.evidence === 'some') {
    const selected = new Set(choice.selected);
    if (!evidence.some(item => selected.has(item.objectId))) throw new AccessChoiceError('Choose at least one file, or choose "No files".');
    const excluded = evidence.filter(item => !selected.has(item.objectId)).map(item => item.objectId).sort();
    if (excluded.length) excludedObjectIds = excluded;
  }
  const future = sharesEvidence && choice.future;
  const limit = future ? request.objectRevisionLimit
    : Math.min(currentRevision, request.objectRevisionLimit ?? Number.MAX_SAFE_INTEGER);
  const duration = DURATIONS.find(item => item.id === choice.duration);
  if (!duration) throw new AccessChoiceError('Choose how long access lasts.');
  return { grantId: request.requestId, scopes, objectRevisionLimit: limit,
    expiresAt: duration.ms === null ? null : now + Math.min(duration.ms, MAX_GRANT_LIFETIME_MS),
    ...(excludedObjectIds ? { excludedObjectIds } : {}) };
}

export function expiresAtFor(duration: DurationId, now: number): number | null {
  const found = DURATIONS.find(item => item.id === duration);
  if (!found) throw new AccessChoiceError('Choose how long access lasts.');
  return found.ms === null ? null : now + found.ms;
}

const date = (value: number) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
export function formatDate(value: number): string { return date(value); }

export type ExpiryState = { state: 'open-ended' } | { state: 'active'; endsAt: number; daysLeft: number }
  | { state: 'ending-soon'; endsAt: number; daysLeft: number } | { state: 'ended'; endsAt: number };
export function expiryState(expiresAt: number | null, now: number): ExpiryState {
  if (expiresAt === null) return { state: 'open-ended' };
  if (expiresAt <= now) return { state: 'ended', endsAt: expiresAt };
  const daysLeft = Math.ceil((expiresAt - now) / DAY);
  return { state: daysLeft <= EXPIRY_WARNING_DAYS ? 'ending-soon' : 'active', endsAt: expiresAt, daysLeft };
}
export function expiryText(expiresAt: number | null, now: number): string {
  const value = expiryState(expiresAt, now);
  if (value.state === 'open-ended') return 'Until you revoke it';
  if (value.state === 'ended') return `Ended on ${date(value.endsAt)}`;
  return `Until ${date(value.endsAt)} (${value.daysLeft} day${value.daysLeft === 1 ? '' : 's'} left)`;
}

export function isContactOnly(grant: Pick<AccessGrant, 'scopes'>): boolean {
  return grant.scopes.every(scope => scope === 'contact' || scope === 'identity');
}

/** How many current evidence files one organization's active access does not cover. */
export function unsharedFiles(grants: readonly AccessGrant[], evidence: readonly EvidenceEntry[], now: number): number {
  const covering = grants.filter(grant => !isContactOnly(grant) && grant.scopes.includes('evidence') && grantActiveAt(grant, now));
  return evidence.filter(entry => !covering.some(grant => !(grant.excludedObjectIds ?? []).includes(entry.objectId) &&
    (grant.objectRevisionLimit === null || entry.objectRevision <= grant.objectRevisionLimit))).length;
}

/** Plain-English list of what one organization's current grants share. */
export function describeAccess(grants: readonly AccessGrant[], evidence: EvidenceEntry[], now: number): {
  items: string[]; expiresAt: number | null; active: boolean; contactShared: boolean;
} {
  const main = grants.filter(grant => !isContactOnly(grant));
  const items: string[] = [];
  if (main.some(grant => grant.scopes.includes('narrative'))) items.push('Your report');
  const evidenceGrants = main.filter(grant => grant.scopes.includes('evidence'));
  if (evidenceGrants.length) {
    const covered = evidence.filter(entry => evidenceGrants.some(grant => !(grant.excludedObjectIds ?? []).includes(entry.objectId) &&
      (grant.objectRevisionLimit === null || entry.objectRevision <= grant.objectRevisionLimit)));
    const future = evidenceGrants.some(grant => grant.objectRevisionLimit === null);
    const count = covered.length === evidence.length ? (evidence.length === 1 ? 'Your evidence file' : `All ${evidence.length} evidence files`)
      : `${covered.length} of ${evidence.length} evidence files`;
    items.push(evidence.length ? `${count}${future ? ', and files you add later' : ''}` : future ? 'Files you add later' : 'No evidence files');
  }
  const contactShared = grants.some(grant => isContactOnly(grant) && grantActiveAt(grant, now));
  if (contactShared) items.push('Your contact details');
  const relevant = main.length ? main : grants;
  const expiresAt = relevant.some(grant => grant.expiresAt === null) ? null
    : relevant.length ? Math.max(...relevant.map(grant => grant.expiresAt as number)) : null;
  return { items, expiresAt, active: relevant.some(grant => grantActiveAt(grant, now)), contactShared };
}

export const FEE_LABELS: Record<AccessRequestDetails['feeBasis'], string> = {
  'no-fee': 'No fee (pro bono)', contingency: 'Contingency (paid only if the case succeeds)', hourly: 'Hourly',
  fixed: 'Fixed fee', 'to-discuss': 'To discuss with you',
};
export const RESPONSE_LABELS: Record<AccessRequestDetails['responseTime'], string> = {
  'two-days': 'Within 2 days', 'one-week': 'Within a week', 'two-weeks': 'Within 2 weeks', 'one-month': 'Within a month',
};
/** Show an organization's website only when it is on the domain that confirmed
 * its key; any other link could send the reporter somewhere else. */
export function trustedWebsite(website: string | null | undefined, domain: string): string | null {
  if (!website) return null;
  try {
    const url = new URL(website);
    return url.protocol === 'https:' && (url.hostname === domain || url.hostname.endsWith(`.${domain}`)) ? url.href : null;
  } catch { return null; }
}

/** The organization profile carried inside a signed request. It is copied from
 * the profile the organization signed with its approved key (coded practice areas,
 * shown by label), never typed into the request, so the reporter cannot be shown
 * two profiles that disagree. Empty when no signed profile was read. */
export function requestProfileFields(profile: FirmProfile | null):
  Pick<AccessRequestDetails, 'practiceAreas' | 'jurisdiction' | 'website'> {
  if (!profile) return { practiceAreas: [], jurisdiction: '', website: null };
  return { practiceAreas: profile.practiceAreas.map(area => FIRM_PRACTICE_AREAS[area]),
    jurisdiction: profile.jurisdiction, website: profile.website };
}

/** Client-side checks with plain messages; the signed request is validated again
 * by the protocol code before anything is encrypted. */
export function validateRequestForm(input: { purpose: string; conflicts: 'yes' | 'no' | ''; feeBasis: string; responseTime: string },
  profile: FirmProfile | null): { errors: Record<string, string>; details?: AccessRequestDetails } {
  const errors: Record<string, string> = {};
  const purpose = input.purpose.trim();
  if (!purpose) errors.purpose = 'Write a short message to the reporter.';
  else if (purpose.length > 1000) errors.purpose = 'Keep the message under 1,000 characters.';
  if (input.conflicts !== 'yes' && input.conflicts !== 'no') errors.conflicts = 'Say whether you have checked for conflicts of interest.';
  if (!(FEE_BASES as readonly string[]).includes(input.feeBasis)) errors.feeBasis = 'Choose how fees would work.';
  if (!(RESPONSE_TIMES as readonly string[]).includes(input.responseTime)) errors.responseTime = 'Choose when the reporter can expect a reply.';
  if (Object.keys(errors).length) return { errors };
  return { errors, details: { kind: 'new', conflictsChecked: input.conflicts === 'yes',
    feeBasis: input.feeBasis as AccessRequestDetails['feeBasis'], responseTime: input.responseTime as AccessRequestDetails['responseTime'],
    ...requestProfileFields(profile) } };
}

