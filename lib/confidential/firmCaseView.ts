import { categoryLabel } from '../reportCategories';
import type { CaseScope } from '../../enclave/src/confidential/authorization';
import type { DirectoryListing, FirmRequestStatus } from './firmCase';

/** Presentation logic for the legal organization portal (/legal). Pure functions
 * over data this device already decrypted or verified; nothing here reads the
 * network, storage or logs. React renders every value as text. */

const DAY = 86_400_000;
/** Both sides are warned this long before access ends (see accessChoices.ts). */
export const ENDING_SOON = 14 * DAY;

/** `open-ended`: access lasts until the reporter revokes it (`expiresAt: null`). */
export type AccessEnd = { kind: 'open-ended' } | { kind: 'ends'; at: number; daysLeft: number; endingSoon: boolean };
export function accessEnd(expiresAt: number | null, now: number): AccessEnd {
  if (expiresAt === null) return { kind: 'open-ended' };
  const left = Math.max(0, expiresAt - now);
  return { kind: 'ends', at: expiresAt, daysLeft: Math.ceil(left / DAY), endingSoon: left <= ENDING_SOON };
}

/** When all of this organization's current access ends: the latest grant expiry,
 * or `null` when any grant lasts until the reporter revokes it. */
export function latestAccessEnd(grants: readonly { expiresAt: number | null }[]): number | null {
  if (!grants.length || grants.some(grant => grant.expiresAt === null)) return null;
  return Math.max(...grants.map(grant => grant.expiresAt as number));
}

export function formatDate(value: number): string {
  return new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
export function formatDateTime(value: number): string {
  return new Date(value).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
}

// ---------------------------------------------------------------------------
// Report document

export type DocumentField = { label: string; value: string };
export type CaseDocument = {
  /** The reporter's own account ("what happened"). */
  account: string | null;
  dates: DocumentField[];
  place: DocumentField[];
  about: DocumentField[];
  /** Fields this version of the portal does not know, shown rather than hidden. */
  other: DocumentField[];
  /** Separately granted records such as contact details. */
  records: { title: string; fields: DocumentField[] }[];
};
type Scalar = string | boolean | null;

const NARRATIVE: Record<string, { section: 'account' | 'dates' | 'place' | 'about'; label: string; format?: (value: string) => string }> = {
  description: { section: 'account', label: 'Account' },
  dateOfIncident: { section: 'dates', label: 'When it happened', format: value => calendarDate(value) },
  location: { section: 'place', label: 'Place' },
  jurisdiction: { section: 'place', label: 'Jurisdiction' },
  category: { section: 'about', label: 'Category', format: value => categoryLabel(value) || value },
  urgency: { section: 'about', label: 'Urgency', format: value => value.charAt(0).toUpperCase() + value.slice(1) },
  wantsReward: { section: 'about', label: 'Interested in a whistleblower reward' },
};
const RECORD_TITLES: Partial<Record<CaseScope, string>> = {
  contact: 'Contact details shared by the reporter',
  identity: 'Identity shared by the reporter',
  rewards: 'Reward details',
};
const RECORD_LABELS: Record<string, string> = {
  email: 'Email', signal: 'Signal', imessage: 'iMessage',
  contactMethod: 'Preferred contact method', contactValue: 'Contact',
  submitterName: 'Name', submitterContactMethod: 'Preferred contact method', submitterContactValue: 'Contact',
  submitterConsent: 'Agreed to be identified',
};

export function humanLabel(key: string): string {
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim().toLowerCase();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : 'Detail';
}
function display(value: Scalar): string | null {
  if (value === null) return null;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (value === 'true') return 'Yes';
  if (value === 'false') return 'No';
  return value.trim() ? value : null;
}
/** ISO calendar dates are shown in words without shifting across time zones;
 * anything else the reporter typed is shown as written. */
export function calendarDate(value: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim());
  if (!match) return value;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  if (date.getUTCFullYear() !== Number(match[1]) || date.getUTCMonth() !== Number(match[2]) - 1) return value;
  return date.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
}

export function caseDocument(narrative: Record<string, Scalar> | null,
  records: { scope: CaseScope; fields: Record<string, Scalar> }[]): CaseDocument {
  const result: CaseDocument = { account: null, dates: [], place: [], about: [], other: [], records: [] };
  for (const [key, raw] of Object.entries(narrative ?? {})) {
    const text = display(raw);
    if (text === null) continue;
    const known = Object.prototype.hasOwnProperty.call(NARRATIVE, key) ? NARRATIVE[key] : null;
    if (!known) { result.other.push({ label: humanLabel(key), value: text }); continue; }
    if (known.section === 'account') { result.account = text; continue; }
    const value = known.format && typeof raw === 'string' ? known.format(text) : text;
    result[known.section].push({ label: known.label, value });
  }
  for (const record of records) {
    const fields = Object.entries(record.fields).flatMap(([key, raw]) => {
      const text = display(raw);
      return text === null ? [] : [{ label: RECORD_LABELS[key] ?? humanLabel(key), value: text }];
    });
    if (fields.length) result.records.push({ title: RECORD_TITLES[record.scope] ?? humanLabel(record.scope), fields });
  }
  return result;
}

// ---------------------------------------------------------------------------
// Access, status and timeline

const SCOPE_WORDS: Record<CaseScope, string> = {
  narrative: 'the report', evidence: 'files', messages: 'messages', contact: 'contact details', identity: 'identity details',
  rewards: 'reward details',
};
export function scopeSentence(scopes: readonly CaseScope[]): string {
  const order: CaseScope[] = ['narrative', 'evidence', 'contact', 'identity', 'rewards'];
  const words = order.filter(scope => scopes.includes(scope)).map(scope => SCOPE_WORDS[scope]);
  if (words.length <= 1) return words[0] ?? 'nothing';
  return `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

export type TimelineEvent = { at: number; kind: 'requested' | 'allowed' | 'changed' | 'update-approved' |
  'message-received' | 'message-sent' | 'access-ends'; title: string; detail?: string; upcoming?: boolean };

/** Only events this organization is entitled to see: its own request (from this
 * device), its own current grants, the reporter's approval of the running
 * secure-service version, and its own message thread. Other organizations,
 * earlier report versions and private history are never inferred or shown. */
export function firmTimeline(input: {
  requestedAt: number | null; grants: { issuedAt: number; expiresAt: number | null; scopes: CaseScope[] }[];
  releaseApprovedAt: number | null; messages: { sender: 'owner' | 'organization'; sentAt: number }[]; now: number;
}): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  if (input.requestedAt !== null) {
    events.push({ at: input.requestedAt, kind: 'requested', title: 'Your organization requested access' });
  }
  const grants = [...input.grants].sort((a, b) => a.issuedAt - b.issuedAt);
  grants.forEach((grant, index) => events.push({ at: grant.issuedAt, kind: index === 0 ? 'allowed' : 'changed',
    title: index === 0 ? 'The reporter allowed access' : 'The reporter changed your access',
    detail: `Includes ${scopeSentence(grant.scopes)}.` }));
  const firstGrant = grants[0]?.issuedAt ?? null;
  if (input.releaseApprovedAt !== null && firstGrant !== null && input.releaseApprovedAt > firstGrant) {
    events.push({ at: input.releaseApprovedAt, kind: 'update-approved', title: 'The reporter approved an update to the secure service' });
  }
  for (const message of input.messages) {
    events.push(message.sender === 'owner'
      ? { at: message.sentAt, kind: 'message-received', title: 'Message from the reporter' }
      : { at: message.sentAt, kind: 'message-sent', title: 'Your organization sent a message' });
  }
  events.sort((a, b) => a.at - b.at);
  if (grants.length) {
    const end = accessEnd(latestAccessEnd(grants), input.now);
    if (end.kind === 'ends') {
      events.push({ at: end.at, kind: 'access-ends', title: 'Access ends', upcoming: true,
        detail: 'Unless the reporter renews it. Files you already downloaded stay under your organization\'s obligations.' });
    }
  }
  return events;
}

/** One status per report, derived from the service's answer and
 * whether this device has opened the report before. */
export type FirmCaseStatus =
  | { kind: 'checking' } | { kind: 'error' } | { kind: 'unconfirmed' }
  /** `renewalPending`: this organization asked to renew and the reporter has not answered yet. */
  | { kind: 'granted'; expiresAt: number | null; contactShared?: boolean; renewalPending?: boolean } | { kind: 'update-pending' }
  | { kind: 'waiting'; requestExpiresAt: number | null }
  | { kind: 'declined' } | { kind: 'expired' } | { kind: 'withdrawn' } | { kind: 'ended' } | { kind: 'unknown' } | { kind: 'not-shared' };

export function caseStatus(status: FirmRequestStatus, openedBefore: boolean, hasRequest = true): FirmCaseStatus {
  if (status.access === 'unknown') {
    // The release check failed after opening this firm's envelope. That explains
    // why access cannot be checked; it does not prove a current, unexpired grant.
    if (status.releaseApproved === false) return { kind: 'update-pending' };
    // A locked report hides current access, but the request row still answers
    // for a report this device never opened: a pending, declined, lapsed or
    // withdrawn request cannot have access behind it. Only an approved request,
    // or a report opened before (access may exist or have ended), must be
    // verified by opening the report.
    if (openedBefore) return { kind: 'unconfirmed' };
    switch (status.request) {
      case 'pending': return { kind: 'waiting', requestExpiresAt: status.requestExpiresAt };
      case 'declined': return { kind: 'declined' };
      case 'expired': return { kind: 'expired' };
      case 'withdrawn': return { kind: 'withdrawn' };
      default: return { kind: 'unconfirmed' };
    }
  }
  if (status.access === 'granted') {
    if (!status.releaseApproved) return { kind: 'update-pending' };
    return { kind: 'granted', expiresAt: status.expiresAt, contactShared: status.contactShared,
      ...(status.request === 'pending' ? { renewalPending: true } : {}) };
  }
  if (status.request === 'pending') return { kind: 'waiting', requestExpiresAt: status.requestExpiresAt };
  // The latest request was declined (for example a renewal after access ended):
  // the reporter was told the organization sees the decline, so say so rather
  // than offering to ask again.
  if (status.request === 'declined') return { kind: 'declined' };
  // Access this organization key held has ended (revoked or expired), or an
  // approved request no longer has access behind it.
  if (status.ended === 'expired' || status.ended === 'revoked' || status.request === 'approved') return { kind: 'ended' };
  if (status.request === 'withdrawn') return { kind: 'withdrawn' };
  // A lapsed or unrecorded request on a report this device opened before means
  // the access that existed has ended (revoked or expired).
  if (openedBefore) return { kind: 'ended' };
  if (status.request === 'expired') return { kind: 'expired' };
  return { kind: hasRequest ? 'unknown' : 'not-shared' };
}

/** The status to show after the service refused this organization the report
 * (`not-granted`). While the case is locked `request-status` cannot read the
 * sealed grants and answers `unknown`, but the refusal came from the enclave's
 * own grant check (open-case, or unlock-case with this organization's key), so
 * the status is read as "no access now": a report opened before, or an approved
 * request, has access that ended. Advisory text only; it grants nothing. */
export function refusedCaseStatus(status: FirmRequestStatus, openedBefore: boolean): FirmCaseStatus {
  return caseStatus(status.access === 'unknown'
    ? { access: 'none', request: status.request, requestExpiresAt: status.requestExpiresAt } : status, openedBefore);
}

export type BadgeTone = 'positive' | 'attention' | 'neutral' | 'negative';
export function statusBadge(status: FirmCaseStatus, now: number): { label: string; tone: BadgeTone; description: string } {
  switch (status.kind) {
    case 'unconfirmed': return { label: 'Access not yet checked', tone: 'neutral',
      description: 'Open the report to verify current access. The secure service has not confirmed your access yet.' };
    case 'checking': return { label: 'Checking…', tone: 'neutral', description: 'Checking your organization’s access to this report.' };
    case 'error': return { label: 'Status unavailable', tone: 'neutral',
      description: 'The status could not be checked right now. Open the report or try again later.' };
    case 'granted': {
      const contact = (status.contactShared ? ' The reporter has shared contact details with you.' : '') +
        (status.renewalPending ? ' You asked to renew; waiting for the reporter.' : '');
      const end = accessEnd(status.expiresAt, now);
      return end.kind === 'open-ended'
        ? { label: 'Access allowed', tone: 'positive', description: `Access lasts until the reporter revokes it.${contact}` }
        : { label: end.endingSoon ? 'Access ending soon' : 'Access allowed', tone: end.endingSoon ? 'attention' : 'positive',
          description: `Access ends ${formatDate(end.at)} unless the reporter renews it.${contact}` };
    }
    case 'update-pending': return { label: 'Waiting for reporter to approve update', tone: 'attention',
      description: 'The reporter needs to open their report status page with their recovery key and choose “Approve update”. Current access will be checked after they approve the update.' };
    case 'waiting': return { label: 'Waiting for reporter', tone: 'neutral', description: status.requestExpiresAt
      ? `The reporter has not decided yet. The request lapses on ${formatDate(status.requestExpiresAt)}.`
      : 'The reporter has not decided yet.' };
    case 'declined': return { label: 'Declined', tone: 'negative', description: 'The reporter declined this request.' };
    case 'expired': return { label: 'Request expired', tone: 'negative', description: 'The reporter did not answer before the request lapsed.' };
    case 'withdrawn': return { label: 'Withdrawn', tone: 'neutral', description: 'Your organization withdrew this request.' };
    case 'ended': return { label: 'Access ended', tone: 'negative', description: 'Your organization no longer has access. The reporter may have revoked it or let it expire.' };
    case 'unknown': return { label: 'Status unknown', tone: 'neutral', description: 'The service has no record of this request.' };
    case 'not-shared': return { label: 'Access not granted', tone: 'neutral', description: 'Your organization key does not currently have access to this report. You can request access.' };
  }
}
/** Statuses with an "Ask to renew" action: access has ended or ends soon. It
 * does not depend on whether this session pinned the reporter key; the key
 * comes from the request row when the lawyer asks (firmPortal ownerFromRequest). */
/** Pre-filled message when asking a reporter to allow access again after the
 * organization replaced its key. The key can be replaced with or without a
 * member being removed (a lost or copied device), so the wording must not
 * claim a reason the reporter cannot verify. */
export const RENEW_PURPOSE = 'Our organization replaced its key. Please allow our access again so we can continue working on your report.';

export function canAskToRenew(status: FirmCaseStatus | undefined, now: number): boolean {
  if (!status) return false;
  return status.kind === 'ended' ||
    (status.kind === 'granted' && !status.renewalPending && statusBadge(status, now).tone === 'attention');
}
/** Statuses with a pending request this organization can withdraw: a first
 * request, or a renewal asked for while access continues. */
export function canWithdraw(status: FirmCaseStatus | undefined): boolean {
  return status?.kind === 'waiting' || (status?.kind === 'granted' && status.renewalPending === true);
}
/** Statuses for which a new request can be sent from the directory. */
export function canRequestAgain(status: FirmCaseStatus): boolean {
  return ['declined', 'expired', 'withdrawn', 'ended', 'unknown', 'not-shared'].includes(status.kind);
}

// ---------------------------------------------------------------------------
// Directory triage

export type DirectoryShow = 'all' | 'not-requested' | 'requested';
export type DirectorySort = 'directory' | 'not-requested-first';
export type DirectoryFilter = { show: DirectoryShow };
export const EMPTY_FILTER: DirectoryFilter = { show: 'all' };

export function filterActive(filter: DirectoryFilter): boolean { return filter.show !== 'all'; }

export function triageDirectory(listings: readonly DirectoryListing[], filter: DirectoryFilter, sort: DirectorySort,
  requested: ReadonlySet<string>): DirectoryListing[] {
  const matching = listings.filter(item => filter.show === 'all' || (filter.show === 'requested') === requested.has(item.caseId));
  const indexed = matching.map((item, index) => ({ item, index }));
  const key = (entry: { item: DirectoryListing }): number => sort === 'not-requested-first' && requested.has(entry.item.caseId) ? 1 : 0;
  return indexed.sort((a, b) => key(a) - key(b) || a.index - b.index).map(entry => entry.item);
}

// ---------------------------------------------------------------------------
// Downloads

// Evidence file names are cleaned by lib/confidential/safeDownload.ts (safeDownloadName).

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
