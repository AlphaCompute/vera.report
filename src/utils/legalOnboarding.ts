/**
 * Admin onboarding of legal organizations: the shared contract between the
 * Express routes, the Next admin proxy and the admin screens.
 *
 * Everything here is roster metadata: organization names, domains, public keys,
 * identity-provider identifiers, invitations and member leases. Nothing names a
 * case, a grant, an access request or any case content, and every layer
 * re-projects replies through these functions so an addition upstream can never
 * widen what reaches an administrator's browser.
 */

export const LEGAL_ORGANIZATION_ID = /^[a-f0-9]{64}$/;
export const LEGAL_INVITATION_ID = /^[a-f0-9]{64}$/;
export const LEGAL_PROVIDER_ORGANIZATION_ID = /^org_[a-zA-Z0-9]{1,64}$/;
export const LEGAL_SUBJECT = /^[a-zA-Z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/;
export const LEGAL_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
/** Public onboarding hints only; the signed roster remains authoritative.
 * A fragment keeps these identifiers out of HTTP requests. */
export function legalSetupPath(organizationId: string, domain: string): string {
  return `/legal/enroll#${new URLSearchParams({ organization: organizationId, domain })}`;
}
export function readLegalSetup(fragment: string): { organizationId: string; domain: string } | null {
  const params = new URLSearchParams(fragment.replace(/^#/, ''));
  const organizationId = params.get('organization') ?? '', domain = params.get('domain') ?? '';
  return LEGAL_ORGANIZATION_ID.test(organizationId) && LEGAL_DOMAIN.test(domain) ? { organizationId, domain } : null;
}

export const LEGAL_AUDIT_CURSOR = /^([1-9][0-9]{0,15})_([a-f0-9]{32})$/;
export const LEGAL_AUDIT_PAGE_MAX = 100;
/** The enclave caps membership leases (= invitation lifetime) at seven days. */
export const LEGAL_INVITATION_MAX_DAYS = 7;

export const LEGAL_AUDIT_ACTION_LABELS = {
  organization_created: 'Organization added',
  organization_registered: 'Key registered by the onboarding authority',
  organization_revoked: 'Organization revoked',
  invitation_issued: 'Invitation issued',
  invitation_redeemed: 'Invitation accepted',
  invitation_revoked: 'Invitation revoked',
  member_removed: 'Member removed',
} as const;
export type LegalAuditActionName = keyof typeof LEGAL_AUDIT_ACTION_LABELS;

export type LegalOrganizationStatus = 'awaiting-registration' | 'active' | 'revoked';
export type LegalOrganizationView = {
  organizationId: string; displayName: string; domain: string; providerOrganizationId: string | null;
  status: LegalOrganizationStatus;
  /** Registered (onboarding-signed) firm key; null until registration. Public data. */
  recipientKeyId: string | null; publicKey: string | null;
  candidateBindingDocument?: string | null; candidateSubject?: string | null;
  /** Rotation statement signed by the registered key and the candidate key (key changes only). */
  candidateContinuity?: string | null;
  createdAt: number | null; createdBy: string | null; registeredAt: number | null;
  revokedAt: number | null; revokedBy: string | null;
  pendingInvitations: number; activeMembers: number;
};
export type LegalInvitationStatus = 'pending' | 'expired' | 'accepted' | 'revoked';
export type LegalInvitationView = {
  invitationId: string; subject: string; createdAt: number; createdBy: string; expiresAt: number;
  status: LegalInvitationStatus; revokedAt: number | null; revokedBy: string | null;
};
/** `key-replaced`: enrolled with a key the organization has since replaced. The
 * enclave denies the person until they accept a new invitation. */
export type LegalMemberStatus = 'active' | 'expired' | 'key-replaced' | 'removed';
export type LegalMemberView = { subject: string; status: LegalMemberStatus; accessUntil: number | null; updatedAt: number | null };
export type LegalAuditView = {
  eventId: string; at: number; action: LegalAuditActionName; organizationId: string; actor: string;
  invitationId: string | null; subject: string | null;
};
export type LegalOrganizationDetail = {
  organization: LegalOrganizationView; invitations: LegalInvitationView[]; members: LegalMemberView[];
};
export type LegalAuditPage = { events: LegalAuditView[]; next: string | null };

/** Stable error codes shared by the store, routes and screens. */
export const LEGAL_ONBOARDING_ERRORS = {
  'duplicate-provider-organization': 'Another active legal organization already uses this identity-provider organization.',
  'duplicate-domain': 'Another active legal organization already uses this domain.',
  revoked: 'This legal organization has been revoked. Add it again as a new organization if it should return.',
  'not-found': 'This record no longer exists. Refresh and try again.',
  'not-pending': 'This invitation was already accepted, revoked or replaced.',
  mismatch: 'The registration does not match the organization record.',
} as const;
export type LegalOnboardingErrorCode = keyof typeof LEGAL_ONBOARDING_ERRORS;

export class LegalOnboardingConflict extends Error {
  readonly legalOnboardingConflict = true;
  constructor(readonly code: LegalOnboardingErrorCode) { super(code); }
}
export function legalConflictCode(error: unknown): LegalOnboardingErrorCode | null {
  const value = error as { legalOnboardingConflict?: unknown; code?: unknown } | null;
  return value?.legalOnboardingConflict === true && typeof value.code === 'string' &&
    Object.prototype.hasOwnProperty.call(LEGAL_ONBOARDING_ERRORS, value.code) ? value.code as LegalOnboardingErrorCode : null;
}

export const LEGAL_TEXT_CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);
const time = (value: unknown): number | null => {
  const ms = value instanceof Date ? value.getTime() : typeof value === 'number' ? value
    : typeof value === 'string' && value ? Date.parse(value) : NaN;
  return Number.isSafeInteger(ms) && ms > 0 ? ms : null;
};
const text = (value: unknown, max: number): string | null =>
  typeof value === 'string' && value.length > 0 && value.length <= max && !LEGAL_TEXT_CONTROL.test(value) ? value : null;
const count = (value: unknown): number => Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : 0;

export type NewLegalOrganization = { displayName: string; domain: string; providerOrganizationId: string };
export type NewLegalOrganizationErrors = Partial<Record<keyof NewLegalOrganization, string>>;

/** Normalizes a pasted domain ("https://Firm.example/" -> "firm.example") only
 * where the intent is unambiguous; anything else is reported, never guessed. */
export function normalizeLegalDomain(input: string): string {
  return input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
}

export function validateNewLegalOrganization(input: unknown):
  { ok: true; value: NewLegalOrganization } | { ok: false; errors: NewLegalOrganizationErrors } {
  const body = isRecord(input) ? input : {};
  const errors: NewLegalOrganizationErrors = {};
  const displayName = typeof body.displayName === 'string' ? body.displayName.trim().replace(/\s+/g, ' ') : '';
  if (displayName.length < 2 || displayName.length > 160 || LEGAL_TEXT_CONTROL.test(displayName)) {
    errors.displayName = 'Enter the organization’s name (2 to 160 characters).';
  }
  const domain = typeof body.domain === 'string' ? normalizeLegalDomain(body.domain) : '';
  if (!LEGAL_DOMAIN.test(domain)) {
    errors.domain = 'Enter the organization’s own web domain only, for example counsel.example.';
  }
  const providerOrganizationId = typeof body.providerOrganizationId === 'string' ? body.providerOrganizationId.trim() : '';
  if (!LEGAL_PROVIDER_ORGANIZATION_ID.test(providerOrganizationId)) {
    errors.providerOrganizationId = 'Enter the identity-provider organization ID. It starts with “org_”.';
  }
  const keys = Object.keys(body).filter(key => !['displayName', 'domain', 'providerOrganizationId'].includes(key));
  if (keys.length) errors.displayName ??= 'Unexpected fields.';
  return Object.keys(errors).length ? { ok: false, errors } : { ok: true, value: { displayName, domain, providerOrganizationId } };
}

/** Actor recorded in the onboarding audit trail (the admin's verified email, set by the proxy). */
export function validActor(value: unknown): string | null {
  return text(value, 320);
}

export function invitationStatus(state: unknown, expiresAt: number, now: number): LegalInvitationStatus | null {
  if (state === 'redeemed') return 'accepted';
  if (state === 'revoked') return 'revoked';
  if (state === 'pending') return expiresAt > now ? 'pending' : 'expired';
  return null;
}

export function projectLegalOrganization(raw: unknown): LegalOrganizationView | null {
  if (!isRecord(raw)) return null;
  const organizationId = raw.organizationId ?? raw._id;
  const displayName = text(raw.displayName, 160), domain = typeof raw.domain === 'string' && LEGAL_DOMAIN.test(raw.domain) ? raw.domain : null;
  if (typeof organizationId !== 'string' || !LEGAL_ORGANIZATION_ID.test(organizationId) || !displayName || !domain) return null;
  const provider = typeof raw.providerOrganizationId === 'string' && LEGAL_PROVIDER_ORGANIZATION_ID.test(raw.providerOrganizationId)
    ? raw.providerOrganizationId : null;
  const revokedAt = time(raw.revokedAt);
  // Accepts a store row (approved/registration/revokedAt) or an already projected view (status).
  let status: LegalOrganizationStatus | null;
  if (raw.status !== undefined) {
    status = raw.status === 'awaiting-registration' || raw.status === 'active' || raw.status === 'revoked' ? raw.status : null;
  } else {
    status = revokedAt !== null ? 'revoked'
      : raw.approved === true && typeof raw.registration === 'string' && raw.registration.length > 0 ? 'active' : 'awaiting-registration';
  }
  if (!status) return null;
  const recipientKeyId = typeof raw.recipientKeyId === 'string' && LEGAL_ORGANIZATION_ID.test(raw.recipientKeyId) ? raw.recipientKeyId : null;
  const publicKey = typeof raw.publicKey === 'string' && raw.publicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') &&
    raw.publicKey.length <= 65_536 ? raw.publicKey : null;
  return {
    organizationId, displayName, domain, providerOrganizationId: provider, status,
    recipientKeyId: status === 'awaiting-registration' ? null : recipientKeyId,
    publicKey: status === 'awaiting-registration' ? null : publicKey,
    candidateBindingDocument: typeof raw.candidateBindingDocument === 'string' &&
      raw.candidateBindingDocument.length <= 65_536 && !raw.candidateBindingDocument.includes('PRIVATE KEY')
      ? raw.candidateBindingDocument : null,
    candidateSubject: typeof raw.candidateSubject === 'string' && LEGAL_SUBJECT.test(raw.candidateSubject) ? raw.candidateSubject : null,
    candidateContinuity: typeof raw.candidateContinuity === 'string' && raw.candidateContinuity.length <= 65_536 &&
      !raw.candidateContinuity.includes('PRIVATE KEY') ? raw.candidateContinuity : null,
    createdAt: time(raw.createdAt), createdBy: text(raw.createdBy, 320), registeredAt: time(raw.registeredAt),
    revokedAt, revokedBy: text(raw.revokedBy, 320),
    pendingInvitations: count(raw.pendingInvitations), activeMembers: count(raw.activeMembers),
  };
}

export function projectLegalInvitation(raw: unknown, now: number): LegalInvitationView | null {
  if (!isRecord(raw)) return null;
  const expiresAt = time(raw.expiresAt), createdAt = time(raw.createdAt);
  const subject = typeof raw.subject === 'string' && LEGAL_SUBJECT.test(raw.subject) ? raw.subject : null;
  if (typeof raw.invitationId !== 'string' || !LEGAL_INVITATION_ID.test(raw.invitationId) || !subject || !expiresAt || !createdAt) return null;
  const status = raw.status === 'pending' || raw.status === 'expired' || raw.status === 'accepted' || raw.status === 'revoked'
    ? (raw.status === 'pending' && expiresAt <= now ? 'expired' : raw.status) : invitationStatus(raw.state, expiresAt, now);
  if (!status) return null;
  return { invitationId: raw.invitationId, subject, createdAt, createdBy: text(raw.createdBy, 320) ?? 'unknown', expiresAt, status,
    revokedAt: time(raw.revokedAt), revokedBy: text(raw.revokedBy, 320) };
}

export function projectLegalMember(raw: unknown, now: number): LegalMemberView | null {
  if (!isRecord(raw) || typeof raw.subject !== 'string' || !LEGAL_SUBJECT.test(raw.subject)) return null;
  const accessUntil = time(raw.accessUntil ?? raw.leaseExpiresAt);
  const status: LegalMemberStatus = raw.status === 'removed' || raw.active === false ? 'removed'
    : raw.status === 'key-replaced' || raw.keyReplaced === true ? 'key-replaced'
    : accessUntil !== null && accessUntil > now ? 'active' : 'expired';
  return { subject: raw.subject, status, accessUntil, updatedAt: time(raw.updatedAt) };
}

export function projectLegalAuditEvent(raw: unknown): LegalAuditView | null {
  if (!isRecord(raw)) return null;
  const eventId = raw.eventId ?? raw._id, at = time(raw.at), actor = text(raw.actor, 320);
  if (typeof eventId !== 'string' || !/^[a-f0-9]{32}$/.test(eventId) || !at || !actor ||
      typeof raw.action !== 'string' || !Object.prototype.hasOwnProperty.call(LEGAL_AUDIT_ACTION_LABELS, raw.action) ||
      typeof raw.organizationId !== 'string' || !LEGAL_ORGANIZATION_ID.test(raw.organizationId)) return null;
  return { eventId, at, action: raw.action as LegalAuditActionName, organizationId: raw.organizationId, actor,
    invitationId: typeof raw.invitationId === 'string' && LEGAL_INVITATION_ID.test(raw.invitationId) ? raw.invitationId : null,
    subject: typeof raw.subject === 'string' && LEGAL_SUBJECT.test(raw.subject) ? raw.subject : null };
}

const list = <T>(value: unknown, project: (item: unknown) => T | null): T[] =>
  Array.isArray(value) ? value.flatMap(item => { const projected = project(item); return projected ? [projected] : []; }) : [];

export function projectLegalOrganizationList(data: unknown): LegalOrganizationView[] {
  return list(isRecord(data) ? data.organizations : null, projectLegalOrganization);
}
export function projectLegalOrganizationDetail(data: unknown, now: number): LegalOrganizationDetail | null {
  if (!isRecord(data)) return null;
  const organization = projectLegalOrganization(data.organization);
  if (!organization) return null;
  return { organization, invitations: list(data.invitations, item => projectLegalInvitation(item, now)),
    members: list(data.members, item => projectLegalMember(item, now)) };
}
export function auditCursor(event: { at: number; eventId: string }): string { return `${event.at}_${event.eventId}`; }
export function parseAuditCursor(value: unknown): { at: number; id: string } | null {
  const match = typeof value === 'string' ? LEGAL_AUDIT_CURSOR.exec(value) : null;
  return match && Number.isSafeInteger(Number(match[1])) ? { at: Number(match[1]), id: match[2] } : null;
}
export function projectLegalAuditPage(data: unknown): LegalAuditPage {
  const body = isRecord(data) ? data : {};
  return { events: list(body.events, projectLegalAuditEvent), next: parseAuditCursor(body.next) ? body.next as string : null };
}

/** Groups a 64-hex key ID for reading aloud when confirming it with the firm. */
export function groupKeyId(value: string): string {
  return value.replace(/(.{4})(?=.)/g, '$1 ');
}
/** A Key ID as typed by a person reading it from another channel: spaces,
 * dashes and case are ignored. Returns null unless it is a full 64-hex Key ID. */
export function normalizeKeyId(value: string): string | null {
  const compact = value.replace(/[\s-]/g, '').toLowerCase();
  return /^[a-f0-9]{64}$/.test(compact) ? compact : null;
}

/** Minimal public-roster operations used by application approval. No case access. */
export interface LegalOrganizationPreparationSource {
  createLegalOrganization(value: { organizationId: string; displayName: string; domain: string; providerOrganizationId: string },
    actor: string, now: number): Promise<void>;
  getLegalOrganizationRecord(organizationId: string): Promise<unknown | null>;
}
