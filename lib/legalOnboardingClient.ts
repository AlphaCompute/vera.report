import {
  legalSetupPath, LEGAL_ONBOARDING_ERRORS, projectLegalAuditPage, projectLegalOrganization, projectLegalOrganizationDetail,
  projectLegalOrganizationList,
} from '@/src/utils/legalOnboarding';
import type {
  LegalAuditPage, LegalOnboardingErrorCode, LegalOrganizationDetail, LegalOrganizationView, NewLegalOrganization,
  NewLegalOrganizationErrors,
} from '@/src/utils/legalOnboarding';

/** Browser side of the admin legal-organization screens. Every reply is
 * re-projected, and identifiers travel only in same-origin admin API paths. */
export type LegalAdminFailure =
  | { kind: 'signed-out' } | { kind: 'forbidden' } | { kind: 'not-enabled' } | { kind: 'busy' }
  | { kind: 'invalid'; fields: NewLegalOrganizationErrors } | { kind: 'conflict'; code: LegalOnboardingErrorCode }
  | { kind: 'unavailable' };
export class LegalAdminError extends Error {
  constructor(readonly failure: LegalAdminFailure) { super(failure.kind); }
}

export function legalAdminMessage(failure: LegalAdminFailure): string {
  switch (failure.kind) {
    case 'signed-out': return 'Your VERA admin session has ended. Sign in again to continue.';
    case 'forbidden': return 'Only VERA administrators can manage legal organizations.';
    case 'not-enabled': return 'Encrypted reports are not enabled on this deployment, so legal organizations cannot be managed here.';
    case 'busy': return 'Too many requests. Wait a moment and try again.';
    case 'invalid': return Object.values(failure.fields)[0] ?? 'Check the highlighted fields.';
    case 'conflict': return LEGAL_ONBOARDING_ERRORS[failure.code];
    default: return 'The result could not be confirmed. Refresh the organization and audit trail before retrying a change.';
  }
}

const BASE = '/api/admin/confidential/legal';

async function call(path: string, init?: { method: 'POST'; body: Record<string, unknown> }): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(`${BASE}/${path}`, { cache: 'no-store', credentials: 'same-origin', referrerPolicy: 'no-referrer',
      ...(init ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(init.body) } : {}) });
  } catch { throw new LegalAdminError({ kind: 'unavailable' }); }
  const data = await response.json().catch(() => null) as { error?: unknown; fields?: unknown } | null;
  if (response.ok) return data;
  if (response.status === 401) throw new LegalAdminError({ kind: 'signed-out' });
  if (response.status === 403) throw new LegalAdminError({ kind: 'forbidden' });
  if (response.status === 429) throw new LegalAdminError({ kind: 'busy' });
  if (response.status === 404 && data?.error === 'not-enabled') throw new LegalAdminError({ kind: 'not-enabled' });
  if (response.status === 400) {
    const fields = data?.fields && typeof data.fields === 'object' ? data.fields as NewLegalOrganizationErrors : {};
    throw new LegalAdminError({ kind: 'invalid', fields: Object.keys(fields).length ? fields : { displayName: 'The request was not accepted. Check the details and try again.' } });
  }
  if ((response.status === 404 || response.status === 409) && typeof data?.error === 'string' &&
      Object.prototype.hasOwnProperty.call(LEGAL_ONBOARDING_ERRORS, data.error)) {
    throw new LegalAdminError({ kind: 'conflict', code: data.error as LegalOnboardingErrorCode });
  }
  throw new LegalAdminError({ kind: 'unavailable' });
}

export async function listLegalOrganizations(): Promise<LegalOrganizationView[]> {
  return projectLegalOrganizationList(await call('organizations'));
}
export async function createLegalOrganization(input: NewLegalOrganization): Promise<LegalOrganizationView> {
  const data = await call('organizations', { method: 'POST', body: { ...input } }) as { organization?: unknown } | null;
  const organization = projectLegalOrganization(data?.organization);
  if (!organization) throw new LegalAdminError({ kind: 'unavailable' });
  return organization;
}
export async function getLegalOrganization(organizationId: string): Promise<LegalOrganizationDetail> {
  const detail = projectLegalOrganizationDetail(await call(`organizations/${encodeURIComponent(organizationId)}`), Date.now());
  if (!detail) throw new LegalAdminError({ kind: 'unavailable' });
  return detail;
}
export async function revokeLegalOrganization(organizationId: string): Promise<{ invitationsRevoked: number; membersRemoved: number }> {
  const data = await call(`organizations/${encodeURIComponent(organizationId)}/revoke`, { method: 'POST', body: {} }) as Record<string, unknown> | null;
  return { invitationsRevoked: Number(data?.invitationsRevoked) || 0, membersRemoved: Number(data?.membersRemoved) || 0 };
}
export async function removeLegalMember(organizationId: string, subject: string): Promise<void> {
  await call(`organizations/${encodeURIComponent(organizationId)}/members/remove`, { method: 'POST', body: { subject } });
}
export async function revokeLegalInvitation(invitationId: string): Promise<void> {
  await call(`invitations/${encodeURIComponent(invitationId)}/revoke`, { method: 'POST', body: {} });
}
export async function listLegalAudit(input: { organizationId?: string; before?: string | null; limit?: number } = {}): Promise<LegalAuditPage> {
  const query = new URLSearchParams();
  if (input.organizationId) query.set('organizationId', input.organizationId);
  if (input.before) query.set('before', input.before);
  query.set('limit', String(input.limit ?? 25));
  return projectLegalAuditPage(await call(`audit?${query}`));
}

/** Public key candidate submitted by an authenticated member of the approved organization.
 * Platform approval binds this key to the domain; no website publishing is required. */
export type DomainCheck =
  | { kind: 'verified'; organizationId: string; domain: string; recipientKeyId: string; issuedAt: number; publicKey: string;
      /** Replacement of a registered key: the rotation statement, verified here
       * against the registered key. The enclave checks it again. */
      bindingDocument?: string; continuity?: string; matchesRegistered: boolean | null }
  | { kind: 'unreachable' | 'not-found' | 'malformed' | 'other-organization' | 'bad-signature' | 'no-continuity'; status?: number };
export const DOMAIN_CHECK_MESSAGES: Record<Exclude<DomainCheck['kind'], 'verified'>, string> = {
  unreachable: 'The organization key could not be loaded. Try again.',
  'not-found': 'The organization has not submitted its public key yet.',
  malformed: 'The submitted public key is invalid. Ask the organization to submit it again.',
  'other-organization': 'The submitted key belongs to a different organization or domain.',
  'bad-signature': 'The submitted key failed its signature check. Do not approve it.',
  'no-continuity': 'A replacement key was submitted without a valid statement signed by the registered organization key. Do not approve it. Only the holder of the current organization key can replace it.',
};

export async function checkLegalDomain(organization: Pick<LegalOrganizationView, 'organizationId' | 'domain' | 'recipientKeyId'>,
  fetcher?: typeof fetch): Promise<DomainCheck> {
  // Bound the entire check, including stream cleanup, loading the verifier and
  // cryptography. Aborting fetch alone does not settle those later promises.
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<DomainCheck>(resolve => {
    timer = setTimeout(() => {
      resolve({ kind: 'unreachable' });
      controller.abort();
    }, 10_000);
  });
  try {
    // The losing verification promise cannot publish a late success to callers.
    return await Promise.race([verifyLegalDomain(organization, fetcher ?? fetch, controller.signal), deadline]);
  } finally { clearTimeout(timer); }
}

async function verifyLegalDomain(organization: Pick<LegalOrganizationView, 'organizationId' | 'domain' | 'recipientKeyId'>,
  fetcher: typeof fetch, signal: AbortSignal): Promise<DomainCheck> {
  let response: Response;
  try {
    response = await fetcher(`${BASE}/organizations/${encodeURIComponent(organization.organizationId)}`, { cache: 'no-store', credentials: 'same-origin', redirect: 'error',
      referrerPolicy: 'no-referrer', signal });
  } catch { return { kind: 'unreachable' }; }
  if (response.redirected || (response.status >= 300 && response.status < 400)) return { kind: 'unreachable' };
  if (response.status === 404 || response.status === 410) return { kind: 'not-found', status: response.status };
  if (!response.ok) return { kind: 'unreachable', status: response.status };
  let document: string;
  const reader = response.body?.getReader();
  if (!reader) return { kind: 'malformed' };
  try {
    const chunks: Uint8Array[] = [];
    let length = 0;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.byteLength;
      if (length > 64 * 1024) return { kind: 'malformed' };
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    document = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch { return { kind: 'unreachable' }; }
  finally { await reader.cancel().catch(() => {}); }
  let submitted: LegalOrganizationDetail;
  try {
    const detail = projectLegalOrganizationDetail(JSON.parse(document), Date.now());
    if (!detail) return { kind: 'malformed' };
    submitted = detail;
  } catch { return { kind: 'malformed' }; }
  const row = submitted.organization;
  if (row.organizationId !== organization.organizationId || row.domain !== organization.domain) return { kind: 'other-organization' };
  if (row.status === 'revoked') return { kind: 'not-found' };
  if (!row.candidateBindingDocument) {
    if (row.status !== 'active' || !row.publicKey || !row.recipientKeyId) return { kind: 'not-found' };
    return { kind: 'verified', organizationId: row.organizationId, domain: row.domain,
      recipientKeyId: row.recipientKeyId, publicKey: row.publicKey, issuedAt: row.registeredAt ?? 0,
      matchesRegistered: organization.recipientKeyId === row.recipientKeyId };
  }
  document = row.candidateBindingDocument;
  try {
    signal.throwIfAborted();
    const { verifyFirmKeyBinding } = await import('@/enclave/src/confidential/firmKeyBinding');
    signal.throwIfAborted();
    const verified = await verifyFirmKeyBinding(document, { domain: organization.domain, organizationId: organization.organizationId });
    signal.throwIfAborted();
    // A registered organization's key may be replaced only by the holder of the
    // registered key: require its continuity statement. The submitter's user ID
    // is never used here, so a planted candidate cannot prefill the invitation.
    let continuity: string | undefined;
    if (row.status === 'active' && row.recipientKeyId && row.recipientKeyId !== verified.binding.recipientKeyId) {
      if (!row.candidateContinuity || !row.publicKey) return { kind: 'no-continuity' };
      try {
        const [{ verifyOrganizationKeyContinuity }, { readKey }] = await Promise.all([
          import('@/enclave/src/confidential/firmMembers'), import('@/enclave/src/confidential/pgp')]);
        const proof = await verifyOrganizationKeyContinuity(row.candidateContinuity, { organizationId: organization.organizationId,
          previousPublicKey: await readKey({ armoredKey: row.publicKey }) });
        if (proof.statement.previousRecipientKeyId !== row.recipientKeyId ||
            proof.statement.nextRecipientKeyId !== verified.binding.recipientKeyId) return { kind: 'no-continuity' };
      } catch { return { kind: 'no-continuity' }; }
      continuity = row.candidateContinuity;
    }
    signal.throwIfAborted();
    return { kind: 'verified', organizationId: organization.organizationId, domain: organization.domain, recipientKeyId: verified.binding.recipientKeyId, issuedAt: verified.binding.issuedAt,
      publicKey: verified.publicKey.armor(), bindingDocument: document, ...(continuity ? { continuity } : {}),
      matchesRegistered: organization.recipientKeyId ? organization.recipientKeyId === verified.binding.recipientKeyId : null };
  } catch { return { kind: 'bad-signature' }; }
}

/** Hand-off from the admin screens to the invitation page (same tab). Holds only
 * roster identifiers, never a key, code or token, and is read once. */
const SELECTION_KEY = 'vera-legal-invitation-selection';
export type InvitationSelection = { organizationId: string };
export function rememberInvitationSelection(selection: InvitationSelection): void {
  try { window.sessionStorage.setItem(SELECTION_KEY, JSON.stringify(selection)); } catch { /* selection can be made again */ }
}
export function readInvitationSelection(): InvitationSelection | null {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(SELECTION_KEY) ?? 'null');
    if (!value || typeof value.organizationId !== 'string' || !/^[a-f0-9]{64}$/.test(value.organizationId)) return null;
    return { organizationId: value.organizationId };
  } catch { return null; }
}
export function clearInvitationSelection(): void {
  try { window.sessionStorage.removeItem(SELECTION_KEY); } catch { /* nothing stored */ }
}

/** Plain-text onboarding note for the organization. Contains no secret. */
export function onboardingNote(organization: Pick<LegalOrganizationView, 'displayName' | 'organizationId' | 'domain'>, origin: string): string {
  return [
    `VERA legal organization onboarding: ${organization.displayName}`,
    '',
    `Organization ID: ${organization.organizationId}`,
    `Domain: ${organization.domain}`,
    '',
    'Next steps for your key holder:',
    `1. Open ${origin}${legalSetupPath(organization.organizationId, organization.domain)} to create your organization key. The approved details are already filled in.`,
    '2. Save the encrypted key file and its recovery code separately. VERA cannot recover them.',
    '3. Submit your organization profile. Only the public key is sent to VERA for approval.',
    '4. Open the Finish setup link from VERA with your key still open; access activates automatically. Then add colleagues with verified email addresses at your approved domain.',
  ].join('\n');
}

export const ORGANIZATION_STATUS_LABELS = {
  'awaiting-registration': 'Waiting for key', active: 'Active', revoked: 'Revoked',
} as const;
export const INVITATION_STATUS_LABELS = { pending: 'Pending', expired: 'Expired', accepted: 'Accepted', revoked: 'Revoked' } as const;
export const MEMBER_STATUS_LABELS = { active: 'Active', expired: 'Access ended',
  'key-replaced': 'Needs a new invitation (key replaced)', removed: 'Removed' } as const;
/** Remove is offered for every person not already removed, including one whose
 * access has ended: removal also sets the cutoff and withdraws pending renewals,
 * which an admin offboarding someone after a lapse still needs. */
export function canRemoveMember(status: keyof typeof MEMBER_STATUS_LABELS): boolean {
  return status !== 'removed';
}

export type OnboardingStep = { id: string; label: string; state: 'done' | 'todo' | 'problem'; detail: string };
/** The organization's onboarding checklist, derived only from roster data and the
 * latest domain check in this browser. */
export function onboardingSteps(detail: LegalOrganizationDetail, check: DomainCheck | null): OnboardingStep[] {
  const { organization, invitations, members } = detail;
  const keyState: OnboardingStep['state'] = !check ? 'todo'
    : check.kind === 'verified' && check.matchesRegistered !== false ? 'done' : 'problem';
  const keyDetail = !check ? 'Not checked from this browser yet.'
    : check.kind === 'verified' ? (check.matchesRegistered === false ? 'The organization has submitted a replacement key.'
      : 'The submitted key has a valid signature.')
    : 'Not verified yet. See the key check below.';
  const invited = invitations.length > 0;
  const accepted = members.length > 0 || invitations.some(item => item.status === 'accepted');
  return [
    { id: 'created', label: 'Organization added', state: 'done', detail: 'Organization ID sent to the organization.' },
    { id: 'key', label: 'Organization key submitted', state: keyState, detail: keyDetail },
    { id: 'registered', label: 'Key registered', state: organization.status === 'active' || (organization.status === 'revoked' && organization.registeredAt) ? 'done' : 'todo',
      detail: organization.status === 'awaiting-registration' ? 'Happens when the first invitation is issued.' : 'Signed by the onboarding authority.' },
    { id: 'invited', label: 'First person invited', state: invited ? 'done' : 'todo',
      detail: invited ? `${invitations.length} invitation${invitations.length === 1 ? '' : 's'} issued.` : 'No invitation issued yet.' },
    { id: 'accepted', label: 'Invitation accepted', state: accepted ? 'done' : 'todo',
      detail: accepted ? `${organization.activeMembers} with current access.` : 'Waiting for the invited person to accept.' },
  ];
}

/** Invitations must be issued before this many days pass on a member's access,
 * so the admin screens can show "renew soon". */
export const RENEWAL_WINDOW_MS = 2 * 24 * 60 * 60 * 1000;
export function needsRenewal(accessUntil: number | null, now: number): boolean {
  return accessUntil !== null && accessUntil > now && accessUntil - now <= RENEWAL_WINDOW_MS;
}
export function formatAdminTime(value: number | null): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return new Date(value).toISOString(); }
}

export type InvitationPlan = { ready: true; recipientKeyId: string; register: boolean } | { ready: false; reason: string };
/** Every invitation needs the Key ID independently read back by the organization.
 * A candidate self-signature and an admin checkbox alone do not establish identity.
 * Key replacement additionally needs explicit selection by the operator. */
export function invitationPlan(input: { organization: LegalOrganizationView | null; check: DomainCheck | null;
  keyConfirmed: boolean; readbackKeyId?: string; replaceKey: boolean }): InvitationPlan {
  const { organization, check } = input;
  if (!organization) return { ready: false, reason: 'Choose a legal organization.' };
  if (organization.status === 'revoked') return { ready: false, reason: 'This legal organization is revoked.' };
  if (!organization.providerOrganizationId) return { ready: false, reason: 'This organization has no identity-provider organization ID. Add it again with one.' };
  if (!check) return { ready: false, reason: 'Check the organization’s submitted key first.' };
  if (check.kind !== 'verified') return { ready: false, reason: DOMAIN_CHECK_MESSAGES[check.kind] };
  if (check.organizationId !== organization.organizationId || check.domain !== organization.domain) {
    return { ready: false, reason: 'Check the selected organization’s submitted key first.' };
  }
  const readback = (input.readbackKeyId ?? '').replace(/\s/g, '').toLowerCase();
  if (!input.keyConfirmed || !/^[a-f0-9]{64}$/.test(readback) || readback !== check.recipientKeyId) {
    return { ready: false, reason: 'Independently confirm the organization’s Key ID by phone or in person.' };
  }
  // Compare against the organization as it is now (it may have been registered since the check ran).
  if (organization.status === 'active' && organization.recipientKeyId === check.recipientKeyId) {
    return { ready: true, recipientKeyId: organization.recipientKeyId, register: false };
  }
  if (organization.status === 'active' && !input.replaceKey) {
    return { ready: false, reason: 'The submitted key differs from the registered key.' };
  }
  if (!check.bindingDocument) return { ready: false, reason: 'The organization must submit its public key before registration.' };
  if (organization.status === 'active' && !check.continuity) return { ready: false, reason: DOMAIN_CHECK_MESSAGES['no-continuity'] };
  return { ready: true, recipientKeyId: check.recipientKeyId, register: true };
}

export const INVITATION_UNCONFIRMED = 'Invitation issuance could not be confirmed. Check the organization’s invitations and audit trail before retrying. If an invitation was created but its link was lost, revoke it and issue a new one.';

/** Do not promise clipboard erasure: browsers can reject it, and delayed writes
 * could overwrite unrelated data the administrator copied afterward. */
export async function copyInvitationLink(link: string, clipboard: Pick<Clipboard, 'writeText'>): Promise<string> {
  try {
    await clipboard.writeText(link);
    return 'Link copied. Send it privately, then clear your clipboard and clipboard history.';
  } catch { return 'Copy failed. Select the link and copy it instead.'; }
}
