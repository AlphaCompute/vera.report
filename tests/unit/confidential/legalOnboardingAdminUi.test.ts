import { webcrypto } from 'node:crypto';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import * as firmKeyBinding from '../../../enclave/src/confidential/firmKeyBinding';
import {
  DOMAIN_CHECK_MESSAGES, INVITATION_UNCONFIRMED, canRemoveMember, copyInvitationLink, checkLegalDomain, invitationPlan, needsRenewal, onboardingNote, onboardingSteps,
} from '../../../lib/legalOnboardingClient';
import type { DomainCheck } from '../../../lib/legalOnboardingClient';
import {
  groupKeyId, projectLegalAuditPage, projectLegalOrganization, projectLegalOrganizationDetail, validateNewLegalOrganization,
} from '../../../src/utils/legalOnboarding';
import type { LegalOrganizationDetail, LegalOrganizationView } from '../../../src/utils/legalOnboarding';
import { CreateOrganizationForm, LegalOrganizationsView } from '../../../components/vera/admin/LegalOrganizationsView';
import { SendDetails } from '../../../components/vera/admin/LegalOrganizationDetail';
import { FailureNotice, OrganizationStatusBadge } from '../../../components/vera/admin/LegalOnboardingParts';
import LegalAdministration from '../../../pages/legal/administration';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const ORG = hex(0xa1);
const organization = (overrides: Partial<LegalOrganizationView> = {}): LegalOrganizationView => ({
  organizationId: ORG, displayName: 'Harbor Counsel LLP', domain: 'harbor.example', providerOrganizationId: 'org_harbor',
  status: 'awaiting-registration', recipientKeyId: null, publicKey: null, createdAt: 1, createdBy: 'admin@example.org',
  registeredAt: null, revokedAt: null, revokedBy: null, pendingInvitations: 0, activeMembers: 0, ...overrides });

let firm: PrivateKey, other: PrivateKey, firmKeyId: string, binding: string;
beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [firm, other] = await Promise.all(['firm', 'other'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  firmKeyId = await caseRecipientKeyId(firm.toPublic());
  binding = await createFirmKeyBinding({ domain: 'harbor.example', organizationId: ORG, issuedAt: 1_800_000_000_000 }, firm);
}, 60_000);

describe('new organization validation', () => {
  it('normalizes a pasted URL and whitespace, and names each bad field', () => {
    expect(validateNewLegalOrganization({ displayName: ' Harbor  Counsel ', domain: 'https://Harbor.Example/', providerOrganizationId: ' org_harbor ' }))
      .toEqual({ ok: true, value: { displayName: 'Harbor Counsel', domain: 'harbor.example', providerOrganizationId: 'org_harbor' } });
    const bad = validateNewLegalOrganization({ displayName: 'H', domain: 'harbor.example/path', providerOrganizationId: 'harbor' });
    expect(bad.ok).toBe(false);
    expect(Object.keys((bad as { errors: object }).errors).sort()).toEqual(['displayName', 'domain', 'providerOrganizationId']);
    expect(validateNewLegalOrganization({ displayName: 'Harbor\u0000', domain: 'harbor.example', providerOrganizationId: 'org_x' }).ok).toBe(false);
    expect(validateNewLegalOrganization({ displayName: 'Harbor', domain: 'harbor.example', providerOrganizationId: 'org_x', organizationId: ORG }).ok).toBe(false);
  });
});

describe('projections', () => {
  it('never carry registration, claims or unknown fields to the browser', () => {
    const projected = projectLegalOrganization({ _id: ORG, displayName: 'Harbor', domain: 'harbor.example', approved: true,
      registration: 'SIGNED', recipientKeyId: hex(2), publicKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----x', providerClaim: 'org_harbor',
      caseIds: ['CASE'] });
    expect(projected).toMatchObject({ status: 'active', recipientKeyId: hex(2) });
    expect(JSON.stringify(projected)).not.toMatch(/SIGNED|providerClaim|CASE/);
    expect(projectLegalOrganization({ _id: ORG, displayName: 'Harbor', domain: 'harbor.example', publicKey: '-----BEGIN PGP PRIVATE KEY BLOCK-----' }))
      .toMatchObject({ status: 'awaiting-registration', publicKey: null });
    expect(projectLegalOrganization({ organizationId: ORG, displayName: 'Harbor', domain: 'harbor.example', status: 'owner' })).toBeNull();
    expect(projectLegalOrganizationDetail({ organization: { organizationId: 'x' } }, 0)).toBeNull();
    expect(projectLegalAuditPage({ events: [{ eventId: 'e'.repeat(32), at: 5, action: 'grant_created', organizationId: ORG, actor: 'a' }],
      next: 'nonsense' })).toEqual({ events: [], next: null });
  });
  it('groups key IDs for reading aloud', () => {
    expect(groupKeyId('abcd1234ef')).toBe('abcd 1234 ef');
  });
});

describe('submitted organization key check', () => {
  const reply = (candidate: string | null, changes: Partial<LegalOrganizationView> = {}) => jest.fn(async () => new Response(JSON.stringify({
    organization: organization({ candidateBindingDocument: candidate, candidateSubject: 'auth0|lawyer', ...changes }), invitations: [], members: [],
  }))) as unknown as typeof fetch;
  it('checks a signed candidate through the admin API without visiting the firm website', async () => {
    const fetcher = reply(binding);
    const checked = await checkLegalDomain(organization(), fetcher);
    expect(checked).toMatchObject({ kind: 'verified', recipientKeyId: firmKeyId, bindingDocument: binding, matchesRegistered: null });
    // The submitter's user ID is host data: it never reaches the invitation form.
    expect(checked).not.toHaveProperty('subject');
    expect(fetcher).toHaveBeenCalledWith(`/api/admin/confidential/legal/organizations/${ORG}`,
      expect.objectContaining({ credentials: 'same-origin', referrerPolicy: 'no-referrer' }));
    expect(await checkLegalDomain(organization({ recipientKeyId: firmKeyId }), reply(binding))).toMatchObject({ matchesRegistered: true });
    expect(await checkLegalDomain(organization({ recipientKeyId: hex(9) }), reply(binding))).toMatchObject({ matchesRegistered: false });
  });
  it('rejects absent, tampered, cross-organization and revoked candidates', async () => {
    expect(await checkLegalDomain(organization(), reply(null))).toEqual({ kind: 'not-found' });
    expect(await checkLegalDomain(organization(), reply(binding.replace('harbor.example', 'other.example')))).toMatchObject({ kind: 'bad-signature' });
    expect(await checkLegalDomain(organization(), reply(binding, { organizationId: hex(9) }))).toMatchObject({ kind: 'other-organization' });
    expect(await checkLegalDomain(organization(), reply(binding, { status: 'revoked' }))).toMatchObject({ kind: 'not-found' });
  });
  it('a replacement for a registered key needs continuity signed by the registered key', async () => {
    const { rotateOrganizationKey } = await import('../../../enclave/src/confidential/firmMembers');
    const rotated = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: 1_800_000_000_000 }, firm);
    const next = await createFirmKeyBinding({ domain: 'harbor.example', organizationId: ORG, issuedAt: 1_800_000_000_000 }, rotated.organizationKey);
    const planted = await createFirmKeyBinding({ domain: 'harbor.example', organizationId: ORG, issuedAt: 1_800_000_000_000 }, other);
    const active = organization({ status: 'active', recipientKeyId: firmKeyId, publicKey: firm.toPublic().armor() });
    // A key planted in VERA's database (no continuity) is refused.
    expect(await checkLegalDomain(active, reply(planted, active))).toEqual({ kind: 'no-continuity' });
    // Continuity from another key does not verify against the registered one.
    const forged = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: 1_800_000_000_000 }, other);
    const forgedNext = await createFirmKeyBinding({ domain: 'harbor.example', organizationId: ORG, issuedAt: 1_800_000_000_000 }, forged.organizationKey);
    expect(await checkLegalDomain(active, reply(forgedNext, { ...active, candidateContinuity: forged.continuity })))
      .toEqual({ kind: 'no-continuity' });
    expect(await checkLegalDomain(active, reply(planted, { ...active, candidateContinuity: rotated.continuity })))
      .toEqual({ kind: 'no-continuity' });
    expect(await checkLegalDomain(active, reply(next, { ...active, candidateContinuity: rotated.continuity }))).toMatchObject({
      kind: 'verified', recipientKeyId: rotated.statement.nextRecipientKeyId, continuity: rotated.continuity, matchesRegistered: false });
  });
  it('reuses an approved key without a pending candidate', async () => {
    const current = organization({ status: 'active', recipientKeyId: firmKeyId, publicKey: firm.toPublic().armor() });
    expect(await checkLegalDomain(current, reply(null, current))).toMatchObject({ kind: 'verified', matchesRegistered: true });
  });
  it('bounds a nonresponsive API request', async () => {
    jest.useFakeTimers();
    try {
      const pending = checkLegalDomain(organization(), (() => new Promise(() => {})) as typeof fetch);
      await jest.advanceTimersByTimeAsync(10_000);
      expect(await pending).toEqual({ kind: 'unreachable' });
    } finally { jest.useRealTimers(); }
  });
});

describe('invitation plan', () => {
  it('a checkbox alone, stale readback, or a different key cannot approve a candidate', () => {
    for (const status of ['awaiting-registration', 'active'] as const) {
      const input = { organization: organization({ status, recipientKeyId: status === 'active' ? firmKeyId : null }),
        check: verified(firmKeyId), keyConfirmed: true, replaceKey: false };
      expect(invitationPlan(input).ready).toBe(false);
      expect(invitationPlan({ ...input, readbackKeyId: hex(123) }).ready).toBe(false);
      expect(invitationPlan({ ...input, readbackKeyId: firmKeyId, keyConfirmed: false }).ready).toBe(false);
      expect(invitationPlan({ ...input, readbackKeyId: groupKeyId(firmKeyId).toUpperCase() }).ready).toBe(true);
    }
  });
  const verified = (recipientKeyId: string): DomainCheck => ({ kind: 'verified', organizationId: ORG, domain: 'harbor.example', recipientKeyId, issuedAt: 1, publicKey: 'k', bindingDocument: binding, matchesRegistered: null });
  it('never treats a delayed check for another selected organization as authority', () => {
    expect(invitationPlan({ organization: organization({ organizationId: hex(2) }), check: verified(firmKeyId),
      keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: true }).ready).toBe(false);
    expect(invitationPlan({ organization: organization({ domain: 'other.example' }), check: verified(firmKeyId),
      keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: true }).ready).toBe(false);
  });
  it('first registration needs a verified key and a confirmed Key ID', () => {
    expect(invitationPlan({ organization: null, check: null, keyConfirmed: false, replaceKey: false })).toMatchObject({ ready: false });
    expect(invitationPlan({ organization: organization(), check: null, keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: false }))
      .toEqual({ ready: false, reason: 'Check the organization’s submitted key first.' });
    expect(invitationPlan({ organization: organization(), check: { kind: 'not-found' }, keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: false }).ready).toBe(false);
    expect(invitationPlan({ organization: organization(), check: verified(firmKeyId), keyConfirmed: false, replaceKey: false }).ready).toBe(false);
    // Approval needs the Key ID the organization read out over another channel.
    expect(invitationPlan({ organization: organization(), check: verified(firmKeyId), keyConfirmed: true, replaceKey: false }).ready).toBe(false);
    expect(invitationPlan({ organization: organization(), check: verified(firmKeyId), keyConfirmed: true, readbackKeyId: hex(5), replaceKey: false }).ready).toBe(false);
    expect(invitationPlan({ organization: organization(), check: verified(firmKeyId), keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: false }))
      .toEqual({ ready: true, recipientKeyId: firmKeyId, register: true });
  });
  it('a registered key still needs independent readback; replacement is explicit', () => {
    const active = organization({ status: 'active', recipientKeyId: firmKeyId });
    expect(invitationPlan({ organization: active, check: verified(firmKeyId), keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: false }))
      .toEqual({ ready: true, recipientKeyId: firmKeyId, register: false });
    expect(invitationPlan({ organization: active, check: verified(hex(7)), keyConfirmed: true, readbackKeyId: hex(7), replaceKey: false }).ready).toBe(false);
    expect(invitationPlan({ organization: active, check: verified(hex(7)), keyConfirmed: false, replaceKey: true }).ready).toBe(false);
    // Without the organization's continuity statement a replacement is never ready.
    expect(invitationPlan({ organization: active, check: verified(hex(7)), keyConfirmed: true, replaceKey: true,
      readbackKeyId: hex(7) }).ready).toBe(false);
    const continued = { ...verified(hex(7)), continuity: '{}' } as DomainCheck;
    expect(invitationPlan({ organization: active, check: continued, keyConfirmed: true, replaceKey: true }).ready).toBe(false);
    expect(invitationPlan({ organization: active, check: continued, keyConfirmed: true, replaceKey: true, readbackKeyId: hex(7) }))
      .toEqual({ ready: true, recipientKeyId: hex(7), register: true });
    expect(invitationPlan({ organization: organization({ status: 'revoked' }), check: verified(firmKeyId), keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: false }).ready).toBe(false);
    expect(invitationPlan({ organization: organization({ providerOrganizationId: null }), check: verified(firmKeyId), keyConfirmed: true, readbackKeyId: firmKeyId, replaceKey: false }).ready).toBe(false);
  });
});

describe('onboarding checklist and renewal', () => {
  const detail = (overrides: Partial<LegalOrganizationDetail> = {}): LegalOrganizationDetail =>
    ({ organization: organization(), invitations: [], members: [], ...overrides });
  it('ticks steps from roster data and the latest domain check', () => {
    expect(onboardingSteps(detail(), null).map(step => step.state)).toEqual(['done', 'todo', 'todo', 'todo', 'todo']);
    expect(onboardingSteps(detail(), { kind: 'not-found' })[1]).toMatchObject({ state: 'problem' });
    const active = detail({ organization: organization({ status: 'active', recipientKeyId: firmKeyId, activeMembers: 1 }),
      invitations: [{ invitationId: hex(1), subject: 'auth0|a', createdAt: 1, createdBy: 'x', expiresAt: 2, status: 'accepted', revokedAt: null, revokedBy: null }],
      members: [{ subject: 'auth0|a', status: 'active', accessUntil: 5, updatedAt: 1 }] });
    expect(onboardingSteps(active, { kind: 'verified', organizationId: ORG, domain: 'harbor.example', recipientKeyId: firmKeyId, issuedAt: 1, publicKey: 'k', matchesRegistered: true })
      .map(step => step.state)).toEqual(['done', 'done', 'done', 'done', 'done']);
    expect(onboardingSteps(active, { kind: 'verified', organizationId: ORG, domain: 'harbor.example', recipientKeyId: hex(3), issuedAt: 1, publicKey: 'k', matchesRegistered: false })[1].state).toBe('problem');
  });
  it('flags access that ends within two days', () => {
    const now = 1_000_000_000_000;
    expect(needsRenewal(now + 60_000, now)).toBe(true);
    expect(needsRenewal(now + 3 * 86_400_000, now)).toBe(false);
    expect(needsRenewal(now - 1, now)).toBe(false);
    expect(needsRenewal(null, now)).toBe(false);
  });
  it('the note for the organization carries only non-secret onboarding details', () => {
    const note = onboardingNote(organization(), 'https://vera.example');
    expect(note).toContain(ORG);
    expect(note).toContain('https://vera.example/legal/enroll');
    expect(note).toContain('Submit your organization profile');
    expect(note).not.toContain('/.well-known/');
    expect(note).not.toMatch(/invitation=|token|password/i);
  });
});

describe('rendered admin screens', () => {
  it('create form labels every field with its hint', () => {
    const html = renderToStaticMarkup(React.createElement(CreateOrganizationForm, { onCreated: () => {}, onCancel: () => {} }));
    for (const label of ['Organization name', 'Organization’s own web domain', 'Identity-provider organization ID']) expect(html).toContain(label);
    expect(html).toContain('for="legal-domain"');
    expect(html).toContain('aria-describedby="legal-domain-hint"');
    expect(html).toContain('Add organization');
  });
  it('tab opens on the roster with explanatory copy and a loading state', () => {
    const html = renderToStaticMarkup(React.createElement(LegalOrganizationsView));
    expect(html).toContain('Legal organizations');
    expect(html).toContain('Nothing here gives access to any report');
    expect(html).toContain('role="status"');
  });
  it('status, failure and send-details pieces', () => {
    expect(renderToStaticMarkup(React.createElement(OrganizationStatusBadge, { status: 'awaiting-registration' }))).toContain('Waiting for key');
    const signedOut = renderToStaticMarkup(React.createElement(FailureNotice, { failure: { kind: 'signed-out' }, onRetry: () => {} }));
    expect(signedOut).toContain('role="alert"');
    expect(signedOut).toContain('Sign in again');
    expect(signedOut).not.toContain('Try again');
    const conflict = renderToStaticMarkup(React.createElement(FailureNotice, { failure: { kind: 'conflict', code: 'duplicate-domain' } }));
    expect(conflict).toContain('already uses this domain');
    const send = renderToStaticMarkup(React.createElement(SendDetails, { organization: organization() }));
    expect(send).toContain('Copy organization ID');
    expect(send).toContain('not a secret');
  });
  it('invitation page runs nothing and explains itself when this build has no confidential cases', () => {
    const html = renderToStaticMarkup(React.createElement(LegalAdministration));
    expect(html).toContain('Legal onboarding');
    expect(html).toContain('The legal portal is not available on this site.');
    expect(html).not.toContain('Loading legal organizations');
  });
});

describe('invitation result handling', () => {
  it('reports clipboard failure without promising erasure', async () => {
    const writeText = jest.fn().mockRejectedValue(new Error('denied'));
    expect(await copyInvitationLink('private-link', { writeText })).toMatch(/Copy failed/);
    expect(writeText).toHaveBeenCalledTimes(1);
  });
  it('copies once and leaves later clipboard management with the administrator', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    expect(await copyInvitationLink('private-link', { writeText })).toMatch(/clipboard history/);
    expect(writeText.mock.calls).toEqual([['private-link']]);
    expect(INVITATION_UNCONFIRMED).toMatch(/could not be confirmed/);
    expect(INVITATION_UNCONFIRMED).toMatch(/revoke it/);
    expect(INVITATION_UNCONFIRMED).not.toMatch(/Nothing was issued/);
  });
});

describe('member removal', () => {
  test('Remove is offered for a person whose access ended, not only active ones', () => {
    expect(canRemoveMember('active')).toBe(true);
    expect(canRemoveMember('key-replaced')).toBe(true);
    expect(canRemoveMember('expired')).toBe(true);
    expect(canRemoveMember('removed')).toBe(false);
  });
});
