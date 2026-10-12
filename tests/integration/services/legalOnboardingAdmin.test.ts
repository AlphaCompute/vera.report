/**
 * Admin onboarding of legal organizations, end to end at the service layer:
 * the admin roster record in MongoDB, the enclave's real invitation issuance and
 * redemption (real JWTs, onboarding-authority and firm-key signatures), and the
 * admin revocation paths. Only the identity provider is synthetic.
 */
import { randomBytes, webcrypto } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import * as jose from 'jose';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { signOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';
import { signMembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';
import { signEnrollmentChallenge } from '../../../enclave/src/confidential/enrollmentProof';
import { rotateOrganizationKey } from '../../../enclave/src/confidential/firmMembers';
import { LEGAL_ASSURANCE_CLAIM } from '../../../enclave/src/legal/identity';
import { createLegalEnrollmentRedeemer, createLegalEnrollmentService } from '../../../enclave/src/legal/enrollment';
import type { EnrollmentStore } from '../../../enclave/src/legal/enrollment';
import { LegalProvisioningError } from '../../../src/utils/legalApplications';
import type { ApplicationOrganizations } from '../../../src/services/legalApplicationOrganizations';
import { auditCursor, projectLegalAuditEvent, projectLegalInvitation, projectLegalMember, projectLegalOrganization } from '../../../src/utils/legalOnboarding';

const ISSUER = 'https://identity.example/';
const ADMIN = 'admin@example.org';
const DAY = 24 * 60 * 60 * 1000;

describe('legal organization onboarding (admin roster + enclave issuance)', () => {
  let server: MongoMemoryReplSet, client: MongoClient, store: MongoConfidentialCaseStore;
  let issuer: Awaited<ReturnType<typeof jose.generateKeyPair>>, jwks: jose.JSONWebKeySet;
  let onboarding: PrivateKey, firm: PrivateKey, otherFirm: PrivateKey;
  let service: ReturnType<typeof createLegalEnrollmentService>;
  const organizationId = randomBytes(32).toString('hex');
  let associateToken = '';
  const policy = (kind: 'admin' | 'legal') => ({ issuer: ISSUER, audience: `https://api.example/${kind}`, clientId: `${kind}-client`, jwks });
  const token = (kind: 'admin' | 'legal', sub = kind === 'admin' ? 'auth0|operator' : 'auth0|lawyer') => {
    const iat = Math.floor(Date.now() / 1000) - 1;
    return new jose.SignJWT({ iss: ISSUER, aud: policy(kind).audience, azp: policy(kind).clientId, sub,
      org_id: kind === 'admin' ? 'org_admin' : 'org_harbor', scope: kind === 'admin' ? 'legal:invite' : 'legal:enroll',
      iat, exp: iat + 300, [LEGAL_ASSURANCE_CLAIM]: kind === 'admin' ? 'mfa-verified-email' : 'approved-member-verified-email' })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key' }).sign(issuer.privateKey);
  };
  async function issue(subject: string, options: { key?: PrivateKey; register?: { domain: string; key: PrivateKey; displayName?: string; continuity?: string } } = {}) {
    const now = Date.now(), lifetimeMs = 3 * DAY, key = options.register?.key ?? options.key ?? firm;
    const recipientKeyId = await caseRecipientKeyId(key.toPublic());
    const authorization = await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId,
      providerOrganizationId: 'org_harbor', recipientKeyId, subject, issuedAt: now, expiresAt: now + lifetimeMs }, onboarding);
    let registration;
    if (options.register) {
      const displayName = options.register.displayName ?? 'Harbor Counsel LLP';
      registration = { domain: options.register.domain, displayName,
        bindingDocument: await createFirmKeyBinding({ domain: options.register.domain, organizationId, issuedAt: now }, key),
        authorization: await signOrganizationRegistration({ format: 'vera-organization-registration/v1', organizationId,
          providerOrganizationId: 'org_harbor', recipientKeyId, publicKey: key.toPublic().armor(), displayName,
          domain: options.register.domain, approved: true, issuedAt: now }, onboarding),
        ...(options.register.continuity ? { continuity: options.register.continuity } : {}) };
    }
    return service.issueInvitation(await token('admin'), organizationId, subject, lifetimeMs, authorization, registration);
  }
  async function redeem(invitationToken: string, subject = 'auth0|lawyer', key: PrivateKey = firm) {
    const access = await token('legal', subject);
    const challenge = await service.getChallenge(invitationToken, access);
    return service.redeemInvitation(invitationToken, access, await signEnrollmentChallenge(challenge, key));
  }
  const invitationsOf = async () => (await store.listLegalInvitationRecords(organizationId))
    .map(item => projectLegalInvitation(item, Date.now())!);

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    server = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(server.getUri());
    store = await MongoConfidentialCaseStore.fromDatabase(client.db('test_legal_onboarding'), client);
    issuer = await jose.generateKeyPair('RS256');
    jwks = { keys: [{ ...await jose.exportJWK(issuer.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer-key' }] };
    [onboarding, firm, otherFirm] = await Promise.all(['onboarding', 'firm', 'other'].map(async name =>
      (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
    service = createLegalEnrollmentService({ adminIdentity: policy('admin'), legalIdentity: policy('legal'), adminOrganizationId: 'org_admin',
      onboardingPublicKey: onboarding.toPublic().armor(), store: store as unknown as EnrollmentStore, clock: () => Date.now() });
  }, 120_000);
  afterAll(async () => { await client?.close(); await server?.stop(); });

  test('first-time setup and candidate authorization use the real projected store', async () => {
    const id = randomBytes(32).toString('hex'), now = Date.now();
    await store.createLegalOrganization({ organizationId: id, displayName: 'New Firm', domain: 'new.example',
      providerOrganizationId: 'org_harbor' }, ADMIN, now);
    const projected = { getOrganization: store.getOrganization.bind(store),
      getLegalOrganizationRecord: store.getLegalOrganizationKeySetup.bind(store),
      submitLegalOrganizationKeyCandidate: store.submitLegalOrganizationKeyCandidate.bind(store) } as EnrollmentStore;
    const redeemer = createLegalEnrollmentRedeemer({ legalIdentity: policy('legal'),
      onboardingPublicKey: onboarding.toPublic().armor(), store: projected, clock: Date.now });
    expect(await store.getLegalOrganizationKeySetup(id)).toMatchObject({ approved: false });
    await expect(redeemer.getOrganizationKey(await token('legal'), id, 'new.example')).resolves.toMatchObject({ state: 'awaiting-key' });
    const bindingDocument = await createFirmKeyBinding({ domain: 'new.example', organizationId: id, issuedAt: now }, firm);
    await expect(redeemer.submitOrganizationKey(await token('legal'), id, bindingDocument)).resolves.toMatchObject({ submitted: true });
    const recipientKeyId = await caseRecipientKeyId(firm.toPublic());
    const registration = await signOrganizationRegistration({ format: 'vera-organization-registration/v1', organizationId: id,
      providerOrganizationId: 'org_harbor', recipientKeyId, publicKey: firm.toPublic().armor(), displayName: 'New Firm',
      domain: 'new.example', approved: true, issuedAt: now }, onboarding);
    await store.upsertLegalOrganization({ organizationId: id, displayName: 'New Firm', domain: 'new.example',
      providerOrganizationId: 'org_harbor', approved: true, recipientKeyId, publicKey: firm.toPublic().armor(), registration, bindingDocument }, now);
    const planted = await createFirmKeyBinding({ domain: 'new.example', organizationId: id, issuedAt: now }, otherFirm);
    await expect(redeemer.submitOrganizationKey(await token('legal', 'auth0|unenrolled'), id, planted)).rejects.toThrow();
    expect((await store.getLegalOrganizationRecord(id))?.candidateBindingDocument).toBeUndefined();
    // A current-key self-signature still permits a profile refresh.
    await expect(redeemer.submitOrganizationKey(await token('legal'), id, bindingDocument)).resolves.toMatchObject({ submitted: true });
    await client.db('test_legal_onboarding').collection('confidential_legal_organizations').deleteOne({ _id: id } as never);
  });

  test('submitted public key candidates never activate or replace the registered key', async () => {
    const id = randomBytes(32).toString('hex'), now = Date.now();
    await store.createLegalOrganization({ organizationId: id, displayName: 'Candidate Firm', domain: 'candidate.example',
      providerOrganizationId: 'org_candidate' }, ADMIN, now);
    const bindingDocument = await createFirmKeyBinding({ domain: 'candidate.example', organizationId: id, issuedAt: now }, firm);
    const candidate = { organizationId: id, domain: 'candidate.example', providerOrganizationId: 'org_candidate',
      bindingDocument, subject: 'auth0|candidate', recipientKeyId: await caseRecipientKeyId(firm.toPublic()) };
    await store.submitLegalOrganizationKeyCandidate(candidate, now);
    expect(projectLegalOrganization(await store.getLegalOrganizationRecord(id))).toMatchObject({
      status: 'awaiting-registration', publicKey: null, recipientKeyId: null,
      candidateBindingDocument: bindingDocument, candidateSubject: 'auth0|candidate' });
    expect(await store.getOrganization(id)).toBeNull();
    await expect(store.submitLegalOrganizationKeyCandidate({ ...candidate, providerOrganizationId: 'org_other' }, now))
      .rejects.toMatchObject({ code: 'mismatch' });
    await store.upsertLegalOrganization({ organizationId: id, displayName: 'Candidate Firm', domain: candidate.domain,
      providerOrganizationId: candidate.providerOrganizationId, approved: true, publicKey: firm.toPublic().armor(),
      recipientKeyId: candidate.recipientKeyId, registration: 'synthetic-signed-registration', bindingDocument }, now);
    expect((await store.getLegalOrganizationRecord(id))?.candidateBindingDocument).toBeUndefined();
    const otherBinding = await createFirmKeyBinding({ domain: candidate.domain, organizationId: id, issuedAt: now }, otherFirm);
    const replacement = { ...candidate, bindingDocument: otherBinding, subject: 'auth0|colleague',
      recipientKeyId: await caseRecipientKeyId(otherFirm.toPublic()) };
    // Once registered, a colleague without the organization key cannot plant a
    // replacement candidate: only a change naming the registered key (whose
    // continuity the enclave verified) is stored.
    await expect(store.submitLegalOrganizationKeyCandidate(replacement, now)).rejects.toMatchObject({ code: 'mismatch' });
    expect((await store.getLegalOrganizationRecord(id))?.candidateBindingDocument).toBeUndefined();
    await expect(store.submitLegalOrganizationKeyCandidate({ ...replacement, previousRecipientKeyId: 'f'.repeat(64),
      continuity: '{"synthetic":"continuity"}' }, now)).rejects.toMatchObject({ code: 'mismatch' });
    await store.submitLegalOrganizationKeyCandidate({ ...replacement, previousRecipientKeyId: candidate.recipientKeyId,
      continuity: '{"synthetic":"continuity"}' }, now);
    expect(await store.getLegalOrganizationRecord(id)).toMatchObject({ candidateBindingDocument: otherBinding,
      candidateContinuity: '{"synthetic":"continuity"}' });
    // A first-time submission can no longer target the registered organization.
    await expect(store.submitLegalOrganizationKeyCandidate({ ...candidate, recipientKeyId: replacement.recipientKeyId }, now))
      .rejects.toMatchObject({ code: 'mismatch' });
    expect(await store.getOrganization(id)).toMatchObject({ publicKey: firm.toPublic().armor(),
      recipientKeyId: candidate.recipientKeyId, registration: 'synthetic-signed-registration' });
    const updatedProfile = await createFirmKeyBinding({ domain: candidate.domain, organizationId: id, issuedAt: now + 1 }, firm);
    await store.submitLegalOrganizationKeyCandidate({ ...candidate, bindingDocument: updatedProfile }, now + 1);
    expect(await store.getOrganization(id)).toMatchObject({ bindingDocument: updatedProfile,
      publicKey: firm.toPublic().armor(), recipientKeyId: candidate.recipientKeyId, registration: 'synthetic-signed-registration' });
    // Updating the active key's profile must preserve a different pending rotation.
    expect((await store.getLegalOrganizationRecord(id))?.candidateBindingDocument).toBe(otherBinding);
    // This organization was manually onboarded: no application record is needed.
    const invite = jest.fn(async () => {});
    store.configureLegalMemberInvitations({ organization: async () => candidate.providerOrganizationId, invite: async () => {}, inviteMember: invite });
    const invitation = { organizationId: id, providerOrganizationId: candidate.providerOrganizationId,
      domain: candidate.domain, email: 'colleague@candidate.example' };
    await expect(store.inviteLegalOrganizationMember(invitation, now)).resolves.toEqual({ invited: true });
    expect(invite).toHaveBeenCalledWith({ email: invitation.email, domain: candidate.domain, providerOrganizationId: candidate.providerOrganizationId }, expect.any(AbortSignal));
    await expect(store.inviteLegalOrganizationMember({ ...invitation, email: 'outsider@other.example' }, now)).rejects.toThrow();
    await expect(store.inviteLegalOrganizationMember({ ...invitation, providerOrganizationId: 'org_other' }, now)).rejects.toThrow();
    expect(invite).toHaveBeenCalledTimes(1);
    await expect(store.inviteLegalOrganizationMember(invitation, now)).resolves.toEqual({ invited: true });
    expect(invite).toHaveBeenCalledTimes(1);
    let releaseInvite!: () => void, enteredInvite!: () => void;
    const invitationEntered = new Promise<void>(resolve => { enteredInvite = resolve; });
    const invitationGate = new Promise<void>(resolve => { releaseInvite = resolve; });
    invite.mockImplementationOnce(async () => { enteredInvite(); await invitationGate; });
    const concurrent = { ...invitation, email: 'parallel@candidate.example' };
    const firstInvite = store.inviteLegalOrganizationMember(concurrent, now);
    await invitationEntered;
    try { await expect(store.inviteLegalOrganizationMember(concurrent, now)).rejects.toThrow('already pending'); }
    finally { releaseInvite(); }
    await expect(firstInvite).resolves.toEqual({ invited: true });
    const burst = await Promise.allSettled(Array.from({ length: 21 }, (_, index) =>
      store.inviteLegalOrganizationMember({ ...invitation, email: `burst${index}@candidate.example` }, now)));
    expect(burst.filter(result => result.status === 'fulfilled')).toHaveLength(18);
    expect(burst.filter(result => result.status === 'rejected')).toHaveLength(3);
    expect(invite).toHaveBeenCalledTimes(20);
    // A provider timeout may have sent mail. Keep its reservation before retrying.
    invite.mockRejectedValueOnce(new Error('synthetic ambiguous timeout'));
    const uncertain = { ...invitation, email: 'uncertain@candidate.example' };
    await expect(store.inviteLegalOrganizationMember(uncertain, now + 3_600_001)).rejects.toThrow('ambiguous timeout');
    await expect(store.inviteLegalOrganizationMember(uncertain, now + 3_600_002)).rejects.toThrow('already pending');
    expect(invite).toHaveBeenCalledTimes(21);

    const memberId = randomBytes(32).toString('hex'), deviceFingerprint = 'd'.repeat(40);
    const device = { organizationId: id, memberId, providerOrganizationId: candidate.providerOrganizationId,
      subject: 'auth0|colleague', devicePublicKey: firm.toPublic().armor(), deviceFingerprint, profile: 'encrypted-profile',
      state: 'approved' as const, envelope: 'encrypted-key', keyEpoch: 1, continuity: null, revision: 1,
      registeredAt: now, updatedAt: now };
    expect(await store.putFirmDevice(device, 0)).toBe(true);
    const enrollment = { challenge: { format: 'vera-legal-enrollment/v1' as const, invitationId: randomBytes(32).toString('hex'),
      organizationId: id, providerOrganizationId: candidate.providerOrganizationId, subject: device.subject,
      recipientKeyId: candidate.recipientKeyId, nonce: randomBytes(32).toString('hex'), expiresAt: now + DAY },
      authorization: 'firm-signed-membership', proof: 'firm-enrollment-proof',
      delegation: { memberId, deviceFingerprint, deviceProof: 'device-possession-proof' } };
    const lease = { organizationId: id, subject: device.subject, providerOrganizationId: candidate.providerOrganizationId,
      recipientKeyId: candidate.recipientKeyId, enrollment };
    expect(await store.putFirmDeviceMembership(lease, now)).toBe(true);
    expect(await store.getMember(device.subject, candidate.providerOrganizationId)).toMatchObject({ active: true, enrollment });
    expect(await store.removeFirmDevice({ ...device, state: 'removed', envelope: null, continuity: null, revision: 2, updatedAt: now + 1 }, 1)).toBe(true);
    expect(await store.putFirmDeviceMembership(lease, now + 2)).toBe(false);
    expect(await store.getMember(device.subject, candidate.providerOrganizationId)).toMatchObject({ active: false });
    store.configureLegalMemberInvitations(null);
    await client.db('test_legal_onboarding').collection('confidential_legal_organizations').deleteOne({ _id: id } as never);
  }, 60_000);

  test('an admin-created record is unusable until the onboarding authority registers the submitted public key', async () => {
    await store.createLegalOrganization({ organizationId, displayName: 'Harbor Counsel LLP', domain: 'harbor.example',
      providerOrganizationId: 'org_harbor' }, ADMIN, Date.now());
    const other = randomBytes(32).toString('hex');
    await expect(store.createLegalOrganization({ organizationId: other, displayName: 'Copy', domain: 'harbor.example',
      providerOrganizationId: 'org_other' }, ADMIN, Date.now())).rejects.toMatchObject({ code: 'duplicate-domain' });
    await expect(store.createLegalOrganization({ organizationId: other, displayName: 'Copy', domain: 'copy.example',
      providerOrganizationId: 'org_harbor' }, ADMIN, Date.now())).rejects.toMatchObject({ code: 'duplicate-provider-organization' });

    expect(await store.getOrganization(organizationId)).toBeNull();
    expect(await store.listLegalOrganizations()).toEqual([]);
    expect(projectLegalOrganization(await store.getLegalOrganizationRecord(organizationId))).toMatchObject({
      status: 'awaiting-registration', createdBy: ADMIN, recipientKeyId: null, publicKey: null });
    // Without a registration the enclave refuses to invite anyone.
    await expect(issue('auth0|lawyer')).rejects.toThrow();
    // A registration for another domain than the admin record is refused by the store.
    await expect(issue('auth0|lawyer', { register: { domain: 'elsewhere.example', key: firm } })).rejects.toThrow();
    expect((await store.getLegalOrganizationRecord(organizationId))?.approved).toBe(false);
  }, 60_000);

  test('first invitation registers the key; the person redeems it; admin views never expose tokens or proofs', async () => {
    const issued = await issue('auth0|lawyer', { register: { domain: 'harbor.example', key: firm } });
    const record = projectLegalOrganization(await store.getLegalOrganizationRecord(organizationId))!;
    expect(record).toMatchObject({ status: 'active', recipientKeyId: await caseRecipientKeyId(firm.toPublic()) });
    expect(record.registeredAt).not.toBeNull();
    expect(await store.listLegalOrganizations()).toHaveLength(1);

    const raw = await store.listLegalInvitationRecords(organizationId);
    expect(Object.keys(raw[0]).sort()).toEqual(['createdAt', 'createdBy', 'expiresAt', 'invitationId', 'organizationId', 'state', 'subject']);
    expect(JSON.stringify(raw)).not.toContain(issued.token);
    expect(await invitationsOf()).toEqual([expect.objectContaining({ invitationId: issued.invitationId, subject: 'auth0|lawyer',
      status: 'pending', createdBy: 'auth0|operator' })]);
    expect(await store.countLegalOnboarding(Date.now())).toEqual({ [organizationId]: { pendingInvitations: 1, activeMembers: 0 } });

    await expect(redeem(issued.token)).resolves.toMatchObject({ organizationId, subject: 'auth0|lawyer' });
    await expect(redeem(issued.token)).rejects.toThrow();
    const members = await store.listLegalMemberRecords(organizationId);
    expect(JSON.stringify(members)).not.toMatch(/proof|authorization|BEGIN PGP/);
    expect(members.map(item => projectLegalMember(item, Date.now()))).toEqual([
      { subject: 'auth0|lawyer', status: 'active', accessUntil: issued.expiresAt, updatedAt: expect.any(Number) }]);
    expect((await invitationsOf())[0].status).toBe('accepted');

    // Later invitations reuse the registered key and do not re-register it.
    associateToken = (await issue('auth0|associate')).token;
    const events = (await store.listLegalAudit({ organizationId, limit: 50 })).map(item => projectLegalAuditEvent(item)!);
    expect(events.map(event => event.action)).toEqual(['invitation_issued', 'invitation_redeemed', 'invitation_issued',
      'organization_registered', 'organization_created']);
    expect(events.find(event => event.action === 'invitation_redeemed')).toMatchObject({ actor: 'auth0|lawyer', subject: 'auth0|lawyer' });
    expect(events.find(event => event.action === 'organization_created')).toMatchObject({ actor: ADMIN });
  }, 60_000);

  test('a revoked invitation can never be redeemed', async () => {
    const issued = await issue('auth0|paralegal');
    await store.revokeLegalInvitation(issued.invitationId, ADMIN, Date.now());
    await expect(redeem(issued.token, 'auth0|paralegal')).rejects.toThrow();
    await expect(store.revokeLegalInvitation(issued.invitationId, ADMIN, Date.now())).rejects.toMatchObject({ code: 'not-pending' });
    await expect(store.revokeLegalInvitation(randomBytes(32).toString('hex'), ADMIN, Date.now())).rejects.toMatchObject({ code: 'not-found' });
    expect((await invitationsOf()).find(item => item.invitationId === issued.invitationId)).toMatchObject({ status: 'revoked', revokedBy: ADMIN });
  }, 60_000);

  test('removal rejects an already-authorized invitation inserted late, but fresh approval permits re-enrollment', async () => {
    let ready!: () => void, resume!: () => void;
    const reached = new Promise<void>(resolve => { ready = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const insert = store.insertInvitation.bind(store);
    let staleAuthorization = '';
    const paused = jest.spyOn(store, 'insertInvitation').mockImplementationOnce(async invitation => {
      staleAuthorization = invitation.authorization;
      ready(); await gate; return insert(invitation);
    });
    const late = issue('auth0|lawyer').then(() => true, () => false);
    try {
      await reached;
      await store.removeLegalMember(organizationId, 'auth0|lawyer', ADMIN, Date.now());
      resume();
      expect(await late).toBe(false);
      expect((await store.getMember('auth0|lawyer', 'org_harbor'))?.active).toBe(false);
    } finally { resume(); paused.mockRestore(); }
    const fresh = await issue('auth0|lawyer');
    await expect(redeem(fresh.token)).resolves.toMatchObject({ subject: 'auth0|lawyer' });
    // Re-enrollment does not erase the cutoff or revive the earlier signed approval.
    await expect(service.issueInvitation(await token('admin'), organizationId, 'auth0|lawyer', 3 * DAY,
      staleAuthorization)).rejects.toThrow();
  }, 60_000);

  test('removing a person also withdraws their pending renewal', async () => {
    const renewal = await issue('auth0|lawyer');
    await store.removeLegalMember(organizationId, 'auth0|lawyer', ADMIN, Date.now());
    expect((await store.getMember('auth0|lawyer', 'org_harbor'))?.active).toBe(false);
    await expect(redeem(renewal.token)).rejects.toThrow();
    expect((await invitationsOf()).find(item => item.invitationId === renewal.invitationId)?.status).toBe('revoked');
    await expect(store.removeLegalMember(organizationId, 'auth0|lawyer', ADMIN, Date.now())).rejects.toMatchObject({ code: 'not-found' });
    const [latest] = await store.listLegalAudit({ organizationId, limit: 1 });
    expect(projectLegalAuditEvent(latest)).toMatchObject({ action: 'member_removed', actor: ADMIN, subject: 'auth0|lawyer' });
  }, 60_000);

  test('an admin can remove a person whose access already ended: the cutoff is set and a pending renewal withdrawn', async () => {
    const enrolled = await issue('auth0|lawyer');
    await expect(redeem(enrolled.token)).resolves.toMatchObject({ subject: 'auth0|lawyer' });
    const members = client.db('test_legal_onboarding').collection('confidential_legal_members');
    // Inactive but never cut off (as a row deactivated without a removal leaves it).
    await members.updateOne({ subject: 'auth0|lawyer', providerOrganizationId: 'org_harbor' },
      { $set: { active: false }, $unset: { removedAt: '' } });
    const renewal = await issue('auth0|lawyer');
    await store.removeLegalMember(organizationId, 'auth0|lawyer', ADMIN, Date.now());
    const row = await members.findOne({ subject: 'auth0|lawyer', providerOrganizationId: 'org_harbor' });
    expect(row?.removedAt).toBeInstanceOf(Date);
    expect(row?.active).toBe(false);
    expect((await invitationsOf()).find(item => item.invitationId === renewal.invitationId))
      .toMatchObject({ status: 'revoked', revokedBy: ADMIN });
    await expect(redeem(renewal.token)).rejects.toThrow();
    const [latest] = await store.listLegalAudit({ organizationId, limit: 1 });
    expect(projectLegalAuditEvent(latest)).toMatchObject({ action: 'member_removed', actor: ADMIN, subject: 'auth0|lawyer' });
    // Nothing left to remove: not-found, and no second audit event.
    await expect(store.removeLegalMember(organizationId, 'auth0|lawyer', ADMIN, Date.now())).rejects.toMatchObject({ code: 'not-found' });
    const [again] = await store.listLegalAudit({ organizationId, limit: 1 });
    expect(again._id).toBe(latest._id);
  }, 60_000);

  test('removal by the organization steward also sets the cutoff, withdraws a pending renewal and is audited', async () => {
    const enrolled = await issue('auth0|lawyer');
    await expect(redeem(enrolled.token)).resolves.toMatchObject({ subject: 'auth0|lawyer' });
    const renewal = await issue('auth0|lawyer');
    // The enclave's `legal.member-remove` calls this after the steward's proof checks.
    await store.deactivateFirmMember(organizationId, 'org_harbor', 'auth0|lawyer', Date.now());
    expect((await store.getMember('auth0|lawyer', 'org_harbor'))?.active).toBe(false);
    const row = await client.db('test_legal_onboarding').collection('confidential_legal_members')
      .findOne({ subject: 'auth0|lawyer', providerOrganizationId: 'org_harbor' });
    expect(row?.removedAt).toBeInstanceOf(Date);
    // The earlier renewal link cannot bring the person back.
    await expect(redeem(renewal.token)).rejects.toThrow();
    expect((await store.getMember('auth0|lawyer', 'org_harbor'))?.active).toBe(false);
    expect((await invitationsOf()).find(item => item.invitationId === renewal.invitationId))
      .toMatchObject({ status: 'revoked', revokedBy: 'organization steward' });
    const [latest] = await store.listLegalAudit({ organizationId, limit: 1 });
    expect(projectLegalAuditEvent(latest)).toMatchObject({ action: 'member_removed', actor: 'organization steward', subject: 'auth0|lawyer' });
    // A repeat is a no-op: no duplicate audit event.
    await store.deactivateFirmMember(organizationId, 'org_harbor', 'auth0|lawyer', Date.now());
    const [again] = await store.listLegalAudit({ organizationId, limit: 1 });
    expect(again._id).toBe(latest._id);
    // A fresh approval issued after the removal still works.
    const fresh = await issue('auth0|lawyer');
    await expect(redeem(fresh.token)).resolves.toMatchObject({ subject: 'auth0|lawyer' });
  }, 60_000);

  test('a key the domain replaced is registered only through the onboarding authority, and old invitations stop working', async () => {
    const statusOf = async (subject: string) => (await store.listLegalMemberRecords(organizationId))
      .map(item => projectLegalMember(item, Date.now())!).find(item => item.subject === subject)?.status;
    expect(await statusOf('auth0|lawyer')).toBe('active');
    expect((await store.countLegalOnboarding(Date.now()))[organizationId].activeMembers).toBe(1);
    // The onboarding authority alone cannot swap a registered firm's key: the
    // organization's continuity statement, signed by the registered key, is required.
    await expect(issue('auth0|lawyer', { register: { domain: 'harbor.example', key: otherFirm } })).rejects.toThrow();
    expect((await store.getOrganization(organizationId))?.recipientKeyId).toBe(await caseRecipientKeyId(firm.toPublic()));
    const rotated = await rotateOrganizationKey({ organizationId, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: Date.now() }, firm);
    otherFirm = rotated.organizationKey;
    const reinvite = await issue('auth0|lawyer', { register: { domain: 'harbor.example', key: otherFirm, continuity: rotated.continuity } });
    // The enclave denies people enrolled with the replaced key: the roster must not show them as active.
    expect(await statusOf('auth0|lawyer')).toBe('key-replaced');
    expect((await store.countLegalOnboarding(Date.now()))[organizationId].activeMembers).toBe(0);
    expect(JSON.stringify(await store.listLegalMemberRecords(organizationId))).not.toContain(await caseRecipientKeyId(firm.toPublic()));
    // Issued for the previous key: its enrollment proof no longer matches the registered key.
    await expect(redeem(associateToken, 'auth0|associate')).rejects.toThrow();
    expect((await store.getOrganization(organizationId))?.recipientKeyId).toBe(await caseRecipientKeyId(otherFirm.toPublic()));
    const [latest, previous] = await store.listLegalAudit({ organizationId, limit: 2 });
    expect([latest.action, previous.action]).toEqual(['invitation_issued', 'organization_registered']);
    // Accepting the new invitation binds the person to the current key again.
    await expect(redeem(reinvite.token, 'auth0|lawyer', otherFirm)).resolves.toMatchObject({ subject: 'auth0|lawyer' });
    expect(await statusOf('auth0|lawyer')).toBe('active');
    expect((await store.countLegalOnboarding(Date.now()))[organizationId].activeMembers).toBe(1);
  }, 60_000);

  test('revoking an organization is final and releases its domain for a new record', async () => {
    const pending = await issue('auth0|counsel', { key: otherFirm });
    const spare = await issue('auth0|spare', { key: otherFirm });
    // Control: the new key's invitations work until the organization is revoked.
    await expect(redeem(spare.token, 'auth0|spare', otherFirm)).resolves.toMatchObject({ subject: 'auth0|spare' });
    let ready!: () => void, resume!: () => void;
    const reached = new Promise<void>(resolve => { ready = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const insert = store.insertInvitation.bind(store);
    const paused = jest.spyOn(store, 'insertInvitation').mockImplementationOnce(async invitation => {
      ready(); await gate; return insert(invitation);
    });
    const late = issue('auth0|late', { key: otherFirm }).then(() => true, () => false);
    await reached;
    const result = await store.revokeLegalOrganization(organizationId, ADMIN, Date.now());
    resume();
    try { expect(await late).toBe(false); } finally { paused.mockRestore(); }

    expect(result.invitationsRevoked).toBeGreaterThanOrEqual(1);
    expect(await store.getOrganization(organizationId)).toMatchObject({ approved: false });
    expect(await store.listLegalOrganizations()).toEqual([]);
    expect(await store.getMember('auth0|associate', 'org_harbor')).toBeNull();
    await expect(redeem(pending.token, 'auth0|counsel', otherFirm)).rejects.toThrow();
    expect((await store.getMember('auth0|spare', 'org_harbor'))?.active).toBe(false);
    // The onboarding authority cannot quietly re-approve a revoked organization.
    await expect(issue('auth0|lawyer', { register: { domain: 'harbor.example', key: firm } })).rejects.toThrow();
    expect((await store.getLegalOrganizationRecord(organizationId))?.approved).toBe(false);
    await expect(store.revokeLegalOrganization(organizationId, ADMIN, Date.now())).rejects.toMatchObject({ code: 'revoked' });
    await expect(store.revokeLegalOrganization(randomBytes(32).toString('hex'), ADMIN, Date.now())).rejects.toMatchObject({ code: 'not-found' });
    expect(await store.countLegalOnboarding(Date.now())).toEqual({});
    await store.createLegalOrganization({ organizationId: randomBytes(32).toString('hex'), displayName: 'Harbor Counsel (new)',
      domain: 'harbor.example', providerOrganizationId: 'org_harbor' }, ADMIN, Date.now());
    const listed = (await store.listLegalOrganizationRecords()).map(projectLegalOrganization);
    expect(listed.map(item => item?.status).sort()).toEqual(['awaiting-registration', 'revoked']);
    expect(JSON.stringify(await store.listLegalOrganizationRecords())).not.toMatch(/providerClaim|domainClaim/);
  }, 60_000);

  test('startup claims cover legacy rows, detect duplicates and tolerate concurrent startup', async () => {
    const db = client.db('legacy_onboarding_claims');
    const legacy = { _id: randomBytes(32).toString('hex'), displayName: 'Legacy Counsel', domain: 'legacy.example',
      providerOrganizationId: 'org_legacy', publicKey: '', approved: false };
    await db.collection('confidential_legal_organizations').insertOne(legacy as never);
    const [migrated] = await Promise.all([MongoConfidentialCaseStore.fromDatabase(db, client),
      MongoConfidentialCaseStore.fromDatabase(db, client)]);
    await expect(migrated.createLegalOrganization({ organizationId: randomBytes(32).toString('hex'),
      displayName: 'Duplicate', domain: 'legacy.example', providerOrganizationId: 'org_new' }, ADMIN, Date.now()))
      .rejects.toMatchObject({ code: 'duplicate-domain' });
    await expect(migrated.createLegalOrganization({ organizationId: randomBytes(32).toString('hex'),
      displayName: 'Duplicate', domain: 'new.example', providerOrganizationId: 'org_legacy' }, ADMIN, Date.now()))
      .rejects.toMatchObject({ code: 'duplicate-provider-organization' });
    const conflictDb = client.db('legacy_onboarding_conflict');
    await conflictDb.collection('confidential_legal_organizations').insertMany([
      legacy, { ...legacy, _id: randomBytes(32).toString('hex'), providerOrganizationId: 'org_other' },
    ] as never);
    await expect(MongoConfidentialCaseStore.fromDatabase(conflictDb, client)).rejects.toMatchObject({ code: 'duplicate-domain' });
    const noClient = await MongoConfidentialCaseStore.fromDatabase(client.db('no_transaction_client'));
    await expect(noClient.createLegalOrganization({ organizationId: randomBytes(32).toString('hex'),
      displayName: 'No transaction', domain: 'no.example', providerOrganizationId: 'org_no' }, ADMIN, Date.now()))
      .rejects.toThrow('transactions require a Mongo client');
  }, 60_000);

  test('the audit trail pages newest first without gaps', async () => {
    const all = (await store.listLegalAudit({ limit: 100 })).map(item => projectLegalAuditEvent(item)!);
    expect(all.length).toBeGreaterThan(8);
    const seen: string[] = [];
    let before: { at: number; id: string } | undefined;
    for (;;) {
      const page = (await store.listLegalAudit({ limit: 3, ...(before ? { before } : {}) })).map(item => projectLegalAuditEvent(item)!);
      if (!page.length) break;
      seen.push(...page.map(event => event.eventId));
      const last = page[page.length - 1];
      const [at, id] = auditCursor(last).split('_');
      before = { at: Number(at), id };
    }
    expect(seen).toEqual(all.map(event => event.eventId));
    expect(all.every((event, index) => index === 0 || all[index - 1].at >= event.at)).toBe(true);
    expect(JSON.stringify(all)).not.toMatch(/BEGIN PGP|tokenDigest|nonce/);
  }, 60_000);

  test('a membership job for a deleted Auth0 organization is cancelled and the roster entry retired', async () => {
    const id = randomBytes(32).toString('hex'), now = Date.now();
    await store.createLegalOrganization({ organizationId: id, displayName: 'Deleted Firm', domain: 'deleted.example',
      providerOrganizationId: 'org_deleted' }, ADMIN, now);
    const getById = jest.fn(async () => null);
    const provider = { nativeEntry: true, organization: jest.fn(), invite: jest.fn(),
      applicationOrganizations: { getById } as unknown as ApplicationOrganizations,
      registrationApproval: jest.fn(async () => { throw new LegalProvisioningError('provider_binding', 'organization_deleted'); }),
      candidate: jest.fn(), createApprovedAccount: jest.fn(), approveMembership: jest.fn() };
    store.configureLegalMemberInvitations(provider);
    await store.queueLegalAuth0Membership({ organizationId: id, providerOrganizationId: 'org_deleted', domain: 'deleted.example',
      email: 'lawyer@deleted.example', approvalId: 'b'.repeat(64), expires: now + DAY });
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
    try { expect(await store.provisionLegalAuth0Membership()).toBe(true); }
    finally { store.configureLegalMemberInvitations(null); }
    expect(await client.db('test_legal_onboarding').collection('legal_auth0_membership_approvals').findOne({ organizationId: id }))
      .toMatchObject({ state: 'cancelled' });
    // Retirement re-confirms the deletion by id before revoking.
    expect(getById).toHaveBeenCalledWith('org_deleted', expect.any(AbortSignal));
    expect(await store.getLegalOrganizationRecord(id)).toMatchObject({ approved: false, revokedBy: 'system:auth0-organization-deleted' });
    expect(provider.candidate).not.toHaveBeenCalled(); expect(provider.createApprovedAccount).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith('Legal membership job failed', expect.any(String), 'cancelled', 'provider_binding:organization_deleted');
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/deleted\.example|org_deleted/);
    warn.mockRestore();
  }, 60_000);
});
