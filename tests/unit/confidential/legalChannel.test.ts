import { signOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';
import { signMembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';
import { createHash, randomBytes, webcrypto } from 'node:crypto';

// Only the AWS quote check is mocked. JWTs, firm-key proofs, channel encryption,
// sealed storage and case authorization are real.
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

import * as jose from 'jose';
import { createMessage, generateKey, readKey, sign } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { encodeBase64, findCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { caseRecipientKeyId, openGrantedCaseObject } from '../../../enclave/src/confidential/caseObject';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { createLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { requestTimeBucket } from '../../../enclave/src/confidential/requestRouting';
import { sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation } from '../../../enclave/src/confidential/participantRequest';
import { verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseManifest } from '../../../enclave/src/confidential/authorization';
import { sealChannelRequest } from '../../../enclave/src/confidential/channelMessage';
import { LEGAL_ASSURANCE_CLAIM } from '../../../enclave/src/legal/identity';
import type { EnrollmentStore, FirmEnrollmentBinding, LegalInvitation } from '../../../enclave/src/legal/enrollment';
import { signEnrollmentChallenge } from '../../../enclave/src/confidential/enrollmentProof';
import { createLegalCaseDispatcher } from '../../../enclave/src/cases/legalChannel';
import type { LegalMember, LegalMembershipStore } from '../../../enclave/src/cases/legalChannel';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import type { CaseRecord, CaseStore, StoredAccessRequest, StoredMessage, StoredObject } from '../../../enclave/src/cases/service';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { createCaseChannelDispatch } from '../../../enclave/src/confidential-server';
import { ConfidentialUnavailableError, ownerOperation, publishPreparedCase } from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';
import { allowAccess, readOwnerInbox, restoreOwnerSession, verifiedRequests, verifiedRoster } from '../../../lib/confidential/ownerCase';
import { readMembershipStatus } from '../../../lib/confidential/firmOnboarding';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const AUDIENCE = 'vera-confidential-cases', ISSUER = 'https://identity.example/';
const IDENTITY = { issuer: ISSUER, audience: 'https://api.example/legal', clientId: 'legal-client' };
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

/** TEST-ONLY untrusted host store; no await between compare and mutation. */
function memoryStore(organizations: Map<string, FirmEnrollmentBinding & { displayName: string; domain: string }>) {
  const cases = new Map<string, CaseRecord>(), staged = new Map<string, string>();
  const objects = new Map<string, StoredObject>(), envelopes = new Map<string, Record<string, string>>();
  const requests: StoredAccessRequest[] = [], messages: StoredMessage[] = [];
  const store = {
    staged,
    async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
    async putObjects(caseId: string, items: StoredObject[]) { for (const item of items) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item)); },
    async getObjects(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]) {
      return refs.map(ref => objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`)).filter(Boolean).map(clone) as StoredObject[];
    },
    async getOwnerEnvelopes(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]) {
      return (await store.getObjects(caseId, refs)).map(({ objectId, ciphertextDigest, ownerEnvelope }) => ({ objectId, ciphertextDigest, ownerEnvelope }));
    },
    async getEnvelopes() { return []; },
    async readGrantedObjects(caseId: string, recipientKeyId: string, checkpointDigest: string, refs: { objectId: string; ciphertextDigest: string }[]) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      const result = [];
      for (const ref of refs) {
        const item = objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`);
        const envelope = envelopes.get(caseId)?.[`${ref.objectId}:${recipientKeyId}`];
        if (!item || !envelope) return null;
        result.push({ objectId: ref.objectId, ciphertextDigest: ref.ciphertextDigest, ciphertext: item.ciphertext, recipientEnvelope: envelope });
      }
      return result;
    },
    async createCase(record: CaseRecord) { if (cases.has(record.caseId)) return false; cases.set(record.caseId, clone(record)); return true; },
    async getCase(caseId: string) { const value = cases.get(caseId); return value ? clone(value) : null; },
    async commitTransition(caseId: string, expected: string, update: Parameters<CaseStore['commitTransition']>[2]) {
      const record = cases.get(caseId);
      if (!record || record.currentCheckpointDigest !== expected) return false;
      for (const item of update.objects) objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, clone(item));
      const boxes = envelopes.get(caseId) ?? {};
      for (const item of update.envelopes) boxes[`${item.objectId}:${item.recipientKeyId}`] = item.envelope;
      envelopes.set(caseId, boxes);
      cases.set(caseId, { ...record, statements: { ...record.statements, ...update.statements },
        checkpoints: [...record.checkpoints, update.checkpoint], currentCheckpointDigest: update.checkpointDigest,
        listingDigest: update.listingDigest, recoveryPackage: update.recoveryPackage ?? record.recoveryPackage,
        ...(update.stateEnvelopes ? { stateEnvelopes: update.stateEnvelopes } : {}),
        ...(update.stateEpoch !== undefined ? { stateEpoch: update.stateEpoch } : {}) });
      return true;
    },
    async listListedCases(limit: number, after: string | null) {
      return [...cases.values()].filter(item => item.listingDigest !== null).sort((a, b) => a.caseId.localeCompare(b.caseId))
        .filter(item => after === null || item.caseId > after).slice(0, limit).map(clone);
    },
    async listLegalOrganizations() {
      return [...organizations.values()].map(({ organizationId, displayName, domain, publicKey, approved, bindingDocument }) =>
        ({ organizationId, displayName, domain, publicKey, approved, bindingDocument }));
    },
    async insertAccessRequestAtCheckpoint(request: StoredAccessRequest, guard: { checkpointDigest: string; now: number }) {
      const record = cases.get(request.caseId);
      if (!record || record.currentCheckpointDigest !== guard.checkpointDigest || record.listingDigest === null) return 'conflict' as const;
      const existing = requests.find(item => item.caseId === request.caseId && item.organizationId === request.organizationId && item.requestId === request.requestId);
      if (existing) return existing.state === 'pending' && existing.ciphertext === request.ciphertext ? 'stored' as const : 'conflict' as const;
      if (requests.some(item => item.caseId === request.caseId && item.organizationId === request.organizationId && item.state === 'pending')) return 'conflict' as const;
      requests.push(clone(request));
      return 'stored' as const;
    },
    async getAccessRequest(caseId: string, organizationId: string, requestId: string) {
      return requests.find(item => item.caseId === caseId && item.organizationId === organizationId && item.requestId === requestId) ?? null;
    },
    async listAccessRequests(caseId: string) { return requests.filter(item => item.caseId === caseId).map(clone); },
    async expireAccessRequests() { /* not exercised */ },
    async withdrawAccessRequest(caseId: string, organizationId: string, requestId: string) {
      const found = requests.find(item => item.caseId === caseId && item.organizationId === organizationId &&
        item.requestId === requestId && item.state === 'pending');
      if (!found) return false;
      found.state = 'withdrawn';
      return true;
    },
    async appendMessage(message: StoredMessage, guard: { checkpointDigest: string }) {
      if (cases.get(message.caseId)?.currentCheckpointDigest !== guard.checkpointDigest) return 'conflict' as const;
      messages.push(clone(message)); return 'stored' as const;
    },
    async readMessagesAtCheckpoint(caseId: string, organizationId: string, limit: number, checkpointDigest: string) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      return messages.filter(item => item.caseId === caseId && item.organizationId === organizationId).slice(-limit).map(clone);
    },
    async readInboxAtCheckpoint(caseId: string, checkpointDigest: string) {
      if (cases.get(caseId)?.currentCheckpointDigest !== checkpointDigest) return null;
      return { requests: requests.filter(item => item.caseId === caseId && item.state === 'pending').map(clone),
        messages: messages.filter(item => item.caseId === caseId).map(clone) };
    },
    async countMessages(filter: { caseId: string; organizationId: string }) {
      return messages.filter(item => item.caseId === filter.caseId && item.organizationId === filter.organizationId).length;
    },
    dump() { return JSON.stringify({ cases: [...cases.values()], requests, messages }); },
  };
  return store;
}

describe('firm-side case operations over the attested channel', () => {
  let issuer: jose.GenerateKeyPairResult, rogueIssuer: jose.GenerateKeyPairResult;
  let onboarding: PrivateKey;
  let firm: PrivateKey, otherFirm: PrivateKey, attacker: PrivateKey;
  let org: FirmEnrollmentBinding & { displayName: string; domain: string }, otherOrg: typeof org;
  let relay: ChannelRelay, backing: ReturnType<typeof memoryStore>, keyring: ReturnType<typeof createCaseKeyring>;
  let prepared: Awaited<ReturnType<typeof prepareConfidentialSubmission>>;
  let sessions: ReturnType<typeof createSessionCore>, releaseDigest: string;
  const organizations = new Map<string, FirmEnrollmentBinding & { displayName: string; domain: string }>();
  const members = new Map<string, LegalMember>();
  let memberHook: ((member: LegalMember | null) => LegalMember | null) | null = null;
  let countFailure = false;
  const invitations = new Map<string, LegalInvitation>();
  /** TEST-ONLY atomic enrollment adapter (no await between compare and write). */
  const enrollment: EnrollmentStore = {
    async getOrganization(organizationId) { return membership.getOrganization(organizationId); },
    async insertInvitation() { throw new Error('not reachable from the enclave'); },
    async getInvitation(digest) { const found = invitations.get(digest); return found ? clone(found) : null; },
    async commitEnrollment(expected, member, time) {
      const stored = invitations.get(expected.tokenDigest), binding = organizations.get(member.organizationId);
      if (!stored || stored.state !== 'pending' || stored.version !== expected.version || stored.expiresAt <= time ||
          !binding?.approved || binding.recipientKeyId !== member.recipientKeyId) return false;
      invitations.set(expected.tokenDigest, { ...stored, state: 'redeemed', version: stored.version + 1 });
      const key = `${expected.providerOrganizationId}/${member.subject}`;
      members.set(key, { ...member, providerOrganizationId: expected.providerOrganizationId,
        revision: (members.get(key)?.revision ?? 0) + 1, active: true });
      return true;
    },
  };
  const membership: LegalMembershipStore = {
    async getMember(subject, providerOrganizationId) {
      const found = members.get(`${providerOrganizationId}/${subject}`) ?? null;
      return memberHook ? memberHook(found && clone(found)) : found && clone(found);
    },
    async getOrganization(organizationId) {
      const found = organizations.get(organizationId);
      if (!found) return null;
      const { organizationId: id, providerOrganizationId, recipientKeyId, publicKey, approved, registration } = found;
      return { organizationId: id, providerOrganizationId, recipientKeyId, publicKey, approved, registration };
    },
    async countMembers(organizationId, recipientKeyId, time) {
      if (countFailure) throw new Error('Confidential storage unavailable');
      return [...members.values()].filter(item => item.organizationId === organizationId && item.recipientKeyId === recipientKeyId &&
        item.active && (item.enrollment?.challenge.expiresAt ?? 0) > time).length;
    },
  };

  async function token(overrides: Record<string, unknown> = {}, key = issuer.privateKey) {
    const iat = Math.floor(Date.now() / 1000);
    return new jose.SignJWT({ iss: ISSUER, aud: IDENTITY.audience, azp: IDENTITY.clientId, sub: 'auth0|lawyer',
      org_id: 'org_firm', scope: 'legal:directory legal:case', iat, exp: iat + 300,
      [LEGAL_ASSURANCE_CLAIM]: 'approved-member-verified-email', ...overrides })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key' }).sign(key);
  }
  const token_ = (overrides: Record<string, unknown>) => token(overrides);
  async function session() {
    const nonce = randomBytes(32).toString('hex');
    const evidence = await relay.open(nonce);
    const serverKey = await readKey({ binaryKey: evidence.publicKey });
    return { nonce, serverKey, serverKeyId: await caseRecipientKeyId(serverKey) };
  }
  async function exchange(channel: Awaited<ReturnType<typeof session>>, request: unknown): Promise<any> {
    const pending = await sealChannelRequest(channel.serverKey, channel.nonce, encode(request));
    const reply = await pending.openResponse(await relay.call(channel.nonce, pending.ciphertext));
    return JSON.parse(new TextDecoder().decode(reply));
  }
  /** Firm portal: challenge and proof on the same attested session. */
  async function legal(operation: ParticipantOperation, body: unknown, options: {
    accessToken?: string; key?: PrivateKey; organizationId?: string; caseId?: string;
    proofSession?: Awaited<ReturnType<typeof session>>; request?: (value: Record<string, unknown>) => Record<string, unknown>;
  } = {}) {
    const raw = encode(body);
    const channel = await session();
    const { challenge } = await exchange(channel, { operation: 'legal.challenge' });
    const binding = options.proofSession ?? channel;
    const proof = await signParticipantRequest({ audience: AUDIENCE, role: 'organization', caseId: options.caseId ?? prepared.caseId,
      organizationId: options.organizationId ?? org.organizationId, operation, body: raw, challenge, issuedAt: Date.now(),
      nonce: binding.nonce, serverKeyId: binding.serverKeyId }, options.key ?? firm);
    const request = { operation: `legal.${operation}`, accessToken: options.accessToken ?? await token(), proof,
      body: Buffer.from(raw).toString('base64') };
    return exchange(channel, options.request ? options.request(request) : request);
  }

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    [issuer, rogueIssuer] = await Promise.all([jose.generateKeyPair('RS256'), jose.generateKeyPair('RS256')]);
    const jwks = { keys: [{ ...await jose.exportJWK(issuer.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer-key' }] };
    [firm, otherFirm, attacker] = await Promise.all(['firm', 'other', 'attacker'].map(async name =>
      (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
    onboarding = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' })).privateKey;
    org = { organizationId: hex(0xf1), providerOrganizationId: 'org_firm', recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
      publicKey: firm.toPublic().armor(), approved: true, displayName: 'Synthetic Counsel LLP', domain: 'counsel.example' };
    otherOrg = { organizationId: hex(0xf2), providerOrganizationId: 'org_other', recipientKeyId: await caseRecipientKeyId(otherFirm.toPublic()),
      publicKey: otherFirm.toPublic().armor(), approved: true, displayName: 'Other Counsel', domain: 'other.example' };
    for (const organization of [org, otherOrg]) organization.registration = await signOrganizationRegistration({
      format: 'vera-organization-registration/v1', ...organization, issuedAt: Date.now() }, onboarding);
    organizations.set(org.organizationId, org).set(otherOrg.organizationId, otherOrg);
    async function certificate(binding: typeof org, key: PrivateKey) {
      const challenge = { format: 'vera-legal-enrollment/v1' as const, invitationId: hex(50), nonce: hex(51),
        organizationId: binding.organizationId, recipientKeyId: binding.recipientKeyId,
        providerOrganizationId: binding.providerOrganizationId, subject: 'auth0|lawyer', expiresAt: Date.now() + 86400000 };
      return { challenge, proof: await signEnrollmentChallenge(challenge, key), authorization: await signMembershipAuthorization({
        format: 'vera-membership-authorization/v1', organizationId: binding.organizationId, providerOrganizationId: binding.providerOrganizationId,
        subject: challenge.subject, recipientKeyId: binding.recipientKeyId, issuedAt: Date.now(), expiresAt: challenge.expiresAt }, onboarding) };
    }
    members.set('org_firm/auth0|lawyer', { subject: 'auth0|lawyer', providerOrganizationId: 'org_firm', organizationId: org.organizationId,
      recipientKeyId: org.recipientKeyId, revision: 1, active: true, enrollment: await certificate(org, firm) });
    members.set('org_other/auth0|lawyer', { subject: 'auth0|lawyer', providerOrganizationId: 'org_other', organizationId: otherOrg.organizationId,
      recipientKeyId: otherOrg.recipientKeyId, revision: 1, active: true, enrollment: await certificate(otherOrg, otherFirm) });

    backing = memoryStore(organizations);
    keyring = createCaseKeyring({ clock: Date.now });
    releaseDigest = (await readReleaseManifest(MANIFEST)).digest;
    const options = { store: createSealedCaseStore(backing as unknown as CaseStore, keyring), keyring, clock: Date.now, audience: AUDIENCE, releaseDigest };
    const dispatch = createCaseChannelDispatch(createOwnerCaseControlDispatcher(options),
      createLegalCaseDispatcher({ ...options, identity: { ...IDENTITY, jwks }, members: membership, enrollment, administration: { identity: { ...IDENTITY, audience: 'admin-api', clientId: 'admin-client', jwks }, organizationId: 'org_admin', onboardingPublicKey: onboarding.toPublic().armor() } }));
    const channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
    sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(channelKey.privateKey,
      { nonce, publicKey: Buffer.from(channelKey.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => 1,
      // The synthetic clock never advances, so sessions never expire: room for the whole file.
      { capacity: 1024 });
    relay = {
      async stageChunk() { throw new Error('No evidence in this suite'); },
      async stage(ciphertext) {
        const digest = createHash('sha256').update(ciphertext, 'utf8').digest('hex');
        backing.staged.set(digest, ciphertext);
        return digest;
      },
      async open(nonce) {
        const identity = await sessions.open(nonce);
        return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(identity.publicKey, 'base64')) };
      },
      async call(nonce, ciphertext, last) { return sessions.execute(nonce, ciphertext, { last }); },
    };
    prepared = await prepareConfidentialSubmission({ summary: 'Firm-visible summary', narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE' },
      contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT' }, identity: null, files: [] }, MANIFEST, Date.now());
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now: Date.now(), prepared });
  }, 180_000);
  afterAll(() => sessions?.close());
  afterEach(() => { memberHook = null; });

  const denied = 'Confidential channel unavailable';
  const keysBody = () => ({ caseId: prepared.caseId });

  test('legacy grant still opens the report but both message senders and thread reads are retired', async () => {
    const directory = await exchange(await session(), { operation: 'legal.directory', accessToken: await token(), after: null, limit: 10 });
    expect(directory).toEqual({ listings: [{ caseId: prepared.caseId, summary: 'Firm-visible summary', publishedAt: expect.any(Number), hasAttachments: false,
      ownerPublicKey: prepared.owner.trust.ownerPublicKey.armor(), listing: expect.any(String) }], next: null });
    // The firm verifies the owner-signed listing itself.
    const signedListing = await verifyOwnerStatement(directory.listings[0].listing, { caseId: prepared.caseId,
      ownerPublicKey: await readKey({ armoredKey: directory.listings[0].ownerPublicKey }),
      ownerFingerprint: prepared.owner.trust.ownerFingerprint });
    expect(signedListing.statement).toMatchObject({ kind: 'listing', summary: 'Firm-visible summary' });
    expect(JSON.stringify(directory)).not.toMatch(/checkpoint|grant|manifest/);

    const now = Date.now();
    const ciphertext = await createLegalAccessRequest({ requestId: hex(0x301), scopes: ['narrative', 'messages'], objectRevisionLimit: null,
      purpose: 'Counsel review', issuedAt: now, expiresAt: now + 86_400_000 }, org.organizationId, firm, prepared.owner.trust);
    await expect(legal('request-access', { caseId: prepared.caseId, requestId: hex(0x301), ciphertext, expiresAt: now + 86_400_000 }))
      .resolves.toEqual({ state: 'requested' });
    await expect(legal('request-status', { caseId: prepared.caseId, requestIds: [hex(0x301)] })).resolves.toEqual({
      access: { state: 'none', expiresAt: null, scopes: [], contactShared: false, releaseApproved: true },
      // The host row keeps the expiry only to the UTC day, rounded down.
      requests: [{ requestId: hex(0x301), state: 'requested', expiresAt: requestTimeBucket(now + 86_400_000) }] });
    // Before a grant: a structured answer the portal can show.
    await expect(legal('open-case', keysBody())).resolves.toEqual({ error: 'not-granted' });

    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const inbox = await readOwnerInbox(owner, Date.now());
    const profile = { practiceAreas: ['whistleblower' as const], jurisdiction: 'England and Wales', website: 'https://counsel.example/' };
    const binding = await createFirmKeyBinding({ domain: org.domain, organizationId: org.organizationId, issuedAt: now, profile }, firm);
    org.bindingDocument = binding;
    const roster = await verifiedRoster(owner, Date.now());
    expect(roster.find(item => item.organizationId === org.organizationId)?.profile).toEqual(profile);
    const [request] = await verifiedRequests(owner, inbox, roster, Date.now());
    await allowAccess(owner, inbox, roster, request, { grantId: hex(0x401), scopes: ['narrative', 'messages'],
      objectRevisionLimit: null, expiresAt: Date.now() + 86_400_000 }, Date.now());
    // The key check before sharing read the organization's own signed profile,
    // and this session keeps showing it without contacting the domain again.
    expect(roster.find(item => item.organizationId === org.organizationId)?.profile).toEqual(profile);
    const reloaded = await verifiedRoster(owner, Date.now());
    expect(reloaded.find(item => item.organizationId === org.organizationId)?.profile).toEqual(profile);

    // Enclave restart equivalent: the in-memory key is gone and the case is locked.
    keyring.delete(prepared.caseId);
    await expect(legal('open-case', keysBody())).resolves.toEqual({ error: 'locked' });
    const { stateEnvelopes } = await legal('read-state-keys', keysBody());
    const state = await findCaseStateKey(stateEnvelopes, prepared.caseId, firm, prepared.owner.trust.ownerPublicKey);
    await expect(legal('unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }))
      .resolves.toEqual({ unlocked: true });

    const opened = await legal('open-case', keysBody());
    const manifest = (await verifyOwnerStatement(opened.manifest, prepared.owner.trust)).statement as CaseManifest;
    const narrative = manifest.objects.find(entry => entry.scope === 'narrative')!;
    expect(opened.objects).toHaveLength(1);
    const plaintext = await openGrantedCaseObject({ ciphertext: opened.objects[0].ciphertext, recipientEnvelope: opened.objects[0].recipientEnvelope },
      { caseId: prepared.caseId, objectId: narrative.objectId, scope: 'narrative', keyEpoch: 1, objectRevision: 1 }, firm,
      { trust: prepared.owner.trust, grant: opened.grants[0], release: opened.release, manifest: opened.manifest,
        checkpoint: opened.checkpoint, checkpointDigest: opened.checkpointDigest, request: { organizationId: org.organizationId,
          recipientKeyId: org.recipientKeyId, objectId: narrative.objectId, ciphertextDigest: narrative.ciphertextDigest, scope: 'narrative',
          releaseDigest, keyEpoch: 1, objectRevision: 1, now: Date.now() } });
    expect(JSON.parse(new TextDecoder().decode(plaintext)).description).toBe('PRIVATE-SENTINEL-NARRATIVE');

    const message = await sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: Date.now(), body: 'PRIVATE-SENTINEL-MESSAGE' },
      { owner: prepared.owner.trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } }, firm);
    await expect(legal('send-message', { caseId: prepared.caseId, organizationId: org.organizationId, ciphertext: message }))
      .rejects.toThrow(denied);
    await expect(legal('read-messages', keysBody())).rejects.toThrow(denied);
    const ownerMessage = await sealCaseMessage({ sender: 'owner', sequence: 1, sentAt: Date.now(), body: 'PRIVATE-SENTINEL-OWNER-MESSAGE' },
      { owner: prepared.owner.trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } }, owner.owner);
    await expect(ownerOperation({ relay, releaseManifest: MANIFEST, now: Date.now(), caseId: prepared.caseId, owner: owner.owner,
      operation: 'send-message', body: encode({ caseId: prepared.caseId, organizationId: org.organizationId, ciphertext: ownerMessage }) }))
      .rejects.toBeInstanceOf(ConfidentialUnavailableError);
    expect((await readOwnerInbox(owner, Date.now())).messages).toEqual([]);
    expect(backing.dump()).not.toContain('PRIVATE-SENTINEL');
  }, 180_000);

  test('request status: a firm sees only its own request and access, and nothing sealed while locked', async () => {
    const body = { caseId: prepared.caseId, requestIds: [hex(0x301)] };
    // The earlier grant (ID 0x401) did not answer request 0x301, which stays requested.
    await expect(legal('request-status', body)).resolves.toEqual({
      access: { state: 'active', expiresAt: expect.any(Number), scopes: ['messages', 'narrative'], contactShared: false, releaseApproved: true },
      requests: [{ requestId: hex(0x301), state: 'requested', expiresAt: expect.any(Number) }] });
    // Another organization, with its own valid key and membership, learns nothing about this request.
    await expect(legal('request-status', body, { accessToken: await token({ org_id: 'org_other' }), key: otherFirm,
      organizationId: otherOrg.organizationId })).resolves.toEqual({
      access: { state: 'none', expiresAt: null, scopes: [], contactShared: false, releaseApproved: true },
      requests: [{ requestId: hex(0x301), state: 'unknown' }] });
    await expect(legal('request-status', { ...body, organizationId: org.organizationId })).rejects.toThrow(denied);
    await expect(legal('request-status', body, { request: value => ({ ...value, operation: 'legal.withdraw-request' }) })).rejects.toThrow(denied);
    await expect(legal('request-status', body, { key: attacker })).rejects.toThrow(denied);
    // A valid login and a valid private key must belong to the SAME organization.
    // This remains enforced by the enclave even if the browser gate is bypassed.
    for (const operation of ['read-state-keys', 'open-case', 'read-messages'] as const) {
      await expect(legal(operation, keysBody(), { key: otherFirm, organizationId: otherOrg.organizationId })).rejects.toThrow(denied);
      await expect(legal(operation, keysBody(), { accessToken: await token({ org_id: 'org_other' }), key: firm,
        organizationId: org.organizationId })).rejects.toThrow(denied);
    }
    // Current membership is required.
    const member = members.get('org_firm/auth0|lawyer')!;
    members.set('org_firm/auth0|lawyer', { ...member, active: false });
    try { await expect(legal('request-status', body)).rejects.toThrow(denied); }
    finally { members.set('org_firm/auth0|lawyer', member); }
    // Locked: grants are sealed, so only the (blinded) request row is consulted.
    keyring.delete(prepared.caseId);
    await expect(legal('request-status', body)).resolves.toEqual({
      access: { state: 'unknown', expiresAt: null, scopes: [], contactShared: false, releaseApproved: null },
      requests: [{ requestId: hex(0x301), state: 'requested', expiresAt: expect.any(Number) }] });
    expect(backing.dump()).not.toContain(hex(0x301));
    const { stateEnvelopes } = await legal('read-state-keys', keysBody());
    const state = await findCaseStateKey(stateEnvelopes, prepared.caseId, firm, prepared.owner.trust.ownerPublicKey);
    await expect(legal('unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }))
      .resolves.toEqual({ unlocked: true });
  }, 120_000);

  test('one organization proof checks a batch, isolates failures and preserves organization boundaries', async () => {
    const target = { caseId: prepared.caseId, requestId: hex(0x301) };
    const body = { cases: [target, { caseId: hex(0xbad), requestId: null }] };
    const asFirm = { caseId: org.organizationId };
    const single = await legal('request-status', { caseId: target.caseId, requestIds: [target.requestId] });
    await expect(legal('request-status-batch', body, asFirm)).resolves.toEqual({ statuses: [
      { caseId: target.caseId, status: single }, { caseId: hex(0xbad), error: 'unavailable' },
    ] });
    const other = await legal('request-status-batch', body, { caseId: otherOrg.organizationId,
      accessToken: await token({ org_id: 'org_other' }), key: otherFirm, organizationId: otherOrg.organizationId });
    expect(other.statuses[0].status).toMatchObject({ access: { state: 'none' }, requests: [{ requestId: target.requestId, state: 'unknown' }] });
    await expect(legal('request-status-batch', body, { ...asFirm, key: attacker })).rejects.toThrow(denied);
    await expect(legal('request-status-batch', body)).rejects.toThrow(denied); // Wrong signed scope (case instead of organization).
    await expect(legal('request-status-batch', body, { ...asFirm, accessToken: await token({ org_id: 'org_other' }) })).rejects.toThrow(denied);
    await expect(legal('request-status-batch', body, { ...asFirm, request: value => ({ ...value,
      body: Buffer.from(encode({ cases: [body.cases[1]] })).toString('base64') }) })).rejects.toThrow(denied);
    for (const cases of [[], [target, target], Array.from({ length: 257 }, (_, i) => ({ caseId: hex(i), requestId: null }))]) {
      await expect(legal('request-status-batch', { cases }, asFirm)).rejects.toThrow(denied);
    }
    let calls = 0;
    memberHook = value => (++calls > 1 && value ? { ...value, revision: value.revision + 1 } : value);
    try { await expect(legal('request-status-batch', body, asFirm)).rejects.toThrow(denied); }
    finally { memberHook = null; }
    expect(calls).toBe(2);
  }, 120_000);

  test('state-key envelopes: only a current grantee gets them, and their count reveals no access changes', async () => {
    const asOther = async () => ({ accessToken: await token({ org_id: 'org_other' }), key: otherFirm, organizationId: otherOrg.organizationId });
    // Unlocked: an enrolled organization without access learns nothing, not even how many parties hold access.
    await expect(legal('read-state-keys', keysBody(), await asOther())).resolves.toEqual({ error: 'not-granted' });
    // The grantee gets a padded list: owner + one firm is not visible as two.
    const { stateEnvelopes } = await legal('read-state-keys', keysBody());
    expect(stateEnvelopes).toHaveLength(16);
    const state = await findCaseStateKey(stateEnvelopes, prepared.caseId, firm, prepared.owner.trust.ownerPublicKey);
    // Locked: grants are sealed, so the stored (padded, unchanging) list is served; it opens for no one else.
    keyring.delete(prepared.caseId);
    const locked = await legal('read-state-keys', keysBody(), await asOther());
    expect(locked.stateEnvelopes).toHaveLength(16);
    expect([...locked.stateEnvelopes].sort()).toEqual([...stateEnvelopes].sort());
    await expect(findCaseStateKey(locked.stateEnvelopes, prepared.caseId, otherFirm, prepared.owner.trust.ownerPublicKey)).rejects.toThrow();
    await expect(legal('unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }))
      .resolves.toEqual({ unlocked: true });
    await expect(legal('read-state-keys', keysBody(), await asOther())).resolves.toEqual({ error: 'not-granted' });
  }, 120_000);

  test('a token for another organization cannot act for this firm', async () => {
    const other = await token({ org_id: 'org_other' });
    await expect(legal('read-state-keys', keysBody(), { accessToken: other })).rejects.toThrow(denied);
    // Its own firm key and org authenticate (the org comes from the token + membership),
    // but it holds no access to this report, so it gets no envelopes.
    await expect(legal('read-state-keys', keysBody(), { accessToken: other, key: otherFirm, organizationId: otherOrg.organizationId }))
      .resolves.toEqual({ error: 'not-granted' });
    await expect(legal('read-state-keys', keysBody(), { accessToken: await token({ org_id: 'org_unknown' }) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { accessToken: await token({}, rogueIssuer.privateKey) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { accessToken: await token({ scope: 'legal:directory' }) })).rejects.toThrow(denied);
  }, 60_000);

  test('host rows and shared firm keys cannot forge or extend onboarding authorization', async () => {
    const original = members.get('org_firm/auth0|lawyer')!;
    const forged = { ...original.enrollment!, authorization: await signMembershipAuthorization({
      format: 'vera-membership-authorization/v1', organizationId: org.organizationId, providerOrganizationId: 'org_firm',
      recipientKeyId: org.recipientKeyId, subject: original.subject, issuedAt: Date.now(),
      expiresAt: original.enrollment!.challenge.expiresAt }, firm) };
    try {
      for (const enrollment of [undefined, forged, { ...original.enrollment!, challenge: { ...original.enrollment!.challenge,
        expiresAt: original.enrollment!.challenge.expiresAt + 1000 } }]) {
        members.set('org_firm/auth0|lawyer', { ...original, enrollment });
        await expect(legal('read-state-keys', keysBody())).rejects.toThrow(denied);
      }
    } finally { members.set('org_firm/auth0|lawyer', original); }
  }, 60000);

  test('a removed member is refused, including removal during the operation', async () => {
    const member = members.get('org_firm/auth0|lawyer')!;
    members.set('org_firm/auth0|lawyer', { ...member, active: false, revision: member.revision + 1 });
    try {
      await expect(legal('read-state-keys', keysBody())).rejects.toThrow(denied);
      await expect(exchange(await session(), { operation: 'legal.directory', accessToken: await token(), after: null, limit: 5 }))
        .rejects.toThrow(denied);
    } finally { members.set('org_firm/auth0|lawyer', member); }
    let calls = 0;
    memberHook = value => (++calls > 1 && value ? { ...value, revision: value.revision + 1 } : value);
    await expect(legal('read-state-keys', keysBody())).rejects.toThrow(denied);
    expect(calls).toBe(2);
    memberHook = null;
    await expect(legal('read-state-keys', keysBody())).resolves.toHaveProperty('stateEnvelopes');
  }, 60_000);

  test('host key substitution and attacker-signed proofs are refused', async () => {
    const original = { ...org };
    const attackerKeyId = await caseRecipientKeyId(attacker.toPublic());
    try {
      // Swapped key with a matching key ID: the enrolled member's key ID no longer matches.
      organizations.set(org.organizationId, { ...original, publicKey: attacker.toPublic().armor(), recipientKeyId: attackerKeyId });
      await expect(legal('read-state-keys', keysBody(), { key: attacker })).rejects.toThrow(denied);
      // Swapped key with the old key ID: the key ID is recomputed in the enclave.
      organizations.set(org.organizationId, { ...original, publicKey: attacker.toPublic().armor() });
      await expect(legal('read-state-keys', keysBody(), { key: attacker })).rejects.toThrow(denied);
      organizations.set(org.organizationId, { ...original, approved: false });
      await expect(legal('read-state-keys', keysBody())).rejects.toThrow(denied);
    } finally { organizations.set(org.organizationId, original); }
    // Valid token, genuine binding, but the proof is not signed by the firm key.
    await expect(legal('read-state-keys', keysBody(), { key: attacker })).rejects.toThrow(denied);
  }, 60_000);

  test('missing or malformed proofs, extra fields and wrong channel binding are refused', async () => {
    await expect(legal('read-state-keys', keysBody(), { request: ({ proof: _proof, ...rest }) => rest })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { request: value => ({ ...value, proof: '' }) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { request: value => ({ ...value, organizationId: org.organizationId }) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { request: value => ({ ...value, operation: 'legal.read-inbox' }) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { request: ({ accessToken: _token, ...rest }) => rest })).rejects.toThrow(denied);
    // A challenge issued in another session is refused, even with a proof bound to this one.
    const issuer = await session(), target = await session();
    const { challenge: foreign } = await exchange(issuer, { operation: 'legal.challenge' });
    const raw = encode(keysBody());
    await expect(exchange(target, { operation: 'legal.read-state-keys', accessToken: await token(),
      body: Buffer.from(raw).toString('base64'), proof: await signParticipantRequest({ audience: AUDIENCE, role: 'organization',
        caseId: prepared.caseId, organizationId: org.organizationId, operation: 'read-state-keys', body: raw, challenge: foreign,
        issuedAt: Date.now(), nonce: target.nonce, serverKeyId: target.serverKeyId }, firm) })).rejects.toThrow(denied);
    // Proof bound to another session's nonce and key cannot be replayed on this one.
    const elsewhere = await session();
    await expect(legal('read-state-keys', keysBody(), { proofSession: elsewhere })).rejects.toThrow(denied);
    await expect(exchange(await session(), { operation: 'legal.directory', accessToken: await token(), after: null, limit: 500 })).rejects.toThrow(denied);
    await expect(exchange(await session(), { operation: 'admin.read-private' })).rejects.toThrow(denied);
    await expect(exchange(await session(), { operation: 'legal.challenge' })).resolves.toHaveProperty('challenge');
  }, 60_000);

  test('one proof format: retired legal-operation envelopes are refused and the participant proof carries every binding', async () => {
    const raw = encode(keysBody()), body = Buffer.from(raw).toString('base64'), accessToken = await token();
    const detached = await sign({ message: await createMessage({ binary: raw }), signingKeys: firm, detached: true, format: 'armored' });
    const window = { issuedAt: Date.now(), expiresAt: Date.now() + 60_000 };
    for (const request of [
      { operation: 'case.request-access', accessToken, signature: detached, ...window, body },
      { operation: 'case.read', accessToken, signature: detached, ...window, body },
      { operation: 'legal.read-state-keys', accessToken, signature: detached, ...window, body },
      { operation: 'legal.read-state-keys', accessToken, proof: detached, body },
    ]) await expect(exchange(await session(), request)).rejects.toThrow(denied);
    // Organization (the retired organizationId/providerOrganizationId/recipientKeyId fields).
    await expect(legal('read-state-keys', keysBody(), { organizationId: otherOrg.organizationId })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { accessToken: await token({ org_id: 'org_other' }) })).rejects.toThrow(denied);
    // Case, exact body bytes and operation.
    await expect(legal('read-state-keys', keysBody(), { caseId: hex(0x999) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { request: value => ({ ...value,
      body: Buffer.from(encode({ caseId: prepared.caseId, extra: true })).toString('base64') }) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { request: value => ({ ...value, operation: 'legal.open-case' }) })).rejects.toThrow(denied);
    // Positive control: the same firm, token and body with a correctly bound proof.
    await expect(legal('read-state-keys', keysBody())).resolves.toBeDefined();
  }, 60_000);

  test('invitation redemption over the channel creates a usable membership', async () => {
    const token = randomBytes(32).toString('base64url');
    const tokenDigest = createHash('sha256').update(token, 'utf8').digest('hex');
    const expiresAt = Date.now() + 3_600_000;
    const authorization = await signMembershipAuthorization({ format: 'vera-membership-authorization/v1',
      organizationId: org.organizationId, providerOrganizationId: 'org_firm', subject: 'auth0|associate',
      recipientKeyId: org.recipientKeyId, issuedAt: Date.now(), expiresAt }, onboarding);
    invitations.set(tokenDigest, { authorization, format: 'vera-legal-enrollment/v1', invitationId: hex(0x501), organizationId: org.organizationId,
      providerOrganizationId: 'org_firm', subject: 'auth0|associate', recipientKeyId: org.recipientKeyId, nonce: hex(0x502),
      expiresAt, tokenDigest, createdAt: Date.now(), createdBy: 'auth0|admin', version: 1, state: 'pending' });
    const enrollToken = await token_({ sub: 'auth0|associate', scope: 'legal:enroll' });
    const call = (operation: string, body: unknown, accessToken = enrollToken) => session().then(channel => exchange(channel,
      { operation, accessToken, body: Buffer.from(JSON.stringify(body)).toString('base64') }));
    // Not yet a member: case operations are refused.
    await expect(legal('read-state-keys', keysBody(), { accessToken: await token_({ sub: 'auth0|associate' }) })).rejects.toThrow(denied);
    await expect(call('legal.enrollment-challenge', { token }, await token_({ sub: 'auth0|associate', scope: 'legal:case' }))).rejects.toThrow(denied);
    await expect(call('legal.enrollment-challenge', { token: 'x'.repeat(43) })).rejects.toThrow(denied);
    const challenge = await call('legal.enrollment-challenge', { token });
    expect(challenge).toMatchObject({ invitationId: hex(0x501), subject: 'auth0|associate', recipientKeyId: org.recipientKeyId });
    await expect(call('legal.enroll', { token, proof: await signEnrollmentChallenge(challenge, attacker).catch(() => 'bad') })).rejects.toThrow(denied);
    await expect(call('legal.enroll', { token, proof: await signEnrollmentChallenge(challenge, firm) }))
      .resolves.toEqual({ organizationId: org.organizationId, subject: 'auth0|associate', recipientKeyId: org.recipientKeyId });
    await expect(call('legal.enroll', { token, proof: await signEnrollmentChallenge(challenge, firm) })).rejects.toThrow(denied);
    await expect(legal('read-state-keys', keysBody(), { accessToken: await token_({ sub: 'auth0|associate' }) }))
      .resolves.toHaveProperty('stateEnvelopes');
  }, 60_000);

  test('members read their own onboarding status; tampered rows are refused, not reported as missing', async () => {
    const status = (accessToken: string, firmKey = { organizationId: org.organizationId, recipientKeyId: org.recipientKeyId }) =>
      readMembershipStatus({ relay, releaseManifest: MANIFEST, accessToken, firm: firmKey, now: Date.now() });
    const enrolled = await status(await token({ scope: 'legal:directory' }));
    expect(enrolled).toEqual({ state: 'enrolled', leaseExpiresAt: members.get('org_firm/auth0|lawyer')!.enrollment!.challenge.expiresAt,
      members: expect.any(Number), keyMatches: true });
    expect((enrolled as { members: number }).members).toBeGreaterThanOrEqual(1);
    // Another key held by the browser than the one the member enrolled with.
    await expect(status(await token(), { organizationId: org.organizationId, recipientKeyId: otherOrg.recipientKeyId }))
      .resolves.toMatchObject({ state: 'enrolled', keyMatches: false });
    await expect(status(await token({ sub: 'auth0|stranger' }))).resolves.toEqual({ state: 'not-enrolled' });
    // The host-counted number is informational: a failing count hides it, nothing else.
    countFailure = true;
    await expect(status(await token())).resolves.toMatchObject({ state: 'enrolled', members: null, keyMatches: true });
    countFailure = false;
    memberHook = value => value && { ...value, active: false };
    await expect(status(await token())).resolves.toEqual({ state: 'lapsed' });
    memberHook = value => value && { ...value, enrollment: { ...value.enrollment!, challenge: { ...value.enrollment!.challenge, expiresAt: Date.now() - 1 } } };
    await expect(status(await token())).resolves.toEqual({ state: 'lapsed' });
    memberHook = value => value && { ...value, recipientKeyId: otherOrg.recipientKeyId };
    await expect(status(await token())).rejects.toThrow('secure connection');
    memberHook = null;
    await expect(status(await token({}, rogueIssuer.privateKey))).rejects.toThrow('secure connection');
    await expect(status(await token({ scope: 'legal:case' }))).rejects.toThrow('secure connection');
    await expect(exchange(await session(), { operation: 'legal.membership', accessToken: await token(), organizationId: org.organizationId }))
      .rejects.toThrow(denied);
  }, 60_000);

  test('a grant that lapsed while the case is locked: unlock-case refuses the still-current key with not-granted', async () => {
    const asOther = async () => ({ accessToken: await token({ org_id: 'org_other' }), key: otherFirm, organizationId: otherOrg.organizationId });
    const now = Date.now();
    const ciphertext = await createLegalAccessRequest({ requestId: hex(0x302), scopes: ['narrative'], objectRevisionLimit: null,
      purpose: 'Short review', issuedAt: now, expiresAt: now + 86_400_000 }, otherOrg.organizationId, otherFirm, prepared.owner.trust);
    await expect(legal('request-access', { caseId: prepared.caseId, requestId: hex(0x302), ciphertext, expiresAt: now + 86_400_000 }, await asOther()))
      .resolves.toEqual({ state: 'requested' });
    otherOrg.bindingDocument = await createFirmKeyBinding({ domain: otherOrg.domain, organizationId: otherOrg.organizationId, issuedAt: now,
      profile: { practiceAreas: ['whistleblower'], jurisdiction: 'England and Wales', website: 'https://other.example/' } }, otherFirm);
    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const inbox = await readOwnerInbox(owner, Date.now());
    const roster = await verifiedRoster(owner, Date.now());
    const request = (await verifiedRequests(owner, inbox, roster, Date.now()))
      .find(item => item.request.organizationId === otherOrg.organizationId)!;
    const ends = Date.now() + 5_000;
    await allowAccess(owner, inbox, roster, request, { grantId: hex(0x402), scopes: ['narrative'], objectRevisionLimit: null, expiresAt: ends }, Date.now());
    await new Promise(resolve => setTimeout(resolve, Math.max(0, ends - Date.now()) + 500));

    // Locked after the end date, on the same checkpoint and key epoch: the stored
    // list is served, and this organization's own envelope still opens.
    keyring.delete(prepared.caseId);
    const { stateEnvelopes } = await legal('read-state-keys', keysBody(), await asOther());
    const state = await findCaseStateKey(stateEnvelopes, prepared.caseId, otherFirm, prepared.owner.trust.ownerPublicKey);
    // The enclave checks the grant, drops the key and answers so the portal can show "no access".
    await expect(legal('unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }, await asOther()))
      .resolves.toEqual({ error: 'not-granted' });
    expect(keyring.get(prepared.caseId)).toBeNull();
    await expect(legal('open-case', keysBody())).resolves.toEqual({ error: 'locked' });
    // A key that does not open the sealed state is still refused without an answer.
    await expect(legal('unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(new Uint8Array(32).fill(7)), stateEpoch: state.stateEpoch },
      await asOther())).rejects.toThrow(denied);
    // The organization with a current grant still unlocks with the same stored list.
    const current = await findCaseStateKey(stateEnvelopes, prepared.caseId, firm, prepared.owner.trust.ownerPublicKey);
    await expect(legal('unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(current.key), stateEpoch: current.stateEpoch }))
      .resolves.toEqual({ unlocked: true });
  }, 120_000);
});
