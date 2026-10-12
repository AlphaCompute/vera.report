import { createDeviceVault } from '../../../lib/confidential/deviceVault';
import type { VaultRecord, VaultStore } from '../../../lib/confidential/deviceVault';
import { signOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';
import { signMembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';
import { createHash, randomBytes, webcrypto } from 'node:crypto';

// Only the AWS quote check is mocked. JWTs, organization-key proofs, channel
// encryption, sealed storage, member envelopes and owner grants are real.
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

import * as jose from 'jose';
import { generateKey, readKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { findCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { firmMemberId, formatDeviceCode, rotateOrganizationKey, wrapOrganizationKeyForMember } from '../../../enclave/src/confidential/firmMembers';
import { FirmSharedListKeyChanged } from '../../../enclave/src/confidential/firmSharedList';
import type { SharedRequest } from '../../../enclave/src/confidential/firmSharedList';
import type { AccessRequestDetails } from '../../../enclave/src/confidential/accessRequest';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import * as participantProof from '../../../enclave/src/confidential/participantRequest';
import { sealChannelRequest } from '../../../enclave/src/confidential/channelMessage';
import { verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { LEGAL_ASSURANCE_CLAIM } from '../../../enclave/src/legal/identity';
import type { FirmEnrollmentBinding } from '../../../enclave/src/legal/enrollment';
import { signEnrollmentChallenge } from '../../../enclave/src/confidential/enrollmentProof';
import { createLegalCaseDispatcher } from '../../../enclave/src/cases/legalChannel';
import type { LegalMember, LegalMembershipStore } from '../../../enclave/src/cases/legalChannel';
import type { FirmDevice, LegalFirmStore } from '../../../enclave/src/cases/legalFirm';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import type { CaseRecord, CaseStore, StoredAccessRequest, StoredMessage, StoredObject } from '../../../enclave/src/cases/service';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { createCaseChannelDispatch } from '../../../enclave/src/confidential-server';
import { ConfidentialUnavailableError, RelayHttpError, RelayNetworkError, publishPreparedCase } from '../../../lib/confidential/client';
import { setAttestedTimeClocksForTests } from '../../../lib/confidential/attestedTime';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';
import type { ChannelRelay } from '../../../lib/confidential/client';
import { FirmCaseError, assertFirmSetupComplete, createFirmSession, openFirmCase, readLegalDirectory, requestCaseAccess, withdrawCaseRequest } from '../../../lib/confidential/firmCase';
import { readFirmSetup, recordFirmSetup } from '../../../lib/confidential/firmSetup';
import { FIRM_ONBOARDING_TERMS_VERSION, firmOnboardingTermsDigest, signFirmSetupStatement } from '../../../enclave/src/confidential/firmSetup';
import type { FirmSession } from '../../../lib/confidential/firmCase';
import type { FirmIdentity } from '../../../lib/confidential/firmKey';
import {
  enrollApprovedMemberDevice, inviteOrganizationMember, submitReplacementOrganizationKey, FirmMemberError, approveMemberDevice, createMemberDeviceKey, listMemberDevices, openApprovedDevice, readMemberDeviceStatus,
  registerMemberDevice, removeMemberDevice, rotateOrganizationAfterRemoval, unfinishedRemovals,
} from '../../../lib/confidential/firmMemberDevices';
import { SharedListRollbackError, moveSharedListToKey, readSharedList, updateSharedList } from '../../../lib/confidential/firmSharedRequests';
import { openLegalWorkspace, pendingDevicePayload, prepareStewardDevice } from '../../../lib/confidential/firmDeviceSession';
import { currentFirmDevice, currentFirmPayload, setFirmSession, setFirmVault } from '../../../lib/confidential/firmPortal';
import {
  allowAccess, currentGrantees, readOwnerInbox, readOwnerThreads, renewAccess, replacedKeyGrant, restoreOwnerSession, sendOwnerMessage,
  verifiedRequests, verifiedRoster,
} from '../../../lib/confidential/ownerCase';

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
const ORG = hex(0xf1), DOMAIN = 'counsel.example';
const DETAILS: AccessRequestDetails = { kind: 'new', conflictsChecked: true, feeBasis: 'no-fee', responseTime: 'one-week',
  practiceAreas: ['Employment'], jurisdiction: 'England and Wales', website: 'https://counsel.example/team' };

function memoryStore(organizations: Map<string, FirmEnrollmentBinding & { displayName: string; domain: string }>) {
  const challenges = new Map<string, number>(), cases = new Map<string, CaseRecord>(), staged = new Map<string, string>();
  const objects = new Map<string, StoredObject>(), envelopes = new Map<string, Record<string, string>>();
  const requests: StoredAccessRequest[] = [], messages: StoredMessage[] = [];
  const store = {
    staged,
    async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
    async putChallenge(challenge: string, expiresAt: number) { challenges.set(challenge, expiresAt); },
    async consumeChallenge(challenge: string, time: number) {
      const expiry = challenges.get(challenge); challenges.delete(challenge); return expiry !== undefined && expiry > time;
    },
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
      return [...organizations.values()].map(({ organizationId, displayName, domain, publicKey, approved }) =>
        ({ organizationId, displayName, domain, publicKey, approved }));
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

/** TEST-ONLY untrusted host rows for member devices and the shared list. */
function firmStore(members: Map<string, LegalMember>) {
  const devices = new Map<string, FirmDevice>();
  const lists = new Map<string, { version: number; record: string }>();
  const setup = new Map<string, { custody: string | null; terms: string | null }>();
  let beforeListWrite: (() => Promise<void>) | null = null;
  const store: LegalFirmStore & { devices: typeof devices; lists: typeof lists; setup: typeof setup; hook(fn: (() => Promise<void>) | null): void } = {
    async putFirmDeviceMembership(value) {
      const delegated = value.enrollment.delegation!;
      const found = devices.get(`${value.organizationId}/${delegated.memberId}`);
      if (!found || found.state !== 'approved' || found.deviceFingerprint !== delegated.deviceFingerprint) return false;
      const key = `${value.providerOrganizationId}/${value.subject}`;
      members.set(key, { ...value, active: true, revision: (members.get(key)?.revision ?? 0) + 1 });
      return true;
    },
    devices, lists, setup,
    async getOrganizationSetup(organizationId) { const found = setup.get(organizationId); return found ? clone(found) : null; },
    async putOrganizationSetup(organizationId, kind, statement) {
      setup.set(organizationId, { ...(setup.get(organizationId) ?? { custody: null, terms: null }), [kind]: statement }); return true;
    },
    hook(fn) { beforeListWrite = fn; },
    async listFirmDevices(organizationId) { return [...devices.values()].filter(item => item.organizationId === organizationId).map(clone); },
    async getFirmDevice(organizationId, memberId) { const found = devices.get(`${organizationId}/${memberId}`); return found ? clone(found) : null; },
    async putFirmDevice(device, expectedRevision) {
      const key = `${device.organizationId}/${device.memberId}`, found = devices.get(key);
      if ((found?.revision ?? 0) !== expectedRevision || device.revision !== expectedRevision + 1) return false;
      devices.set(key, clone(device)); return true;
    },
    async removeFirmDevice(device, expectedRevision) {
      const key = `${device.organizationId}/${device.memberId}`, found = devices.get(key);
      if (!found || found.state === 'removed' || found.revision !== expectedRevision || device.revision !== expectedRevision + 1) return false;
      const memberKey = `${device.providerOrganizationId}/${device.subject}`, member = members.get(memberKey);
      if (member && member.organizationId === device.organizationId && member.active) members.set(memberKey, { ...member, active: false, revision: member.revision + 1 });
      devices.set(key, clone(device)); return true;
    },
    async getFirmSharedList(organizationId) { const found = lists.get(organizationId); return found ? clone(found) : null; },
    async putFirmSharedList(organizationId, expectedVersion, next) {
      if (beforeListWrite) { const run = beforeListWrite; beforeListWrite = null; await run(); }
      if ((lists.get(organizationId)?.version ?? 0) !== expectedVersion || next.version !== expectedVersion + 1) return false;
      lists.set(organizationId, clone(next)); return true;
    },
  };
  return store;
}

describe('firm member devices, removal with key rotation, and the shared request list', () => {
  let issuer: jose.GenerateKeyPairResult, onboarding: PrivateKey, firmKey: PrivateKey, attacker: PrivateKey;
  let org: FirmEnrollmentBinding & { displayName: string; domain: string };
  let relay: ChannelRelay, backing: ReturnType<typeof memoryStore>, firm: ReturnType<typeof firmStore>;
  let prepared: Awaited<ReturnType<typeof prepareConfidentialSubmission>>;
  let sessions: ReturnType<typeof createSessionCore>, aliceDevice: PrivateKey;
  let carol: { device: PrivateKey; memberId: string; saved: unknown; deps: Parameters<typeof openLegalWorkspace>[1] };
  const organizations = new Map<string, FirmEnrollmentBinding & { displayName: string; domain: string }>();
  const members = new Map<string, LegalMember>();
  const membership: LegalMembershipStore = {
    async getMember(subject, providerOrganizationId) { const found = members.get(`${providerOrganizationId}/${subject}`); return found ? clone(found) : null; },
    async getOrganization(organizationId) {
      const found = organizations.get(organizationId);
      if (!found) return null;
      const { organizationId: id, providerOrganizationId, recipientKeyId, publicKey, approved, registration } = found;
      return { organizationId: id, providerOrganizationId, recipientKeyId, publicKey, approved, registration };
    },
  };

  async function token(sub: string, scope = 'legal:directory legal:case legal:enroll') {
    const iat = Math.floor(Date.now() / 1000);
    return new jose.SignJWT({ iss: ISSUER, aud: IDENTITY.audience, azp: IDENTITY.clientId, sub, org_id: 'org_firm', scope,
      iat, exp: iat + 300, [LEGAL_ASSURANCE_CLAIM]: 'approved-member-verified-email' })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key' }).sign(issuer.privateKey);
  }
  /** VERA onboarding registers (or re-registers) the organization key. */
  async function register(key: PrivateKey) {
    org = { organizationId: ORG, providerOrganizationId: 'org_firm', recipientKeyId: await caseRecipientKeyId(key.toPublic()),
      publicKey: key.toPublic().armor(), approved: true, displayName: 'Synthetic Counsel LLP', domain: DOMAIN };
    org.registration = await signOrganizationRegistration({ format: 'vera-organization-registration/v1', ...org, issuedAt: Date.now() }, onboarding);
    organizations.set(ORG, org);
  }
  /** Invitation redemption result: an enrolled member row for this subject and key. */
  async function enroll(subject: string, key: PrivateKey) {
    const recipientKeyId = await caseRecipientKeyId(key.toPublic());
    const challenge = { format: 'vera-legal-enrollment/v1' as const, invitationId: hex(50), nonce: hex(51), organizationId: ORG,
      recipientKeyId, providerOrganizationId: 'org_firm', subject, expiresAt: Date.now() + 86_400_000 };
    const previous = members.get(`org_firm/${subject}`);
    members.set(`org_firm/${subject}`, { subject, providerOrganizationId: 'org_firm', organizationId: ORG, recipientKeyId,
      revision: (previous?.revision ?? 0) + 1, active: true, enrollment: { challenge, proof: await signEnrollmentChallenge(challenge, key),
        authorization: await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId: ORG,
          providerOrganizationId: 'org_firm', subject, recipientKeyId, issuedAt: Date.now(), expiresAt: challenge.expiresAt }, onboarding) } });
  }
  const identity = async (key: PrivateKey): Promise<FirmIdentity> =>
    ({ organizationId: ORG, domain: DOMAIN, privateKey: key, recipientKeyId: await caseRecipientKeyId(key.toPublic()) });
  async function session(key: PrivateKey, subject: string): Promise<FirmSession> {
    return createFirmSession({ relay, releaseManifest: MANIFEST, firm: await identity(key), accessToken: () => token(subject) });
  }
  async function exchange(request: unknown): Promise<any> {
    const nonce = randomBytes(32).toString('hex');
    const evidence = await relay.open(nonce);
    const serverKey = await readKey({ binaryKey: evidence.publicKey });
    const pending = await sealChannelRequest(serverKey, nonce, encode(request));
    return JSON.parse(new TextDecoder().decode(await pending.openResponse(await relay.call(nonce, pending.ciphertext))));
  }
  async function join(subject: string, name: string) {
    const device = await createMemberDeviceKey();
    const status = await registerMemberDevice({ relay, releaseManifest: MANIFEST, accessToken: await token(subject, 'legal:enroll'),
      now: Date.now(), organizationId: ORG, organizationPublicKey: firmKey.toPublic(), device, profile: { name, contact: `${name}@counsel.example` } });
    return { device, status };
  }
  const status = async (subject: string) => readMemberDeviceStatus({ relay, releaseManifest: MANIFEST,
    accessToken: await token(subject, 'legal:enroll'), now: Date.now(), organizationId: ORG });

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    issuer = await jose.generateKeyPair('RS256');
    const jwks = { keys: [{ ...await jose.exportJWK(issuer.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer-key' }] };
    const pair = async (name: string) => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey;
    [onboarding, firmKey, attacker] = await Promise.all([pair('Synthetic onboarding'), pair('Synthetic firm'), pair('Synthetic attacker')]);
    await register(firmKey);
    await enroll('auth0|steward', firmKey);
    backing = memoryStore(organizations);
    firm = firmStore(members);
    const keyring = createCaseKeyring({ clock: Date.now });
    const options = { store: createSealedCaseStore(backing as unknown as CaseStore, keyring), keyring, clock: Date.now, audience: AUDIENCE,
      releaseDigest: (await readReleaseManifest(MANIFEST)).digest };
    const dispatch = createCaseChannelDispatch(createOwnerCaseControlDispatcher(options),
      createLegalCaseDispatcher({ ...options, identity: { ...IDENTITY, jwks }, members: membership, firm,
        administration: { identity: { ...IDENTITY, audience: 'admin-api', clientId: 'admin-client', jwks }, organizationId: 'org_admin',
          onboardingPublicKey: onboarding.toPublic().armor() } }));
    const channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
    sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(channelKey.privateKey,
      { nonce, publicKey: Buffer.from(channelKey.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => 1);
    relay = {
      async stage(ciphertext) {
        const digest = createHash('sha256').update(ciphertext, 'utf8').digest('hex');
        backing.staged.set(digest, ciphertext);
        return digest;
      },
      async open(nonce) {
        const opened = await sessions.open(nonce);
        return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(opened.publicKey, 'base64')) };
      },
      async call(nonce, ciphertext, last) { return sessions.execute(nonce, ciphertext, { last }); },
    };
    prepared = await prepareConfidentialSubmission({ summary: 'Firm-visible summary', narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE' },
      contact: null, identity: null, files: [] }, MANIFEST, Date.now());
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now: Date.now(), prepared });
    const initial = await session(firmKey, 'auth0|steward');
    await recordFirmSetup(initial, 'custody', Date.now());
    await recordFirmSetup(initial, 'terms', Date.now());
  }, 180_000);
  afterAll(() => { sessions?.close(); setFirmSession(null); });

  test('a large valid device roster stays readable over bounded channel replies', async () => {
    const saved = new Map(firm.devices);
    const now = Date.now(), key = attacker.toPublic();
    try {
      for (let i = 0; i < 64; i++) {
        const subject = `auth0|large-roster-${i}`, memberId = await firmMemberId('org_firm', subject);
        firm.devices.set(`${ORG}/${memberId}`, { organizationId: ORG, memberId, subject, providerOrganizationId: 'org_firm',
          devicePublicKey: key.armor(), deviceFingerprint: key.getFingerprint(),
          profile: '-----BEGIN PGP MESSAGE-----'.padEnd(8192, '\u0000'), state: 'pending', envelope: null, continuity: null,
          keyEpoch: null, revision: 1, registeredAt: now + (63 - i), updatedAt: now + (63 - i) });
      }
      const devices = await listMemberDevices(await session(firmKey, 'auth0|steward'), now);
      expect(devices).toHaveLength(64);
      expect(new Set(devices.map(device => device.memberId)).size).toBe(64);
      expect(devices.every(device => device.profile === null)).toBe(true);
      expect(devices.map(device => device.registeredAt)).toEqual(Array.from({ length: 64 }, (_, i) => now + i));
      const accessToken = await token('auth0|steward');
      const first = await exchange({ operation: 'legal.members', accessToken,
        body: Buffer.from(encode({ organizationId: ORG })).toString('base64') });
      expect(first.next).toEqual(expect.any(String));
      expect(Buffer.byteLength(JSON.stringify(first))).toBeLessThan(200 * 1024);
      const changed = firm.devices.values().next().value!;
      firm.devices.set(`${ORG}/${changed.memberId}`, { ...changed, revision: changed.revision + 1 });
      await expect(exchange({ operation: 'legal.members', accessToken,
        body: Buffer.from(encode({ organizationId: ORG, cursor: first.next })).toString('base64') }))
        .resolves.toEqual({ error: 'roster-changed' });
      const originalList = firm.listFirmDevices.bind(firm);
      let reads = 0;
      const list = jest.spyOn(firm, 'listFirmDevices').mockImplementation(async organizationId => {
        if (++reads === 2) {
          const current = firm.devices.get(`${ORG}/${changed.memberId}`)!;
          firm.devices.set(`${ORG}/${changed.memberId}`, { ...current, revision: current.revision + 1 });
        }
        return originalList(organizationId);
      });
      try {
        const refreshed = await listMemberDevices(await session(firmKey, 'auth0|steward'), now);
        expect(refreshed).toHaveLength(64);
        expect(new Set(refreshed.map(device => device.memberId)).size).toBe(64);
        expect(refreshed.find(device => device.memberId === changed.memberId)?.revision).toBe(changed.revision + 2);
        // Repeated changes must fail after one restart, never loop indefinitely.
        list.mockImplementation(async organizationId => {
          const current = firm.devices.get(`${ORG}/${changed.memberId}`)!;
          firm.devices.set(`${ORG}/${changed.memberId}`, { ...current, revision: current.revision + 1 });
          return originalList(organizationId);
        });
        list.mockClear();
        await expect(listMemberDevices(await session(firmKey, 'auth0|steward'), now)).rejects.toThrow();
        expect(list).toHaveBeenCalledTimes(4);
      } finally { list.mockRestore(); }
      // Exact-byte public key caching must never preserve a stale fingerprint
      // when the untrusted host changes a previously seen row's key.
      const current = firm.devices.get(`${ORG}/${changed.memberId}`)!;
      firm.devices.set(`${ORG}/${changed.memberId}`, { ...current, devicePublicKey: firmKey.toPublic().armor() });
      await expect(exchange({ operation: 'legal.members', accessToken,
        body: Buffer.from(encode({ organizationId: ORG })).toString('base64') })).rejects.toThrow();
      firm.devices.set(`${ORG}/${changed.memberId}`, { ...current, devicePublicKey: attacker.armor() });
      await expect(exchange({ operation: 'legal.members', accessToken,
        body: Buffer.from(encode({ organizationId: ORG })).toString('base64') })).rejects.toThrow();
    } finally { firm.devices.clear(); for (const [id, device] of saved) firm.devices.set(id, device); }
  }, 120_000);

  test('the initial steward bootstraps a renewable device without another platform invitation', async () => {
    const savedDevices = new Map(firm.devices), savedMember = clone(members.get('org_firm/auth0|steward')!);
    try {
      const steward = await session(firmKey, 'auth0|steward');
      setFirmSession(steward);
      await expect(prepareStewardDevice(steward, Date.now())).resolves.toBeNull();
      expect(firm.devices.size).toBe(savedDevices.size);
      const records = new Map<string, VaultRecord>();
      const vaultStore: VaultStore = { generation: async () => 0, list: async () => [...records.values()],
        get: async id => records.get(id) ?? null, put: async record => { records.set(record.id, record); },
        remove: async id => { records.delete(id); }, clear: async () => { records.clear(); } };
      const vault = await createDeviceVault(vaultStore, 'legal', 'synthetic long steward backup passphrase', currentFirmPayload());
      setFirmVault(vault);
      const local = await prepareStewardDevice(steward, Date.now());
      if (!local) throw new Error('Expected consented device bootstrap');
      expect((await prepareStewardDevice(steward, Date.now()))?.privateKey.getFingerprint()).toBe(local.privateKey.getFingerprint());
      expect(vault.read()).toMatchObject({ device: { memberId: local.memberId } });
      expect(members.get('org_firm/auth0|steward')?.enrollment?.delegation?.memberId).toBe(local.memberId);
      const saved = clone(currentFirmPayload());
      expect(saved.device?.memberId).toBe(local.memberId);
      // The member lease can lapse while the approved device remains authorized.
      const lapsed = clone(members.get('org_firm/auth0|steward')!);
      lapsed.enrollment!.challenge.expiresAt = Date.now() - 1;
      members.set('org_firm/auth0|steward', lapsed);
      await expect(readLegalDirectory(steward, null, Date.now())).rejects.toThrow();
      const reopened = await openLegalWorkspace(saved, { relay, releaseManifest: MANIFEST,
        accessToken: () => token('auth0|steward'), published: async () => firmKey.toPublic(),
        start: async firm => createFirmSession({ relay, releaseManifest: MANIFEST, firm, accessToken: () => token('auth0|steward') }) }, null);
      await expect(readLegalDirectory(reopened.session, null, Date.now())).resolves.toBeDefined();
      const row = firm.devices.get(`${ORG}/${local.memberId}`)!;
      firm.devices.set(`${ORG}/${local.memberId}`, { ...row, state: 'removed', envelope: null, continuity: null });
      await expect(enrollApprovedMemberDevice({ relay, releaseManifest: MANIFEST, accessToken: await token('auth0|steward'),
        now: Date.now(), firm: await identity(firmKey), device: local.privateKey, memberId: local.memberId })).rejects.toThrow();
    } finally {
      firm.devices.clear(); for (const [key, value] of savedDevices) firm.devices.set(key, value);
      members.set('org_firm/auth0|steward', savedMember); setFirmSession(null);
    }
  }, 120_000);

  test('replacement candidates require live enrollment and a fresh current-key proof', async () => {
    const writes: unknown[] = [], original = firm.submitLegalOrganizationKeyCandidate;
    firm.submitLegalOrganizationKeyCandidate = async value => { writes.push(value); };
    try {
      // The holder of the registered key rotates it: the continuity statement is
      // signed by the registered key and the new one.
      const rotated = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: Date.now() }, firmKey);
      const next = await identity(rotated.organizationKey);
      const document = await createFirmKeyBinding({ organizationId: ORG, domain: DOMAIN, issuedAt: Date.now() }, rotated.organizationKey);
      const continuity = rotated.continuity;
      // Without continuity from the registered key, even an enrolled steward's
      // fresh proof cannot propose a key: a forged or mismatched statement fails.
      const forgedRotation = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: Date.now() }, attacker);
      await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, document, forgedRotation.continuity, Date.now())).rejects.toThrow();
      await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, document, '{}', Date.now())).rejects.toThrow();
      const otherNext = await createFirmKeyBinding({ organizationId: ORG, domain: DOMAIN, issuedAt: Date.now() }, attacker);
      await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), await identity(attacker), otherNext, continuity, Date.now())).rejects.toThrow();
      expect(writes).toHaveLength(0);
      await submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, document, continuity, Date.now());
      expect(writes).toEqual([expect.objectContaining({ subject: 'auth0|steward', recipientKeyId: next.recipientKeyId,
        previousRecipientKeyId: await caseRecipientKeyId(firmKey.toPublic()), bindingDocument: document, continuity })]);
      const sign = participantProof.signParticipantRequest;
      let captured = '';
      const signer = jest.spyOn(participantProof, 'signParticipantRequest').mockImplementation(async (...args) => {
        captured = await sign(...args); return captured;
      });
      try {
        await submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, document, continuity, Date.now());
        signer.mockResolvedValue(captured);
        await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, document, continuity, Date.now())).rejects.toThrow();
      } finally { signer.mockRestore(); }
      await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|not-enrolled'), next, document, continuity, Date.now())).rejects.toThrow();
      // A valid login and self-signed replacement are insufficient without the old key.
      const forged = { ...await session(firmKey, 'auth0|steward'), firm: { ...await identity(firmKey), privateKey: attacker } };
      await expect(submitReplacementOrganizationKey(forged, next, document, continuity, Date.now())).rejects.toThrow();
      const foreign = await createFirmKeyBinding({ organizationId: hex(999), domain: DOMAIN, issuedAt: Date.now() }, attacker);
      await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, foreign, continuity, Date.now())).rejects.toThrow();
      const steward = members.get('org_firm/auth0|steward')!;
      members.set('org_firm/auth0|steward', { ...steward, active: false });
      try { await expect(submitReplacementOrganizationKey(await session(firmKey, 'auth0|steward'), next, document, continuity, Date.now())).rejects.toThrow(); }
      finally { members.set('org_firm/auth0|steward', steward); }
      expect(writes).toHaveLength(2);
      expect(organizations.get(ORG)?.recipientKeyId).toBe(await caseRecipientKeyId(firmKey.toPublic()));
    } finally { firm.submitLegalOrganizationKeyCandidate = original; }
  });

  test('only an enrolled steward with the firm key can invite an exact-domain colleague', async () => {
    const requests: unknown[] = [];
    const original = firm.inviteLegalOrganizationMember;
    firm.inviteLegalOrganizationMember = async value => { requests.push(value); return { invited: true }; };
    try {
      const steward = await session(firmKey, 'auth0|steward');
      await inviteOrganizationMember(steward, 'New.Lawyer@COUNSEL.EXAMPLE', Date.now());
      expect(requests).toEqual([{ organizationId: ORG, providerOrganizationId: 'org_firm', domain: DOMAIN, email: 'new.lawyer@counsel.example' }]);
      await expect(inviteOrganizationMember(steward, 'lawyer@other.example', Date.now())).rejects.toThrow();
      await expect(inviteOrganizationMember(steward, 'lawyer@sub.counsel.example', Date.now())).rejects.toThrow();
      await expect(inviteOrganizationMember(await session(attacker, 'auth0|steward'), 'lawyer@counsel.example', Date.now())).rejects.toThrow();
      await expect(inviteOrganizationMember(await session(firmKey, 'auth0|not-enrolled'), 'lawyer@counsel.example', Date.now())).rejects.toThrow();
      expect(requests).toHaveLength(1);
      expect(members.has('org_firm/auth0|new-lawyer')).toBe(false);
    } finally { firm.inviteLegalOrganizationMember = original; }
  });

  test('a new lawyer is approved only after the steward sees their device, and receives exactly the organization key', async () => {
    const { device, status: registered } = await join('auth0|alice', 'Synthetic Alice');
    aliceDevice = device;
    expect(registered).toMatchObject({ state: 'pending', memberId: await firmMemberId('org_firm', 'auth0|alice'), envelope: null });
    // The host holds the public device key and ciphertext only.
    expect(JSON.stringify([...firm.devices.values()])).not.toContain('Synthetic Alice');
    // Registering the same device again is idempotent.
    await expect(registerMemberDevice({ relay, releaseManifest: MANIFEST, accessToken: await token('auth0|alice', 'legal:enroll'),
      now: Date.now(), organizationId: ORG, organizationPublicKey: firmKey.toPublic(), device, profile: { name: 'Synthetic Alice', contact: '' } }))
      .resolves.toMatchObject({ state: 'pending' });

    // Not yet a member: cannot see or manage the organization's devices.
    await expect(listMemberDevices(await session(firmKey, 'auth0|alice'), Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);

    const steward = await session(firmKey, 'auth0|steward');
    const [pending] = (await listMemberDevices(steward, Date.now())).filter(item => item.state === 'pending');
    expect(pending.profile).toEqual({ name: 'Synthetic Alice', contact: 'Synthetic Alice@counsel.example' });
    expect(pending.deviceCode).toBe(formatDeviceCode(device.getFingerprint()));
    await approveMemberDevice(steward, pending, 1, Date.now());
    // A replayed approval (old revision) is refused.
    await expect(approveMemberDevice(steward, pending, 1, Date.now())).rejects.toBeInstanceOf(FirmMemberError);

    const approved = await status('auth0|alice');
    expect(approved).toMatchObject({ state: 'approved', keyEpoch: 1, continuity: null });
    const opened = await openApprovedDevice(approved, { organizationId: ORG, device, minimumKeyEpoch: 0, published: async () => firmKey.toPublic() });
    expect(opened.organizationKey.getFingerprint()).toBe(firmKey.getFingerprint());
    // Against a different "published" key (for example a substituted directory row) it does not open.
    await expect(openApprovedDevice(approved, { organizationId: ORG, device, minimumKeyEpoch: 0, published: async () => attacker.toPublic() }))
      .rejects.toMatchObject({ code: 'key-mismatch' });
    // Another device cannot open this envelope.
    await expect(openApprovedDevice(approved, { organizationId: ORG, device: attacker, minimumKeyEpoch: 0,
      published: async () => firmKey.toPublic() })).rejects.toBeInstanceOf(FirmMemberError);
  }, 120_000);

  test('an invited colleague signs in, receives device approval and requests access without VERA per-person enrollment', async () => {
    const inviter = await session(firmKey, 'auth0|steward');
    firm.inviteLegalOrganizationMember = async () => ({ invited: true });
    await inviteOrganizationMember(inviter, 'carol@counsel.example', Date.now());
    const { device, status: registered } = await join('auth0|carol', 'Synthetic Carol');
    const payload = pendingDevicePayload({ organizationId: ORG, domain: DOMAIN, memberId: registered.memberId, device, registeredAt: Date.now() });
    const deps = { relay, releaseManifest: MANIFEST, accessToken: () => token('auth0|carol', 'legal:enroll'),
      start: async (value: FirmIdentity) => { const created = await createFirmSession({ relay, releaseManifest: MANIFEST, firm: value,
        accessToken: () => token('auth0|carol') }); setFirmSession(created); return created; },
      published: async () => firmKey.toPublic() };
    await expect(openLegalWorkspace(payload, deps, null)).rejects.toMatchObject({ name: 'PendingDeviceError' });
    await expect(enrollApprovedMemberDevice({ relay, releaseManifest: MANIFEST, accessToken: await token('auth0|carol'),
      now: Date.now(), firm: await identity(firmKey), device, memberId: registered.memberId })).rejects.toThrow();
    const steward = await session(firmKey, 'auth0|steward');
    const pending = (await listMemberDevices(steward, Date.now())).find(item => item.memberId === registered.memberId)!;
    await approveMemberDevice(steward, pending, 1, Date.now());
    const opened = await openLegalWorkspace(payload, deps, null);
    expect(opened.session.firm.recipientKeyId).toBe(org.recipientKeyId);
    expect(members.get('org_firm/auth0|carol')?.enrollment?.delegation?.memberId).toBe(registered.memberId);
    const directory = await readLegalDirectory(opened.session, null, Date.now());
    const listing = directory.listings.find(item => item.caseId === prepared.caseId)!;
    const requested = await requestCaseAccess(opened.session, listing, { purpose: 'Colleague intake', scopes: ['narrative'], details: DETAILS }, Date.now());
    await withdrawCaseRequest(opened.session, prepared.caseId, requested.requestId, Date.now());
    expect(currentFirmDevice()).toMatchObject({ memberId: registered.memberId, keyEpoch: 1 });
    const saved = currentFirmPayload();
    expect(saved.device).toMatchObject({ memberId: registered.memberId, keyEpoch: 1 });
    // The saved workspace reopens with the device key intact.
    const reopened = await openLegalWorkspace(clone(saved), deps, null);
    expect(currentFirmDevice()?.privateKey.getFingerprint()).toBe(device.getFingerprint());
    expect(reopened.notice).toBeNull();
    carol = { device, memberId: registered.memberId, saved: clone(saved), deps };
  }, 120_000);

  test('members share one request list; concurrent writers merge, rollback and foreign keys are refused', async () => {
    await enroll('auth0|second', firmKey);
    const steward = await session(firmKey, 'auth0|steward'), second = await session(firmKey, 'auth0|second');
    const entry = (caseId: string): SharedRequest => ({ caseId, requestId: hex(0x700), ownerPublicKey: prepared.owner.trust.ownerPublicKey.armor(),
      summary: 'Firm-visible summary', requestedAt: Date.now(), expiresAt: Date.now() + 86_400_000, recipientKeyId: org.recipientKeyId,
      state: 'requested', updatedAt: Date.now(), grantExpiresAt: null });
    const first = await updateSharedList(steward, 0, list => ({ ...list, requests: [...list.requests, entry(hex(0x801))] }), Date.now());
    expect(first.version).toBe(1);
    const older = clone(firm.lists.get(ORG)!);
    expect((await readSharedList(second, 0, Date.now())).list.requests.map(item => item.caseId)).toEqual([hex(0x801)]);
    expect(firm.lists.get(ORG)!.record).not.toContain('Firm-visible summary');

    // Another member writes between this member's read and write: the change is re-applied.
    firm.hook(async () => { await updateSharedList(second, 1, list => ({ ...list, requests: [...list.requests, entry(hex(0x802))] }), Date.now()); });
    const merged = await updateSharedList(steward, 1, list => ({ ...list, requests: [...list.requests, entry(hex(0x803))] }), Date.now());
    expect(merged.version).toBe(3);
    expect(merged.list.requests.map(item => item.caseId).sort()).toEqual([hex(0x801), hex(0x802), hex(0x803)]);

    // The host replays an older stored list: a device that saw version 3 refuses it.
    const newest = clone(firm.lists.get(ORG)!);
    firm.lists.set(ORG, older);
    await expect(readSharedList(second, 3, Date.now())).rejects.toBeInstanceOf(SharedListRollbackError);
    await expect(updateSharedList(second, 3, list => ({ ...list, requests: [] }), Date.now())).rejects.toBeInstanceOf(SharedListRollbackError);
    firm.lists.delete(ORG);
    await expect(readSharedList(second, 3, Date.now())).rejects.toBeInstanceOf(SharedListRollbackError);
    firm.lists.set(ORG, newest);

    // A key that is not the registered organization key cannot write, even as an enrolled member.
    await expect(updateSharedList(await session(attacker, 'auth0|second'), 3, list => ({ ...list, requests: [] }), Date.now()))
      .rejects.toBeInstanceOf(ConfidentialUnavailableError);
    expect(firm.lists.get(ORG)!.version).toBe(3);
  }, 120_000);

  test('shared-list and directory reads reuse the workspace channel; an ambiguous list write is never replayed', async () => {
    const steward = await session(firmKey, 'auth0|steward');
    let opens = 0, writeAttempts = 0, writeNonce = '', dropVersion = 0, dropped = false;
    steward.relay = { ...relay,
      async open(nonce) { if (++opens === 2) writeNonce = nonce; return relay.open(nonce); },
      async call(nonce, ciphertext, last) {
        if (nonce === writeNonce) writeAttempts++;
        const reply = await relay.call(nonce, ciphertext, last);
        if (!dropped && dropVersion && firm.lists.get(ORG)?.version === dropVersion) {
          dropped = true;
          throw new RelayHttpError(503); // Drop the committed write's reply, not a cleanup frame.
        }
        return reply;
      },
    };
    const stored = clone(firm.lists.get(ORG)!);
    try {
      await readSharedList(steward, 0, Date.now());
      await readLegalDirectory(steward, null, Date.now());
      await readSharedList(steward, 0, Date.now());
      expect(opens).toBe(1);
      dropVersion = stored.version + 1;
      await expect(updateSharedList(steward, stored.version, list => ({ ...list,
        requests: list.requests.map(item => ({ ...item, summary: 'Updated synthetic summary' })),
      }), Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
      expect(firm.lists.get(ORG)!.version).toBe(stored.version + 1);
      expect(dropped).toBe(true);
      expect(writeAttempts).toBe(1);
      expect(opens).toBe(2); // The non-replayable write starts on a fresh channel.
    } finally { firm.lists.set(ORG, stored); }
  });

  test('a shared-list write opens a protected fresh session after its cached read session is reclaimed', async () => {
    const steward = await session(firmKey, 'auth0|steward');
    let opens = 0, calls = 0, retirements = 0;
    steward.relay = { ...relay,
      async open(nonce) { opens++; return relay.open(nonce); },
      async call(nonce, ciphertext, last) {
        if (last) { retirements++; return relay.call(nonce, ciphertext, last); }
        calls++;
        if (calls === 2) expect(sessions.release(nonce)).toBe(false); // Fresh session protects its first request.
        const reply = await relay.call(nonce, ciphertext, last);
        // Another workspace behind the same address needs the idle lease while
        // this device decrypts the read and seals its next compare-and-set write.
        if (calls === 1) expect(sessions.release(nonce)).toBe(true);
        return reply;
      },
    };
    const stored = clone(firm.lists.get(ORG)!);
    try {
      await expect(updateSharedList(steward, stored.version, list => ({ ...list,
        requests: list.requests.map(item => ({ ...item, summary: 'Synthetic reclaimed-session update' })),
      }), Date.now())).resolves.toMatchObject({ version: stored.version + 1 });
      expect(opens).toBe(2);
      expect(calls).toBe(2); // Read once, write once; no mutation replay.
      expect(retirements).toBe(1); // A failed close of the already-reclaimed session does not block the write.
    } finally { firm.lists.set(ORG, stored); }
  });

  test('setup checks share the workspace channel and signed writes use attested time without replay', async () => {
    const steward = await session(firmKey, 'auth0|steward');
    let opens = 0, calls = 0, dropAt = 0;
    steward.relay = { ...relay,
      async open(nonce) { opens++; return relay.open(nonce); },
      async call(nonce, ciphertext, last) {
        const number = ++calls;
        const reply = await relay.call(nonce, ciphertext, last);
        if (number === dropAt) throw new RelayHttpError(503);
        return reply;
      },
    };
    const saved = clone(firm.setup.get(ORG)!);
    const skew = 120_000;
    setAttestedTimeClocksForTests({ device: () => Date.now() + skew, monotonic: () => performance.now() });
    try {
      await Promise.all(Array.from({ length: 8 }, () => readFirmSetup(steward, Date.now())));
      await readLegalDirectory(steward, null, Date.now());
      expect(opens).toBe(1);
      const now = Date.now();
      const status = await recordFirmSetup(steward, 'terms', now + skew);
      expect(status.terms!.acknowledgedAt).toBeGreaterThanOrEqual(now - 1_000);
      expect(status.terms!.acknowledgedAt).toBeLessThan(now + 60_000);
      const before = firm.setup.get(ORG)!.terms;
      dropAt = calls + 1;
      await expect(recordFirmSetup(steward, 'terms', Date.now() + skew)).rejects.toBeInstanceOf(ConfidentialUnavailableError);
      expect(firm.setup.get(ORG)!.terms).not.toBe(before);
      expect(calls).toBe(dropAt);
      expect(opens).toBe(1);
    } finally { firm.setup.set(ORG, saved); setAttestedTimeClocksForTests(undefined); }
  });

  test('a relay outage while reading the shared request list is reported as unavailable, never as a verification failure', async () => {
    const working = await session(firmKey, 'auth0|steward');
    const reason = async (promise: Promise<unknown>) => {
      const caught = await promise.then(() => null, (error: unknown) => error);
      expect(caught).toBeInstanceOf(ConfidentialUnavailableError);
      return (caught as ConfidentialUnavailableError).reason;
    };
    const failing = (failure: () => Error, where: 'open' | 'call'): FirmSession => ({ ...working, relay: {
      ...relay,
      async open(nonce) { if (where === 'open') throw failure(); return relay.open(nonce); },
      async call(nonce, ciphertext, last) { if (where === 'call') throw failure(); return relay.call(nonce, ciphertext, last); },
    } });
    for (const where of ['open', 'call'] as const) {
      expect(await reason(readSharedList(failing(() => new RelayHttpError(503), where), 0, Date.now()))).toBe('unavailable');
      expect(await reason(readSharedList(failing(() => new RelayNetworkError(), where), 0, Date.now()))).toBe('offline');
      expect(await reason(readSharedList(failing(() => new ConfidentialRateLimitError(null), where), 0, Date.now()))).toBe('busy');
      expect(await reason(updateSharedList(failing(() => new RelayHttpError(503), where), 0, list => list, Date.now()))).toBe('unavailable');
    }
    // A reply that does not decrypt under the verified channel is still a verification failure.
    const garbled: FirmSession = { ...working, relay: { ...relay, async call() { return 'not-a-sealed-reply'; } } };
    expect(await reason(readSharedList(garbled, 0, Date.now()))).toBe('verification');
  });

  test('the key-holder count refuses an oversized host device list instead of scanning it', async () => {
    const steward = await session(firmKey, 'auth0|steward');
    const row = (index: number) => ({ organizationId: ORG, memberId: hex(0xa000 + index), subject: `auth0|bulk-${index}`,
      providerOrganizationId: 'org_firm', state: 'approved' });
    const list = jest.spyOn(firm, 'listFirmDevices');
    try {
      // At the bound (2 x FIRM_DEVICE_LIMIT) the count still answers; unverifiable rows never count.
      list.mockResolvedValue(Array.from({ length: 128 }, (_, index) => row(index)) as never);
      await expect(readFirmSetup(steward, Date.now())).resolves.toMatchObject({ holders: expect.any(Number) });
      // One row past it is refused outright, like legalFirm's own device reader.
      list.mockResolvedValue(Array.from({ length: 129 }, (_, index) => row(index)) as never);
      await expect(readFirmSetup(steward, Date.now())).rejects.toThrow();
    } finally { list.mockRestore(); }
  });
  test('organization setup requires signed terms; a sole holder may proceed and reporter grants still apply', async () => {
    const steward = await session(firmKey, 'auth0|steward');
    const directory = await readLegalDirectory(steward, null, Date.now());
    const listing = directory.listings.find(item => item.caseId === prepared.caseId)!;
    // Isolate this negative case from every member enrolled by earlier device tests.
    const savedMembers = new Map(members);
    const secondKey = 'org_firm/auth0|second', second = members.get(secondKey)!;
    for (const [key, member] of members) if (member.subject !== 'auth0|steward') {
      members.set(key, { ...member, active: false, revision: member.revision + 1 });
    }
    firm.setup.delete(ORG);
    /** A signed firm case operation sent as-is (no client-side pre-check). */
    const firmCall = async (operation: 'request-access' | 'read-state-keys', value: unknown) => {
      const raw = encode(value);
      // Challenges are single-use and bound to the session that issued them.
      const nonce = randomBytes(32).toString('hex'), evidence = await relay.open(nonce);
      const serverKey = await readKey({ binaryKey: evidence.publicKey });
      const asked = await sealChannelRequest(serverKey, nonce, encode({ operation: 'legal.challenge' }));
      const { challenge } = JSON.parse(new TextDecoder().decode(await asked.openResponse(await relay.call(nonce, asked.ciphertext, false))));
      const proof = await signParticipantRequest({ audience: AUDIENCE, role: 'organization', caseId: prepared.caseId, organizationId: ORG,
        operation, body: raw, challenge, issuedAt: Date.now(), nonce, serverKeyId: await caseRecipientKeyId(serverKey) }, firmKey);
      const sealed = await sealChannelRequest(serverKey, nonce, encode({ operation: `legal.${operation}`, accessToken: await token('auth0|steward'),
        proof, body: Buffer.from(raw).toString('base64') }));
      return JSON.parse(new TextDecoder().decode(await sealed.openResponse(await relay.call(nonce, sealed.ciphertext))));
    };
    try {
      await expect(readFirmSetup(steward, Date.now())).resolves.toEqual({ complete: false, missing: ['terms'], custody: null,
        holders: 1, custodyAttestedAt: null, terms: null, termsVersion: FIRM_ONBOARDING_TERMS_VERSION });
      // Refused by the enclave itself, before the case service sees the request: nothing is stored.
      const before = backing.dump();
      await expect(firmCall('request-access', { caseId: prepared.caseId, requestId: hex(0x901), ciphertext: '-----BEGIN PGP MESSAGE-----',
        expiresAt: Date.now() + 86_400_000 })).resolves.toEqual({ error: 'setup-incomplete', missing: ['terms'] });
      await expect(firmCall('read-state-keys', { caseId: prepared.caseId })).resolves.toEqual({ error: 'setup-incomplete', missing: ['terms'] });
      expect(backing.dump()).toBe(before);
      // The portal checks first and stops before saving anything, naming the missing steps.
      const refused = await assertFirmSetupComplete(steward, Date.now()).catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(FirmCaseError);
      expect(refused).toMatchObject({ code: 'setup-incomplete', missing: ['terms'] });
      expect((refused as Error).message).toMatch(/Acknowledge the onboarding terms under Organization setup/);
      // Sent anyway, the enclave refuses it and the client reports the same steps.
      await expect(requestCaseAccess(steward, listing, { purpose: 'Counsel review', scopes: ['narrative'], details: DETAILS }, Date.now()))
        .rejects.toMatchObject({ code: 'setup-incomplete', missing: ['terms'] });

      // Statements not signed by the registered organization key are refused, and a host row holding one reads as missing.
      const organization = { organizationId: ORG, recipientKeyId: org.recipientKeyId };
      const setupRecord = async (kind: 'custody' | 'terms', statement: string) => exchange({ operation: 'legal.setup-record',
        accessToken: await token('auth0|steward'), body: Buffer.from(encode({ organizationId: ORG, kind, statement })).toString('base64') });
      const foreignTerms = await signFirmSetupStatement({ format: 'vera-legal-onboarding-terms/v1',
        organizationId: ORG, recipientKeyId: await caseRecipientKeyId(attacker.toPublic()), termsVersion: FIRM_ONBOARDING_TERMS_VERSION,
        termsDigest: await firmOnboardingTermsDigest(), acknowledgedAt: Date.now() }, attacker);
      await expect(setupRecord('terms', foreignTerms)).rejects.toThrow();
      const genuine = await signFirmSetupStatement({ format: 'vera-legal-onboarding-terms/v1', ...organization,
        termsVersion: FIRM_ONBOARDING_TERMS_VERSION, termsDigest: await firmOnboardingTermsDigest(), acknowledgedAt: Date.now() }, firmKey);
      const tampered = JSON.parse(genuine);
      tampered.statement.termsVersion = FIRM_ONBOARDING_TERMS_VERSION + 1;
      await expect(setupRecord('terms', JSON.stringify(tampered))).rejects.toThrow();
      await expect(setupRecord('custody', genuine)).rejects.toThrow(); // A terms statement is not a custody attestation.
      firm.setup.set(ORG, { custody: null, terms: foreignTerms });
      await expect(readFirmSetup(steward, Date.now())).resolves.toMatchObject({ missing: ['terms'] });

      // Terms suffice without a second holder; the reporter grant remains required.
      await expect(recordFirmSetup(steward, 'terms', Date.now())).resolves.toMatchObject({ complete: true, missing: [], custody: null,
        terms: { version: FIRM_ONBOARDING_TERMS_VERSION, acknowledgedAt: expect.any(Number) } });
      await expect(firmCall('read-state-keys', { caseId: prepared.caseId })).resolves.toEqual({ error: 'not-granted' });
      // Every member sees the organization's record: another member's session is not asked again.
      members.set(secondKey, { ...second, active: true, revision: second.revision + 2 });
      await expect(readFirmSetup(await session(firmKey, 'auth0|second'), Date.now())).resolves.toMatchObject({ terms: { version: FIRM_ONBOARDING_TERMS_VERSION } });
      members.set(secondKey, { ...second, active: false, revision: second.revision + 3 });

      // Optional custody still requires a genuine key-signed attestation.
      await expect(recordFirmSetup(steward, 'custody', Date.now())).resolves.toMatchObject({ complete: true, missing: [], custody: 'attested' });
      await expect(firmCall('read-state-keys', { caseId: prepared.caseId })).resolves.toEqual({ error: 'not-granted' });
      firm.setup.delete(ORG);

      // Without an attestation, a second enrolled person holding the key on their own device satisfies custody.
      // Alice's approved device row nominates her; her enrollment proof signed by the organization key counts.
      await recordFirmSetup(steward, 'terms', Date.now());
      await expect(readFirmSetup(steward, Date.now())).resolves.toMatchObject({ complete: true, holders: 1, missing: [], custody: null });
      await enroll('auth0|alice', firmKey);
      await expect(readFirmSetup(steward, Date.now())).resolves.toMatchObject({ complete: true, custody: 'members', holders: 2, custodyAttestedAt: null });
      // A device row whose member is not enrolled for this key does not count.
      const alice = members.get('org_firm/auth0|alice')!;
      members.set('org_firm/auth0|alice', { ...alice, active: false, revision: alice.revision + 1 });
      await expect(readFirmSetup(steward, Date.now())).resolves.toMatchObject({ complete: true, holders: 1, custody: null });
      members.set('org_firm/auth0|alice', { ...alice, revision: alice.revision + 2 });
    } finally {
      for (const [key, member] of savedMembers) {
        members.set(key, { ...member, revision: (members.get(key)?.revision ?? member.revision) + 1 });
      }
    }
    await expect(readFirmSetup(steward, Date.now())).resolves.toMatchObject({ complete: true, custody: 'members' });
  }, 180_000);

  test('removal deactivates the member now; rotation re-keys only remaining devices, the list moves, owners must allow again', async () => {
    // Bob is an enrolled lawyer with an approved device; Alice (approved above) stays.
    await enroll('auth0|bob', firmKey);
    const { device: bobDevice } = await join('auth0|bob', 'Synthetic Bob');
    const steward = await session(firmKey, 'auth0|steward');
    const bobPending = (await listMemberDevices(steward, Date.now())).find(item => item.profile?.name === 'Synthetic Bob')!;
    await approveMemberDevice(steward, bobPending, 1, Date.now());
    const bob = await session(firmKey, 'auth0|bob');
    await expect(readLegalDirectory(bob, null, Date.now())).resolves.toMatchObject({ listings: [expect.objectContaining({
      caseId: prepared.caseId, publishedAt: expect.any(Number), hasAttachments: false,
    })] });

    // Before the rotation the firm (old key) holds a grant from the reporter.
    const directory = await readLegalDirectory(steward, null, Date.now());
    const listing = directory.listings.find(item => item.caseId === prepared.caseId)!;
    const oldRequest = await requestCaseAccess(steward, listing, { purpose: 'Counsel review', scopes: ['narrative', 'messages'], details: DETAILS }, Date.now());
    let owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    let inbox = await readOwnerInbox(owner, Date.now());
    let roster = await verifiedRoster(owner, Date.now());
    const [first] = await verifiedRequests(owner, inbox, roster, Date.now());
    await allowAccess(owner, inbox, roster, first, { grantId: first.delivery.requestId, scopes: ['narrative', 'messages'],
      objectRevisionLimit: null, expiresAt: Date.now() + 86_400_000 }, Date.now());
    await expect(openFirmCase(steward, prepared.caseId, Date.now())).resolves.toMatchObject({ narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE' } });

    // Remove Bob: his device loses its envelope and his membership stops at once.
    const devices = await listMemberDevices(steward, Date.now());
    await removeMemberDevice(steward, devices.find(item => item.profile?.name === 'Synthetic Bob')!, Date.now());
    await expect(readLegalDirectory(bob, null, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    expect(await status('auth0|bob')).toMatchObject({ state: 'removed', envelope: null, keyEpoch: 1 });
    // Bob held the current key: until the key is replaced his removal shows as unfinished.
    expect(unfinishedRemovals(await listMemberDevices(steward, Date.now()), 1).map(item => item.profile?.name)).toEqual(['Synthetic Bob']);
    // A removed device cannot be removed again (stale revision or state).
    await expect(removeMemberDevice(steward, devices.find(item => item.profile?.name === 'Synthetic Bob')!, Date.now()))
      .rejects.toBeInstanceOf(FirmMemberError);

    // Declining a request that never held a key needs no rotation.
    await enroll('auth0|dave', firmKey);
    await join('auth0|dave', 'Synthetic Dave');
    const davePending = (await listMemberDevices(steward, Date.now())).find(item => item.profile?.name === 'Synthetic Dave')!;
    await removeMemberDevice(steward, davePending, Date.now());
    expect(await status('auth0|dave')).toMatchObject({ state: 'removed', envelope: null, keyEpoch: null });
    expect(unfinishedRemovals(await listMemberDevices(steward, Date.now()), 1).map(item => item.profile?.name)).toEqual(['Synthetic Bob']);
    // A declined lawyer's enrolled membership stops too.
    await expect(readLegalDirectory(await session(firmKey, 'auth0|dave'), null, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);

    // A continuity from a key other than the registered one is refused.
    const forged = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: Date.now() }, attacker);
    const raw = encode({ organizationId: ORG, continuity: forged.continuity, envelopes: [{ memberId: await firmMemberId('org_firm', 'auth0|alice'),
      expectedRevision: 2, envelope: '-----BEGIN PGP MESSAGE-----' }] });
    const { challenge } = await exchange({ operation: 'legal.challenge' });
    const nonce = randomBytes(32).toString('hex'), evidence = await relay.open(nonce);
    const serverKey = await readKey({ binaryKey: evidence.publicKey });
    const proof = await signParticipantRequest({ audience: AUDIENCE, role: 'organization', caseId: ORG, organizationId: ORG,
      operation: 'manage-members', body: raw, challenge, issuedAt: Date.now(), nonce, serverKeyId: await caseRecipientKeyId(serverKey) }, firmKey);
    const sealed = await sealChannelRequest(serverKey, nonce, encode({ operation: 'legal.members-rotate', accessToken: await token('auth0|steward'),
      proof, body: Buffer.from(raw).toString('base64') }));
    await expect(relay.call(nonce, sealed.ciphertext).then(reply => sealed.openResponse(reply))).rejects.toThrow();

    // Rotate: new key, continuity naming Bob, envelopes for remaining devices only.
    const bobId = await firmMemberId('org_firm', 'auth0|bob');
    const rotation = await rotateOrganizationAfterRemoval(steward, { keyEpoch: 1, removedMemberIds: [bobId],
      devices: await listMemberDevices(steward, Date.now()) }, Date.now());
    expect(rotation.missed).toEqual([]);
    expect(rotation.statement).toMatchObject({ previousKeyEpoch: 1, keyEpoch: 2, removedMemberIds: [bobId], ownerApproval: 'required' });
    const next = rotation.next.privateKey;
    const alice = await status('auth0|alice');
    expect(alice).toMatchObject({ state: 'approved', keyEpoch: 2 });
    expect(await status('auth0|bob')).toMatchObject({ state: 'removed', envelope: null, keyEpoch: 1 });
    expect([...firm.devices.values()].filter(item => item.keyEpoch === 2)).toHaveLength(2); // Alice and Carol.
    expect(unfinishedRemovals(await listMemberDevices(steward, Date.now()), 2)).toEqual([]);
    // Bob was removed but still holds the old organization key. With a cooperating host he writes Carol's
    // row: a continuity signed by the old key naming his own key, and an envelope from his key. Carol's
    // device must not adopt it: only the key the approved registration confirms can be installed.
    const carolRow = firm.devices.get(`${ORG}/${carol.memberId}`)!;
    const rogue = await rotateOrganizationKey({ organizationId: ORG, previousKeyEpoch: 1, removedMemberIds: [], issuedAt: Date.now() }, firmKey);
    firm.devices.set(`${ORG}/${carol.memberId}`, { ...carolRow, continuity: rogue.continuity, keyEpoch: 2,
      envelope: await wrapOrganizationKeyForMember({ organizationId: ORG, memberId: carol.memberId, keyEpoch: 2, issuedAt: Date.now() },
        rogue.organizationKey, carol.device.toPublic(), rogue.organizationKey) });
    const forgedRow = await status('auth0|carol');
    expect(forgedRow).toMatchObject({ state: 'approved', keyEpoch: 2 });
    // The approved registration still names the old key: nothing new is installed yet.
    await expect(openApprovedDevice(forgedRow, { organizationId: ORG, device: carol.device, minimumKeyEpoch: 1, held: firmKey.toPublic(),
      published: async () => firmKey.toPublic() })).rejects.toMatchObject({ code: 'not-confirmed' });
    await expect(openApprovedDevice(forgedRow, { organizationId: ORG, device: carol.device, minimumKeyEpoch: 1, held: firmKey.toPublic(),
      published: async () => { throw new FirmMemberError('domain-unverified'); } })).rejects.toMatchObject({ code: 'not-confirmed' });
    // Once the registration approves the genuine new key, the rogue envelope does not match it.
    await expect(openApprovedDevice(forgedRow, { organizationId: ORG, device: carol.device, minimumKeyEpoch: 1, held: firmKey.toPublic(),
      published: async () => next.toPublic() })).rejects.toMatchObject({ code: 'key-mismatch' });
    // The saved workspace keeps its current key and epoch, and says why.
    const carolDeps = { ...carol.deps, published: async () => next.toPublic() };
    const kept = await openLegalWorkspace(clone(carol.saved), carolDeps, null);
    expect(kept.session.firm.privateKey.getFingerprint()).toBe(firmKey.getFingerprint());
    expect(currentFirmDevice()).toMatchObject({ memberId: carol.memberId, keyEpoch: 1 });
    expect(kept.notice).toMatch(/does not match the approved organization key/);
    const waiting = await openLegalWorkspace(clone(carol.saved), { ...carol.deps, published: async () => firmKey.toPublic() }, null);
    expect(waiting.session.firm.privateKey.getFingerprint()).toBe(firmKey.getFingerprint());
    expect(waiting.notice).toMatch(/new key has not been approved/);
    firm.devices.set(`${ORG}/${carol.memberId}`, carolRow);
    // A new key cannot renew membership before its registration is approved.
    await expect(openLegalWorkspace(clone(carol.saved), carolDeps, null)).rejects.toThrow();

    // Alice's device holds the old key: it installs the new key only once the registration approves it,
    // and shows the continuity (verified from the key it held) as evidence.
    await expect(openApprovedDevice(alice, { organizationId: ORG, device: aliceDevice, minimumKeyEpoch: 1, held: firmKey.toPublic(),
      published: async () => firmKey.toPublic() })).rejects.toMatchObject({ code: 'not-confirmed' });
    const upgraded = await openApprovedDevice(alice, { organizationId: ORG, device: aliceDevice, minimumKeyEpoch: 1, held: firmKey.toPublic(),
      published: async () => next.toPublic() });
    expect(upgraded.organizationKey.getFingerprint()).toBe(next.getFingerprint());
    expect(upgraded.continuity?.removedMemberIds).toEqual([bobId]);
    // A device that missed the continuity (held an older key) still opens from the approved registration, without evidence.
    await expect(openApprovedDevice(alice, { organizationId: ORG, device: aliceDevice, minimumKeyEpoch: 1, held: attacker.toPublic(),
      published: async () => next.toPublic() })).resolves.toMatchObject({ continuity: null, keyEpoch: 2 });
    // The envelope cannot be replayed to a device that already has epoch 2, and Bob's device gets nothing.
    await expect(openApprovedDevice(alice, { organizationId: ORG, device: aliceDevice, minimumKeyEpoch: 2, held: next.toPublic(),
      published: async () => next.toPublic() }))
      .rejects.toBeInstanceOf(FirmMemberError);
    await expect(openApprovedDevice(await status('auth0|bob'), { organizationId: ORG, device: bobDevice, minimumKeyEpoch: 1,
      held: firmKey.toPublic(), published: async () => next.toPublic() })).rejects.toMatchObject({ code: 'not-approved' });

    // The shared list moves to the new key; old-key devices can no longer read it.
    const moved = await moveSharedListToKey(steward, 3, { next, continuity: rotation.continuity, keyEpoch: 2 }, Date.now());
    expect(moved.list.keyEpoch).toBe(2);
    await expect(readSharedList(bob, 0, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError); // Bob is no longer a member.
    await expect(readSharedList(await session(firmKey, 'auth0|second'), 0, Date.now())).rejects.toBeInstanceOf(FirmSharedListKeyChanged);
    const onNewKey = await session(next, 'auth0|second');
    await expect(readSharedList(onNewKey, 0, Date.now())).resolves.toMatchObject({ previousKeySigned: true, list: { keyEpoch: 2 } });
    // Until VERA registers the new key, the new key authorizes nothing.
    await expect(readLegalDirectory(onNewKey, null, Date.now())).resolves.toBeDefined(); // Directory needs membership only.
    await expect(requestCaseAccess(onNewKey, listing, { purpose: 'x', scopes: ['narrative'], details: DETAILS }, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);

    // VERA onboarding registers the new key; the remaining lawyer accepts a new invitation.
    await register(next);
    const rekeyed = await openLegalWorkspace(clone(carol.saved), carolDeps, null);
    expect(rekeyed.session.firm.privateKey.getFingerprint()).toBe(next.getFingerprint());
    expect(currentFirmDevice()).toMatchObject({ memberId: carol.memberId, keyEpoch: 2 });
    expect(rekeyed.notice).toMatch(/now holds the new one/);
    await enroll('auth0|steward', next);
    const renewed = await session(next, 'auth0|steward');
    // Setup statements are bound to the key they were signed with: the new key records them again.
    // Carol's approved device and the steward now both prove possession of the new key.
    // Their membership satisfies custody, but the old key's statements do not carry over.
    await expect(readFirmSetup(renewed, Date.now())).resolves.toMatchObject({ complete: false, missing: ['terms'], holders: 2,
      custody: 'members', custodyAttestedAt: null, terms: null });
    await recordFirmSetup(renewed, 'custody', Date.now());
    await expect(recordFirmSetup(renewed, 'terms', Date.now())).resolves.toMatchObject({ complete: true });
    // The old grant names the old key: the case does not open with the new key.
    await expect(openFirmCase(renewed, prepared.caseId, Date.now())).rejects.toBeDefined();

    // Ask the reporter again (the old pending request is closed first).
    renewed.owners.set(prepared.caseId, listing.owner!);
    await withdrawCaseRequest(renewed, prepared.caseId, oldRequest.requestId, Date.now());
    await requestCaseAccess(renewed, listing, { purpose: 'Our organization replaced its key.', scopes: ['narrative', 'messages'], details: { ...DETAILS, kind: 'renewal' } }, Date.now());

    owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    inbox = await readOwnerInbox(owner, Date.now());
    roster = await verifiedRoster(owner, Date.now());
    const [renewal] = await verifiedRequests(owner, inbox, roster, Date.now());
    expect(renewal.request.recipientKeyId).toBe(rotation.statement.nextRecipientKeyId);
    // The reporter's device recognises that this organization's access is under a replaced key.
    expect(await replacedKeyGrant(owner, inbox, roster, ORG)).not.toBeNull();
    // An approval withdrawn before Allow must not receive new case keys.
    const registeredOrganization = organizations.get(ORG)!;
    organizations.set(ORG, { ...registeredOrganization, approved: false });
    const refused = await allowAccess(owner, inbox, roster, renewal, { grantId: renewal.delivery.requestId, scopes: ['narrative'],
      objectRevisionLimit: null, expiresAt: null }, Date.now()).catch((error: Error) => error);
    expect(refused).toMatchObject({ name: 'OrganizationKeyUnconfirmedError', operation: 'allow', reason: 'failed' });
    expect((refused as Error).message).toMatch(/was not allowed\. Nothing was shared\./);
    organizations.set(ORG, registeredOrganization);
    const unchanged = await readOwnerInbox(owner, Date.now());
    expect(unchanged.checkpointDigest).toBe(inbox.checkpointDigest);
    expect(await replacedKeyGrant(owner, unchanged, roster, ORG)).not.toBeNull();
    await allowAccess(owner, inbox, roster, renewal, { grantId: renewal.delivery.requestId, scopes: ['narrative', 'messages'],
      objectRevisionLimit: null, expiresAt: Date.now() + 86_400_000 }, Date.now());

    // Only the new key holds a grant now, and the state key was rotated away from the old key.
    inbox = await readOwnerInbox(owner, Date.now());
    const grantees = await currentGrantees(owner, inbox, roster);
    expect(grantees).toHaveLength(1);
    expect(grantees[0].grants.map(grant => grant.recipientKeyId)).toEqual([rotation.statement.nextRecipientKeyId]);
    const record = await backing.getCase(prepared.caseId);
    await expect(findCaseStateKey(record!.stateEnvelopes!, prepared.caseId, firmKey, prepared.owner.trust.ownerPublicKey)).rejects.toThrow();
    await expect(findCaseStateKey(record!.stateEnvelopes!, prepared.caseId, next, prepared.owner.trust.ownerPublicKey)).resolves.toBeDefined();
    const reopened = await openFirmCase(renewed, prepared.caseId, Date.now());
    expect(reopened.narrative).toEqual({ description: 'PRIVATE-SENTINEL-NARRATIVE' });
    const checkpoint = await verifyOwnerStatement(inbox.checkpoint, prepared.owner.trust);
    expect(checkpoint.statement.kind).toBe('checkpoint');
  }, 240_000);

  test('a key VERA substitutes for a registered firm opens nothing already shared, and the reporter must allow it explicitly', async () => {
    const legitimate = organizations.get(ORG)!;
    const substitutedKeyId = await caseRecipientKeyId(attacker.toPublic());
    try {
      // Everything VERA controls at once: its host rows, an onboarding-signed
      // registration of its own key for this firm, and an onboarding-signed membership.
      await register(attacker);
      await enroll('auth0|mallory', attacker);
      const mallory = await session(attacker, 'auth0|mallory');
      // The authority also controls this substituted key and can sign its setup statements.
      // Even after satisfying setup, it must not gain the reporter's existing grants.
      await recordFirmSetup(mallory, 'custody', Date.now());
      await recordFirmSetup(mallory, 'terms', Date.now());
      // Existing access names the firm's real key: the substituted key opens nothing.
      await expect(openFirmCase(mallory, prepared.caseId, Date.now())).rejects.toBeDefined();
      const record = await backing.getCase(prepared.caseId);
      await expect(findCaseStateKey(record!.stateEnvelopes!, prepared.caseId, attacker, prepared.owner.trust.ownerPublicKey)).rejects.toThrow();

      // The reporter's device sees the changed key and never re-wraps anything to it.
      const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
      let inbox = await readOwnerInbox(owner, Date.now());
      const roster = await verifiedRoster(owner, Date.now());
      const grantees = await currentGrantees(owner, inbox, roster);
      expect(grantees).toHaveLength(1);
      expect(grantees[0].organization).toBeNull();
      expect(grantees[0].grants.every(grant => grant.recipientKeyId !== substitutedKeyId)).toBe(true);
      expect(await replacedKeyGrant(owner, inbox, roster, ORG)).not.toBeNull();
      await expect(renewAccess(owner, inbox, roster, grantees[0], null, Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
      // Replies would be sealed to the substituted key: the thread is read-only.
      const threads = await readOwnerThreads(owner, inbox, roster, [], grantees);
      for (const thread of threads.filter(item => item.organization.organizationId === ORG)) {
        expect(thread.canSend).toBe(false);
        await expect(sendOwnerMessage(owner, thread, 'PRIVATE-SENTINEL-REPLY', Date.now())).rejects.toBeInstanceOf(ConfidentialUnavailableError);
      }
      expect(backing.dump()).not.toContain('PRIVATE-SENTINEL-REPLY');

      // A request signed by the substituted key reaches the reporter only as a
      // changed key for this organization, which needs an explicit Allow.
      const directory = await readLegalDirectory(mallory, null, Date.now());
      const listing = directory.listings.find(item => item.caseId === prepared.caseId)!;
      mallory.owners.set(prepared.caseId, listing.owner!);
      await requestCaseAccess(mallory, listing, { purpose: 'Our organization replaced its key.', scopes: ['narrative'],
        details: { ...DETAILS, kind: 'renewal' } }, Date.now());
      inbox = await readOwnerInbox(owner, Date.now());
      const [substituted] = await verifiedRequests(owner, inbox, roster, Date.now());
      expect(substituted.request.recipientKeyId).toBe(substitutedKeyId);
      expect(await replacedKeyGrant(owner, inbox, roster, ORG)).not.toBeNull();
    } finally { organizations.set(ORG, legitimate); }
  }, 240_000);
});
